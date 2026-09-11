package main

// Data-plane wiring: build serving identities from the enrollment certs, start the controller's
// gateway + Link sink, and run the worker's inference engine + endpoint. Keeps run.go readable.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/audit"
	"dani.local/agent/internal/config"
	"dani.local/agent/internal/controller"
	"dani.local/agent/internal/engine"
	"dani.local/agent/internal/identity"
	"dani.local/agent/internal/ingest"
	"dani.local/agent/internal/limits"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/internal/node"
	"dani.local/agent/internal/policy"
	"dani.local/agent/internal/secret"
	"dani.local/agent/internal/serving"
	"dani.local/agent/internal/signerprovider"
	"dani.local/agent/internal/training"
)

// controllerIdentity adapts the genesis controller's cert material to the data plane.
func controllerIdentity(c *controller.Controller) serving.Identity {
	return serving.Identity{
		LeafRaw: c.Cert.Raw, InterRaw: c.CA.Intermediate.Raw, Key: c.Key, Root: c.CA.Root, UUID: c.ID,
	}
}

// nodeIdentity adapts an enrolled node's installed identity to the data plane.
func nodeIdentity(id *node.Identity) serving.Identity {
	var inter, root *x509.Certificate
	for _, c := range id.CABundle {
		if c.Subject.String() == c.Issuer.String() {
			root = c
		} else {
			inter = c
		}
	}
	si := serving.Identity{LeafRaw: id.Cert.Raw, Key: id.Key, UUID: id.Cert.Subject.CommonName}
	if inter != nil {
		si.InterRaw = inter.Raw
	}
	si.Root = root
	return si
}

// openRegistry builds the Artifact Store + Model Registry (durable when stateDir is set). Hoisted out
// of buildTrainingAPI so the Raft cluster can be given the SAME model registry as its FSM sink BEFORE
// the data plane starts. signerSpecs, when non-empty, backs each reviewer role with its configured
// custodian (kms / file:<path> / remote:<url> — three-party control); empty = the DEMO shared-KMS
// default (all three in ctrl.KS).
func openRegistry(ctrl *controller.Controller, artifactDir, storeSpec string, gate modelreg.EvalGate, stateDir string, signerSpecs map[modelreg.Role]string) (*artifact.Store, *modelreg.Registry, error) {
	if artifactDir == "" {
		dir, err := os.MkdirTemp("", "dani-artifacts-*")
		if err != nil {
			return nil, nil, err
		}
		artifactDir = dir
	}
	// storeSpec picks the backend (fs default, or azblob:<url>?<sas> shared across HA controllers);
	// artifactDir is the fs dir / the local materialization cache for a remote backend.
	store, err := artifact.OpenSpec(storeSpec, artifactDir)
	if err != nil {
		return nil, nil, err
	}
	models := modelreg.New(ctrl.KS, store).SetGate(gate)
	if len(signerSpecs) > 0 { // three-party control: each reviewer role gets its configured custodian
		signers, err := signerprovider.BuildAll(signerSpecs, ctrl.KS)
		if err != nil {
			return nil, nil, err
		}
		models.WithRoleSigners(signers)
	}
	if stateDir != "" { // durable registry: promoted models survive a controller restart (D-14 #2)
		if _, err := models.SetDurable(filepath.Join(stateDir, "models.json")); err != nil {
			return nil, nil, err
		}
	}
	if err := models.InitSigners(context.Background()); err != nil {
		return nil, nil, err
	}
	return store, models, nil
}

// buildTrainingAPI wires the train->sign->serve control surface: Identity (D39), Ingest
// (classify-at-ingest), the KMS-signed Model Registry (D25), and the Training Subsystem with real
// D17 allocation (live trainer heartbeats joined with Node Registry roles). Jobs execute REMOTELY on
// the allocated trainer node when one is live; otherwise the controller's local Trainer runs them —
// the stub (paced for console progress) or, with trainerExec set (quote-aware; e.g.
// `"C:/Program Files/Python/python.exe" train_qlora.py`), a REAL fine-tune on this machine.
// connectorOpts configures the real Azure Blob data connector (P1-6).
type connectorOpts struct {
	url        string // container URL; empty = connector off
	sasRef     string // SAS as a secret reference (env:/file:) — resolved here, never logged
	collection string
	classMap   string // "prefix=class,prefix=class"
	syncEvery  time.Duration

	// folder connector (filesystem / mounted SMB-NFS share)
	folderPath       string
	folderCollection string
	folderClassMap   string
	folderSyncEvery  time.Duration

	// git connector (RAG over a repository; file@commit lineage)
	gitURL        string
	gitRef        string
	gitTokenRef   string // secret reference (env:/file:) — resolved here, never logged
	gitCollection string
	gitClassMap   string
	gitSyncEvery  time.Duration
}

// startStaticConnector runs a FLAG-configured source through the same lifecycle console-connected
// ones use (StartConnector: register + boot sync + optional ticker + status row) — marked Static so
// the console lists it but cannot remove it (its truth lives in the process invocation).
func startStaticConnector(ing *ingest.Subsystem, def ingest.ConnectorDef) error {
	def.Static = true
	return ing.StartConnector(context.Background(), def)
}

// parseClassMap turns "hr/=internal,finance/=restricted" into the prefix map.
func parseClassMap(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		if pair = strings.TrimSpace(pair); pair == "" {
			continue
		}
		prefix, class, ok := strings.Cut(pair, "=")
		if !ok || class == "" {
			return nil, fmt.Errorf("class map entry %q: want prefix=classification", pair)
		}
		out[prefix] = class
	}
	return out, nil
}

func buildTrainingAPI(ctrl *controller.Controller, plane *serving.Plane, aud *audit.Log, store *artifact.Store, models *modelreg.Registry, pace time.Duration, trainerExec, embedBase, embedModel, ingestDSN string, conn connectorOpts, pol *policy.Engine, stateDir string) (*serving.TrainingAPI, error) {
	ident := identity.New("entra-id")
	// Reviewer principals for real three-party control: each officer role belongs to a DIFFERENT
	// person; under --console-auth an operator can only sign as a role their identity holds.
	ident.Add(identity.Principal{Sub: "dana", Display: "Dana (Security Officer)", Roles: []string{"user", "security-officer"}, Clearance: "secret"})
	ident.Add(identity.Principal{Sub: "erin", Display: "Erin (Governance Officer)", Roles: []string{"user", "governance-officer"}, Clearance: "secret"})
	ident.Add(identity.Principal{Sub: "bob", Display: "Bob (Administrator)", Roles: []string{"user", "admin", "administrator"}, Clearance: "secret"})
	ing := ingest.New()
	ing.SetGitCacheRoot(stateDir) // git working clones live under the controller state dir
	if embedBase != "" { // REAL embeddings via an OpenAI-compatible upstream (Ollama / llama.cpp)
		ing.WithEmbedder(ingest.OpenAIEmbedder{BaseURL: embedBase, Model: embedModel})
	}
	if ingestDSN != "" { // P1-1: datasets + RAG embeddings persist (and rehydrate right here at boot)
		st, err := ingest.OpenStore(context.Background(), ingestDSN)
		if err != nil {
			return nil, err
		}
		if _, err := ing.WithStore(context.Background(), st); err != nil {
			return nil, err
		}
		log.Printf("controller: durable ingest ON — datasets + RAG indexes at %s", secret.RedactDSN(ingestDSN))
	}
	if conn.url != "" { // P1-6: the REAL Azure Blob data connector (credentialed, incremental)
		sas, err := secret.Resolve(conn.sasRef)
		if err != nil {
			return nil, fmt.Errorf("azblob connector SAS: %w", err)
		}
		if sas == "" {
			return nil, fmt.Errorf("azblob connector: --ingest-azblob-sas is required (env:VAR or file:/path)")
		}
		if secret.IsLiteral(conn.sasRef) {
			log.Printf("controller: WARNING — azblob SAS passed as a literal flag; use --ingest-azblob-sas=env:VAR or file:/path in production")
		}
		classMap, err := parseClassMap(conn.classMap)
		if err != nil {
			return nil, fmt.Errorf("azblob connector: %w", err)
		}
		if err := startStaticConnector(ing, ingest.ConnectorDef{
			Kind: "azblob", Collection: conn.collection, URL: conn.url, Secret: sas,
			ClassMap: classMap, SyncEvery: conn.syncEvery,
		}); err != nil {
			return nil, err
		}
		log.Printf("controller: azblob connector ON — %s -> collection %q (SAS %s)", conn.url, conn.collection, secret.Redact(sas))
	}
	if conn.folderPath != "" { // the filesystem / shared-drive connector (files stay where they live)
		classMap, err := parseClassMap(conn.folderClassMap)
		if err != nil {
			return nil, fmt.Errorf("folder connector: %w", err)
		}
		if fi, err := os.Stat(conn.folderPath); err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("folder connector: --ingest-folder %q is not a readable directory", conn.folderPath)
		}
		if err := startStaticConnector(ing, ingest.ConnectorDef{
			Kind: "folder", Collection: conn.folderCollection, Path: conn.folderPath,
			ClassMap: classMap, SyncEvery: conn.folderSyncEvery,
		}); err != nil {
			return nil, err
		}
		log.Printf("controller: folder connector ON — %s -> collection %q", conn.folderPath, conn.folderCollection)
	}
	if conn.gitURL != "" { // the git connector (file@commit lineage; the repo is DATA, never executed)
		classMap, err := parseClassMap(conn.gitClassMap)
		if err != nil {
			return nil, fmt.Errorf("git connector: %w", err)
		}
		token := ""
		if conn.gitTokenRef != "" {
			if token, err = secret.Resolve(conn.gitTokenRef); err != nil {
				return nil, fmt.Errorf("git connector token: %w", err)
			}
			if secret.IsLiteral(conn.gitTokenRef) {
				log.Printf("controller: WARNING — git token passed as a literal flag; use --ingest-git-token=env:VAR or file:/path in production")
			}
		}
		if err := startStaticConnector(ing, ingest.ConnectorDef{
			Kind: "git", Collection: conn.gitCollection, URL: conn.gitURL, Ref: conn.gitRef, Secret: token,
			ClassMap: classMap, SyncEvery: conn.gitSyncEvery,
		}); err != nil {
			return nil, err
		}
		log.Printf("controller: git connector ON — %s (ref %q) -> collection %q", conn.gitURL, conn.gitRef, conn.gitCollection)
	}
	// console-connected sources persisted in the ingest store come back to life here, each resuming
	// from its durable incremental cursor.
	if n, err := ing.RehydrateConnectors(context.Background()); err != nil {
		log.Printf("controller: connector rehydration: %v", err)
	} else if n > 0 {
		log.Printf("controller: rehydrated %d console-connected source(s)", n)
	}
	var local training.Trainer = training.StubTrainer{}
	if pace > 0 {
		local = training.PacedTrainer{Inner: local, Delay: pace}
	}
	if trainerExec != "" {
		parts := training.SplitCommand(trainerExec)                     // quote-aware: paths with spaces work
		local = training.ExecTrainer{Script: parts[0], Args: parts[1:]} // real fine-tune; no pacing
	}
	var auditHook func(string, map[string]any)
	if aud != nil {
		auditHook = func(typ string, payload map[string]any) { _ = aud.Emit(typ, payload) }
	}
	sub := training.New(training.Deps{
		Identity: serving.IdentAdapter{B: ident},
		Data:     serving.IngestAdapter{S: ing},
		Fleet:    serving.PlaneRegistryFleet{Plane: plane, Reg: ctrl.Registry},
		Registry: models,
		Store:    store,
		Trainer:  training.DispatchTrainer{Local: local, Remote: training.RemoteTrainer{Client: plane.Dialer()}},
		Audit:    auditHook,
	})
	api := &serving.TrainingAPI{Ident: ident, Ingest: ing, Models: models, Training: sub, Store: store, Audit: aud, Policy: pol}
	if stateDir != "" {
		api.Deploys = serving.NewDurableDeployments(filepath.Join(stateDir, "deployments.json"))
	}
	return api, nil
}

// startControllerPlane brings up the Link heartbeat sink + OpenAI gateway and persists heartbeats
// into the Node Registry.
func startControllerPlane(ctrl *controller.Controller, aud *audit.Log, gatewayAddr, linkAddr, site, wgEndpoint, wgConfOut string, store *artifact.Store, models *modelreg.Registry, trainPace time.Duration, trainerExec, embedBase, embedModel, translateBase, ingestDSN, configDSN, backupDir string, conn connectorOpts, pol *policy.Engine, stateDir string, manualAdmit, consoleAuth bool, gwTLS *serving.GatewayTLS, oidc oidcOpts, demo bool) (*serving.Plane, error) {
	plane, err := serving.NewPlane(controllerIdentity(ctrl), site)
	if err != nil {
		return nil, err
	}
	if backupDir != "" {
		plane.EnableBackupServe(backupDir) // P2-A2: peers replicate this controller's backups over the mTLS Link
	}
	plane.SetWGEndpoint(wgEndpoint) // the controller's reachable WireGuard endpoint (DANI is the coordinator)
	if gwTLS != nil {
		plane.SetGatewayTLS(gwTLS) // production HTTPS on the external gateway (P0-1)
	}

	// --oidc-issuer: real SSO (P0-2). The console redirects to the IdP; the gateway verifies the
	// signed ID token and maps IdP groups -> DANI roles + clearance. Fails at boot on bad config.
	if oidc.issuer != "" {
		// P0-3: the client secret is a REFERENCE (env:/file:/literal) — the value is resolved here and
		// never logged. A literal secret on the command line is a production footgun, so we warn.
		clientSecret, err := secret.Resolve(oidc.clientSecret)
		if err != nil {
			return nil, fmt.Errorf("OIDC client secret: %w", err)
		}
		if secret.IsLiteral(oidc.clientSecret) && clientSecret != "" {
			log.Printf("controller: WARNING — OIDC client secret passed as a literal flag; use --oidc-client-secret=env:VAR or file:/path in production")
		}
		cfg := serving.OIDCConfig{
			Issuer: oidc.issuer, ClientID: oidc.clientID, ClientSecret: clientSecret,
			RedirectURL: oidc.redirect, GroupsClaim: oidc.groupsClaim,
		}
		if oidc.roleMap != "" {
			groups, def, err := serving.LoadRoleMap(oidc.roleMap)
			if err != nil {
				return nil, err
			}
			cfg.RoleMap, cfg.DefaultRole = groups, def
		}
		oa, err := serving.NewOIDC(context.Background(), cfg)
		if err != nil {
			return nil, fmt.Errorf("OIDC/SSO: %w", err)
		}
		plane.EnableOIDC(oa)
		log.Printf("controller: SSO ON — OIDC issuer %s (login at /auth/login)", oidc.issuer)
	}
	api, err := buildTrainingAPI(ctrl, plane, aud, store, models, trainPace, trainerExec, embedBase, embedModel, ingestDSN, conn, pol, stateDir)
	if err == nil && translateBase != "" {
		api.Translate = &serving.Translator{Base: translateBase}
	}
	if err != nil {
		return nil, err
	}
	plane.EnableTraining(api)
	plane.EnableMetrics()     // P1-2: /metrics (Prometheus) + instrumented gateway — always on, like /healthz
	plane.EnableTracing(1024) // P2-A3: per-request traces at /dani/traces (deep/multi-site + demo fan-out view)
	if demo {
		plane.EnableDemo() // Tier C: /demo/ fan-out coding showcase (+ code-executing /demo/verify)
		log.Printf("controller: DEMO mode ON — fan-out coding showcase at /demo/ (WARNING: /demo/verify executes code; demo machines only)")
	}
	if configDSN != "" { // P1-7: the governed §6.20 config store (four-scope, validated, audited)
		cfgStore, err := config.Open(context.Background(), configDSN)
		if err != nil {
			return nil, err
		}
		plane.EnableConfig(cfgStore, func(typ string, payload map[string]any) {
			if aud != nil {
				_ = aud.Emit(typ, payload)
			}
		})
		log.Printf("controller: governed config store ON — %s (four-scope Fleet/Site/Role/Node, §6.20)", secret.RedactDSN(configDSN))
		// P2-1: the CONTROLLER live-applies its own effective config too — the gateway edge knobs
		// (body cap, per-IP rate) and the per-principal quota land without a restart.
		go func() {
			var last int64 = -1
			attrs := config.NodeAttrs{UUID: ctrl.ID, Site: site, Roles: []string{"controller"}}
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for range t.C {
				v, err := cfgStore.Version(context.Background())
				if err != nil || v == last {
					continue
				}
				eff, err := cfgStore.ResolveAll(context.Background(), attrs)
				if err != nil {
					continue
				}
				flat := make(map[string]string, len(eff))
				for k, r := range eff {
					flat[k] = r.Value
				}
				plane.ApplyGatewayConfig(flat)
				if raw, ok := flat["policy.rate-max"]; ok {
					if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
						pol.SetRate(n)
						log.Printf("controller: config applied policy.rate-max=%d", n)
					}
				}
				last = v
			}
		}()
	}

	// --console-auth: mint a bearer token per directory principal (handed out out-of-band, exactly
	// like bootstrap tokens) and gate every operator ACTION on it; signing additionally requires the
	// reviewer role. Tokens land in console-operators.json next to --state (0600).
	if consoleAuth {
		opAuth := serving.NewOperatorAuth()
		tokens := map[string]string{}
		for _, pr := range api.Ident.Principals() {
			tok, err := opAuth.Mint(serving.OperatorPrincipal{Sub: pr.Sub, Roles: pr.Roles, Clearance: pr.Clearance})
			if err != nil {
				return nil, err
			}
			tokens[pr.Sub] = tok
		}
		dir := stateDir
		if dir == "" {
			dir = "."
		}
		tokFile := filepath.Join(dir, "console-operators.json")
		data, _ := json.MarshalIndent(tokens, "", "  ")
		if err := os.WriteFile(tokFile, data, 0o600); err != nil {
			return nil, fmt.Errorf("write operator tokens: %w", err)
		}
		plane.EnableOperatorAuth(opAuth)
		log.Printf("controller: console auth ON — %d operator tokens written to %s (sign-in with Authorization: Bearer <token>)", len(tokens), tokFile)
	}

	// Node control (console "Nodes" tab): registry + enrollment wired as closures. The pending-queue
	// actions only function with --admit manual (otherwise autoApprove drains the queue first).
	admin := &serving.NodeAdmin{
		Nodes:        ctrl.Registry.DumpAll,
		SetLifecycle: ctrl.Registry.SetLifecycle,
		Revoke:       ctrl.Enroll.Revoke,
		Pending:      ctrl.Enroll.PendingList,
		Reject:       ctrl.Enroll.Reject,
		Audit: func(typ string, payload map[string]any) {
			if aud != nil {
				_ = aud.Emit(typ, payload)
			}
		},
	}
	if manualAdmit {
		admin.Approve = func(ctx context.Context, reqID string) error {
			_, err := ctrl.Enroll.Approve(ctx, reqID, nil, "", site)
			return err
		}
	}
	if stateDir != "" {
		admin.DrainFile = filepath.Join(stateDir, "drained.json")
	}
	plane.EnableNodeAdmin(admin)
	plane.OnHeartbeat(func(hb serving.Heartbeat) {
		_ = ctrl.Registry.Heartbeat(context.Background(), hb.NodeUUID, hb.Health, "1")
	})
	if _, err := plane.ServeLink(linkAddr); err != nil {
		return nil, err
	}
	if _, err := plane.ServeGateway(gatewayAddr); err != nil {
		return nil, err
	}
	// demo mode: extra gateway lanes (ports +1..+4) so the fan-out page beats the browser's
	// ~6-connections-per-origin cap (5 origins x 6 = 30-wide true parallelism from one tab).
	plane.ServeGatewayLanes(gatewayAddr, 4)
	if wgConfOut != "" {
		if err := plane.WriteHubWGConfig(wgConfOut); err != nil {
			return nil, fmt.Errorf("write hub wg config: %w", err)
		}
	}
	return plane, nil
}

// workerEngineOpts configures the worker's engine + data-plane serving.
type workerEngineOpts struct {
	engineKind     string // stub | llama | openai
	modelID        string
	llamaServer    string
	modelPath      string
	engineBase     string // openai: upstream OpenAI-compatible base URL (e.g. Ollama)
	engineModel    string // openai: upstream model name (default = modelID)
	enginePort     int
	threads        int
	inferListen    string // mTLS inference server bind, e.g. :9443
	advertiseHost  string
	maxConcurrent  int
	queueDepth     int
	sloBudget      time.Duration
	controllerHost string // host of the controller (for the Link URL)
	linkPort       int
	linkURLs       []string // explicit Link URLs for HA heartbeat fan-out (overrides controllerHost:linkPort)
	class          string
	site           string
	wgConfOut      string // write importable WireGuard config here
	gatewayURL     string // controller gateway base URL (for fetching the DANI WG config)
	gpuLayers      int    // resolved -ngl (hwcaps auto-detection or the operator's explicit value)
	accel          string // detected acceleration backend (cuda|metal|vulkan|cpu) — advertised on heartbeats
	reverseForce   bool   // NAT traversal FORCE: dispatched only over the outbound tunnel (never dialed)
	reverseAuto    bool   // NAT traversal AUTO: stay dialable but keep the tunnel open as a fallback
	seed           bool   // OPEN-DANI: trusted seed node (verification anchor)
	capPlan        limits.Plan // resolved resource budget (internal/limits): cpuset pin + mem admission
	overrideCores  int         // operator --max-cores (0 = auto); live-tunable via worker.max-cores
	overrideMemMB  int         // operator --max-model-mem-mb (0 = auto); live-tunable
}

func buildEngine(o workerEngineOpts) engine.Engine {
	switch o.engineKind {
	case "llama":
		// the engine's real concurrent-serving capacity == the worker's admission concurrency, so we
		// never advertise (or queue toward) parallelism the engine can't actually batch (D-01).
		return engine.NewLlama(engine.LlamaConfig{
			Model: o.modelID, BinPath: o.llamaServer, ModelPath: o.modelPath,
			Port: o.enginePort, Threads: o.threads, Parallel: o.maxConcurrent,
			GPULayers: o.gpuLayers, // hwcaps auto-detection (or the operator's --gpu-layers)
		})
	case "openai":
		// front an existing OpenAI-compatible server (Ollama on a GPU, vLLM, LM Studio, …).
		upstream := o.engineModel
		if upstream == "" {
			upstream = o.modelID
		}
		return engine.NewOpenAIProxy(engine.OpenAIConfig{BaseURL: o.engineBase, Model: upstream})
	default:
		// The stub answers deterministically — it is a TEST engine. Every packaged deployment
		// (Helm "real" sidecar, Azure cloud-init --engine llama) runs real inference; running stub
		// outside CI/bring-up means the fleet is not actually serving a model (P1).
		log.Printf("worker: WARNING — engine=stub is NOT FOR PRODUCTION (deterministic test engine); use --engine llama or --engine openai")
		return engine.NewStub(o.modelID)
	}
}

// runWorkerPlane builds the engine + worker data-plane and serves until ctx is done (blocking).
func runWorkerPlane(ctx context.Context, id *node.Identity, o workerEngineOpts) error {
	// ENFORCE the resource budget before the engine starts: pin this process (the llama-server child
	// inherits the CPU mask), and refuse a model that wouldn't fit the memory budget rather than OOM.
	if err := o.capPlan.PinCPU(); err != nil {
		log.Printf("worker: CPU pin to %d cores failed (continuing with --threads only): %v", o.capPlan.Cores, err)
	}
	if o.engineKind == "llama" && o.modelPath != "" {
		if ok, need := o.capPlan.FitsMem(o.modelPath); !ok {
			return fmt.Errorf("model %s needs ~%dMB but this node's budget is %dMB (raise --max-model-mem-mb or worker.max-model-mem-mb, or use a smaller/more-quantized model)",
				o.modelID, need/(1<<20), o.capPlan.MemBudgetMB())
		}
	}
	log.Printf("worker: resource budget — %s", o.capPlan.Summary())
	eng := buildEngine(o)
	host := o.advertiseHost
	if host == "" {
		host = primaryIP(fmt.Sprintf("%s:%d", o.controllerHost, o.linkPort))
	}
	urls := o.linkURLs
	if len(urls) == 0 {
		urls = []string{fmt.Sprintf("https://%s:%d", o.controllerHost, o.linkPort)}
	}
	w := serving.NewWorker(serving.WorkerConfig{
		Identity: nodeIdentity(id), Engine: eng, ModelID: o.modelID, Class: o.class, Site: o.site,
		AdvertiseHost: host, ControllerURLs: urls,
		MaxConcurrent: o.maxConcurrent, QueueDepth: o.queueDepth, SLOBudget: o.sloBudget,
		OverrideCores: o.overrideCores, OverrideMemMB: o.overrideMemMB, CapPlan: o.capPlan,
		WGConfOut: o.wgConfOut, GatewayURL: o.gatewayURL, Accel: o.accel,
		ReverseTunnel: o.reverseForce, ReverseAuto: o.reverseAuto, Seed: o.seed,
	})
	return w.Serve(ctx, o.inferListen)
}

// primaryIP discovers the local source IP the OS would use to reach target (no packets sent for UDP).
func primaryIP(target string) string {
	conn, err := net.Dial("udp", target)
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// hostOf strips the port from a host:port (the enrollment --controller address).
func hostOf(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.TrimSuffix(hostport, ":")
}
