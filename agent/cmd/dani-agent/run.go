package main

// Controller and worker run-modes — the long-lived processes the docker-compose harness and the
// Azure fleet run. One binary, role by subcommand (DL-R11-01). The handshake, mTLS renewal, and the
// SQLite Node Registry are the real components from internal/*; only the AI inference is out of scope
// for this DEMO (M5: Tier-0 attestation, no engine supervision yet).
//
// Trust + token distribution is modeled over a shared directory (a docker volume / Azure file share):
//   <shared>/ca-root.pem      the provisioned trust anchor (the dormant root) — DL-R11-08
//   <shared>/tokens/<i>.token  N single-use bootstrap tokens, one per worker slot — DL-R11.2-01
//   <shared>/ready             touched once the controller is serving and tokens are written
// This stands in for the operator handing each node its join token out-of-band.

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dani.local/agent/internal/audit"
	"dani.local/agent/internal/backup"
	"dani.local/agent/internal/cluster"
	"dani.local/agent/internal/controller"
	"dani.local/agent/internal/engine"
	"dani.local/agent/internal/enrollment"
	"dani.local/agent/internal/hwcaps"
	"dani.local/agent/internal/kms"
	"dani.local/agent/internal/limits"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/internal/node"
	"dani.local/agent/internal/openid"
	"dani.local/agent/internal/policy"
	"dani.local/agent/internal/secret"
	"dani.local/agent/internal/serving"
	"dani.local/agent/internal/signerprovider"
	"dani.local/agent/internal/training"

	"net"
)

// slogLineWriter routes stdlib `log` lines through slog, so with --log-json EVERY component logs
// structured JSON (timestamp/level/msg) without touching each call site (P1-2).
type slogLineWriter struct{}

func (slogLineWriter) Write(p []byte) (int, error) {
	slog.Info(strings.TrimRight(string(p), "\r\n"))
	return len(p), nil
}

// setupLogging switches the process to structured JSON logs when jsonOut is set (aggregator-ready:
// Loki/ELK/Azure Monitor ingest it as fields, not regex-parsed lines).
func setupLogging(jsonOut bool) {
	if !jsonOut {
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	log.SetFlags(0)
	log.SetOutput(slogLineWriter{})
}

// parsePeers parses "id@raftAddr@applyURL,..." into the raft peer set + an id->applyURL map (for
// follower→leader write-forwarding).
func parsePeers(s string) ([]cluster.Peer, map[string]string) {
	var peers []cluster.Peer
	applyURL := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		parts := strings.Split(p, "@")
		if len(parts) < 2 {
			continue
		}
		peers = append(peers, cluster.Peer{ID: parts[0], RaftAddr: parts[1]})
		if len(parts) >= 3 {
			applyURL[parts[0]] = parts[2]
		}
	}
	return peers, applyURL
}

// runController boots the genesis control plane, serves enrollment/renewal over TLS, auto-approves
// the pending-join queue (the DEMO drain policy), and reports registry health on a heartbeat.
func runController(args []string) {
	fs := flag.NewFlagSet("controller", flag.ExitOnError)
	listen := fs.String("listen", ":8443", "TLS listen address for the enrollment API")
	org := fs.String("org", "AcmeBank", "organization name")
	deployment := fs.String("deployment", "dep-1", "deployment id (token replay scope)")
	site := fs.String("site", "site-hq", "site tag assigned to admitted nodes")
	registryDSN := fs.String("registry", "/data/registry.db", "Node Registry DSN: a SQLite path, or postgres://user:pw@host/db (HA)")
	shared := fs.String("shared", "/shared", "shared dir for trust anchor + bootstrap tokens")
	tokens := fs.Int("tokens", 24, "number of single-use bootstrap tokens to mint for the fleet")
	tokenTTL := fs.Duration("token-ttl", 24*time.Hour, "bootstrap token lifetime")
	report := fs.Duration("report-every", 15*time.Second, "registry health report interval")
	gateway := fs.String("gateway", ":8081", "OpenAI gateway listen address (external chat API)")
	link := fs.String("link", ":8444", "Link heartbeat sink listen address (mTLS)")
	wgEndpoint := fs.String("wg-endpoint", "", "controller's reachable WireGuard endpoint host:port (DANI-coordinated overlay)")
	wgConfOut := fs.String("wg-conf-out", "", "write the controller's own hub WireGuard config here (to bring up wg0)")
	artifactDir := fs.String("artifacts", "", "Artifact Store directory (content-addressed models/adapters/datasets; empty = temp dir)")
	artifactStore := fs.String("artifact-store", "", "artifact backend: fs:<dir> | azblob:<containerURL>?<sas> (empty = fs at --artifacts; azblob shares artifacts across HA controllers)")
	trainPace := fs.Duration("train-pace", 3*time.Second, "delay per training checkpoint so the console shows live progress (0 = instant; ignored by a real ExecTrainer)")
	trainerExec := fs.String("trainer-exec", "", "run a REAL fine-tune via this command (e.g. \"python infra/trainer/train_qlora.py\"); empty = deterministic stub")
	embedBase := fs.String("embeddings-base", "", "OpenAI-compatible /v1 base for REAL embeddings (Ollama/llama.cpp); empty = deterministic BoW")
	translateBase := fs.String("translate-base", "", "in-perimeter MT sidecar base URL (NLLB/ctranslate2) for the multilingual RAG bridge; empty = off")
	embedModel := fs.String("embeddings-model", "nomic-embed-text", "embedding model name at --embeddings-base")
	gateTask := fs.Float64("gate-min-task", 0, "promotion gate: minimum held-out task-recall score (0 = off)")
	gatePpl := fs.Float64("gate-max-perplexity", 0, "promotion gate: maximum eval perplexity (0 = off)")
	gateSafety := fs.Float64("gate-min-safety", 0, "promotion gate: minimum adversarial-safety score [0,1] (0 = off)")
	rateMax := fs.Int("policy-rate-max", 0, "Policy Engine: max requests per principal per minute (0 = unlimited)")
	auditDB := fs.String("audit-db", "", "audit hash-chain DSN: SQLite path (empty=in-memory), or postgres://user:pw@host/db (HA)")
	ingestDB := fs.String("ingest-db", "", "durable ingest DSN (datasets + RAG embeddings survive restart): SQLite path or postgres://... (HA); empty = <state dir>/ingest.db when --state is set, else in-memory")
	azblobURL := fs.String("ingest-azblob", "", "REAL data connector (P1-6): Azure Blob container URL to crawl (https://<acct>.blob.core.windows.net/<container>); requires --ingest-azblob-sas")
	azblobSAS := fs.String("ingest-azblob-sas", "", "container SAS query string as a SECRET REFERENCE (env:VAR / file:/path; needs Read+List) — never logged")
	azblobCollection := fs.String("ingest-azblob-collection", "azblob", "collection name the connector syncs into")
	azblobClassMap := fs.String("ingest-azblob-classmap", "", "blob-prefix -> classification floors, e.g. \"hr/=internal,finance/=restricted\" (longest prefix wins; default floor internal)")
	azblobSyncEvery := fs.Duration("ingest-azblob-sync-every", 0, "re-sync the connector on this interval (0 = sync at boot + on each console/API ingest of the collection)")
	folderPath := fs.String("ingest-folder", "", "REAL data connector: crawl this directory tree (a local folder or a mounted SMB/NFS share) — files stay where they live; txt/md/code, html, pdf and docx are extracted, classified and indexed")
	folderCollection := fs.String("ingest-folder-collection", "files", "collection name the folder connector syncs into")
	folderClassMap := fs.String("ingest-folder-classmap", "", "relative-path prefix -> classification floors, e.g. \"hr/=internal,finance/=restricted\" (longest prefix wins; default floor internal)")
	folderSyncEvery := fs.Duration("ingest-folder-sync-every", 0, "re-scan the folder on this interval (0 = sync at boot + on each ingest of the collection)")
	gitURL := fs.String("ingest-git", "", "REAL data connector: RAG over a git repository (https clone URL) — shallow clone, incremental by commit, citations carry file@commit lineage; the repo is data, never executed")
	gitRef := fs.String("ingest-git-ref", "", "branch or tag to track (empty = the remote default branch)")
	gitToken := fs.String("ingest-git-token", "", "token for a private repo as a SECRET REFERENCE (env:VAR / file:/path) — never logged")
	gitCollection := fs.String("ingest-git-collection", "repo", "collection name the git connector syncs into")
	gitClassMap := fs.String("ingest-git-classmap", "", "path prefix -> classification floors, e.g. \"ops/=restricted\" (longest prefix wins; default floor internal)")
	gitSyncEvery := fs.Duration("ingest-git-sync-every", 0, "re-fetch the repo on this interval (0 = sync at boot + on each ingest of the collection)")
	configDB := fs.String("config-db", "", "governed config store DSN (§6.20 four-scope Fleet/Site/Role/Node): SQLite path or postgres://... (HA); empty = <state dir>/config.db when --state is set, else off")
	backupDir := fs.String("backup-dir", "", "P2: write scheduled, consistent state-dir snapshots here (any path — local disk, NFS, a peer-site mount; NO cloud dependency); empty = off")
	backupEvery := fs.Duration("backup-every", 6*time.Hour, "interval between automatic state snapshots (with --backup-dir)")
	backupKeep := fs.Int("backup-keep", 14, "retain this many newest snapshots; older are pruned")
	replicateFrom := fs.String("replicate-from", "", "P2: continuously pull a PEER controller's latest backup over the mTLS Link (e.g. https://site-a-ctrl:8444) — cloud-free cross-site warm standby; empty = off")
	replicateTo := fs.String("replicate-to", "", "where pulled peer backups are stored (default: <backup-dir>/replicated)")
	replicateEvery := fs.Duration("replicate-every", 10*time.Minute, "interval to pull the peer's latest backup")
	demoMode := fs.Bool("demo", false, "Tier C: serve the fan-out coding demo at /demo/ (includes a code-EXECUTING /demo/verify — demo machines only, never production)")
	auditSignEvery := fs.Duration("audit-sign-every", 30*time.Second, "how often to anchor the audit chain head with the KMS signing key")
	// multi-controller (Raft) flags
	clusterID := fs.String("cluster-id", "ctrl-001", "raft server id (the bootstrap controller must stay ctrl-001 to match its identity cert)")
	raftBind := fs.String("raft-bind", "", "raft transport bind host:port; empty = standalone (no cluster)")
	raftAdv := fs.String("raft-advertise", "", "advertised raft addr (default = raft-bind)")
	clusterData := fs.String("cluster-data", "", "raft bolt store dir; empty = in-memory")
	bootstrapCluster := fs.Bool("bootstrap", false, "bootstrap a new raft cluster (exactly one controller)")
	peersFlag := fs.String("peers", "", "comma list id@raftAddr@applyURL for ALL controllers")
	applyBind := fs.String("cluster-apply", "", "mTLS write-forward apply endpoint bind host:port")
	bundleOut := fs.String("bundle-out", "", "write the CA bundle here (bootstrap; peers import via --bundle-in)")
	bundleIn := fs.String("bundle-in", "", "import a CA bundle to JOIN an existing cluster")
	statePath := fs.String("state", "", "persist the CA+KMS authority here so a standalone restart resumes the SAME deployment (D-14; empty = ephemeral genesis)")
	signerDir := fs.String("model-signer-dir", "", "sugar: back all 3 reviewer roles with per-role software keystores under this dir (three-party control)")
	signerSpecs := fs.String("model-signers", "", "per-role signer backends: \"security=remote:https://hsm-a,governance=file:/k/gov,admin=kms\" (overrides --model-signer-dir per role; empty = shared-KMS default)")
	publish := fs.Bool("publish", true, "write ca-root + bootstrap tokens + ready to --shared (bootstrap only; cluster joiners pass --publish=false)")
	kmsSpec := fs.String("kms", "", "KMS backend for the CA/enrollment/audit keys: software (default) | software-file:<path> | remote:<url> (HSM/cloud-KMS — the HSM is the shared authority, so --state/--bundle HA is unavailable)")
	admit := fs.String("admit", "auto", "join admission: auto (DEMO drain policy — every pending join admitted) | manual (SO approves each join in the console — Mode-2 batch-confirm)")
	openEnroll := fs.Bool("open-enroll", false, "OPEN-DANI: permissionless join — no operator, no bootstrap token. Self-minted nodes prove work (--pow-bits) and are auto-approved as open workers. NEVER enable on an enterprise deployment.")
	powBits := fs.Int("pow-bits", 20, "OPEN-DANI: proof-of-work difficulty (leading zero bits) a self-minted node must solve to join")
	verifySeed := fs.Bool("verify-seed", false, "OPEN-DANI: seed-anchored verification — cross-check a low-reputation volunteer's answer against a trusted --seed node; on disagreement serve the seed's answer and dock the volunteer. Protects the brand on a public network.")
	requirePoW := fs.Bool("require-pow", false, "OPEN-DANI: NAT-agnostic abuse control — require a per-request proof-of-work (client attaches X-Dani-PoW). Prices each request in CPU instead of rate-limiting by IP (which is wrong behind NAT).")
	powRequestBits := fs.Int("pow-request-bits", 16, "OPEN-DANI: per-request proof-of-work difficulty (leading zero bits)")
	moderateDeny := fs.String("moderate-denylist", "", "OPEN-DANI: comma-separated terms that refuse a prompt (content gate floor; a real classifier plugs in via code). Empty = off.")
	ledgerOn := fs.Bool("ledger", false, "OPEN-DANI: contribution economy — contributors (who serve verified work) get priority; everyone else is best-effort (served on spare capacity). Nobody is hard-blocked. Off = enterprise behavior.")
	ledgerReserve := fs.Float64("ledger-reserve", 0.25, "OPEN-DANI: fraction of fleet capacity held for contributors (best-effort rides the rest)")
	consoleAuth := fs.Bool("console-auth", false, "gate console WRITE actions on per-principal bearer tokens (minted at start into console-operators.json); signing requires the reviewer role")
	profile := fs.String("profile", "demo", "deployment posture: demo (permissive conveniences allowed) | production (REFUSES to start until the posture is hardened: no --demo, TLS or declared ingress, console auth, manual admission, durable state + audit)")
	plainGateway := fs.Bool("plain-gateway-behind-ingress", false, "production profile only: assert that TLS terminates at an upstream ingress, so a plaintext gateway is intentional (otherwise --profile production refuses a plaintext gateway)")
	gwTLS := fs.String("gateway-tls", "off", "external gateway transport: off (plain HTTP; dev / behind a TLS ingress) | on (HTTPS — mounted cert if --gateway-tls-cert set, else self-signed)")
	gwCert := fs.String("gateway-tls-cert", "", "PEM certificate file for the gateway (production HTTPS)")
	gwKey := fs.String("gateway-tls-key", "", "PEM private-key file for the gateway (production HTTPS)")
	oidcIssuer := fs.String("oidc-issuer", "", "OIDC issuer URL for SSO (e.g. https://login.microsoftonline.com/<tenant>/v2.0); empty = SSO off")
	oidcClientID := fs.String("oidc-client-id", "", "OIDC client id")
	oidcClientSecret := fs.String("oidc-client-secret", "", "OIDC client secret (prefer @file or env:VAR via --secrets; see P0-3)")
	oidcRedirect := fs.String("oidc-redirect-url", "", "OIDC redirect URL, e.g. https://<gateway>/auth/callback")
	oidcRoleMap := fs.String("oidc-role-map", "", "path to the IdP-group -> DANI role/clearance JSON map")
	oidcGroups := fs.String("oidc-groups-claim", "groups", "ID-token claim holding the caller's groups")
	logJSON := fs.Bool("log-json", false, "emit structured JSON logs (aggregator-ready) instead of plain lines")
	drainTimeout := fs.Duration("drain-timeout", 15*time.Second, "graceful shutdown: max wait for in-flight requests on SIGTERM (P1-3)")
	_ = fs.Parse(args)
	setupLogging(*logJSON)

	// PRODUCTION PROFILE: the one-switch guard against shipping a demo-postured controller. Judged
	// BEFORE anything binds, and it aggregates every violation so the operator fixes the whole
	// checklist in one pass. `demo` (default) keeps every convenience available.
	if strings.EqualFold(*profile, "production") {
		warnings, gErr := productionGate(prodInputs{
			demo: *demoMode, gwTLS: strings.EqualFold(*gwTLS, "on"), plainGateway: *plainGateway,
			consoleAuth: *consoleAuth, admit: *admit, statePath: *statePath, auditDB: *auditDB,
			kmsSpec: *kmsSpec, backupDir: *backupDir, replicateFrom: *replicateFrom,
		})
		for _, w := range warnings {
			logf("controller: PRODUCTION advisory — %s", w)
		}
		check(gErr) // refuses to start, printing every violation at once
		logf("controller: PRODUCTION profile accepted — posture hardened")
	}

	// P1-3: SIGTERM/SIGINT cancels this context — the shutdown path below drains before exit
	// (Kubernetes sends SIGTERM on every rolling restart; systemd on every stop).
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	// P0-3: DSNs may be secret references (env:/file:) so a Postgres URL with a password comes from a
	// mounted Secret, not the flag / ps output / manifest. Resolve once; all downstream uses see it.
	if v, err := secret.Resolve(*registryDSN); err != nil {
		check(err)
	} else {
		*registryDSN = v
	}
	if v, err := secret.Resolve(*auditDB); err != nil {
		check(err)
	} else {
		*auditDB = v
	}
	if v, err := secret.Resolve(*ingestDB); err != nil {
		check(err)
	} else {
		*ingestDB = v
	}
	var ctrl *controller.Controller
	resumed := false
	stateDir := "" // --state also anchors the durable model-registry + placement snapshots
	if *statePath != "" {
		stateDir = filepath.Dir(*statePath)
	}
	if *ingestDB == "" && stateDir != "" {
		// a stateful controller defaults to durable ingest too — restart survival is the point of --state
		*ingestDB = filepath.Join(stateDir, "ingest.db")
	}
	if *configDB == "" && stateDir != "" {
		*configDB = filepath.Join(stateDir, "config.db") // stateful controller → governed config on by default
	}
	if v, err := secret.Resolve(*configDB); err != nil {
		check(err)
	} else {
		*configDB = v
	}
	if *kmsSpec != "" && *kmsSpec != "software" {
		// D-28: run genesis on an operator-selected KMS backend (persisted software keystore, or an
		// external HSM/cloud-KMS where the issuing key never enters DANI).
		prov, err := kms.Open(*kmsSpec)
		check(err)
		if !prov.Exportable && (*statePath != "" || *bundleOut != "") {
			check(fmt.Errorf("--kms %s is not exportable: --state / --bundle-out HA is unavailable (the HSM is the shared authority — point every controller's --kms at the same endpoint)", *kmsSpec))
		}
		ctrl, err = controller.GenesisWithKMS(ctx, prov.KS(), *org, *deployment, *registryDSN)
		check(err)
		logf("controller %s: genesis ceremony on KMS backend %q (org=%s deployment=%s)", *clusterID, *kmsSpec, *org, *deployment)
		if prov.Exportable && *bundleOut != "" {
			b, err := ctrl.ExportBundle()
			check(err)
			data, _ := json.Marshal(b)
			check(os.WriteFile(*bundleOut, data, 0o600))
			logf("controller %s: wrote CA bundle to %s (peers JOIN with --bundle-in)", ctrl.ID, *bundleOut)
		}
	} else if *bundleIn != "" {
		data, err := os.ReadFile(*bundleIn)
		check(err)
		var b controller.Bundle
		check(json.Unmarshal(data, &b))
		ctrl, err = controller.NewFromBundle(ctx, &b, *clusterID, *site, *registryDSN)
		check(err)
		logf("controller %s: joined deployment %q via shared CA bundle", *clusterID, b.DeploymentID)
	} else if *statePath != "" {
		var err error
		ctrl, resumed, err = controller.GenesisOrResume(ctx, *org, *deployment, *registryDSN, *statePath, *clusterID, *site)
		check(err)
		if resumed {
			logf("controller %s: RESUMED deployment %q from %s (same CA + KMS — worker certs stay valid)", *clusterID, ctrl.DeploymentID, *statePath)
		} else {
			logf("controller %s: genesis ceremony (org=%s deployment=%s), authority persisted to %s", *clusterID, *org, *deployment, *statePath)
		}
		// a resumable bootstrap can still anchor a Raft cluster: same bundle on genesis AND resume,
		// so peers can (re)join whether or not this controller has restarted since genesis.
		if *bundleOut != "" {
			b, err := ctrl.ExportBundle()
			check(err)
			data, _ := json.Marshal(b)
			check(os.WriteFile(*bundleOut, data, 0o600))
			logf("controller %s: wrote CA bundle to %s (peers JOIN with --bundle-in)", ctrl.ID, *bundleOut)
		}
	} else {
		logf("controller %s: genesis ceremony (org=%s deployment=%s)", *clusterID, *org, *deployment)
		var err error
		ctrl, err = controller.Genesis(ctx, *org, *deployment, *registryDSN)
		check(err)
		if *bundleOut != "" {
			b, err := ctrl.ExportBundle()
			check(err)
			data, _ := json.Marshal(b)
			check(os.WriteFile(*bundleOut, data, 0o600))
			logf("controller %s: wrote CA bundle to %s (peers JOIN with --bundle-in)", ctrl.ID, *bundleOut)
		}
	}
	logf("controller %s: CA online — root=%q intermediate=%q; identity CN=%s",
		ctrl.ID, ctrl.CA.Root.Subject.CommonName, ctrl.CA.Intermediate.Subject.CommonName, ctrl.Cert.Subject.CommonName)

	// the audit hash chain: genesis record = the FIRST link (DL-R11-13); heads anchored on a ticker.
	auditDSN := *auditDB
	if auditDSN == "" {
		auditDSN = ":memory:"
	}
	aud, err := audit.Open(ctx, auditDSN, ctrl.KS)
	check(err)
	rootFp := sha256.Sum256(ctrl.CA.Root.Raw)
	bootEvent := "genesis"
	if resumed {
		bootEvent = "controller.resumed" // the SAME authority came back — the chain continues, no new genesis
	}
	check(aud.Emit(bootEvent, map[string]any{"controller": ctrl.ID, "rootFp": hex.EncodeToString(rootFp[:8]), "deployment": *deployment}))
	aud.StartSigning(ctx, *auditSignEvery)

	// publish the trust anchor + tokens (bootstrap controller only; in a cluster the joiners share the
	// same Azure Files dir and must not overwrite these — they pass --publish=false).
	if *publish {
		tokenDir := filepath.Join(*shared, "tokens")
		check(os.MkdirAll(tokenDir, 0o755))
		rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ctrl.CA.Root.Raw})
		check(os.WriteFile(filepath.Join(*shared, "ca-root.pem"), rootPEM, 0o644))
		for i := 0; i < *tokens; i++ {
			tok, _, err := enrollment.IssueToken(ctx, ctrl.KS, *deployment, []string{"worker"}, *tokenTTL)
			check(err)
			check(os.WriteFile(filepath.Join(tokenDir, fmt.Sprintf("%d.token", i)), tok, 0o600))
		}
		logf("controller: published trust anchor + %d bootstrap tokens to %s", *tokens, *shared)
	}

	// serve the enrollment gRPC over TLS.
	lis, err := net.Listen("tcp", *listen)
	check(err)
	ctrl.Serve(lis)
	logf("controller: serving enrollment/renewal on %s (mTLS for renewal)", lis.Addr())

	// Build the Artifact Store + Model Registry NOW (before the cluster) so the Raft FSM can replicate
	// promotions into the SAME registry the data plane serves — a joining controller catches up on
	// promoted models, not just enrolled nodes.
	// Assemble per-role signer specs: --model-signer-dir expands to file: keystores for all three,
	// then --model-signers overrides per role (three-party control, ROADMAP §2 / D-19 / D-20).
	roleSpecs := map[modelreg.Role]string{}
	if *signerDir != "" {
		check(os.MkdirAll(*signerDir, 0o700))
		roleSpecs[modelreg.RoleSecurity] = "file:" + filepath.Join(*signerDir, "security.kms")
		roleSpecs[modelreg.RoleGovernance] = "file:" + filepath.Join(*signerDir, "governance.kms")
		roleSpecs[modelreg.RoleAdmin] = "file:" + filepath.Join(*signerDir, "admin.kms")
	}
	if *signerSpecs != "" {
		parsed, err := signerprovider.ParseSpecMap(*signerSpecs)
		check(err)
		for role, spec := range parsed {
			roleSpecs[role] = spec
		}
	}
	store, models, err := openRegistry(ctrl, *artifactDir, *artifactStore, modelreg.EvalGate{MinTask: *gateTask, MinSafety: *gateSafety, MaxPerplexity: *gatePpl}, stateDir, roleSpecs)
	check(err)

	// multi-controller: join the Raft-replicated registry so any controller serves the same view.
	var clusterNode *cluster.Node
	if *raftBind != "" {
		peers, applyURLByID := parsePeers(*peersFlag)
		node, err := cluster.New(cluster.Config{
			ID: *clusterID, RaftBind: *raftBind, Advertise: *raftAdv, DataDir: *clusterData,
			Bootstrap: *bootstrapCluster, Peers: peers, Reg: ctrl.Registry, Models: models,
		})
		check(err)
		ctrl.EnableCluster(node)
		node.Forward = ctrl.Forwarder(applyURLByID)
		models.SetReplicator(node.ApplyModelSnapshot) // promotions now replicate across controllers
		if *applyBind != "" {
			_, err := ctrl.ServeClusterApply(*applyBind)
			check(err)
		}
		clusterNode = node
		logf("controller %s: RAFT cluster mode (bind=%s advertise=%s bootstrap=%v peers=%d); model registry replicated", *clusterID, *raftBind, *raftAdv, *bootstrapCluster, len(peers))
	}

	// data plane: OpenAI gateway + Link heartbeat sink (load-aware routing to workers over mTLS).
	plane, err := startControllerPlane(ctrl, aud, *gateway, *link, *site, *wgEndpoint, *wgConfOut, store, models, *trainPace, *trainerExec, *embedBase, *embedModel, *translateBase, *ingestDB, *configDB, *backupDir, connectorOpts{url: *azblobURL, sasRef: *azblobSAS, collection: *azblobCollection, classMap: *azblobClassMap, syncEvery: *azblobSyncEvery,
		folderPath: *folderPath, folderCollection: *folderCollection, folderClassMap: *folderClassMap, folderSyncEvery: *folderSyncEvery,
		gitURL: *gitURL, gitRef: *gitRef, gitTokenRef: *gitToken, gitCollection: *gitCollection, gitClassMap: *gitClassMap, gitSyncEvery: *gitSyncEvery}, policy.New(*rateMax, time.Minute), stateDir, *admit == "manual", *consoleAuth, gatewayTLS(*gwTLS, *gwCert, *gwKey), oidcOpts{issuer: *oidcIssuer, clientID: *oidcClientID, clientSecret: *oidcClientSecret, redirect: *oidcRedirect, roleMap: *oidcRoleMap, groupsClaim: *oidcGroups}, *demoMode)
	if err != nil {
		logf("controller: data plane failed to start: %v", err)
	} else {
		logf("controller: gateway on %s, Link sink on %s", *gateway, *link)
		if *verifySeed && plane != nil {
			plane.EnableSeedVerify(0, 0) // Open-DANI: cross-check volunteers against trusted seeds
			logf("controller: OPEN-DANI seed-anchored verification ON — low-reputation volunteers are cross-checked against --seed nodes")
		}
		if *requirePoW && plane != nil {
			plane.EnableRequestPoW(*powRequestBits, 30) // NAT-agnostic per-request admission
			logf("controller: OPEN-DANI request proof-of-work ON — %d bits/request (NAT-agnostic abuse control, not per-IP)", *powRequestBits)
		}
		if *moderateDeny != "" && plane != nil {
			plane.EnableModeration(strings.Split(*moderateDeny, ","), nil)
			logf("controller: OPEN-DANI content moderation ON — denylist gate on prompts")
		}
		if *ledgerOn && plane != nil {
			plane.EnableLedger(*ledgerReserve)
			logf("controller: OPEN-DANI contribution economy ON — contributors get priority, best-effort rides %.0f%% spare capacity", (1-*ledgerReserve)*100)
		}
	}

	// surface the control-plane membership on the gateway (/dani/cluster) so the console shows
	// EVERY controller (and who leads), not just the one it happens to be talking to.
	if plane != nil && clusterNode != nil {
		selfID := *clusterID
		plane.SetClusterInfo(func() ([]serving.ClusterMember, string) {
			_, leaderID := clusterNode.LeaderID()
			var ms []serving.ClusterMember
			for _, m := range clusterNode.Members() {
				ms = append(ms, serving.ClusterMember{ID: m.ID, Addr: m.RaftAddr, Leader: m.ID == leaderID, Self: m.ID == selfID})
			}
			return ms, leaderID
		})
	}

	if *openEnroll {
		// OPEN-DANI permissionless join: self-minted nodes prove work and are auto-approved INLINE
		// at EnrollProof (no queue, no operator). Enterprise deployments never set this.
		ctrl.Enroll.EnableOpenEnroll(*powBits)
		logf("controller: OPEN-DANI permissionless enrollment ON — no token, proof-of-work %d bits, self-minted open workers auto-approved", *powBits)
	} else if *admit == "manual" {
		logf("controller: MANUAL admission — pending joins wait for operator approval (console Nodes tab / POST /dani/enroll/approve)")
	} else {
		// DEMO drain policy: auto-admit the pending-join queue (stands in for the SO batch-confirm).
		go autoApprove(ctx, ctrl, *site, aud)
	}

	// P2 (cloud-agnostic): scheduled, consistent, retained snapshots of the whole --state dir to a
	// path the operator controls (local/NFS/peer-site) — no cloud DB or object store assumed.
	if *backupDir != "" && stateDir != "" {
		go backup.Run(ctx, backup.Config{
			StateDir: stateDir, DestDir: *backupDir, Every: *backupEvery, Keep: *backupKeep,
			Audit: func(typ string, payload map[string]any) { _ = aud.Emit(typ, payload) },
			Log:   func(f string, a ...any) { logf(f, a...) },
		})
		logf("controller: scheduled backups ON — every %s to %s (keep %d, consistent VACUUM snapshots, cloud-free)", *backupEvery, *backupDir, *backupKeep)
	} else if *backupDir != "" {
		logf("controller: --backup-dir set but --state is not; scheduled backups need a durable state dir")
	}

	// P2-A2 (cloud-agnostic cross-site DR): pull a peer site's latest backup over the mTLS Link
	// (rides the DANI WireGuard mesh) into a local warm-standby dir — no cloud object store.
	if *replicateFrom != "" && plane != nil {
		dest := *replicateTo
		if dest == "" {
			base := *backupDir
			if base == "" {
				base = stateDir
			}
			dest = filepath.Join(base, "replicated")
		}
		go backup.Replicate(ctx, backup.ReplicateConfig{
			PeerBase: *replicateFrom, DestDir: dest, Client: plane.Dialer(), Every: *replicateEvery, Keep: *backupKeep,
			Audit: func(typ string, payload map[string]any) { _ = aud.Emit(typ, payload) },
			Log:   func(f string, a ...any) { logf(f, a...) },
		})
		logf("controller: cross-site replication ON — pulling %s every %s into %s (mTLS, cloud-free)", *replicateFrom, *replicateEvery, dest)
	}

	// signal readiness so workers stop waiting (bootstrap publishes; joiners share the dir).
	if *publish {
		check(os.WriteFile(filepath.Join(*shared, "ready"), []byte(time.Now().UTC().Format(time.RFC3339)), 0o644))
	}

	// registry health heartbeat — the live registry is the operator's source of truth.
	tick := time.NewTicker(*report)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// P1-3 graceful shutdown: drain the data plane (finish in-flight requests, stop
			// accepting), anchor the audit chain head, and close the stores — a rolling restart
			// leaves no dropped request and no unsigned audit tail.
			logf("controller: shutdown signal — draining (up to %s)", *drainTimeout)
			shCtx, cancel := context.WithTimeout(context.Background(), *drainTimeout)
			if plane != nil {
				if err := plane.Shutdown(shCtx); err != nil {
					logf("controller: drain incomplete: %v", err)
				}
			}
			if err := aud.SignHead(shCtx); err != nil {
				logf("controller: final audit anchor failed: %v", err)
			}
			_ = aud.Close()
			cancel()
			logf("controller: drained cleanly — exiting")
			return
		case <-tick.C:
			n, err := ctrl.Registry.Count(context.Background())
			if err != nil {
				logf("controller: registry count error: %v", err)
				continue
			}
			logf("controller: registry holds %d enrolled node(s)", n)
		}
	}
}

// autoApprove drains the pending-join queue by admitting every waiting node with its declared
// attributes (Approve falls back to declared roles/class) and the controller's site tag.
func autoApprove(ctx context.Context, ctrl *controller.Controller, site string, aud *audit.Log) {
	for {
		for _, reqID := range ctrl.Enroll.Waiting() {
			if _, err := ctrl.Enroll.Approve(ctx, reqID, nil, "", site); err != nil {
				logf("controller: approve %s failed: %v", reqID, err)
				continue
			}
			logf("controller: admitted pending request %s (site=%s)", reqID, site)
			_ = aud.Emit("node.enrolled", map[string]any{"request": reqID, "site": site})
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// runWorker waits for the controller to be ready, reads its trust anchor + a join token, enrolls,
// then renews on a schedule over mutual mTLS — exercising the full certificate lifecycle.
func runWorker(args []string) {
	fs := flag.NewFlagSet("worker", flag.ExitOnError)
	addr := fs.String("controller", "controller:8443", "controller enrollment address")
	shared := fs.String("shared", "/shared", "shared dir for trust anchor + bootstrap tokens")
	uuid := fs.String("uuid", hostname(), "node uuid (defaults to hostname)")
	slot := fs.Int("slot", -1, "bootstrap-token slot index (-1 = auto-claim a free slot)")
	roles := fs.String("roles", "worker", "declared role")
	class := fs.String("class", "restricted", "declared classification")
	renewEvery := fs.Duration("renew-every", 60*time.Second, "renewal interval (mutual mTLS)")
	waitFor := fs.Duration("wait", 90*time.Second, "how long to wait for the controller to be ready")
	// data-plane (inference) flags
	engineKind := fs.String("engine", "stub", "inference engine: stub | llama | openai")
	modelID := fs.String("model-id", "stub-slm", "model id advertised + served")
	llamaServer := fs.String("llama-server", "/usr/local/bin/llama-server", "path to llama.cpp llama-server")
	modelPath := fs.String("model-path", "", "path to the .gguf model (engine=llama)")
	engineBase := fs.String("engine-base", "http://127.0.0.1:11434/v1", "engine=openai: upstream OpenAI-compatible base URL (Ollama default)")
	engineModel := fs.String("engine-model", "", "engine=openai: upstream model name (default = --model-id)")
	enginePort := fs.Int("engine-port", 8080, "local llama-server port")
	threads := fs.Int("threads", 0, "llama-server CPU threads (0=auto)")
	gpuLayers := fs.String("gpu-layers", "auto", "llama-server GPU offload (-ngl): auto = detect this node's GPU/iGPU and offload fully when present; an integer forces that many layers (0 = pure CPU)")
	inferListen := fs.String("infer-listen", ":9443", "mTLS inference endpoint bind")
	advertiseHost := fs.String("advertise-host", "", "host the controller dials for dispatch (default: auto)")
	site := fs.String("site", "", "worker site tag (locality routing on non-flat networks)")
	maxConc := fs.Int("max-concurrent", 4, "serving slots (concurrent inferences)")
	maxCoresStr := fs.String("max-cores", "auto", "CPU cores DANI may use: auto (all inside a cgroup limit; on a bare host leave 2 for the user when >2 cores, take all when <=2) | all (this machine is dedicated to DANI) | N. Pins a cpuset + sets engine threads. Live-tunable via config worker.max-cores")
	dedicated := fs.Bool("dedicated", false, "this machine belongs to DANI — take every core (same as --max-cores all)")
	maxModelMemMB := fs.Int("max-model-mem-mb", 0, "model-memory budget in MB; refuse to load a model that wouldn't fit rather than OOM the host (0 = auto/unbounded). Live-tunable via config worker.max-model-mem-mb")
	queueDepth := fs.Int("queue-depth", 0, "DP4 admission queue depth before back-pressure (0=2x max-concurrent)")
	sloBudget := fs.Duration("slo-budget", 20*time.Second, "max time a request may wait in queue before back-pressure")
	linkPort := fs.Int("link-port", 8444, "controller Link sink port")
	controllers := fs.String("controllers", "", "comma list of controller Link URLs to heartbeat to (HA fan-out; default: the --controller host)")
	wgConfOut := fs.String("wg-conf-out", "", "write this node's importable WireGuard config to this path (join the DANI overlay)")
	gatewayURL := fs.String("gateway-url", "", "controller gateway base URL for fetching the DANI WG config (default http://<controller-host>:8081)")
	reverseTunnel := fs.String("reverse-tunnel", "off", "NAT/firewall traversal (NAT-TRANSPORT.md): off = dial-only | auto = stay dialable but keep an outbound tunnel open, the controller falls back to it if it can't dial you (recommended — no operator foreknowledge needed) | on = FORCE the tunnel, never expect an inbound dial (for known UDP-blocked/no-privilege segments)")
	openJoin := fs.Bool("open-join", false, "OPEN-DANI: join a PUBLIC network with no token — self-mint a keypair, derive the node id from it, solve the proof-of-work, and enroll. Requires --ca-root (the network's PUBLIC trust anchor) + --deployment + --pow-bits matching the controller.")
	openDeployment := fs.String("deployment", "dep-1", "OPEN-DANI open-join: the network's deployment id (binds the proof-of-work; published with the download)")
	openPowBits := fs.Int("pow-bits", 20, "OPEN-DANI open-join: proof-of-work difficulty to solve (must match the controller's --pow-bits)")
	caRoot := fs.String("ca-root", "", "OPEN-DANI open-join: path to the network's PUBLIC CA root PEM (default: <shared>/ca-root.pem)")
	seedNode := fs.Bool("seed", false, "OPEN-DANI: mark this worker a TRUSTED seed — the operator-run correctness anchor that volunteer answers are verified against (never itself verified)")
	// dedicated trainer node (D17) flags — used only with --roles trainer
	trainListen := fs.String("train-listen", ":9444", "trainer node: mTLS /train endpoint bind")
	workerTrainerExec := fs.String("trainer-exec", "", "trainer node: run REAL fine-tunes via this command (quote-aware; empty = deterministic stub)")
	logJSON := fs.Bool("log-json", false, "emit structured JSON logs (aggregator-ready) instead of plain lines")
	_ = fs.Parse(args)
	setupLogging(*logJSON)

	var linkURLs []string
	for _, u := range strings.Split(*controllers, ",") {
		if u = strings.TrimSpace(u); u != "" {
			linkURLs = append(linkURLs, u)
		}
	}

	// ADAPT to this box: detect the local acceleration hardware once, resolve the llama offload,
	// and advertise the truth at enrollment + on every heartbeat. Detection never blocks or fails —
	// a bare VM simply reports cpu.
	gpu := hwcaps.Detect()
	ngl := hwcaps.ResolveNGL(*gpuLayers, gpu)
	logf("worker %s: hardware — accel=%s device=%q vram=%dMB npu=%q → llama -ngl %d (--gpu-layers %s)",
		*uuid, gpu.Backend, gpu.Device, gpu.VRAMMB, gpu.NPU, ngl, *gpuLayers)
	// BENCHMARK-THEN-DECIDE: on an accelerated box in auto mode, don't trust detection — measure.
	// One short timed generation per candidate (offloaded vs pure CPU) with the REAL model; the
	// verdict is cached next to the model so this costs ~30-60s once per box-and-model. An explicit
	// --gpu-layers integer bypasses it (operator knows best).
	if *engineKind == "llama" && strings.EqualFold(strings.TrimSpace(*gpuLayers), "auto") && gpu.Accelerated() {
		ngl = engine.CalibrateLlama(context.Background(), engine.LlamaConfig{
			Model: *modelID, BinPath: *llamaServer, ModelPath: *modelPath,
			Port: *enginePort, Threads: *threads,
		}, gpu.Backend, logf)
	}

	// P1-3: SIGTERM/SIGINT cancels ctx — Worker.Serve announces "draining" and finishes in-flight.
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	var enrollParams node.EnrollParams
	var root *x509.Certificate
	if *openJoin {
		// SAFETY INVARIANT (OPEN-DANI-LAUNCH.md §Safety): a public volunteer node is inference-only —
		// no code-execution surface. Refuse startup if a trainer role / exec is requested.
		check(enforceOpenWorkerSafety(*roles, *workerTrainerExec))
		// OPEN-DANI permissionless join: no operator, no token. Self-mint a keypair, derive the id
		// from its pubkey (self-certifying), solve the proof-of-work, and enroll. Trust the network
		// by its PUBLIC CA root (shipped with the download / pinned) — the anchor is public.
		caPath := *caRoot
		if caPath == "" {
			caPath = filepath.Join(*shared, "ca-root.pem")
		}
		root = mustTrustRoot(caPath)
		pub, priv, gerr := ed25519.GenerateKey(crand.Reader)
		check(gerr)
		selfID := openid.DeriveUUID(pub)
		logf("worker %s: OPEN-DANI join — self-minted id, solving proof-of-work (%d bits) ...", selfID, *openPowBits)
		nonce, ok := openid.Solve(*openDeployment, selfID, *openPowBits, 0)
		if !ok {
			check(fmt.Errorf("proof-of-work unsolved"))
		}
		logf("worker %s: proof-of-work solved (nonce=%d) — enrolling against %s (no token)", selfID, nonce, *addr)
		*uuid = selfID
		*roles, *class = "worker", "unrestricted" // open workers serve public traffic; keep serving-side attrs consistent with the issued cert
		enrollParams = node.EnrollParams{
			Addr: *addr, TrustRoot: root, Token: openid.EncodeNonce(nonce), Key: priv,
			NodeUUID: selfID, Roles: []string{"worker"}, Class: "unrestricted",
			Caps: hwcaps.CapsJSON(gpu), Timeout: 60 * time.Second,
		}
	} else {
		logf("worker %s: waiting for controller readiness (slot %d)", *uuid, *slot)
		waitReady(filepath.Join(*shared, "ready"), *waitFor)
		root = mustTrustRoot(filepath.Join(*shared, "ca-root.pem"))
		tokenDir := filepath.Join(*shared, "tokens")
		claimed := *slot
		if claimed < 0 {
			claimed = claimSlot(tokenDir, *waitFor)
			logf("worker %s: claimed bootstrap-token slot %d", *uuid, claimed)
		}
		tok, terr := os.ReadFile(filepath.Join(tokenDir, fmt.Sprintf("%d.token", claimed)))
		check(terr)
		logf("worker %s: enrolling against %s", *uuid, *addr)
		enrollParams = node.EnrollParams{
			Addr: *addr, TrustRoot: root, Token: tok,
			NodeUUID: *uuid, Roles: []string{*roles}, Class: *class,
			Caps: hwcaps.CapsJSON(gpu), Timeout: 60 * time.Second,
		}
	}
	id, err := node.Enroll(ctx, enrollParams)
	check(err)
	logf("worker %s: ENROLLED — cert serial=%x notAfter=%s", *uuid, id.Cert.SerialNumber, id.Cert.NotAfter.Format(time.RFC3339))

	// keep renewing in the background (registry generation + the 45-day grace runway).
	go func() {
		tick := time.NewTicker(*renewEvery)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				newCert, err := node.Renew(ctx, *addr, root, id)
				if err != nil {
					logf("worker %s: renewal failed: %v", *uuid, err)
					continue
				}
				id.Cert = newCert
				logf("worker %s: RENEWED — new serial=%x notAfter=%s", *uuid, newCert.SerialNumber, newCert.NotAfter.Format(time.RFC3339))
			}
		}
	}()

	// A dedicated trainer node (D17) never serves inference. It runs the TRAINER data plane instead:
	// an mTLS /train endpoint that executes fine-tunes on THIS node's hardware, plus a trainer-marked
	// heartbeat (skipped by the router; read by the controller's allocator for the /train address).
	if *roles == "trainer" {
		var tr training.Trainer = training.PacedTrainer{Inner: training.StubTrainer{}, Delay: 2 * time.Second}
		if *workerTrainerExec != "" {
			parts := training.SplitCommand(*workerTrainerExec)
			tr = training.ExecTrainer{Script: parts[0], Args: parts[1:]}
		}
		host := *advertiseHost
		if host == "" {
			host = primaryIP(fmt.Sprintf("%s:%d", hostOf(*addr), *linkPort))
		}
		urls := linkURLs
		if len(urls) == 0 {
			urls = []string{fmt.Sprintf("https://%s:%d", hostOf(*addr), *linkPort)}
		}
		node := serving.NewTrainerNode(serving.TrainerNodeConfig{
			Identity: nodeIdentity(id), Trainer: tr, Class: *class, Site: *site,
			AdvertiseHost: host, ControllerURLs: urls,
		})
		logf("trainer %s: dedicated training hardware (D17) — /train on %s, no inference data plane", *uuid, *trainListen)
		if err := node.Serve(ctx, *trainListen); err != nil && ctx.Err() == nil {
			check(err)
		}
		return
	}

	// run the inference data plane (engine + mTLS endpoint + Link heartbeat) — blocks.
	// RESOURCE BUDGET (internal/limits): full inside a cgroup that already caps us, polite (leave 2
	// cores for the user; <=2-core boxes go all-in) on a bare host, or an explicit override.
	maxCores, err := parseMaxCores(*maxCoresStr, *dedicated)
	check(err)
	capPlan := limits.Resolve(maxCores, *maxModelMemMB)
	logf("worker %s: resource budget — %s", *uuid, capPlan.Summary())
	effThreads := *threads
	if effThreads == 0 {
		effThreads = capPlan.Cores
	}

	logf("worker %s: starting %s engine + inference endpoint (model=%s)", *uuid, *engineKind, *modelID)
	opts := workerEngineOpts{
		engineKind: *engineKind, modelID: *modelID, llamaServer: *llamaServer, modelPath: *modelPath,
		engineBase: *engineBase, engineModel: *engineModel,
		enginePort: *enginePort, threads: effThreads, inferListen: *inferListen, advertiseHost: *advertiseHost,
		capPlan: capPlan, overrideCores: maxCores, overrideMemMB: *maxModelMemMB,
		maxConcurrent: *maxConc, queueDepth: *queueDepth, sloBudget: *sloBudget,
		controllerHost: hostOf(*addr), linkPort: *linkPort, linkURLs: linkURLs, class: *class, site: *site,
		wgConfOut: *wgConfOut, gatewayURL: gwURL(*gatewayURL, hostOf(*addr)),
		gpuLayers: ngl, accel: gpu.Backend, seed: *seedNode,
	}
	opts.reverseForce, opts.reverseAuto = parseReverseMode(*reverseTunnel)
	if err := runWorkerPlane(ctx, id, opts); err != nil && ctx.Err() == nil {
		check(err)
	}
}

// enforceOpenWorkerSafety is the no-code-execution invariant for PUBLIC nodes (OPEN-DANI-LAUNCH.md
// §Safety): a volunteer worker does inference ONLY. The one exec surface a worker could otherwise
// have is the TRAINER role (ExecTrainer shells out to a fine-tune command), so an open-join worker
// must never be a trainer and must never carry a --trainer-exec. Returns an error to refuse startup.
func enforceOpenWorkerSafety(role, trainerExec string) error {
	if strings.EqualFold(strings.TrimSpace(role), "trainer") {
		return fmt.Errorf("open-join workers are inference-only and cannot take the trainer role (it executes code)")
	}
	if strings.TrimSpace(trainerExec) != "" {
		return fmt.Errorf("open-join workers cannot set --trainer-exec (no code-execution surface on a public node)")
	}
	return nil
}

// parseMaxCores maps the friendly --max-cores spelling (auto | all | N) + --dedicated to the
// internal override: 0 = auto, limits.AllCores = dedicated, N = explicit cap.
func parseMaxCores(s string, dedicated bool) (int, error) {
	if dedicated {
		return limits.AllCores, nil
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto", "0":
		return 0, nil
	case "all", "dedicated":
		return limits.AllCores, nil
	default:
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("--max-cores %q: want auto, all, or a positive integer", s)
		}
		return n, nil
	}
}

// parseReverseMode maps the --reverse-tunnel value to (force, auto). Anything other than the two
// tunnel modes — including a typo — is dial-only (off), the conservative documented default.
func parseReverseMode(mode string) (force, auto bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "on", "force":
		return true, false
	case "auto":
		return false, true
	default: // off / empty / unrecognized
		return false, false
	}
}

// claimSlot atomically reserves a free bootstrap-token slot so concurrent worker replicas never
// collide on a single-use token. It creates <i>.lock with O_CREATE|O_EXCL (atomic on Linux and
// Windows); the first creator owns slot i. Retries until a slot is free or the timeout elapses.
func claimSlot(tokenDir string, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		entries, err := os.ReadDir(tokenDir)
		check(err)
		for _, e := range entries {
			var i int
			if _, err := fmt.Sscanf(e.Name(), "%d.token", &i); err != nil {
				continue
			}
			lock := filepath.Join(tokenDir, fmt.Sprintf("%d.lock", i))
			f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				continue // already claimed by another worker
			}
			_ = f.Close()
			return i
		}
		if time.Now().After(deadline) {
			check(fmt.Errorf("no free bootstrap-token slot in %s after %s", tokenDir, timeout))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// gwURL returns the controller gateway base URL — explicit override, else http://<host>:8081.
func gwURL(override, host string) string {
	if override != "" {
		return override
	}
	if host == "" {
		return ""
	}
	return fmt.Sprintf("http://%s:8081", host)
}

func waitReady(path string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			check(fmt.Errorf("controller not ready after %s (no %s)", timeout, path))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func mustTrustRoot(path string) *x509.Certificate {
	pemBytes, err := os.ReadFile(path)
	check(err)
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		check(fmt.Errorf("trust anchor %s is not PEM", path))
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	check(err)
	return cert
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "worker"
	}
	return h
}

func logf(format string, a ...any) {
	log.Printf(format, a...)
}

// gatewayTLS builds the external-gateway TLS config from the flags. "off" (default) = plain HTTP
// (dev / behind a TLS-terminating ingress); "on" = HTTPS with the mounted cert if provided, else a
// self-signed cert so HTTPS is available even before a real cert is provisioned (PRODUCTION P0-1).
func gatewayTLS(mode, cert, key string) *serving.GatewayTLS {
	if mode != "on" {
		return &serving.GatewayTLS{Enabled: false}
	}
	return &serving.GatewayTLS{Enabled: true, CertFile: cert, KeyFile: key}
}

// oidcOpts carries the SSO flags to the plane wiring.
type oidcOpts struct {
	issuer, clientID, clientSecret, redirect, roleMap, groupsClaim string
}
