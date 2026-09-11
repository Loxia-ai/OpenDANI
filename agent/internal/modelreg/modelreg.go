// Package modelreg is the Model Registry (Architecture §6.21 #7, §6.17.4).
//
// Two entry paths:
//   - Register: an administrator adds a model directly (DEMO seeding) — state=available immediately.
//   - SubmitCandidate: a training-produced model enters as state=draft and must pass the full v1.0
//     3-signer promotion workflow (§6.17.4, D25): the Security Officer, Governance Officer, and DANI
//     Administrator each cryptographically sign; only when all three signatures verify does the model
//     become available (routable).
//
// Signatures are REAL Ed25519 signatures produced by the KMS (unlike the simulator's per-object
// keypairs — DANI already has a KMS, so the three reviewer roles are three purpose keys). Each
// signature covers canonical(modelID, contentHash, role); Resolve re-verifies every signature on use
// (verify-on-use, DP13), so tampering with the entry or its artifact hash makes it stop routing.
//
// Immutable versions: an entry's identity is (id); its content is pinned by the artifact hash.
package modelreg

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/pkg/dani"
)

// Role is one of the three reviewer roles required to promote a model (D25).
type Role string

const (
	RoleSecurity   Role = "security-officer"
	RoleGovernance Role = "governance-officer"
	RoleAdmin      Role = "administrator"
)

// signerRoles is the required signer set, in canonical order.
var signerRoles = []Role{RoleSecurity, RoleGovernance, RoleAdmin}

// rolePurpose maps each reviewer role to its KMS signing key (pkg/dani).
var rolePurpose = map[Role]dani.KeyPurpose{
	RoleSecurity:   dani.PurposeModelSignSecurity,
	RoleGovernance: dani.PurposeModelSignGovernance,
	RoleAdmin:      dani.PurposeModelSignAdmin,
}

// nowFn is a seam so tests get deterministic timestamps (production: time.Now).
var nowFn = time.Now

// Signature is one reviewer's approval over an entry.
type Signature struct {
	Role   Role      `json:"role"`
	PubDER []byte    `json:"pub"` // SPKI public key the signature verifies against (self-describing)
	Sig    []byte    `json:"sig"`
	At     time.Time `json:"at"`
}

// Lineage records where a trained model came from (dataset + method + engineer).
type Lineage struct {
	Base, DatasetID, Method, Collection, Engineer string
}

// Entry is a registered model.
type Entry struct {
	ID, Name, Version string
	Engine            string
	Classification    string
	Base              string // base model id for a fine-tune; "" for a base
	Artifact          artifact.Ref
	Lineage           *Lineage
	Evals             map[string]float64
	State             string // draft | available | deprecated
	Signatures        map[Role]Signature
	GateFailed        string // non-empty: automated evals below the promotion bar (blocks available)
}

// EvalGate is the automated quality bar a training-produced candidate must clear before its
// signatures can promote it (§6.17.6 automated evals + §6.17.4 promotion). Thresholds are minimums
// (>=) except MaxPerplexity (<=); a zero threshold is "not checked". This is a DEMO-scope policy
// knob — centralizing thresholds in the Policy Engine is the v1.0 home (flagged).
type EvalGate struct {
	MinTask       float64 // e.g. corpus-recall score
	MinSafety     float64
	MaxPerplexity float64 // eval_perplexity ceiling (0 = unchecked)
}

// check returns "" if the evals clear the gate, else a human-readable failure reason.
func (g EvalGate) check(ev map[string]float64) string {
	get := func(k string) (float64, bool) { v, ok := ev[k]; return v, ok }
	if g.MinTask > 0 {
		if v, ok := get("task"); ok && v < g.MinTask {
			return fmt.Sprintf("task %.2f < min %.2f", v, g.MinTask)
		}
	}
	if g.MinSafety > 0 {
		if v, ok := get("safety"); ok && v < g.MinSafety {
			return fmt.Sprintf("safety %.2f < min %.2f", v, g.MinSafety)
		}
	}
	if g.MaxPerplexity > 0 {
		if v, ok := get("eval_perplexity"); ok && v > g.MaxPerplexity {
			return fmt.Sprintf("eval_perplexity %.1f > max %.1f", v, g.MaxPerplexity)
		}
	}
	return ""
}

// RagAlias is a RAG-compound alias (M9): a virtual model `<base>-rag-<collection>` that routes to
// the BASE model with classification-filtered retrieval bolted on. It is not a registry entry and
// needs no signatures — the base already passed promotion, the collection already passed
// classification-at-ingest.
type RagAlias struct {
	Alias, BaseModelID, Collection string
}

// Registry is the Model Registry. In-memory by default; SetDurable persists every mutation so a
// controller restart (paired with the resumed KMS authority, D-14 #2) keeps promoted models,
// their signatures, and RAG aliases — verify-on-use still re-checks each signature against the
// pinned content hash on every pull, so a tampered snapshot cannot smuggle a model in.
type Registry struct {
	mu         sync.Mutex
	ks         dani.KeyStore          // default/shared backing keystore (used to build the DEMO signers)
	signers    map[Role]RoleSigner    // one signer PER reviewer role — three distinct principals in prod
	store      *artifact.Store
	models     map[string]*Entry
	aliases    map[string]string
	ragAliases map[string]RagAlias
	gate       EvalGate // automated promotion quality bar (zero value = no gate)
	durable    string   // "" = in-memory only; else snapshot path written on every mutation
	// replicate ships the post-mutation snapshot bytes to the Raft cluster (leader applies to all
	// replicas' FSMs). nil = single-controller. Always invoked AFTER r.mu is released — the leader's
	// own FSM.Apply reloads the snapshot under r.mu, so replicating while holding it would deadlock.
	replicate func([]byte) error
}

// SetReplicator wires cluster replication: after each durable mutation the registry ships its full
// snapshot through the callback (the controller points this at the Raft node's ApplyModelSnapshot).
func (r *Registry) SetReplicator(fn func([]byte) error) *Registry {
	r.mu.Lock()
	r.replicate = fn
	r.mu.Unlock()
	return r
}

// snapshotBytesLocked marshals the authoritative state (r.mu must be held).
func (r *Registry) snapshotBytesLocked() []byte {
	data, _ := json.Marshal(regSnapshot{Models: r.models, Aliases: r.aliases, RagAliases: r.ragAliases})
	return data
}

// SnapshotBytes returns the current authoritative snapshot (for Raft FSM log compaction / joiner
// catch-up). Safe to call concurrently.
func (r *Registry) SnapshotBytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshotBytesLocked()
}

// LoadSnapshotBytes replaces the registry's state from replicated snapshot bytes (the FSM's apply
// path on every replica). It does NOT persist or re-replicate — it is the terminal sink. A corrupt
// snapshot is an error so the FSM surfaces it rather than silently diverging.
func (r *Registry) LoadSnapshotBytes(data []byte) error {
	var snap regSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("modelreg: bad replicated snapshot: %w", err)
	}
	r.mu.Lock()
	if snap.Models != nil {
		r.models = snap.Models
	}
	if snap.Aliases != nil {
		r.aliases = snap.Aliases
	}
	if snap.RagAliases != nil {
		r.ragAliases = snap.RagAliases
	}
	err := r.save() // a replica persists what it received (durability + replication compose)
	r.mu.Unlock()
	return err
}

// regSnapshot is the durable serialization of the registry's authoritative state.
type regSnapshot struct {
	Models     map[string]*Entry   `json:"models"`
	Aliases    map[string]string   `json:"aliases"`
	RagAliases map[string]RagAlias `json:"ragAliases"`
}

// SetDurable makes the registry persistent: existing state at path is rehydrated NOW, and every
// subsequent mutation rewrites the snapshot (0600). A corrupt snapshot is a hard error — silently
// starting empty would un-promote every model in the deployment.
func (r *Registry) SetDurable(path string) (*Registry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.durable = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil // first boot: nothing to rehydrate
	}
	if err != nil {
		return nil, err
	}
	var snap regSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("modelreg: snapshot %s is corrupt (refusing to start empty): %w", path, err)
	}
	if snap.Models != nil {
		r.models = snap.Models
	}
	if snap.Aliases != nil {
		r.aliases = snap.Aliases
	}
	if snap.RagAliases != nil {
		r.ragAliases = snap.RagAliases
	}
	return r, nil
}

// save persists the snapshot (mu must be held). No-op when in-memory.
func (r *Registry) save() error {
	if r.durable == "" {
		return nil
	}
	data, _ := json.Marshal(regSnapshot{Models: r.models, Aliases: r.aliases, RagAliases: r.ragAliases})
	if err := os.WriteFile(r.durable, data, 0o600); err != nil {
		return fmt.Errorf("modelreg: persist snapshot: %w", err)
	}
	return nil
}

// SetGate configures the automated eval promotion bar. Returns the registry for chaining.
func (r *Registry) SetGate(g EvalGate) *Registry {
	r.mu.Lock()
	r.gate = g
	r.mu.Unlock()
	return r
}

// New builds a Model Registry backed by a KMS (reviewer signing keys) and an Artifact Store. By
// default the three reviewer roles are backed by ks (the DEMO's shared-KMS model); call
// WithRoleSigners to give each role its own principal/HSM (production three-party control).
func New(ks dani.KeyStore, store *artifact.Store) *Registry {
	return &Registry{ks: ks, signers: defaultSigners(ks), store: store, models: map[string]*Entry{},
		aliases: map[string]string{}, ragAliases: map[string]RagAlias{}}
}

// WithRoleSigners replaces the reviewer signers so each role signs through its OWN principal — the
// production three-party control (ROADMAP §2): each key in a distinct HSM, no single actor able to
// mint all three approvals. Every signerRole must be present (enforced at InitSigners/Sign). Returns
// the registry for chaining.
func (r *Registry) WithRoleSigners(signers map[Role]RoleSigner) *Registry {
	r.mu.Lock()
	r.signers = signers
	r.mu.Unlock()
	return r
}

// InitSigners eagerly materializes each reviewer role's signing key (like the enrollment key at
// genesis) so a controller can verify signatures and — for the shared-KMS DEMO — every controller
// shares identical approval keys. Fails if any reviewer role has no signer configured.
func (r *Registry) InitSigners(ctx context.Context) error {
	for _, role := range signerRoles {
		s, ok := r.signers[role]
		if !ok {
			return fmt.Errorf("modelreg: no signer configured for reviewer role %q", role)
		}
		if _, err := s.Public(ctx); err != nil {
			return err
		}
	}
	return nil
}

// canonical is the deterministic byte string a reviewer signs: the model id, its pinned content hash,
// and the role. Binding the hash means a re-signed/tampered artifact invalidates every signature.
func canonical(modelID, contentHash string, role Role) []byte {
	b, _ := json.Marshal(struct {
		ModelID     string `json:"modelId"`
		ContentHash string `json:"contentHash"`
		Role        Role   `json:"role"`
	}{modelID, contentHash, role})
	return b
}

// RegisterMeta describes an administrator-added model.
type RegisterMeta struct {
	ID, Name, Version, Engine, Classification string
	Aliases                                   []string
}

// Register adds a model directly as available (DEMO admin seeding — no approval workflow). data is the
// model's bytes (or a descriptor for a pulled model); it is content-addressed into the store.
func (r *Registry) Register(_ context.Context, meta RegisterMeta, data []byte) (*Entry, error) {
	ref, err := r.store.Put("model", data)
	if err != nil {
		return nil, err
	}
	e := &Entry{
		ID: meta.ID, Name: meta.Name, Version: meta.Version, Engine: meta.Engine,
		Classification: defClass(meta.Classification), Artifact: ref, State: "available",
		Signatures: map[Role]Signature{},
	}
	r.mu.Lock()
	r.models[e.ID] = e
	r.aliases[e.Name] = e.ID
	for _, a := range meta.Aliases {
		r.aliases[a] = e.ID
	}
	snap, err := r.commitLocked()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := r.replicateSnap(snap); err != nil {
		return nil, err
	}
	return e, nil
}

// commitLocked persists the current state and returns the snapshot bytes to replicate (r.mu held).
func (r *Registry) commitLocked() ([]byte, error) {
	if err := r.save(); err != nil {
		return nil, err
	}
	if r.replicate == nil {
		return nil, nil
	}
	return r.snapshotBytesLocked(), nil
}

// replicateSnap ships snap through the cluster (no-op when nil). Called AFTER r.mu is released.
func (r *Registry) replicateSnap(snap []byte) error {
	if snap == nil || r.replicate == nil {
		return nil
	}
	return r.replicate(snap)
}

// CandidateMeta describes a training-produced candidate.
type CandidateMeta struct {
	ID, Name, Version, Engine, Classification, Base string
	Lineage                                         *Lineage
	Evals                                           map[string]float64
}

// SubmitCandidate enters a training-produced model as a draft awaiting 3-signer promotion. data is the
// produced adapter/model bytes; they are content-addressed into the store (kind adapter for LoRA).
func (r *Registry) SubmitCandidate(_ context.Context, meta CandidateMeta, kind string, data []byte) (*Entry, error) {
	ref, err := r.store.Put(kind, data)
	if err != nil {
		return nil, err
	}
	e := &Entry{
		ID: meta.ID, Name: meta.Name, Version: meta.Version, Engine: meta.Engine,
		Classification: defClass(meta.Classification), Base: meta.Base, Artifact: ref,
		Lineage: meta.Lineage, Evals: meta.Evals, State: "draft", Signatures: map[Role]Signature{},
	}
	r.mu.Lock()
	r.models[e.ID] = e
	snap, err := r.commitLocked()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := r.replicateSnap(snap); err != nil {
		return nil, err
	}
	return e, nil
}

// Sign applies one reviewer role's cryptographic approval to a draft model. When all three roles have
// signed and every signature verifies, the model transitions draft → available (routable).
func (r *Registry) Sign(ctx context.Context, modelID string, role Role) (*Entry, error) {
	if _, ok := rolePurpose[role]; !ok {
		return nil, fmt.Errorf("modelreg: unknown signer role %q", role)
	}
	r.mu.Lock()
	signer, ok := r.signers[role]
	if !ok {
		r.mu.Unlock()
		return nil, fmt.Errorf("modelreg: no signer configured for reviewer role %q", role)
	}
	e, ok := r.models[modelID]
	if !ok {
		r.mu.Unlock()
		return nil, errors.New("modelreg: unknown model")
	}
	if e.State != "draft" {
		r.mu.Unlock()
		return nil, fmt.Errorf("modelreg: model not in draft (state=%s)", e.State)
	}
	// Each role signs through its OWN principal (three-party control): a distinct HSM in production,
	// a shared software KMS in the DEMO. The signature carries its own public key for verify-on-use.
	msg := canonical(e.ID, e.Artifact.Hash, role)
	sig, err := signer.Sign(ctx, msg)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	pub, err := signer.Public(ctx)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	e.Signatures[role] = Signature{Role: role, PubDER: pub, Sig: sig, At: nowFn().UTC()}
	if r.fullySigned(e) && r.verify(e) {
		// automated quality gate (§6.17.6): three human signatures are necessary but not sufficient —
		// a candidate whose measured evals miss the bar stays a draft (officers can't rubber-stamp a
		// bad model). The gate is re-checked here so evals updated after submission still apply.
		if reason := r.gate.check(e.Evals); reason != "" {
			e.GateFailed = reason
		} else {
			e.GateFailed = ""
			e.State = "available"
		}
	}
	snap, err := r.commitLocked()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := r.replicateSnap(snap); err != nil {
		return nil, err
	}
	return e, nil
}

// fullySigned reports whether all three reviewer roles have signed (caller holds the lock).
func (r *Registry) fullySigned(e *Entry) bool {
	for _, role := range signerRoles {
		if _, ok := e.Signatures[role]; !ok {
			return false
		}
	}
	return true
}

// verify re-checks every present signature against the entry's current id + artifact hash. Any missing
// or failing signature => not approved (caller holds the lock; pure crypto, no KMS round-trip).
func (r *Registry) verify(e *Entry) bool {
	for _, role := range signerRoles {
		s, ok := e.Signatures[role]
		if !ok {
			return false
		}
		pubAny, err := x509.ParsePKIXPublicKey(s.PubDER)
		if err != nil {
			return false
		}
		pub, ok := pubAny.(ed25519.PublicKey)
		if !ok {
			return false
		}
		if !ed25519.Verify(pub, canonical(e.ID, e.Artifact.Hash, role), s.Sig) {
			return false
		}
	}
	return true
}

// VerifyApproval reports whether a model currently carries three valid reviewer signatures.
func (r *Registry) VerifyApproval(modelID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.models[modelID]
	if !ok {
		return false
	}
	return r.verify(e)
}

// Resolve returns a model by id or alias ONLY if it is routable: state=available and, if it came
// through the approval workflow, its signatures still verify (verify-on-use, DP13). Tampering with the
// entry or artifact hash makes Resolve return nil. Admin-registered bases have no signatures and route
// on state alone.
func (r *Registry) Resolve(idOrAlias string) *Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.models[idOrAlias]
	if !ok {
		if id, aliased := r.aliases[idOrAlias]; aliased {
			e, ok = r.models[id]
		}
	}
	if !ok || e.State != "available" {
		return nil
	}
	if len(e.Signatures) > 0 && !r.verify(e) {
		return nil // was approved but no longer verifies — refuse to route (DP13)
	}
	return e
}

// RegisterRagAlias creates (or refreshes) a RAG-compound alias `<base>-rag-<collection>` (M9).
func (r *Registry) RegisterRagAlias(baseModelID, collection string) RagAlias {
	a := RagAlias{Alias: baseModelID + "-rag-" + collection, BaseModelID: baseModelID, Collection: collection}
	r.mu.Lock()
	r.ragAliases[a.Alias] = a
	snap, _ := r.commitLocked() // best-effort: an alias is re-creatable with one POST
	r.mu.Unlock()
	_ = r.replicateSnap(snap)
	return a
}

// ResolveRag returns the RAG alias for name (ok=false if none).
func (r *Registry) ResolveRag(name string) (RagAlias, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.ragAliases[name]
	return a, ok
}

// RagAliases lists registered RAG-compound aliases, alias-ordered.
func (r *Registry) RagAliases() []RagAlias {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RagAlias, 0, len(r.ragAliases))
	for _, a := range r.ragAliases {
		out = append(out, a)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Alias < out[j-1].Alias; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Get returns an entry by id regardless of state (nil if unknown).
func (r *Registry) Get(id string) *Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.models[id]
}

// All returns every entry, ordered by id.
func (r *Registry) All() []*Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Entry, 0, len(r.models))
	for _, e := range r.models {
		out = append(out, e)
	}
	sortByID(out)
	return out
}

// Drafts returns entries awaiting promotion.
func (r *Registry) Drafts() []*Entry {
	var out []*Entry
	for _, e := range r.All() {
		if e.State == "draft" {
			out = append(out, e)
		}
	}
	return out
}

func defClass(c string) string {
	if c == "" {
		return "unrestricted"
	}
	return c
}

func sortByID(es []*Entry) {
	for i := 1; i < len(es); i++ {
		for j := i; j > 0 && es[j-1].ID > es[j].ID; j-- {
			es[j-1], es[j] = es[j], es[j-1]
		}
	}
}
