package training

import (
	"context"
	"errors"
	"os"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/kms"
	"dani.local/agent/internal/modelreg"
)

// --- test doubles ---

type stubIdent map[string]string // engineer -> clearance

func (s stubIdent) Resolve(e string) (Principal, bool) {
	c, ok := s[e]
	if !ok {
		return Principal{}, false
	}
	return Principal{Name: e, Clearance: c}, true
}

type stubData map[string][]string // collection -> chunk classifications

func (s stubData) Collection(name string) (Collection, bool) {
	classes, ok := s[name]
	if !ok {
		return Collection{}, false
	}
	col := Collection{}
	for _, c := range classes {
		col.Chunks = append(col.Chunks, Chunk{Classification: c})
	}
	return col, true
}

type stubFleet struct{ uuid, addr string }

func (f stubFleet) ActiveTrainer() (string, string, bool) {
	if f.uuid == "" {
		return "", "", false
	}
	return f.uuid, f.addr, true
}

type errTrainer struct{}

func (errTrainer) Run(context.Context, Spec, func(int, int)) (Result, error) {
	return Result{}, errors.New("cuda oom")
}

func newSub(t *testing.T, ident stubIdent, data stubData, fleet stubFleet, tr Trainer) (*Subsystem, *modelreg.Registry) {
	t.Helper()
	ks, _ := kms.NewSoftware()
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reg := modelreg.New(ks, store)
	if err := reg.InitSigners(context.Background()); err != nil {
		t.Fatal(err)
	}
	sub := New(Deps{Identity: ident, Data: data, Fleet: fleet, Registry: reg, Store: store, Trainer: tr})
	return sub, reg
}

func TestSubmitHappyPathHandsOffCandidate(t *testing.T) {
	sub, reg := newSub(t,
		stubIdent{"bob": "restricted"},
		stubData{"legal": {"internal", "restricted"}}, // dataClass = restricted
		stubFleet{uuid: "trainer-1"},
		StubTrainer{})
	job, err := sub.Submit(context.Background(), Request{
		BaseModelID: "qwen2.5-1.5b", Collection: "legal", Method: "lora", Engineer: "bob",
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "completed" {
		t.Fatalf("state=%s err=%s", job.State, job.Err)
	}
	if job.DataClass != "restricted" || job.OutputClass != "restricted" {
		t.Fatalf("classification: data=%s out=%s", job.DataClass, job.OutputClass)
	}
	if job.CkptsDone != 3 || job.CkptsTotal != 3 {
		t.Fatalf("checkpoints %d/%d", job.CkptsDone, job.CkptsTotal)
	}
	if job.TrainerUUID != "trainer-1" {
		t.Fatalf("trainer=%s", job.TrainerUUID)
	}
	if job.Candidate == "" || reg.Get(job.Candidate) == nil {
		t.Fatal("candidate not handed to the model registry")
	}
	cand := reg.Get(job.Candidate)
	if cand.State != "draft" || cand.Base != "qwen2.5-1.5b" || cand.Artifact.Kind != "adapter" {
		t.Fatalf("bad candidate %+v", cand)
	}
	if cand.Lineage == nil || cand.Lineage.Method != "lora" || cand.Lineage.Collection != "legal" {
		t.Fatalf("bad lineage %+v", cand.Lineage)
	}
	// full end-to-end: promote and ensure it becomes routable.
	for _, role := range []modelreg.Role{modelreg.RoleSecurity, modelreg.RoleGovernance, modelreg.RoleAdmin} {
		reg.Sign(context.Background(), job.Candidate, role)
	}
	if reg.Resolve(job.Candidate) == nil {
		t.Fatal("promoted trained model should route")
	}
}

func TestSubmitDefaultsAndFullMethod(t *testing.T) {
	sub, reg := newSub(t,
		stubIdent{"alice": "secret"},
		stubData{"corp": {"unrestricted"}},
		stubFleet{uuid: "t"},
		StubTrainer{})
	// No method (defaults to lora... but test full-ft here), no name, no outputClass.
	job, err := sub.Submit(context.Background(), Request{
		BaseModelID: "llama-3.1-8b", Collection: "corp", Method: "full-ft", Engineer: "alice", BaseEngine: "vllm",
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Name != "llama-3.1-8b-full-ft-corp" {
		t.Fatalf("default name wrong: %s", job.Name)
	}
	if job.CkptsTotal != 6 {
		t.Fatalf("full-ft should have 6 ckpts, got %d", job.CkptsTotal)
	}
	if got := reg.Get(job.Candidate); got.Artifact.Kind != "model" || got.Engine != "vllm" {
		t.Fatalf("full-ft should store a full model via vllm, got kind=%s engine=%s", got.Artifact.Kind, got.Engine)
	}
}

func TestSubmitDefaultMethodLora(t *testing.T) {
	sub, _ := newSub(t, stubIdent{"bob": "internal"}, stubData{"c": {"internal"}}, stubFleet{uuid: "t"}, StubTrainer{})
	job, err := sub.Submit(context.Background(), Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if job.Method != "lora" || job.CkptsTotal != 3 {
		t.Fatalf("default method should be lora/3, got %s/%d", job.Method, job.CkptsTotal)
	}
}

func TestSubmitOutputClassDowngradeAllowed(t *testing.T) {
	sub, _ := newSub(t, stubIdent{"bob": "secret"}, stubData{"c": {"restricted"}}, stubFleet{uuid: "t"}, StubTrainer{})
	job, err := sub.Submit(context.Background(), Request{BaseModelID: "m", Collection: "c", Engineer: "bob", OutputClass: "internal"})
	if err != nil {
		t.Fatal(err)
	}
	if job.OutputClass != "internal" {
		t.Fatalf("explicit downgrade should hold, got %s", job.OutputClass)
	}
}

func TestSubmitAuthZAndAllocationFailures(t *testing.T) {
	cases := []struct {
		name  string
		ident stubIdent
		data  stubData
		fleet stubFleet
		req   Request
	}{
		{"unknown engineer", stubIdent{}, stubData{"c": {"internal"}}, stubFleet{uuid: "t"},
			Request{BaseModelID: "m", Collection: "c", Engineer: "ghost"}},
		{"dataset not ingested", stubIdent{"bob": "secret"}, stubData{}, stubFleet{uuid: "t"},
			Request{BaseModelID: "m", Collection: "missing", Engineer: "bob"}},
		{"clearance below data", stubIdent{"bob": "internal"}, stubData{"c": {"secret"}}, stubFleet{uuid: "t"},
			Request{BaseModelID: "m", Collection: "c", Engineer: "bob"}},
		{"output exceeds min", stubIdent{"bob": "secret"}, stubData{"c": {"internal"}}, stubFleet{uuid: "t"},
			Request{BaseModelID: "m", Collection: "c", Engineer: "bob", OutputClass: "secret"}},
		{"no trainer hardware", stubIdent{"bob": "secret"}, stubData{"c": {"internal"}}, stubFleet{uuid: ""},
			Request{BaseModelID: "m", Collection: "c", Engineer: "bob"}},
		{"unknown method", stubIdent{"bob": "secret"}, stubData{"c": {"internal"}}, stubFleet{uuid: "t"},
			Request{BaseModelID: "m", Collection: "c", Engineer: "bob", Method: "telepathy"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub, _ := newSub(t, tc.ident, tc.data, tc.fleet, StubTrainer{})
			job, err := sub.Submit(context.Background(), tc.req)
			if err == nil {
				t.Fatalf("expected error, got job %+v", job)
			}
			if job != nil {
				t.Fatal("failed AuthZ/allocation must create no job")
			}
			if len(sub.List()) != 0 {
				t.Fatal("no job should be recorded")
			}
		})
	}
}

func TestSubmitTrainerFailureMarksJobFailed(t *testing.T) {
	sub, _ := newSub(t, stubIdent{"bob": "secret"}, stubData{"c": {"internal"}}, stubFleet{uuid: "t"}, errTrainer{})
	job, err := sub.Submit(context.Background(), Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	if err != nil {
		t.Fatalf("a trainer failure is a job failure, not a submit error: %v", err)
	}
	if job.State != "failed" || job.Err == "" {
		t.Fatalf("expected failed job with error, got %+v", job)
	}
}

func TestSubmitStagingPutError(t *testing.T) {
	ks, _ := kms.NewSoftware()
	dir := filepath.Join(t.TempDir(), "store")
	store, _ := artifact.Open(dir)
	os.RemoveAll(dir)
	os.WriteFile(dir, []byte("x"), 0o600) // make Put fail during dataset staging
	reg := modelreg.New(ks, store)
	reg.InitSigners(context.Background())
	sub := New(Deps{Identity: stubIdent{"bob": "secret"}, Data: stubData{"c": {"internal"}}, Fleet: stubFleet{uuid: "t"}, Registry: reg, Store: store, Trainer: StubTrainer{}})
	job, err := sub.Submit(context.Background(), Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "failed" {
		t.Fatalf("dataset staging Put error should fail the job, got %s", job.State)
	}
}

// trainerFunc adapts a func to the Trainer interface.
type trainerFunc func(context.Context, Spec, func(int, int)) (Result, error)

func (f trainerFunc) Run(ctx context.Context, s Spec, on func(int, int)) (Result, error) {
	return f(ctx, s, on)
}

func TestSubmitCandidateHandoffError(t *testing.T) {
	ks, _ := kms.NewSoftware()
	dir := filepath.Join(t.TempDir(), "store")
	store, _ := artifact.Open(dir)
	reg := modelreg.New(ks, store)
	reg.InitSigners(context.Background())
	// Dataset staging Put runs first (dir exists, succeeds); the trainer then breaks the store, so the
	// candidate-hand-off Put fails — exercising run()'s SubmitCandidate error branch.
	sab := trainerFunc(func(_ context.Context, _ Spec, on func(int, int)) (Result, error) {
		on(1, 1)
		os.RemoveAll(dir)
		os.WriteFile(dir, []byte("x"), 0o600)
		return Result{Bytes: []byte("adapter"), Evals: map[string]float64{"task": 0.5}}, nil
	})
	sub := New(Deps{Identity: stubIdent{"bob": "secret"}, Data: stubData{"c": {"internal"}}, Fleet: stubFleet{uuid: "t"}, Registry: reg, Store: store, Trainer: sab})
	job, err := sub.Submit(context.Background(), Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "failed" || job.Candidate != "" {
		t.Fatalf("hand-off failure should fail the job with no candidate, got %+v", job)
	}
}

func TestAcceptThenExecuteAsync(t *testing.T) {
	sub, reg := newSub(t, stubIdent{"bob": "secret"}, stubData{"c": {"internal"}}, stubFleet{uuid: "t"}, StubTrainer{})
	var audited []string
	sub.audit = func(typ string, _ map[string]any) { audited = append(audited, typ) }
	ctx := context.Background()
	job, err := sub.Accept(ctx, Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if job.State != "staging" || job.Candidate != "" {
		t.Fatalf("Accept must not run the job: %+v", job)
	}
	// List/Get return snapshots, not the live pointer.
	if got := sub.Get(job.ID); got == job {
		t.Fatal("Get must return a copy")
	}
	sub.Execute(ctx, job)
	got := sub.Get(job.ID)
	if got.State != "completed" || got.Candidate == "" {
		t.Fatalf("Execute did not complete: %+v", got)
	}
	if reg.Get(got.Candidate) == nil {
		t.Fatal("candidate missing from registry")
	}
	// Evals map on the snapshot is a copy.
	got.Evals["task"] = -1
	if sub.Get(job.ID).Evals["task"] == -1 {
		t.Fatal("snapshot Evals must be a copy")
	}
	// the audit hook observed the async completion
	if len(audited) != 1 || audited[0] != "training.completed" {
		t.Fatalf("audit hook wrong: %v", audited)
	}
	// and a failure emits training.failed
	subF, _ := newSub(t, stubIdent{"bob": "secret"}, stubData{"c": {"internal"}}, stubFleet{uuid: "t"}, errTrainer{})
	var failed []string
	subF.audit = func(typ string, _ map[string]any) { failed = append(failed, typ) }
	jf, _ := subF.Accept(ctx, Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	subF.Execute(ctx, jf)
	if len(failed) != 1 || failed[0] != "training.failed" {
		t.Fatalf("failure audit hook wrong: %v", failed)
	}
}

func TestListOrderedAndGet(t *testing.T) {
	sub, _ := newSub(t, stubIdent{"bob": "secret"}, stubData{"c": {"internal"}}, stubFleet{uuid: "t"}, StubTrainer{})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		sub.Submit(ctx, Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	}
	list := sub.List()
	if len(list) != 3 || list[0].ID != "job-1" || list[2].ID != "job-3" {
		t.Fatalf("List must be ordered by submission, got %d jobs", len(list))
	}
	if sub.Get("job-2") == nil || sub.Get("nope") != nil {
		t.Fatal("Get by id failed")
	}
}

func TestRankAndMaxClassDefaults(t *testing.T) {
	if rank("bogus") != 1 {
		t.Fatal("unknown class ranks as internal")
	}
	if maxClass("unrestricted", "secret") != "secret" {
		t.Fatal("maxClass wrong")
	}
	if maxClass("secret", "internal") != "secret" {
		t.Fatal("maxClass wrong (a>=b branch)")
	}
	if minRank(2, 5) != 2 || minRank(5, 2) != 2 {
		t.Fatal("minRank wrong")
	}
	if replacePrefix("job-7") != "v7" || replacePrefix("weird") != "weird" {
		t.Fatal("replacePrefix wrong")
	}
}

// flakyFleet returns trainer A first, then trainer B (the re-allocation target).
type flakyFleet struct{ calls int }

func (f *flakyFleet) ActiveTrainer() (string, string, bool) {
	f.calls++
	if f.calls == 1 {
		return "dead-trainer", "127.0.0.1:1", true // remote addr that will fail
	}
	return "live-trainer", "", true // local execution on retry
}

func TestExecuteReallocatesFromDeadRemoteTrainer(t *testing.T) {
	ks, _ := kms.NewSoftware()
	store, _ := artifact.Open(t.TempDir())
	reg := modelreg.New(ks, store)
	reg.InitSigners(context.Background())
	fleet := &flakyFleet{}
	var audited []string
	// remote leg fails (dial 127.0.0.1:1 via a trainer that always errors on remote); local leg = stub
	sub := New(Deps{
		Identity: stubIdent{"bob": "secret"}, Data: stubData{"c": {"internal"}}, Fleet: fleet,
		Registry: reg, Store: store,
		Trainer: DispatchTrainer{Local: StubTrainer{}, Remote: RemoteTrainer{Client: httpClientShortTimeout()}},
		Audit:   func(typ string, _ map[string]any) { audited = append(audited, typ) },
	})
	job, err := sub.Accept(context.Background(), Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if job.TrainerUUID != "dead-trainer" {
		t.Fatalf("first allocation should be the dead trainer, got %s", job.TrainerUUID)
	}
	sub.Execute(context.Background(), job)
	got := sub.Get(job.ID)
	if got.State != "completed" || got.TrainerUUID != "live-trainer" {
		t.Fatalf("job must complete on the re-allocated trainer: %+v", got)
	}
	want := map[string]bool{}
	for _, a := range audited {
		want[a] = true
	}
	if !want["training.reallocated"] || !want["training.completed"] {
		t.Fatalf("audit trail missing re-allocation: %v", audited)
	}
}

func TestExecuteNoRetryWhenSameTrainerReturned(t *testing.T) {
	// re-allocation returns the SAME dead node -> no retry loop, job fails cleanly
	sub, _ := newSub(t, stubIdent{"bob": "secret"}, stubData{"c": {"internal"}},
		stubFleet{uuid: "dead", addr: "127.0.0.1:1"},
		DispatchTrainer{Local: StubTrainer{}, Remote: RemoteTrainer{Client: httpClientShortTimeout()}})
	job, err := sub.Accept(context.Background(), Request{BaseModelID: "m", Collection: "c", Engineer: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	sub.Execute(context.Background(), job)
	if got := sub.Get(job.ID); got.State != "failed" {
		t.Fatalf("same-node re-allocation must not retry forever: %+v", got)
	}
}

func httpClientShortTimeout() *http.Client { return &http.Client{Timeout: 500 * time.Millisecond} }
