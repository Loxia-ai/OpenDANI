// Package training is the Training Subsystem (Architecture §6.21 #15, §6.17.6): fine-tune a model on
// the customer's own data, in-perimeter, and hand the result to the Model Registry for promotion.
//
// Job lifecycle: AuthZ (dataset classification × engineer clearance) -> allocate DEDICATED training
// hardware (a trainer-role node — D17, never an inference worker) -> stage the dataset and record
// lineage (dataset <-> source) -> run the fine-tune with checkpoints -> automated evals -> submit the
// candidate to the Model Registry as a draft (enters the §6.17.4 3-signer promotion workflow).
//
// The fine-tune MATH is the one mocked piece (as inference is elsewhere): it sits behind the Trainer
// interface. StubTrainer is deterministic (the DEMO/CI default; no GPU). ExecTrainer shells a real
// PEFT/TRL QLoRA script on a GPU trainer node. Everything else — AuthZ, D17 allocation, dataset
// lineage, checkpoint accounting, content-addressed artifacts, and the registry hand-off — is real.
package training

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/modelreg"
)

// classRank orders classifications; higher dominates (matches serving.classRank and the sim).
var classRank = map[string]int{"unrestricted": 0, "internal": 1, "restricted": 2, "secret": 3}

func rank(c string) int {
	if r, ok := classRank[c]; ok {
		return r
	}
	return 1 // unknown treated as "internal" (fail-closed-ish), matching the sim's default
}

func maxClass(a, b string) string {
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

func minRank(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// method describes the relative cost of a fine-tune method (D21): checkpoint count + whether it
// produces a small adapter (LoRA/QLoRA) or a full-size model.
type method struct {
	ckpts   int
	adapter bool
}

var methodTable = map[string]method{
	"full-ft":     {ckpts: 6, adapter: false},
	"lora":        {ckpts: 3, adapter: true},
	"qlora":       {ckpts: 3, adapter: true},
	"instruction": {ckpts: 3, adapter: false},
	"rlhf":        {ckpts: 5, adapter: false},
	"dpo":         {ckpts: 4, adapter: false},
}

// nowFn is a seam for deterministic timestamps in tests (production: time.Now).
var nowFn = time.Now

// Principal is the resolved identity of the engineer submitting a job.
type Principal struct {
	Name      string
	Clearance string
}

// IdentityResolver resolves an engineer name to a Principal (the Identity subsystem in production).
type IdentityResolver interface {
	Resolve(engineer string) (Principal, bool)
}

// Chunk is one unit of a dataset. Text is the flattened rendering (classification + text-only
// trainers); a structured example additionally carries Format "chat" plus the OpenAI messages/tools
// JSON, passed straight through to the trainer so it can fine-tune on instruction / multi-turn /
// tool-calling data via the model's chat template.
type Chunk struct {
	Text           string          `json:"text"`
	Classification string          `json:"classification"`
	Format         string          `json:"format,omitempty"`
	Messages       json.RawMessage `json:"messages,omitempty"`
	Tools          json.RawMessage `json:"tools,omitempty"`
}

// Collection is a named, ingested dataset (a list of classified chunks).
type Collection struct{ Chunks []Chunk }

// DataSource provides ingested collections (the Ingest subsystem in production).
type DataSource interface {
	Collection(name string) (Collection, bool)
}

// Fleet finds dedicated training hardware (D17): an active node whose roles include "trainer".
// addr is the node's mTLS /train endpoint when the trainer executes jobs REMOTELY on its own
// hardware; "" means the job executes in-process (the local ExecTrainer/Stub path).
type Fleet interface {
	ActiveTrainer() (uuid, addr string, ok bool)
}

// Spec is the fine-tune request handed to a Trainer.
type Spec struct {
	BaseModelID string
	Method      string
	DatasetID   string
	DatasetFile string // on-disk path of the STAGED dataset (content-addressed; for ExecTrainer)
	TrainerAddr string // the allocated trainer node's /train endpoint ("" = execute in-process)
	Hyper       map[string]any
}

// Result is what a Trainer produces: the adapter/model bytes and evaluation scores.
type Result struct {
	Bytes []byte
	Evals map[string]float64
}

// Trainer runs the fine-tune. onCkpt is called after each checkpoint (done, total). This is the
// mocked seam: StubTrainer for CI/DEMO, ExecTrainer for a real GPU job.
type Trainer interface {
	Run(ctx context.Context, spec Spec, onCkpt func(done, total int)) (Result, error)
}

// Job is a training job's observable state.
type Job struct {
	ID, Name, BaseModelID, Collection, Method string
	Engineer, TrainerUUID                     string
	DataClass, OutputClass                    string
	State                                     string // staging|running|evaluating|completed|failed
	CkptsDone, CkptsTotal                     int
	DatasetID, Candidate                      string
	Evals                                     map[string]float64
	Err                                       string

	// execution context captured at Accept time so Execute can run later (possibly on a goroutine)
	col         Collection
	m           method
	req         Request
	trainerAddr string // "" = in-process execution; else the trainer node's /train endpoint
}

// Subsystem orchestrates training jobs.
type Subsystem struct {
	ident   IdentityResolver
	data    DataSource
	fleet   Fleet
	reg     *modelreg.Registry
	store   *artifact.Store
	trainer Trainer
	audit   func(typ string, payload map[string]any)

	mu    sync.Mutex
	jobs  map[string]*Job
	order []string // job ids in submission order (List is deterministic without sorting a map)
	seq   int
}

// Deps bundles the Training Subsystem's collaborators.
type Deps struct {
	Identity IdentityResolver
	Data     DataSource
	Fleet    Fleet
	Registry *modelreg.Registry
	Store    *artifact.Store
	Trainer  Trainer
	Audit    func(typ string, payload map[string]any) // optional audit hook for async outcomes
}

// New builds a Training Subsystem.
func New(d Deps) *Subsystem {
	return &Subsystem{
		ident: d.Identity, data: d.Data, fleet: d.Fleet, reg: d.Registry,
		store: d.Store, trainer: d.Trainer, audit: d.Audit, jobs: map[string]*Job{},
	}
}

// Request is a training-job submission.
type Request struct {
	BaseModelID string
	Collection  string
	Method      string // default "lora"
	Engineer    string
	Name        string
	OutputClass string // default = dataset classification
	Hyper       map[string]any
	BaseEngine  string // engine of the base model (default "llama.cpp")
}

// Submit validates and runs a training job synchronously (a trainer worker calls this off the request
// path). It performs AuthZ + D17 allocation, then drives staging -> running -> evaluating -> completed
// and hands a draft candidate to the Model Registry. On any AuthZ/allocation failure it returns an
// error and creates no job; on a Trainer failure it returns the job in state=failed.
func (s *Subsystem) Submit(ctx context.Context, req Request) (*Job, error) {
	job, err := s.Accept(ctx, req)
	if err != nil {
		return nil, err
	}
	s.Execute(ctx, job)
	return job, nil
}

// Accept performs AuthZ + D17 allocation and records the job in state=staging WITHOUT running it —
// the async half for callers (the gateway) that Execute on a goroutine and poll progress. On any
// AuthZ/allocation failure it returns an error and creates no job.
func (s *Subsystem) Accept(_ context.Context, req Request) (*Job, error) {
	principal, ok := s.ident.Resolve(req.Engineer)
	if !ok {
		return nil, fmt.Errorf("training: unknown engineer %q", req.Engineer)
	}
	col, ok := s.data.Collection(req.Collection)
	if !ok {
		return nil, fmt.Errorf("training: dataset %q not ingested", req.Collection)
	}
	// Dataset classification = max over chunk classifications (§6.17.6 input classification).
	dataClass := "unrestricted"
	for _, c := range col.Chunks {
		dataClass = maxClass(dataClass, c.Classification)
	}
	// AuthZ: engineer must be cleared for the data (rank(clearance) >= rank(data)).
	if rank(dataClass) > rank(principal.Clearance) {
		return nil, fmt.Errorf("training: AuthZ denied — %s clearance %s < data %s", req.Engineer, principal.Clearance, dataClass)
	}
	outClass := req.OutputClass
	if outClass == "" {
		outClass = dataClass
	}
	// Output classification must not exceed min(clearance, data).
	if rank(outClass) > minRank(rank(principal.Clearance), rank(dataClass)) {
		return nil, fmt.Errorf("training: output classification %s exceeds min(clearance, data)", outClass)
	}
	trainerUUID, trainerAddr, ok := s.fleet.ActiveTrainer()
	if !ok {
		return nil, fmt.Errorf("training: no training hardware available (deploy a trainer node — D17)")
	}

	methodName := req.Method
	if methodName == "" {
		methodName = "lora"
	}
	m, ok := methodTable[methodName]
	if !ok {
		return nil, fmt.Errorf("training: unknown method %q", methodName)
	}

	s.mu.Lock()
	s.seq++
	id := fmt.Sprintf("job-%d", s.seq)
	s.mu.Unlock()

	name := req.Name
	if name == "" {
		name = fmt.Sprintf("%s-%s-%s", req.BaseModelID, methodName, req.Collection)
	}
	job := &Job{
		ID: id, Name: name, BaseModelID: req.BaseModelID, Collection: req.Collection, Method: methodName,
		Engineer: req.Engineer, TrainerUUID: trainerUUID, DataClass: dataClass, OutputClass: outClass,
		State: "staging", CkptsTotal: m.ckpts, DatasetID: fmt.Sprintf("ds-%s-%s", req.Collection, id),
		col: col, m: m, req: req, trainerAddr: trainerAddr,
	}
	s.mu.Lock()
	s.jobs[id] = job
	s.order = append(s.order, id)
	s.mu.Unlock()
	return job, nil
}

// Execute runs an Accepted job to completion (or failure). Safe to call on a goroutine: all job
// mutations happen under the subsystem lock, so Get/List snapshots observe consistent progress.
//
// Dead-node resilience: allocation reads heartbeats, and a node can die INSIDE the staleness
// window — allocation then hands out a corpse (observed live, Run 9). If a REMOTE run fails, the
// job re-allocates once; a re-allocation that lands on a DIFFERENT live trainer retries there.
func (s *Subsystem) Execute(ctx context.Context, job *Job) {
	err := s.run(ctx, job)
	if err != nil && job.trainerAddr != "" {
		if uuid, addr, ok := s.fleet.ActiveTrainer(); ok && uuid != job.TrainerUUID {
			if s.audit != nil {
				s.audit("training.reallocated", map[string]any{"job": job.ID, "from": job.TrainerUUID, "to": uuid, "error": err.Error()})
			}
			s.mutate(job, func(j *Job) { j.TrainerUUID, j.trainerAddr = uuid, addr; j.State = "staging"; j.CkptsDone = 0 })
			err = s.run(ctx, job)
		}
	}
	if err != nil {
		s.mutate(job, func(j *Job) { j.State = "failed"; j.Err = err.Error() })
		if s.audit != nil {
			s.audit("training.failed", map[string]any{"job": job.ID, "error": err.Error()})
		}
		return
	}
	if s.audit != nil {
		s.audit("training.completed", map[string]any{"job": job.ID, "candidate": job.Candidate, "trainer": job.TrainerUUID})
	}
}

// mutate applies fn to a job under the lock (Execute may be racing HTTP snapshot reads).
func (s *Subsystem) mutate(job *Job, fn func(*Job)) {
	s.mu.Lock()
	fn(job)
	s.mu.Unlock()
}

// run drives a job through staging -> running -> evaluating -> completed and hands off the candidate.
func (s *Subsystem) run(ctx context.Context, job *Job) error {
	col, m, req := job.col, job.m, job.req
	// Stage the REAL dataset (the classified chunk texts) content-addressed, so the lineage points
	// at the exact bytes the fine-tune consumed — and a real trainer reads exactly what was staged.
	dsBytes, _ := json.Marshal(struct {
		DatasetID  string  `json:"datasetId"`
		Collection string  `json:"collection"`
		Chunks     []Chunk `json:"chunks"`
	}{job.DatasetID, job.Collection, col.Chunks}) // plain string fields — cannot fail
	ref, err := s.store.Put("dataset", dsBytes)
	if err != nil {
		return err
	}
	s.mutate(job, func(j *Job) { j.State = "running" })

	spec := Spec{BaseModelID: job.BaseModelID, Method: job.Method, DatasetID: job.DatasetID,
		DatasetFile: s.store.Path(ref.Hash), TrainerAddr: job.trainerAddr, Hyper: req.Hyper}
	res, err := s.trainer.Run(ctx, spec, func(done, total int) {
		// the trainer is authoritative for its own checkpoint count (a real script's epochs can
		// differ from the method table's estimate)
		s.mutate(job, func(j *Job) { j.CkptsDone, j.CkptsTotal = done, total })
	})
	if err != nil {
		return err
	}
	s.mutate(job, func(j *Job) { j.State = "evaluating"; j.Evals = res.Evals })

	engine := req.BaseEngine
	if engine == "" {
		engine = "llama.cpp"
	}
	candID := fmt.Sprintf("%s-ft-%s-%s", job.BaseModelID, job.Collection, replacePrefix(job.ID))
	lineage := &modelreg.Lineage{
		Base: job.BaseModelID, DatasetID: job.DatasetID, Method: job.Method,
		Collection: job.Collection, Engineer: job.Engineer,
	}
	kind := "model"
	if m.adapter {
		kind = "adapter"
	}
	if _, err := s.reg.SubmitCandidate(ctx, modelreg.CandidateMeta{
		ID: candID, Name: candID, Version: "1", Engine: engine, Classification: job.OutputClass,
		Base: job.BaseModelID, Lineage: lineage, Evals: res.Evals,
	}, kind, res.Bytes); err != nil {
		return err
	}
	s.mutate(job, func(j *Job) { j.State = "completed"; j.Candidate = candID })
	_ = nowFn // timestamps flow through modelreg; kept here for parity/future audit stamping
	return nil
}

// replacePrefix turns "job-3" into "v3" for the candidate id (matches the sim).
func replacePrefix(jobID string) string {
	if len(jobID) > 4 && jobID[:4] == "job-" {
		return "v" + jobID[4:]
	}
	return jobID
}

// snapshot copies a job for lock-free reading by callers (Evals map included — Execute may still be
// mutating the original on another goroutine).
func snapshot(j *Job) *Job {
	cp := *j
	if j.Evals != nil {
		cp.Evals = make(map[string]float64, len(j.Evals))
		for k, v := range j.Evals {
			cp.Evals[k] = v
		}
	}
	return &cp
}

// Get returns a consistent copy of a job by id (nil if unknown).
func (s *Subsystem) Get(id string) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil
	}
	return snapshot(j)
}

// List returns consistent copies of all jobs in submission order (job-1, job-2, ...).
func (s *Subsystem) List() []*Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Job, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, snapshot(s.jobs[id]))
	}
	return out
}
