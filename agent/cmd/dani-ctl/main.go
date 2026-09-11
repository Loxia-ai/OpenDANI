// Command dani-ctl is the DANI operator CLI: a thin, scriptable client over the controller gateway
// for the everyday operations an operator or CI pipeline runs — inspect the fleet, drive the
// train -> sign -> promote workflow, and check/export the audit trail.
//
//	dani-ctl fleet                                 live worker fleet (nodes, health, load)
//	dani-ctl models                                model registry (state, signatures, deploy)
//	dani-ctl jobs                                  training jobs + progress
//	dani-ctl principals                            the identity directory
//	dani-ctl ingest <collection>                   classify-at-ingest a corpus
//	dani-ctl train <engineer> <base> <collection>  submit a fine-tune (async)
//	dani-ctl sign <model> <role>                   apply one reviewer signature
//	dani-ctl promote <engineer> <base> <collection>  train, wait, then sign all three roles
//	dani-ctl audit                                 chain shape + integrity verdict
//	dani-ctl audit export [deployment]             fetch the signed Compliance bundle (pipe to dani-verify)
//
// Global flags: --gateway <url> (or $DANI_GATEWAY; default http://127.0.0.1:8081), --json (raw
// server JSON for scripting), --user <sub> (X-Dani-User attribution), --timeout. Exit 0 ok / 1 the
// operation reported failure / 2 usage or transport error.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type cli struct {
	gateway string
	user    string
	asJSON  bool
	client  *http.Client
	out     io.Writer
	errw    io.Writer
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dani-ctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	gw := fs.String("gateway", envOr("DANI_GATEWAY", "http://127.0.0.1:8081"), "controller gateway base URL")
	user := fs.String("user", "", "X-Dani-User attribution (for policy-gated actions)")
	asJSON := fs.Bool("json", false, "print the raw server JSON")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return 2
	}
	c := &cli{
		gateway: strings.TrimRight(*gw, "/"), user: *user, asJSON: *asJSON,
		client: &http.Client{Timeout: *timeout}, out: stdout, errw: stderr,
	}
	switch rest[0] {
	case "fleet":
		return c.fleet()
	case "models":
		return c.models()
	case "jobs":
		return c.jobs()
	case "principals":
		return c.principals()
	case "ingest":
		return c.ingest(rest[1:])
	case "train":
		return c.train(rest[1:])
	case "sign":
		return c.sign(rest[1:])
	case "promote":
		return c.promote(rest[1:])
	case "audit":
		return c.audit(rest[1:])
	default:
		fmt.Fprintf(stderr, "dani-ctl: unknown command %q\n", rest[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: dani-ctl [--gateway URL] [--user SUB] [--json] <command> [args]
  fleet | models | jobs | principals
  ingest <collection>
  train <engineer> <base> <collection>
  sign <model> <role>
  promote <engineer> <base> <collection>
  audit [export [deployment]]
`)
}

// --- transport -------------------------------------------------------------

// get fetches path and decodes JSON into v (v may be nil to just check status).
func (c *cli) get(path string, v any) error {
	req, _ := http.NewRequest(http.MethodGet, c.gateway+path, nil)
	if c.user != "" {
		req.Header.Set("X-Dani-User", c.user)
	}
	return c.do(req, v)
}

// post sends body as JSON to path and decodes the JSON response into v.
func (c *cli) post(path string, body, v any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, c.gateway+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" {
		req.Header.Set("X-Dani-User", c.user)
	}
	return c.do(req, v)
}

func (c *cli) do(req *http.Request, v any) error {
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpError{status: resp.StatusCode, body: strings.TrimSpace(string(data))}
	}
	if v != nil {
		if err := json.Unmarshal(data, v); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string {
	msg := e.body
	var j struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(e.body), &j) == nil && j.Error != "" {
		msg = j.Error
	}
	return fmt.Sprintf("HTTP %d: %s", e.status, msg)
}

// fail prints err and returns the exit code (2 for transport/usage).
func (c *cli) fail(err error) int {
	fmt.Fprintf(c.errw, "dani-ctl: %v\n", err)
	return 2
}

// emitJSON prints raw JSON for a value fetched into a map (scripting mode).
func (c *cli) emitJSON(v any) int {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return 0
}

// --- commands --------------------------------------------------------------

func (c *cli) fleet() int {
	var r struct {
		Count   int `json:"count"`
		Workers []struct {
			UUID, Model, Class, Site, Health string
			Active, MaxConcurrent            int
			Trainer                          bool
		} `json:"workers"`
	}
	if err := c.get("/dani/fleet", &r); err != nil {
		return c.fail(err)
	}
	if c.asJSON {
		return c.emitJSON(r)
	}
	fmt.Fprintf(c.out, "fleet: %d node(s)\n", r.Count)
	for _, w := range r.Workers {
		role := "worker"
		if w.Trainer {
			role = "trainer"
		}
		fmt.Fprintf(c.out, "  %-14s %-8s %-9s %-10s %s  %d/%d\n", w.UUID, role, w.Health, w.Class, w.Model, w.Active, w.MaxConcurrent)
	}
	return 0
}

func (c *cli) models() int {
	var r struct {
		Models []struct {
			ID         string   `json:"id"`
			State      string   `json:"state"`
			Class      string   `json:"classification"`
			Signatures []string `json:"signatures"`
			GateFailed string   `json:"gate_failed"`
			Deployment *struct {
				Node  string `json:"Node"`
				State string `json:"State"`
			} `json:"deployment"`
		} `json:"models"`
	}
	if err := c.get("/dani/models", &r); err != nil {
		return c.fail(err)
	}
	if c.asJSON {
		return c.emitJSON(r)
	}
	if len(r.Models) == 0 {
		fmt.Fprintln(c.out, "no models")
		return 0
	}
	for _, m := range r.Models {
		line := fmt.Sprintf("  %-28s %-10s %-11s sigs=%d/3", m.ID, m.State, m.Class, len(m.Signatures))
		if m.GateFailed != "" {
			line += "  gate:" + m.GateFailed
		}
		if m.Deployment != nil {
			line += fmt.Sprintf("  @%s(%s)", m.Deployment.Node, m.Deployment.State)
		}
		fmt.Fprintln(c.out, line)
	}
	return 0
}

func (c *cli) jobs() int {
	var r struct {
		Jobs []struct {
			ID, State, Candidate, TrainerUUID string
			CkptsDone, CkptsTotal             int
		} `json:"jobs"`
	}
	if err := c.get("/dani/train/jobs", &r); err != nil {
		return c.fail(err)
	}
	if c.asJSON {
		return c.emitJSON(r)
	}
	if len(r.Jobs) == 0 {
		fmt.Fprintln(c.out, "no jobs")
		return 0
	}
	for _, j := range r.Jobs {
		fmt.Fprintf(c.out, "  %-8s %-11s %d/%d  %s @%s\n", j.ID, j.State, j.CkptsDone, j.CkptsTotal, j.Candidate, j.TrainerUUID)
	}
	return 0
}

func (c *cli) principals() int {
	var r map[string]any
	if err := c.get("/dani/principals", &r); err != nil {
		return c.fail(err)
	}
	return c.emitJSON(r)
}

func (c *cli) ingest(args []string) int {
	if len(args) != 1 {
		return c.usageErr("ingest <collection>")
	}
	var r struct {
		Name   string            `json:"name"`
		Chunks []json.RawMessage `json:"chunks"` // the server returns the classified chunks, not a count
	}
	if err := c.post("/dani/ingest", map[string]string{"collection": args[0]}, &r); err != nil {
		return c.fail(err)
	}
	if c.asJSON {
		return c.emitJSON(r)
	}
	fmt.Fprintf(c.out, "ingested %s (%d chunks)\n", r.Name, len(r.Chunks))
	return 0
}

func (c *cli) train(args []string) int {
	if len(args) != 3 {
		return c.usageErr("train <engineer> <base> <collection>")
	}
	id, code := c.submitTrain(args[0], args[1], args[2])
	if code != 0 {
		return code
	}
	fmt.Fprintf(c.out, "submitted job %s\n", id)
	return 0
}

func (c *cli) sign(args []string) int {
	if len(args) != 2 {
		return c.usageErr("sign <model> <role>")
	}
	return c.signOne(args[0], args[1])
}

// promote runs the full workflow: submit -> poll to completion -> sign all three reviewer roles.
func (c *cli) promote(args []string) int {
	if len(args) != 3 {
		return c.usageErr("promote <engineer> <base> <collection>")
	}
	id, code := c.submitTrain(args[0], args[1], args[2])
	if code != 0 {
		return code
	}
	fmt.Fprintf(c.out, "job %s: training", id)
	cand, code := c.waitJob()
	if code != 0 {
		return code
	}
	fmt.Fprintf(c.out, " done -> %s\n", cand)
	for _, role := range []string{"security-officer", "governance-officer", "administrator"} {
		if code := c.signOne(cand, role); code != 0 {
			return code
		}
	}
	// report the final state
	st, gate := c.modelState(cand)
	if gate != "" {
		fmt.Fprintf(c.out, "%s: HELD at %s (gate: %s)\n", cand, st, gate)
		return 1
	}
	fmt.Fprintf(c.out, "%s: %s\n", cand, st)
	return 0
}

func (c *cli) audit(args []string) int {
	if len(args) >= 1 && args[0] == "export" {
		dep := "dep-1"
		if len(args) >= 2 {
			dep = args[1]
		}
		var raw json.RawMessage
		if err := c.get("/dani/audit/export?deployment="+dep, &raw); err != nil {
			return c.fail(err)
		}
		// pass the endpoint payload straight through (pipe to dani-verify)
		fmt.Fprintln(c.out, string(raw))
		return 0
	}
	var r struct {
		Records     int64 `json:"records"`
		SignedHeads int   `json:"signedHeads"`
		Integrity   struct {
			OK  bool   `json:"ok"`
			Why string `json:"why"`
		} `json:"integrity"`
	}
	if err := c.get("/dani/audit", &r); err != nil {
		return c.fail(err)
	}
	if c.asJSON {
		return c.emitJSON(r)
	}
	if r.Integrity.OK {
		fmt.Fprintf(c.out, "audit: VERIFIED — %d records, %d signed heads\n", r.Records, r.SignedHeads)
		return 0
	}
	fmt.Fprintf(c.out, "audit: FAILED — %s\n", r.Integrity.Why)
	return 1
}

// --- helpers ---------------------------------------------------------------

func (c *cli) submitTrain(engineer, base, collection string) (string, int) {
	var r struct {
		ID string `json:"ID"`
	}
	if err := c.post("/dani/train/submit", map[string]string{
		"engineer": engineer, "base": base, "collection": collection, "method": "lora",
	}, &r); err != nil {
		return "", c.fail(err)
	}
	if r.ID == "" {
		return "", c.fail(fmt.Errorf("no job id in response"))
	}
	return r.ID, 0
}

func (c *cli) signOne(model, role string) int {
	var r map[string]any
	if err := c.post("/dani/models/sign", map[string]string{"model": model, "role": role}, &r); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.out, "signed %s as %s\n", model, role)
	return 0
}

// waitJob polls until the latest job is completed|failed; returns its candidate id.
func (c *cli) waitJob() (string, int) {
	for i := 0; i < 60; i++ {
		var r struct {
			Jobs []struct {
				State, Candidate string
			} `json:"jobs"`
		}
		if err := c.get("/dani/train/jobs", &r); err != nil {
			return "", c.fail(err)
		}
		if n := len(r.Jobs); n > 0 {
			j := r.Jobs[n-1]
			switch j.State {
			case "completed":
				return j.Candidate, 0
			case "failed":
				return "", c.fail(fmt.Errorf("training failed"))
			}
		}
		fmt.Fprint(c.out, ".")
		sleep(500 * time.Millisecond)
	}
	return "", c.fail(fmt.Errorf("job did not finish in time"))
}

func (c *cli) modelState(id string) (state, gate string) {
	var r struct {
		Models []struct {
			ID         string `json:"id"`
			State      string `json:"state"`
			GateFailed string `json:"gate_failed"`
		} `json:"models"`
	}
	if c.get("/dani/models", &r) != nil {
		return "?", ""
	}
	for _, m := range r.Models {
		if m.ID == id {
			return m.State, m.GateFailed
		}
	}
	return "?", ""
}

func (c *cli) usageErr(spec string) int {
	fmt.Fprintf(c.errw, "usage: dani-ctl %s\n", spec)
	return 2
}

// sleep is a seam so tests run instantly.
var sleep = time.Sleep

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
