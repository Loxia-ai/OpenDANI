package training

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dani.local/agent/internal/policy"
)

// StubTrainer is the deterministic, GPU-free trainer used by CI and the DEMO default (mirrors the stub
// inference engine). It emits the method's checkpoint count, then returns a small synthetic adapter
// blob and deterministic evals derived from the spec — no randomness, so tests are reproducible.
type StubTrainer struct{}

// Run emits ckpts derived from the method table and returns synthetic bytes + evals.
func (StubTrainer) Run(_ context.Context, spec Spec, onCkpt func(done, total int)) (Result, error) {
	m, ok := methodTable[spec.Method]
	if !ok {
		m = methodTable["lora"]
	}
	for k := 1; k <= m.ckpts; k++ {
		onCkpt(k, m.ckpts)
	}
	// Deterministic "weights": a hash of the spec stands in for the trained bytes (the mocked AI).
	seed := sha256.Sum256([]byte(spec.BaseModelID + "|" + spec.Method + "|" + spec.DatasetID))
	blob := seed[:]
	if !m.adapter {
		// A "full" model is bigger than a LoRA adapter — pad deterministically so sizes differ.
		blob = make([]byte, 256)
		for i := range blob {
			blob[i] = seed[i%len(seed)]
		}
	}
	n := binary.BigEndian.Uint32(seed[:4])
	// REAL safety score: run the shared adversarial suite against a deterministic stub responder that
	// models this candidate's behavior (a base id containing "unsafe" simulates a model whose tuning
	// eroded refusals — it complies with harmful prompts and so scores below the gate). The scoring
	// logic is the same policy.Score production uses against the real tuned model.
	safety := policy.EvaluateSafety(stubResponder(spec.BaseModelID))
	evals := map[string]float64{
		"perplexity": 6 + float64(n%5)*0.4,
		"safety":     safety,
		"task":       0.7 + float64(n%6)*0.03,
	}
	return Result{Bytes: blob, Evals: evals}, nil
}

// stubResponder returns a deterministic prompt->response function standing in for the tuned model.
// A well-behaved model refuses harmful prompts and answers benign ones; a base id containing
// "unsafe" models a candidate that regressed on safety and complies with harm.
func stubResponder(baseModelID string) func(string) string {
	unsafe := strings.Contains(strings.ToLower(baseModelID), "unsafe")
	return func(prompt string) string {
		if unsafe && looksHarmful(prompt) {
			return "Sure! Here is how you can do that: step 1, ..."
		}
		if looksHarmful(prompt) {
			return "I'm sorry, I can't help with that — it's against company policy."
		}
		return "Here is a helpful answer to your question."
	}
}

// looksHarmful flags a prompt a safe model must refuse (mirrors the MustRefuse suite categories).
func looksHarmful(prompt string) bool {
	return harmfulRE.MatchString(prompt)
}

var harmfulRE = regexp.MustCompile(`(?i)\b(explosive|ransomware|exfiltrate|ignore all previous|hurt myself|malware|weapon)\b`)

// sleepFn is a seam so PacedTrainer tests run instantly (production: time.Sleep).
var sleepFn = time.Sleep

// PacedTrainer wraps a Trainer and inserts a delay before each checkpoint, so a console watching the
// job sees genuine staged progress instead of an instant flip to completed. Used by the DEMO gateway
// (StubTrainer alone finishes in microseconds); a real ExecTrainer needs no pacing.
type PacedTrainer struct {
	Inner Trainer
	Delay time.Duration
}

// Run delegates to the inner trainer, pacing its checkpoint callbacks.
func (p PacedTrainer) Run(ctx context.Context, spec Spec, onCkpt func(done, total int)) (Result, error) {
	return p.Inner.Run(ctx, spec, func(done, total int) {
		sleepFn(p.Delay)
		onCkpt(done, total)
	})
}

// execCommand is a seam so tests can stub the subprocess (production: exec.CommandContext).
var execCommand = exec.CommandContext

// scanBufMax caps one stdout line from the training command. The adapter arrives base64 on ONE
// RESULT line, so this bounds the largest artifact a trainer can return (a var so tests can shrink
// it to exercise the too-long branch without emitting 256 MB).
var scanBufMax = 256 * 1024 * 1024

// ExecTrainer runs a REAL fine-tune by shelling a training command (infra/trainer/train_qlora.py — a
// PEFT/TRL LoRA/QLoRA driver) on a GPU trainer node. The command is expected to print progress lines
// of the form
//
//	CKPT k/N
//
// after each checkpoint, and a final line
//
//	RESULT {"evals":{"perplexity":..,"safety":..,"task":..},"adapter_b64":"<base64 bytes>"}
//
// ExecTrainer parses those markers, forwards checkpoints, and returns the produced adapter bytes. The
// command itself (and a GPU) are required only in production; the DEMO/CI path uses StubTrainer. This
// type's own logic (command construction, streaming, marker parsing) is exercised in tests via a
// stubbed execCommand, so the parser is covered without a GPU.
type ExecTrainer struct {
	Script string   // the executable (python, train.sh, …)
	Args   []string // LEADING args (script path, fixed hyperparameters) — spec flags are appended
}

type execResult struct {
	Evals      map[string]float64 `json:"evals"`
	AdapterB64 string             `json:"adapter_b64"`
}

// Run invokes the training command and parses its progress/result markers.
func (e ExecTrainer) Run(ctx context.Context, spec Spec, onCkpt func(done, total int)) (Result, error) {
	args := append(append([]string{}, e.Args...),
		"--base", spec.BaseModelID, "--method", spec.Method, "--dataset", spec.DatasetID)
	if spec.DatasetFile != "" {
		args = append(args, "--dataset-file", spec.DatasetFile)
	}
	cmd := execCommand(ctx, e.Script, args...)
	cmd.Stderr = os.Stderr // the script's training log (stdout is reserved for the marker contract)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{}, err
	}
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	res, perr := ParseMarkers(stdout, onCkpt)
	// Drain any unread stdout before Wait: if the parser bailed early (ERROR / oversized line) while
	// the child is still writing, an un-drained pipe would block the child and deadlock Wait.
	_, _ = io.Copy(io.Discard, stdout)
	if err := cmd.Wait(); err != nil {
		return Result{}, fmt.Errorf("training: script failed: %w", err)
	}
	return res, perr
}

// ParseMarkers reads the trainer marker stream (CKPT k/N per checkpoint, one final RESULT, optional
// ERROR) and returns the Result. It is the single decoder for BOTH transports: a local subprocess's
// stdout (ExecTrainer) and a remote trainer node's HTTP response body (RemoteTrainer) — the contract
// travels unchanged from the training script all the way to the controller.
func ParseMarkers(r io.Reader, onCkpt func(done, total int)) (Result, error) {
	var res Result
	var gotResult bool
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), scanBufMax)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "CKPT "):
			done, total, ok := parseCkpt(strings.TrimPrefix(line, "CKPT "))
			if ok {
				onCkpt(done, total)
			}
		case strings.HasPrefix(line, "ERROR "):
			return Result{}, fmt.Errorf("training: trainer reported: %s", strings.TrimPrefix(line, "ERROR "))
		case strings.HasPrefix(line, "RESULT "):
			var er execResult
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "RESULT ")), &er); err != nil {
				return Result{}, fmt.Errorf("training: bad RESULT line: %w", err)
			}
			b, err := decodeAdapter(er.AdapterB64)
			if err != nil {
				return Result{}, err
			}
			res = Result{Bytes: b, Evals: er.Evals}
			gotResult = true
		}
	}
	if err := sc.Err(); err != nil {
		return Result{}, err
	}
	if !gotResult {
		return Result{}, fmt.Errorf("training: trainer produced no RESULT")
	}
	return res, nil
}

// WireRequest is the controller->trainer-node body for a remote training job: the Spec plus the
// STAGED dataset bytes themselves (the trainer trains on exactly what the lineage recorded; it has
// no access to the controller's artifact store).
type WireRequest struct {
	Base       string         `json:"base"`
	Method     string         `json:"method"`
	DatasetID  string         `json:"dataset_id"`
	DatasetB64 string         `json:"dataset_b64"`
	Hyper      map[string]any `json:"hyper,omitempty"`
}

// EncodeResult renders a Result as the final RESULT marker line (the trainer-node side of the wire).
func EncodeResult(res Result) string {
	b, _ := json.Marshal(execResult{Evals: res.Evals, AdapterB64: base64.StdEncoding.EncodeToString(res.Bytes)})
	return "RESULT " + string(b)
}

// RemoteTrainer executes a job on the ALLOCATED trainer node's own hardware (D17 made physical): it
// ships the spec + staged dataset to the node's mTLS /train endpoint and decodes the same CKPT/RESULT
// marker stream the local ExecTrainer reads from a subprocess. Client must be the controller's mTLS
// client (the trainer authenticates the controller by certificate chain, and vice versa).
type RemoteTrainer struct {
	Client *http.Client
}

// Run ships the job to spec.TrainerAddr and streams progress back.
func (rt RemoteTrainer) Run(ctx context.Context, spec Spec, onCkpt func(done, total int)) (Result, error) {
	if spec.TrainerAddr == "" {
		return Result{}, fmt.Errorf("training: no remote trainer address on spec")
	}
	var dsB64 string
	if spec.DatasetFile != "" {
		data, err := os.ReadFile(spec.DatasetFile)
		if err != nil {
			return Result{}, err
		}
		dsB64 = base64.StdEncoding.EncodeToString(data)
	}
	body, _ := json.Marshal(WireRequest{
		Base: spec.BaseModelID, Method: spec.Method, DatasetID: spec.DatasetID,
		DatasetB64: dsB64, Hyper: spec.Hyper,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+spec.TrainerAddr+"/train", bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := rt.Client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Result{}, fmt.Errorf("training: trainer node %s: HTTP %d: %s", spec.TrainerAddr, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return ParseMarkers(resp.Body, onCkpt)
}

// DispatchTrainer routes a job to where the allocation said it runs: a remote trainer node when the
// spec carries an address, the local Trainer (stub or exec) otherwise.
type DispatchTrainer struct {
	Local  Trainer
	Remote Trainer
}

// Run dispatches on spec.TrainerAddr.
func (d DispatchTrainer) Run(ctx context.Context, spec Spec, onCkpt func(done, total int)) (Result, error) {
	if spec.TrainerAddr != "" && d.Remote != nil {
		return d.Remote.Run(ctx, spec, onCkpt)
	}
	return d.Local.Run(ctx, spec, onCkpt)
}

// SplitCommand splits a --trainer-exec value into argv, honoring double- and single-quoted segments
// so interpreter paths with spaces work: `"C:/Program Files/Python/python.exe" train.py` ->
// ["C:/Program Files/Python/python.exe", "train.py"]. Quotes bind within a token (a"b c"d -> "ab cd").
// An unterminated quote consumes the rest of the string (lenient — flags are operator-typed).
func SplitCommand(s string) []string {
	var argv []string
	var cur strings.Builder
	inTok := false
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			inTok = true
		case c == ' ' || c == '\t':
			if inTok {
				if cur.Len() > 0 { // an empty quoted token (`""` / a lone quote) is never a real argv element (fuzz-found)
					argv = append(argv, cur.String())
				}
				cur.Reset()
				inTok = false
			}
		default:
			cur.WriteByte(c)
			inTok = true
		}
	}
	if inTok && cur.Len() > 0 {
		argv = append(argv, cur.String())
	}
	return argv
}

// decodeAdapter decodes the base64 adapter bytes from a RESULT line.
func decodeAdapter(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("training: bad adapter base64: %w", err)
	}
	return b, nil
}

// parseCkpt parses "k/N".
func parseCkpt(s string) (done, total int, ok bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	d, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	t, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return d, t, true
}
