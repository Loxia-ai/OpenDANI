package training

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is not a real test: it's the child process ExecTrainer's execCommand is pointed at.
// It emits the CKPT/RESULT markers ExecTrainer parses, driven by env vars, so the parser is fully
// exercised without a GPU or Python. (The classic os/exec testing idiom.)
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	switch os.Getenv("HELPER_MODE") {
	case "ok":
		os.Stdout.WriteString("CKPT 1/3\n")
		os.Stdout.WriteString("noise line ignored\n")
		os.Stdout.WriteString("CKPT bad/line\n") // malformed → ignored
		os.Stdout.WriteString("CKPT 2/3\n")
		os.Stdout.WriteString("CKPT 3/3\n")
		adapter := base64.StdEncoding.EncodeToString([]byte("trained-adapter"))
		os.Stdout.WriteString(`RESULT {"evals":{"task":0.81},"adapter_b64":"` + adapter + "\"}\n")
	case "badjson":
		os.Stdout.WriteString("RESULT {not json}\n")
	case "badb64":
		os.Stdout.WriteString(`RESULT {"evals":{},"adapter_b64":"@@@not-base64@@@"}` + "\n")
	case "noresult":
		os.Stdout.WriteString("CKPT 1/1\n")
	case "toolong":
		// A single line larger than the (test-shrunk) scanner max, no newline → bufio.ErrTooLong on
		// Scan, surfacing through sc.Err().
		big := make([]byte, 128*1024)
		for i := range big {
			big[i] = 'x'
		}
		os.Stdout.Write(big)
	case "fail":
		os.Stdout.WriteString("CKPT 1/1\n")
		os.Exit(3) // non-zero exit → cmd.Wait error
	}
	os.Exit(0)
}

// helperCommand builds an execCommand replacement that runs TestHelperProcess in the given mode.
func helperCommand(mode string) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess")
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "HELPER_MODE="+mode)
		return cmd
	}
}

func withHelper(t *testing.T, mode string) {
	t.Helper()
	orig := execCommand
	execCommand = helperCommand(mode)
	t.Cleanup(func() { execCommand = orig })
}

func TestExecTrainerHappyPath(t *testing.T) {
	var gotArgs []string
	orig := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotArgs = args
		return helperCommand("ok")(ctx, name, args...)
	}
	t.Cleanup(func() { execCommand = orig })
	tr := ExecTrainer{Script: "python", Args: []string{"train_qlora.py", "--epochs", "1"}}
	var last int
	res, err := tr.Run(context.Background(),
		Spec{BaseModelID: "m", Method: "qlora", DatasetID: "ds", DatasetFile: "/data/staged.json"},
		func(done, total int) { last = done })
	if err != nil {
		t.Fatal(err)
	}
	// Fixed args LEAD (script path first for interpreter commands); spec flags follow.
	want := []string{"train_qlora.py", "--epochs", "1", "--base", "m", "--method", "qlora",
		"--dataset", "ds", "--dataset-file", "/data/staged.json"}
	if strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Fatalf("arg order wrong:\n got %v\nwant %v", gotArgs, want)
	}
	if last != 3 {
		t.Fatalf("expected last checkpoint 3, got %d", last)
	}
	if string(res.Bytes) != "trained-adapter" {
		t.Fatalf("adapter bytes wrong: %q", res.Bytes)
	}
	if res.Evals["task"] != 0.81 {
		t.Fatalf("evals wrong: %+v", res.Evals)
	}
}

func TestExecTrainerErrors(t *testing.T) {
	origBuf := scanBufMax
	scanBufMax = 64 * 1024 // shrink so "toolong" trips without emitting 256 MB
	t.Cleanup(func() { scanBufMax = origBuf })
	for _, mode := range []string{"badjson", "badb64", "noresult", "fail", "toolong"} {
		t.Run(mode, func(t *testing.T) {
			withHelper(t, mode)
			tr := ExecTrainer{Script: "train.sh"}
			if _, err := tr.Run(context.Background(), Spec{Method: "lora"}, func(int, int) {}); err == nil {
				t.Fatalf("mode %s should error", mode)
			}
		})
	}
}

func TestExecTrainerStartError(t *testing.T) {
	orig := execCommand
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// A command that cannot start (empty path) → cmd.Start fails.
		return exec.CommandContext(ctx, filepathThatDoesNotExist())
	}
	defer func() { execCommand = orig }()
	tr := ExecTrainer{Script: "x"}
	if _, err := tr.Run(context.Background(), Spec{Method: "lora"}, func(int, int) {}); err == nil {
		t.Fatal("start error should propagate")
	}
}

func filepathThatDoesNotExist() string { return "definitely-not-a-real-binary-xyzzy" }

func TestStubTrainerUnknownMethodDefaultsLora(t *testing.T) {
	var total int
	res, err := StubTrainer{}.Run(context.Background(), Spec{BaseModelID: "m", Method: "telepathy", DatasetID: "d"}, func(done, tot int) { total = tot })
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("unknown method should default to lora (3 ckpts), got %d", total)
	}
	if len(res.Bytes) != 32 { // sha256 digest = adapter-sized
		t.Fatalf("lora adapter should be 32 bytes, got %d", len(res.Bytes))
	}
}

func TestParseCkptBranches(t *testing.T) {
	if _, _, ok := parseCkpt("nope"); ok {
		t.Fatal("no slash → not ok")
	}
	if _, _, ok := parseCkpt("a/3"); ok {
		t.Fatal("bad numerator → not ok")
	}
	if _, _, ok := parseCkpt("1/b"); ok {
		t.Fatal("bad denominator → not ok")
	}
	d, tot, ok := parseCkpt(" 2 / 5 ")
	if !ok || d != 2 || tot != 5 {
		t.Fatalf("valid parse failed: %d/%d ok=%v", d, tot, ok)
	}
}

func TestPacedTrainer(t *testing.T) {
	var slept []time.Duration
	orig := sleepFn
	sleepFn = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { sleepFn = orig })
	p := PacedTrainer{Inner: StubTrainer{}, Delay: 2 * time.Second}
	var ckpts int
	res, err := p.Run(context.Background(), Spec{BaseModelID: "m", Method: "lora", DatasetID: "d"}, func(done, total int) { ckpts = done })
	if err != nil {
		t.Fatal(err)
	}
	if ckpts != 3 || len(slept) != 3 || slept[0] != 2*time.Second {
		t.Fatalf("pacing wrong: ckpts=%d sleeps=%v", ckpts, slept)
	}
	if len(res.Bytes) == 0 {
		t.Fatal("result must pass through")
	}
}

func TestSplitCommand(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`python train.py --epochs 6`, []string{"python", "train.py", "--epochs", "6"}},
		{`"C:/Program Files/Python/python.exe" train.py`, []string{"C:/Program Files/Python/python.exe", "train.py"}},
		{`python '/opt/my dir/train.py'`, []string{"python", "/opt/my dir/train.py"}},
		{`a"b c"d`, []string{"ab cd"}},          // quotes bind within a token
		{`  spaced   out  `, []string{"spaced", "out"}},
		{"tab\tsep", []string{"tab", "sep"}},
		{`""`, nil},                              // empty quoted token dropped - an empty argv[0] would be an empty exec path (fuzz-found)
		{`"`, nil},                               // a lone quote likewise
		{`unterminated "rest of line`, []string{"unterminated", "rest of line"}}, // lenient
		{``, nil},
	}
	for _, c := range cases {
		got := SplitCommand(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("%q: got %#v want %#v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%q: got %#v want %#v", c.in, got, c.want)
			}
		}
	}
}

func TestDecodeAdapterError(t *testing.T) {
	if _, err := decodeAdapter("@@@"); err == nil {
		t.Fatal("bad base64 should error")
	}
	if _, err := decodeAdapter(strings.TrimSpace(base64.StdEncoding.EncodeToString([]byte("ok")))); err != nil {
		t.Fatal(err)
	}
}

// TestStubTrainerSafetyEval: the stub's `safety` eval is REAL (computed by the shared adversarial
// suite), not a fabricated stat. A well-behaved base scores a perfect 1.0; an "-unsafe" base models
// a candidate that complies with harmful prompts and scores below any sane gate.
func TestStubTrainerSafetyEval(t *testing.T) {
	safe, err := StubTrainer{}.Run(context.Background(), Spec{BaseModelID: "qwen2.5-0.5b", Method: "lora", DatasetID: "d"}, func(int, int) {})
	if err != nil {
		t.Fatal(err)
	}
	if safe.Evals["safety"] != 1.0 {
		t.Fatalf("a safe stub model must score safety 1.0, got %v", safe.Evals["safety"])
	}
	unsafe, err := StubTrainer{}.Run(context.Background(), Spec{BaseModelID: "qwen2.5-0.5b-unsafe", Method: "lora", DatasetID: "d"}, func(int, int) {})
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.Evals["safety"] >= 0.8 {
		t.Fatalf("an unsafe stub model must score below the gate, got %v", unsafe.Evals["safety"])
	}
}
