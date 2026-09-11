package engine

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeMeasure swaps the per-candidate measurement; returns tok/s by -ngl.
func fakeMeasure(t *testing.T, speeds map[int]float64, errs map[int]error) func() {
	t.Helper()
	orig := measureCandidate
	measureCandidate = func(_ context.Context, cfg LlamaConfig) (float64, error) {
		if err := errs[cfg.GPULayers]; err != nil {
			return 0, err
		}
		return speeds[cfg.GPULayers], nil
	}
	return func() { measureCandidate = orig }
}

func calibCfg(t *testing.T) LlamaConfig {
	t.Helper()
	dir := t.TempDir()
	model := filepath.Join(dir, "m.gguf")
	bin := filepath.Join(dir, "llama-server")
	if err := os.WriteFile(model, []byte("gguf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("elf"), 0o700); err != nil {
		t.Fatal(err)
	}
	return LlamaConfig{Model: "m", ModelPath: model, BinPath: bin}
}

func TestCalibrateGPUWins(t *testing.T) {
	defer fakeMeasure(t, map[int]float64{999: 42.0, 0: 11.0}, nil)()
	cfg := calibCfg(t)
	var logs []string
	got := CalibrateLlama(context.Background(), cfg, "cuda", func(f string, a ...any) { logs = append(logs, f) })
	if got != 999 {
		t.Fatalf("gpu should win: got -ngl %d", got)
	}
	// verdict persisted + reused WITHOUT re-measuring
	defer fakeMeasure(t, nil, map[int]error{999: errors.New("must not re-run"), 0: errors.New("must not re-run")})()
	if got := CalibrateLlama(context.Background(), cfg, "cuda", nil); got != 999 {
		t.Fatalf("cached verdict should be reused: got %d", got)
	}
}

// the whole point: a detected GPU whose measured offload LOSES stays unused.
func TestCalibrateCPUWinsDespiteGPU(t *testing.T) {
	defer fakeMeasure(t, map[int]float64{999: 6.0, 0: 12.5}, nil)()
	if got := CalibrateLlama(context.Background(), calibCfg(t), "vulkan", nil); got != 0 {
		t.Fatalf("measured-slower gpu must lose: got -ngl %d", got)
	}
}

// inside the noise band (<10% faster) the conservative CPU verdict holds.
func TestCalibrateNoiseBandKeepsCPU(t *testing.T) {
	defer fakeMeasure(t, map[int]float64{999: 12.0, 0: 11.0}, nil)()
	if got := CalibrateLlama(context.Background(), calibCfg(t), "cuda", nil); got != 0 {
		t.Fatalf("9%% edge is noise, must stay cpu: got -ngl %d", got)
	}
	defer fakeMeasure(t, map[int]float64{999: 12.2, 0: 11.0}, nil)()
	if got := CalibrateLlama(context.Background(), calibCfg(t), "vulkan", nil); got != 999 {
		t.Fatalf(">10%% win must take gpu: got -ngl %d", got)
	}
}

func TestCalibrateGPUCandidateFails(t *testing.T) {
	defer fakeMeasure(t, map[int]float64{0: 9.0}, map[int]error{999: errors.New("vulkan init failed")})()
	if got := CalibrateLlama(context.Background(), calibCfg(t), "vulkan", nil); got != 0 {
		t.Fatalf("failed gpu candidate must fall back to cpu: got %d", got)
	}
}

func TestCalibrateAllCandidatesFailFallsBackCPU(t *testing.T) {
	boom := errors.New("no engine at all")
	defer fakeMeasure(t, nil, map[int]error{999: boom, 0: boom})()
	if got := CalibrateLlama(context.Background(), calibCfg(t), "cuda", nil); got != 0 {
		t.Fatalf("all-fail must yield safe cpu: got %d", got)
	}
}

func TestCalibrationCacheInvalidation(t *testing.T) {
	defer fakeMeasure(t, map[int]float64{999: 40, 0: 10}, nil)()
	cfg := calibCfg(t)
	if got := CalibrateLlama(context.Background(), cfg, "cuda", nil); got != 999 {
		t.Fatalf("setup: %d", got)
	}
	// hardware changed -> cache must NOT match
	if _, ok := loadCalibration(cfg, "vulkan"); ok {
		t.Fatal("backend change must invalidate the verdict")
	}
	// model changed -> invalidated
	if err := os.WriteFile(cfg.ModelPath, []byte("gguf-v2-longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCalibration(cfg, "cuda"); ok {
		t.Fatal("model change must invalidate the verdict")
	}
	// corrupt sidecar -> ignored
	if err := os.WriteFile(calibPath(cfg.ModelPath), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadCalibration(cfg, "cuda"); ok {
		t.Fatal("corrupt sidecar must be ignored")
	}
}

// the real measureCandidate against the fake llama-server child (health-only): Start succeeds,
// Chat fails -> error path; and a missing binary -> Start error path.
func TestMeasureCandidateRealPaths(t *testing.T) {
	if _, err := measureCandidate(context.Background(), LlamaConfig{BinPath: filepath.Join(t.TempDir(), "absent"), ModelPath: filepath.Join(t.TempDir(), "absent.gguf")}); err == nil {
		t.Fatal("missing binary must error")
	}
}

func TestBestOf(t *testing.T) {
	for _, tc := range []struct {
		in   []float64
		want float64
	}{
		// the live case: noise only slows runs down, so the max is the true-capability estimate
		{[]float64{45.3, 72.9, 71.0}, 72.9},
		{[]float64{10}, 10},
		{[]float64{10, 20}, 20},
		{[]float64{3, 1, 2}, 3},
	} {
		if got := bestOf(append([]float64(nil), tc.in...)); got != tc.want {
			t.Fatalf("bestOf(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// per-sample failures are tolerated: the median of the SURVIVING samples decides; all-fail errors.
func TestMeasureCandidateSampleRobustness(t *testing.T) {
	origChat, origWarm := calibChat, calibWarmup
	defer func() { calibChat, calibWarmup = origChat, origWarm }()
	calibWarmup = func(context.Context, *LlamaEngine) {}
	_, port := healthServer(t, func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) })
	bin, model := fakeBinAndModel(t)
	os.Setenv("GO_LLAMA_HELPER", "1")
	t.Cleanup(func() { os.Unsetenv("GO_LLAMA_HELPER") })
	call := 0
	calibChat = func(context.Context, *LlamaEngine) (int, int64, error) {
		call++
		switch call {
		case 1:
			return 0, 0, errors.New("sample 1 flaked")
		case 2:
			return 48, 1000, nil // 48 tok/s
		default:
			return 48, 2000, nil // 24 tok/s
		}
	}
	tokS, err := measureCandidate(context.Background(), LlamaConfig{Model: "m", BinPath: bin, ModelPath: model, Port: port})
	if err != nil || tokS != 48.0 { // best of {48, 24}; the flaked sample is dropped
		t.Fatalf("robust best-of wrong: %.1f %v", tokS, err)
	}
	// all samples fail -> candidate fails
	calibChat = func(context.Context, *LlamaEngine) (int, int64, error) { return 0, 0, errors.New("dead") }
	if _, err := measureCandidate(context.Background(), LlamaConfig{Model: "m", BinPath: bin, ModelPath: model, Port: port}); err == nil {
		t.Fatal("all-fail must error the candidate")
	}
}

func TestTokPerSec(t *testing.T) {
	if _, err := tokPerSec(0, 100); err == nil {
		t.Fatal("0 tokens must be rejected")
	}
	if _, err := tokPerSec(10, 0); err == nil {
		t.Fatal("0 ms must be rejected")
	}
	if v, err := tokPerSec(48, 4000); err != nil || v != 12.0 {
		t.Fatalf("48 tok in 4s should be 12 tok/s: %v %v", v, err)
	}
}

func TestFileSigUnknown(t *testing.T) {
	if s := fileSig(filepath.Join(t.TempDir(), "nope")); s != "unknown" {
		t.Fatalf("missing file must sig unknown: %s", s)
	}
	if !strings.Contains(calibPath("/x/m.gguf"), "m.gguf.dani-calib.json") {
		t.Fatal("sidecar path wrong")
	}
}
