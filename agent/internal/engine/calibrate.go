package engine

// BENCHMARK-THEN-DECIDE: "auto" GPU offload does not TRUST detection — it MEASURES. A box can
// detect a GPU whose offload is actually slower than its CPU (weak iGPU + strong CPU, CPU-only
// llama build on a GPU box, model too big for VRAM). So on an accelerated box the worker runs one
// short timed generation per candidate (full offload vs pure CPU) with the REAL model and keeps
// the measured winner. The verdict is cached in a sidecar next to the model, keyed by hardware
// backend + model file signature + llama binary signature, so the fleet pays the ~30-60s once per
// box-and-model, not on every restart.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Calibration is the persisted verdict of one benchmark-then-decide run.
type Calibration struct {
	NGL      int                `json:"ngl"`      // the winner
	Backend  string             `json:"backend"`  // hwcaps backend the run measured (cuda|metal|vulkan|...)
	ModelSig string             `json:"modelSig"` // size:mtime of the model file
	BinSig   string             `json:"binSig"`   // size:mtime of llama-server (build swaps invalidate)
	TokS     map[string]float64 `json:"tokS"`     // measured tok/s per candidate ("999", "0")
	When     string             `json:"when"`
}

// calibCandidates: pure CPU first, then full offload. Order matters: the winner must be STRICTLY
// faster, so on a tie (e.g. a CPU-only llama build that silently ignores -ngl) the verdict is the
// conservative 0. Partial-offload search is deliberately out of scope — two points decide the
// question that matters (does THIS gpu beat THIS cpu on THIS model).
var calibCandidates = []int{0, 999}

// calibWarmup runs one short UNCOUNTED generation so cold caches / CPU frequency scaling don't
// bias whichever candidate happens to run first. Result (and any error) deliberately ignored —
// the timed samples are the judges.
var calibWarmup = func(ctx context.Context, e *LlamaEngine) {
	_, _ = e.Chat(ctx, Request{
		Messages:  []Message{{Role: "user", Content: "Say OK."}},
		MaxTokens: 8,
	})
}

// calibChat is ONE timed generation, seam-injected for tests.
var calibChat = func(ctx context.Context, e *LlamaEngine) (tokens int, ms int64, err error) {
	res, err := e.Chat(ctx, Request{
		Messages:  []Message{{Role: "user", Content: "Write a Go function that reverses a string."}},
		MaxTokens: 48,
	})
	if err != nil {
		return 0, 0, err
	}
	return res.CompletionTokens, res.TotalMs, nil
}

func fileSig(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%d:%d", st.Size(), st.ModTime().UnixNano())
}

func calibPath(modelPath string) string { return modelPath + ".dani-calib.json" }

// loadCalibration returns a cached verdict if it matches the current hardware + model + binary.
func loadCalibration(cfg LlamaConfig, backend string) (Calibration, bool) {
	data, err := os.ReadFile(calibPath(cfg.ModelPath))
	if err != nil {
		return Calibration{}, false
	}
	var c Calibration
	if json.Unmarshal(data, &c) != nil {
		return Calibration{}, false
	}
	if c.Backend != backend || c.ModelSig != fileSig(cfg.ModelPath) || c.BinSig != fileSig(cfg.BinPath) {
		return Calibration{}, false // hardware, model, or llama build changed — re-measure
	}
	return c, true
}

// CalibrateLlama measures full-offload vs pure-CPU on the real model and returns the winning -ngl.
// The verdict is cached (sidecar next to the model). A candidate that fails to start or serve is
// simply out of the running (e.g. vulkan build without a usable GPU); if EVERY candidate fails the
// fallback is 0 (pure CPU) and the normal engine start will surface the real error.
// nowFn/logf are injectable-by-parameter: pass log=nil for silent.
func CalibrateLlama(ctx context.Context, cfg LlamaConfig, backend string, log func(string, ...any)) int {
	if log == nil {
		log = func(string, ...any) {}
	}
	if c, ok := loadCalibration(cfg, backend); ok {
		log("calibration: cached verdict for %s on %s — -ngl %d (measured %v)", cfg.Model, backend, c.NGL, c.TokS)
		return c.NGL
	}

	verdict := Calibration{
		Backend: backend, ModelSig: fileSig(cfg.ModelPath), BinSig: fileSig(cfg.BinPath),
		TokS: map[string]float64{}, When: time.Now().UTC().Format(time.RFC3339),
	}
	bestNGL, bestTokS := 0, 0.0
	for _, ngl := range calibCandidates {
		c := cfg
		c.GPULayers = ngl
		c.Parallel = 1
		if c.CtxSize == 0 || c.CtxSize > 1024 {
			c.CtxSize = 1024 // calibration needs a prompt + 48 tokens, not the serving context
		}
		tokS, err := measureCandidate(ctx, c)
		key := fmt.Sprintf("%d", ngl)
		if err != nil {
			log("calibration: -ngl %d candidate failed (%v) — out of the running", ngl, err)
			verdict.TokS[key] = 0
			continue
		}
		verdict.TokS[key] = tokS
		log("calibration: -ngl %d → %.1f tok/s", ngl, tokS)
		// a challenger must CLEARLY beat the incumbent (>10%) — inside the noise band the earlier,
		// more conservative candidate (CPU runs first) keeps the verdict.
		if tokS > bestTokS*1.10 {
			bestTokS, bestNGL = tokS, ngl
		}
	}
	verdict.NGL = bestNGL
	if data, err := json.Marshal(verdict); err == nil {
		_ = os.WriteFile(calibPath(cfg.ModelPath), data, 0o644) // cache is best-effort
	}
	log("calibration: verdict — -ngl %d (%s measured %v)", bestNGL, backend, verdict.TokS)
	return bestNGL
}

// calibSamples: timed generations per candidate. The BEST sample is the measurement: performance
// noise is ONE-SIDED — background load, thermal throttling, and scheduler contention only make a
// run SLOWER than the hardware's true speed, never faster — so max-of-N estimates true capability
// and also cancels the thermal handicap on the later (GPU) candidate. Both candidates use the SAME
// estimator so the race stays fair; the >10% margin still referees.
var calibSamples = 3

// measureCandidate starts a short-lived engine with the candidate offload, runs calibSamples timed
// generations (after the uncounted warmup inside calibChat's first call), and returns the median
// tok/s. Individual failed/degenerate samples are dropped; the candidate fails only if EVERY
// sample does.
var measureCandidate = func(ctx context.Context, cfg LlamaConfig) (float64, error) {
	eng := NewLlama(cfg)
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if err := eng.Start(cctx); err != nil {
		return 0, err
	}
	defer func() { _ = eng.Close() }()
	calibWarmup(cctx, eng)
	var speeds []float64
	var lastErr error
	for i := 0; i < calibSamples; i++ {
		tokens, ms, err := calibChat(cctx, eng)
		if err != nil {
			lastErr = err
			continue
		}
		v, err := tokPerSec(tokens, ms)
		if err != nil {
			lastErr = err
			continue
		}
		speeds = append(speeds, v)
	}
	if len(speeds) == 0 {
		return 0, fmt.Errorf("all %d samples failed (last: %v)", calibSamples, lastErr)
	}
	return bestOf(speeds), nil
}

// bestOf: the fastest sample = the closest observation of true hardware capability (noise only
// ever slows a run down).
func bestOf(v []float64) float64 {
	best := v[0]
	for _, s := range v[1:] {
		if s > best {
			best = s
		}
	}
	return best
}

// tokPerSec guards against degenerate measurements (a 0-token or 0-ms "success" must not win).
func tokPerSec(tokens int, ms int64) (float64, error) {
	if tokens <= 0 || ms <= 0 {
		return 0, fmt.Errorf("degenerate measurement (tokens=%d ms=%d)", tokens, ms)
	}
	return float64(tokens) / (float64(ms) / 1000.0), nil
}
