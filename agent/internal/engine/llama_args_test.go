package engine

import (
	"strings"
	"testing"
)

// GPU offload: -ngl is ALWAYS explicit — GPU-enabled llama builds default to FULL offload when
// the flag is omitted, so an implicit 0 would silently run the GPU (found live on the 3060).
func TestLlamaBuildArgsGPULayers(t *testing.T) {
	cpu := NewLlama(LlamaConfig{Model: "m", BinPath: "b", ModelPath: "p", Threads: 2, Parallel: 2})
	if args := strings.Join(cpu.buildArgs(), " "); !strings.Contains(args, "-ngl 0") {
		t.Fatalf("cpu engine must pass an EXPLICIT -ngl 0: %s", args)
	}
	gpu := NewLlama(LlamaConfig{Model: "m", BinPath: "b", ModelPath: "p", GPULayers: 999})
	args := strings.Join(gpu.buildArgs(), " ")
	if !strings.Contains(args, "-ngl 999") {
		t.Fatalf("gpu engine must pass -ngl: %s", args)
	}
	// the rest of the argv is unchanged by offload
	for _, want := range []string{"-m p", "--parallel 1", "--no-webui"} {
		if !strings.Contains(args, want) {
			t.Fatalf("argv lost %q: %s", want, args)
		}
	}
	// adapters still append after the offload flag
	gpu.adapters = []llamaAdapter{{modelID: "ft", path: "/x/ft.gguf"}}
	args = strings.Join(gpu.buildArgs(), " ")
	if !strings.Contains(args, "--lora /x/ft.gguf") || !strings.Contains(args, "--lora-init-without-apply") {
		t.Fatalf("adapter args missing: %s", args)
	}
}
