package hwcaps

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func base() probes {
	return probes{
		goos: "linux", goarch: "amd64",
		lookPath:   func(string) (string, error) { return "", errors.New("absent") },
		runCommand: func(string, ...string) (string, error) { return "", errors.New("absent") },
		glob:       func(string) []string { return nil },
	}
}

func TestDetectCUDA(t *testing.T) {
	p := base()
	p.lookPath = func(n string) (string, error) {
		if n == "nvidia-smi" {
			return "/usr/bin/nvidia-smi", nil
		}
		return "", errors.New("absent")
	}
	p.runCommand = func(n string, _ ...string) (string, error) {
		return "NVIDIA GeForce RTX 3060, 12288\n", nil
	}
	g := detect(p)
	if g.Backend != "cuda" || g.VRAMMB != 12288 || g.Device != "NVIDIA GeForce RTX 3060" {
		t.Fatalf("cuda detect wrong: %+v", g)
	}
	if !g.Accelerated() {
		t.Fatal("cuda should be accelerated")
	}
}

// nvidia-smi present but broken (driver half-installed): fall through, not fail.
func TestDetectNvidiaSmiBrokenFallsThrough(t *testing.T) {
	p := base()
	p.lookPath = func(n string) (string, error) {
		if n == "nvidia-smi" {
			return "/usr/bin/nvidia-smi", nil
		}
		return "", errors.New("absent")
	}
	// runCommand errors -> next probe; no /dev/dri -> cpu
	if g := detect(p); g.Backend != "cpu" {
		t.Fatalf("broken nvidia-smi should degrade to cpu, got %+v", g)
	}
}

func TestDetectMetal(t *testing.T) {
	p := base()
	p.goos, p.goarch = "darwin", "arm64"
	if g := detect(p); g.Backend != "metal" || !g.Accelerated() {
		t.Fatalf("metal detect wrong: %+v", g)
	}
}

func TestDetectVulkanViaRenderNode(t *testing.T) {
	p := base()
	p.glob = func(pat string) []string {
		if strings.Contains(pat, "renderD") {
			return []string{"/dev/dri/renderD128"}
		}
		return nil
	}
	g := detect(p)
	if g.Backend != "vulkan" || g.Device != "drm-render-node" {
		t.Fatalf("vulkan detect wrong: %+v", g)
	}
}

func TestDetectVulkanRefinesDeviceName(t *testing.T) {
	p := base()
	p.glob = func(string) []string { return []string{"/dev/dri/renderD128"} }
	p.lookPath = func(n string) (string, error) {
		if n == "vulkaninfo" {
			return "/usr/bin/vulkaninfo", nil
		}
		return "", errors.New("absent")
	}
	p.runCommand = func(n string, _ ...string) (string, error) {
		return "GPU0:\n\tdeviceName        = Intel(R) Iris(R) Xe Graphics\n", nil
	}
	if g := detect(p); g.Device != "Intel(R) Iris(R) Xe Graphics" {
		t.Fatalf("vulkaninfo refine failed: %+v", g)
	}
}

func TestDetectCPUFallback(t *testing.T) {
	g := detect(base())
	if g.Backend != "cpu" || g.Accelerated() {
		t.Fatalf("cpu fallback wrong: %+v", g)
	}
}

// windows without any GPU adapter -> cpu (no /dev/dri probe outside linux; CIM query empty)
func TestDetectWindowsNoGPU(t *testing.T) {
	p := base()
	p.goos = "windows"
	p.glob = func(string) []string { return []string{"should-not-be-consulted"} }
	p.runCommand = func(name string, _ ...string) (string, error) {
		if name == "powershell" {
			return "Microsoft Basic Display Adapter\n", nil // no real GPU
		}
		return "", errors.New("absent")
	}
	if g := detect(p); g.Backend != "cpu" {
		t.Fatalf("windows fallback wrong: %+v", g)
	}
}

// the user's guarantee: an iGPU-ONLY Windows box (no dGPU, no nvidia-smi) still detects as
// accelerated, so calibration RACES the iGPU against the CPU instead of silently skipping it.
func TestDetectWindowsIGPUOnly(t *testing.T) {
	p := base()
	p.goos = "windows"
	p.runCommand = func(name string, _ ...string) (string, error) {
		if name == "powershell" {
			return "Intel(R) Iris(R) Xe Graphics\n", nil
		}
		return "", errors.New("absent")
	}
	g := detect(p)
	if g.Backend != "vulkan" || !g.Accelerated() || g.Device != "Intel(R) Iris(R) Xe Graphics" {
		t.Fatalf("windows iGPU must be detected + calibrated: %+v", g)
	}
	if hwNGL := ResolveNGL("auto", g); hwNGL != 999 {
		t.Fatalf("auto on windows iGPU must offer full offload to calibration: %d", hwNGL)
	}
}

func TestParseWindowsGPU(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Microsoft Basic Display Adapter\nAMD Radeon 780M\n", "AMD Radeon 780M"},
		{"NVIDIA GeForce RTX 3060 Laptop GPU\nIntel(R) UHD Graphics\n", "NVIDIA GeForce RTX 3060 Laptop GPU"},
		{"Microsoft Basic Display Adapter\n", ""},
		{"", ""},
	} {
		if got := parseWindowsGPU(tc.in); got != tc.want {
			t.Fatalf("parseWindowsGPU(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDetectDefaultProbesNeverPanics(t *testing.T) {
	_ = Detect() // whatever this machine is, detection must return without error/panic
}

func TestParseNvidiaSMI(t *testing.T) {
	for _, tc := range []struct {
		in   string
		name string
		vram int
		ok   bool
	}{
		{"NVIDIA RTX A2000, 6144", "NVIDIA RTX A2000", 6144, true},
		{"Weird Name Only", "Weird Name Only", 0, true},
		{"Name, notanumber", "Name", 0, true},
		{"  ", "", 0, false},
		{"A, 1\nB, 2", "A", 1, true}, // first GPU wins
	} {
		name, vram, ok := parseNvidiaSMI(tc.in)
		if name != tc.name || vram != tc.vram || ok != tc.ok {
			t.Fatalf("parseNvidiaSMI(%q) = %q,%d,%v", tc.in, name, vram, ok)
		}
	}
}

func TestParseVulkanDevice(t *testing.T) {
	if d := parseVulkanDevice("junk\n deviceName = AMD Radeon 780M \nmore"); d != "AMD Radeon 780M" {
		t.Fatalf("got %q", d)
	}
	if d := parseVulkanDevice("no device line"); d != "" {
		t.Fatalf("expected empty, got %q", d)
	}
	if d := parseVulkanDevice("deviceName-without-equals"); d != "" {
		t.Fatalf("expected empty on malformed line, got %q", d)
	}
}

func TestResolveNGL(t *testing.T) {
	gpu := GPU{Backend: "vulkan"}
	cpu := GPU{Backend: "cpu"}
	for _, tc := range []struct {
		mode string
		g    GPU
		want int
	}{
		{"auto", gpu, 999},
		{"", gpu, 999},
		{"AUTO", cpu, 0},
		{"auto", cpu, 0},
		{"32", cpu, 32}, // explicit wins even on cpu (operator knows best)
		{"0", gpu, 0},   // explicit 0 = force CPU on a GPU box
		{"-5", gpu, 0},  // nonsense -> safe 0
		{"banana", gpu, 0},
	} {
		if got := ResolveNGL(tc.mode, tc.g); got != tc.want {
			t.Fatalf("ResolveNGL(%q,%s) = %d, want %d", tc.mode, tc.g.Backend, got, tc.want)
		}
	}
}

func TestDetectNPU(t *testing.T) {
	// Apple silicon: ANE always present
	p := base()
	p.goos, p.goarch = "darwin", "arm64"
	if g := detect(p); g.NPU != "apple-ane" {
		t.Fatalf("ane missing: %+v", g)
	}
	// Linux accel node (Intel NPU / AMD XDNA)
	p = base()
	p.glob = func(pat string) []string {
		if strings.Contains(pat, "accel") {
			return []string{"/dev/accel/accel0"}
		}
		return nil
	}
	if g := detect(p); g.NPU != "linux-accel-npu" {
		t.Fatalf("linux npu missing: %+v", g)
	}
	// nothing -> empty (and omitted from caps)
	if g := detect(base()); g.NPU != "" {
		t.Fatalf("phantom npu: %+v", g)
	}
	var m map[string]any
	if err := json.Unmarshal(CapsJSON(detect(base())), &m); err != nil {
		t.Fatal(err)
	}
	if _, has := m["npu"]; has {
		t.Fatal("npu key must be omitted when absent")
	}
	withNPU := GPU{Backend: "cpu", NPU: "apple-ane"}
	if err := json.Unmarshal(CapsJSON(withNPU), &m); err != nil || m["npu"] != "apple-ane" {
		t.Fatalf("npu caps wrong: %v %v", m, err)
	}
	if s := withNPU.String(); !strings.Contains(s, "apple-ane") {
		t.Fatalf("String() must show npu: %s", s)
	}
}

func TestCapsJSONAndString(t *testing.T) {
	g := GPU{Backend: "vulkan", VRAMMB: 512, Device: "iGPU"}
	var m map[string]any
	if err := json.Unmarshal(CapsJSON(g), &m); err != nil {
		t.Fatalf("caps not json: %v", err)
	}
	if m["accel"] != "vulkan" || m["device"] != "iGPU" {
		t.Fatalf("caps wrong: %v", m)
	}
	if s := g.String(); !strings.Contains(s, `"backend": "vulkan"`) || !strings.Contains(s, "cpus") {
		t.Fatalf("String() wrong: %s", s)
	}
}
