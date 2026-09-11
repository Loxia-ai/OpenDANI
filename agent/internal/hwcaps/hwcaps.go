// Package hwcaps detects a node's local acceleration hardware so the agent can ADAPT to whatever
// box it landed on — a GPU server, an office PC with an iGPU, a bare VM — with zero configuration.
// DANI's constraint is "real computers, nothing assumed": detection must degrade to plain CPU
// silently, never require a driver to be present, and never block startup.
//
// Detection order (first hit wins — strongest backend first):
//  1. cuda   — nvidia-smi answers (discrete NVIDIA; VRAM from the query)
//  2. metal  — macOS on Apple silicon (unified memory; llama.cpp Metal backend is built-in)
//  3. vulkan — a DRM render node exists (/dev/dri/renderD*): Intel/AMD iGPU or dGPU reachable
//     through the Vulkan backend (needs the vulkan build of llama-server; harmless otherwise)
//  4. cpu    — everything else
//
// The probes are injectable so every path is unit-testable on any machine.
package hwcaps

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// GPU describes the strongest acceleration backend detected on this node.
type GPU struct {
	Backend string `json:"backend"`       // cuda | metal | vulkan | cpu
	VRAMMB  int    `json:"vram_mb"`       // best-effort; 0 = unknown/shared
	Device  string `json:"device"`        // human-readable device name when known
	NPU     string `json:"npu,omitempty"` // detected NPU, ADVERTISED not yet driven: llama.cpp has no
	// NPU backend — utilization today = --engine openai fronting an NPU runtime (OpenVINO/Ryzen AI/
	// CoreML server). Advertising it honestly lets operators see which boxes could host one.
}

// Accelerated reports whether any GPU backend (i.e. not plain CPU) was detected.
func (g GPU) Accelerated() bool { return g.Backend != "" && g.Backend != "cpu" }

// probes are the OS touchpoints, injectable for tests.
type probes struct {
	goos       string
	goarch     string
	lookPath   func(string) (string, error)
	runCommand func(name string, args ...string) (string, error)
	glob       func(pattern string) []string
}

func defaultProbes() probes {
	return probes{
		goos:     runtime.GOOS,
		goarch:   runtime.GOARCH,
		lookPath: exec.LookPath,
		runCommand: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).Output()
			return string(out), err
		},
		glob: func(pattern string) []string {
			m, _ := filepath.Glob(pattern)
			return m
		},
	}
}

// Detect probes the local hardware. It never fails — the zero-confidence answer is {cpu}.
func Detect() GPU { return detect(defaultProbes()) }

func detect(p probes) GPU {
	g := detectGPU(p)
	g.NPU = detectNPU(p)
	return g
}

func detectGPU(p probes) GPU {
	// 1) discrete NVIDIA: nvidia-smi is the canonical, driver-provided probe.
	if _, err := p.lookPath("nvidia-smi"); err == nil {
		out, err := p.runCommand("nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits")
		if err == nil {
			if name, vram, ok := parseNvidiaSMI(out); ok {
				return GPU{Backend: "cuda", VRAMMB: vram, Device: name}
			}
		}
	}
	// 2) Apple silicon: Metal is always available (unified memory — no discrete VRAM figure).
	if p.goos == "darwin" && p.goarch == "arm64" {
		return GPU{Backend: "metal", Device: "apple-silicon"}
	}
	// 3) DRM render node: an Intel/AMD iGPU (or dGPU) the Vulkan backend can drive.
	if p.goos == "linux" && len(p.glob("/dev/dri/renderD*")) > 0 {
		g := GPU{Backend: "vulkan", Device: "drm-render-node"}
		// refine the device name when vulkaninfo is around (it usually is NOT — that's fine)
		if _, err := p.lookPath("vulkaninfo"); err == nil {
			if out, err := p.runCommand("vulkaninfo", "--summary"); err == nil {
				if name := parseVulkanDevice(out); name != "" {
					g.Device = name
				}
			}
		}
		return g
	}
	// 4) Windows iGPU (or a GPU whose nvidia-smi is absent): Win32_VideoController names the
	// adapters; any real GPU there is Vulkan-drivable (the ICD ships with the vendor driver).
	// Without this, an iGPU-only Windows box would silently skip calibration.
	if p.goos == "windows" {
		if out, err := p.runCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_VideoController).Name"); err == nil {
			if name := parseWindowsGPU(out); name != "" {
				return GPU{Backend: "vulkan", Device: name}
			}
		}
	}
	return GPU{Backend: "cpu"}
}

// parseWindowsGPU picks the first real GPU adapter from Win32_VideoController output (skips
// virtual/basic display adapters).
func parseWindowsGPU(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		l := strings.ToLower(line)
		for _, marker := range []string{"intel", "iris", "arc", "amd", "radeon", "nvidia", "geforce", "rtx"} {
			if strings.Contains(l, marker) && !strings.Contains(l, "microsoft basic") {
				return line
			}
		}
	}
	return ""
}

// detectNPU reports a neural accelerator when one is visible. Advertised-only for now (see GPU.NPU).
func detectNPU(p probes) string {
	// Apple Neural Engine ships in every Apple-silicon SoC.
	if p.goos == "darwin" && p.goarch == "arm64" {
		return "apple-ane"
	}
	// Linux accel subsystem: Intel NPU ("Meteor Lake"+) and AMD XDNA expose /dev/accel/accel*.
	if p.goos == "linux" && len(p.glob("/dev/accel/accel*")) > 0 {
		return "linux-accel-npu"
	}
	return ""
}

// parseNvidiaSMI parses "NVIDIA GeForce RTX 3060, 12288" (first GPU line).
func parseNvidiaSMI(out string) (name string, vramMB int, ok bool) {
	line := strings.TrimSpace(strings.Split(strings.TrimSpace(out), "\n")[0])
	if line == "" {
		return "", 0, false
	}
	i := strings.LastIndex(line, ",")
	if i < 0 {
		return strings.TrimSpace(line), 0, true
	}
	name = strings.TrimSpace(line[:i])
	if v, err := strconv.Atoi(strings.TrimSpace(line[i+1:])); err == nil {
		vramMB = v
	}
	return name, vramMB, true
}

// parseVulkanDevice pulls the first "deviceName = X" out of `vulkaninfo --summary`.
func parseVulkanDevice(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "deviceName"); i >= 0 {
			if j := strings.Index(line[i:], "="); j >= 0 {
				return strings.TrimSpace(line[i+j+1:])
			}
		}
	}
	return ""
}

// ResolveNGL turns the operator's --gpu-layers value into the -ngl llama-server receives.
// "auto" (the default) offloads everything when acceleration exists and nothing otherwise;
// an explicit integer is passed through verbatim (0 = force CPU even on a GPU box).
func ResolveNGL(mode string, g GPU) int {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" || mode == "auto" {
		if g.Accelerated() {
			return 999 // llama.cpp clamps to the model's real layer count
		}
		return 0
	}
	if n, err := strconv.Atoi(mode); err == nil && n >= 0 {
		return n
	}
	return 0
}

// CapsJSON renders the enrollment capability declaration for this node — real detected hardware,
// not a hardcoded stub, so operators (and the router, later) can see what each box brings.
func CapsJSON(g GPU) []byte {
	m := map[string]any{
		"engines": []string{"llama.cpp"},
		"accel":   g.Backend,
		"vram_mb": g.VRAMMB,
		"device":  g.Device,
	}
	if g.NPU != "" {
		m["npu"] = g.NPU
	}
	b, _ := json.Marshal(m)
	return b
}

// Hostname-independent debug view (the `dani-agent caps` subcommand prints this).
func (g GPU) String() string {
	m := map[string]any{
		"backend": g.Backend, "vram_mb": g.VRAMMB, "device": g.Device,
		"os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(),
	}
	if g.NPU != "" {
		m["npu"] = g.NPU
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return string(b)
}
