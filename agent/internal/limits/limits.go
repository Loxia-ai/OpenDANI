// Package limits resolves how much of a machine DANI may use, and enforces it.
//
// The default is a GOOD NEIGHBOUR:
//   - inside a container/cgroup that already caps CPU or memory → use everything it's given ("full":
//     the operator sized the box for DANI, so the cgroup IS the cap);
//   - on a bare host with no cap → leave headroom ("polite": reserve ~20% of cores, min 1, and keep
//     ~20% of RAM for the OS), so the machine stays usable and nobody rage-quits DANI.
//
// An operator override (--max-cores / --max-model-mem-mb, or the live config keys worker.max-cores /
// worker.max-model-mem-mb) takes precedence and marks the plan "custom". Enforcement is a Linux
// cpuset pin (real cores, not just a thread hint; the engine child inherits it) plus a memory
// ADMISSION gate — DANI refuses to load a model that wouldn't fit rather than OOM-ing the host.
package limits

import (
	"fmt"
	"math"
	"os"
	"runtime"
)

// AllCores is the override value meaning "this machine is DEDICATED to DANI — take every core"
// (the CLI spells it --max-cores all or --dedicated; the config store accepts the value "all").
const AllCores = -1

// Plan is the resolved resource budget for this node.
type Plan struct {
	Mode          string `json:"mode"`          // full | polite | custom
	Cores         int    `json:"cores"`         // CPU cores DANI may use
	MemBytes      int64  `json:"memBytes"`      // model memory budget (0 = unbounded)
	TotalCores    int    `json:"totalCores"`    // cores the machine has
	TotalMemBytes int64  `json:"totalMemBytes"` // RAM the machine has (0 = unknown)
	Containerized bool   `json:"containerized"` // a cgroup already caps cpu or memory
}

// MemBudgetMB is the model memory budget in whole MB (0 = unbounded) — the shape the heartbeat and
// console use.
func (p Plan) MemBudgetMB() int {
	if p.MemBytes <= 0 {
		return 0
	}
	return int(p.MemBytes / (1 << 20))
}

// Summary is a one-line log/debug description.
func (p Plan) Summary() string {
	mem := "unbounded"
	if p.MemBytes > 0 {
		mem = fmt.Sprintf("%dMB", p.MemBudgetMB())
	}
	where := "bare host"
	if p.Containerized {
		where = "cgroup-capped"
	}
	return fmt.Sprintf("%s — %d/%d cores, model-mem %s (%s)", p.Mode, p.Cores, p.TotalCores, mem, where)
}

// probe abstracts the host facts so Resolve is unit-testable without a real /sys or /proc.
type probe struct {
	numCPU   func() int
	memTotal func() int64          // bytes, 0 if unknown
	cpuQuota func() (float64, bool) // effective cores allowed by cgroup, and whether a cap is set
	memLimit func() (int64, bool)   // bytes allowed by cgroup, and whether a cap is set
}

var host = probe{
	numCPU:   runtime.NumCPU,
	memTotal: readMemTotalBytes,
	cpuQuota: readCgroupCPUQuota,
	memLimit: readCgroupMemLimit,
}

// Resolve computes the plan from this host plus operator overrides (0 = auto/detect).
func Resolve(overrideCores int, overrideMemMB int) Plan {
	return resolve(host, overrideCores, int64(overrideMemMB)<<20)
}

func resolve(h probe, overrideCores int, overrideMemBytes int64) Plan {
	total := h.numCPU()
	if total < 1 {
		total = 1
	}
	totalMem := h.memTotal()
	qCores, cpuCapped := h.cpuQuota()
	mLimit, memCapped := h.memLimit()
	containerized := cpuCapped || memCapped

	// mode: custom (operator wins) > full (a cgroup caps us, or the operator declared the box
	// dedicated with --max-cores all) > polite (bare host).
	mode := "polite"
	if containerized {
		mode = "full"
	}
	if overrideCores > 0 || overrideMemBytes > 0 {
		mode = "custom"
	}
	if overrideCores == AllCores {
		mode = "full" // dedicated: DANI owns the machine
	}

	// cores
	cores := politeCores(total)
	if cpuCapped {
		cores = clampInt(int(math.Ceil(qCores)), 1, total)
	}
	if overrideCores > 0 {
		cores = clampInt(overrideCores, 1, total)
	}
	if overrideCores == AllCores {
		cores = total
	}

	// model-memory budget
	var memB int64
	if totalMem > 0 {
		memB = totalMem * 4 / 5 // polite: keep ~20% for the OS
	}
	if memCapped {
		memB = mLimit
	}
	if overrideMemBytes > 0 {
		memB = overrideMemBytes
	}

	return Plan{
		Mode: mode, Cores: cores, MemBytes: memB,
		TotalCores: total, TotalMemBytes: totalMem, Containerized: containerized,
	}
}

// politeCores is the UNIFORM headroom rule: more than 2 cores → leave exactly 2 for the user;
// 2 or fewer → all go to DANI (tiny boxes are VMs/dedicated nodes in practice — reserving half of a
// 2-core machine punishes the common case to protect a user who isn't there).
func politeCores(total int) int {
	if total > 2 {
		return total - 2
	}
	return total
}

// FitsMem reports whether a model at modelPath fits the plan's memory budget, and the estimated need.
// A GGUF is roughly its file size resident (mmap) plus KV cache + runtime overhead; we budget the
// file + ~20% + 512MB. Unknown size (no path / stat error) is allowed — we don't block on ignorance.
func (p Plan) FitsMem(modelPath string) (ok bool, needBytes int64) {
	if p.MemBytes <= 0 || modelPath == "" {
		return true, 0
	}
	fi, err := os.Stat(modelPath)
	if err != nil || fi.Size() <= 0 {
		return true, 0
	}
	needBytes = fi.Size() + fi.Size()/5 + (512 << 20)
	return needBytes <= p.MemBytes, needBytes
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
