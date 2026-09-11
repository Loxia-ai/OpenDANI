package limits

import (
	"os"
	"path/filepath"
	"testing"
)

func fakeProbe(cpus int, mem int64, quota float64, cpuCapped bool, memLimit int64, memCapped bool) probe {
	return probe{
		numCPU:   func() int { return cpus },
		memTotal: func() int64 { return mem },
		cpuQuota: func() (float64, bool) { return quota, cpuCapped },
		memLimit: func() (int64, bool) { return memLimit, memCapped },
	}
}

const gb = int64(1) << 30

func TestResolve_PoliteOnBareHost(t *testing.T) {
	// 8 cores, 16GB, no cgroup cap → leave ~20% headroom.
	p := resolve(fakeProbe(8, 16*gb, 0, false, 0, false), 0, 0)
	if p.Mode != "polite" {
		t.Fatalf("mode = %q, want polite", p.Mode)
	}
	if p.Cores != 6 { // uniform rule: 8 - 2 for the user → 6
		t.Errorf("cores = %d, want 6", p.Cores)
	}
	if p.MemBytes != 16*gb*4/5 {
		t.Errorf("mem = %d, want %d (80%%)", p.MemBytes, 16*gb*4/5)
	}
	if p.Containerized {
		t.Error("bare host must not be containerized")
	}
}

func TestResolve_PoliteUniformRule(t *testing.T) {
	// UNIFORM: >2 cores → leave exactly 2 for the user; ≤2 → all go to DANI.
	for _, tc := range []struct{ total, want int }{
		{1, 1}, {2, 2}, // tiny boxes are dedicated in practice — DANI takes all
		{3, 1}, {4, 2}, {8, 6}, {16, 14}, // bigger: user always keeps 2
	} {
		if c := resolve(fakeProbe(tc.total, 4*gb, 0, false, 0, false), 0, 0).Cores; c != tc.want {
			t.Errorf("%d-core polite = %d, want %d", tc.total, c, tc.want)
		}
	}
}

func TestResolve_DedicatedAllCores(t *testing.T) {
	// --max-cores all / --dedicated: DANI owns the machine → every core, mode "full".
	p := resolve(fakeProbe(8, 16*gb, 0, false, 0, false), AllCores, 0)
	if p.Mode != "full" || p.Cores != 8 {
		t.Fatalf("dedicated = (%q, %d cores), want (full, 8)", p.Mode, p.Cores)
	}
}

func TestResolve_FullInsideCgroup(t *testing.T) {
	// A pod limited to 3 cores + 4GB → use all it's given.
	p := resolve(fakeProbe(16, 64*gb, 3.0, true, 4*gb, true), 0, 0)
	if p.Mode != "full" {
		t.Fatalf("mode = %q, want full", p.Mode)
	}
	if p.Cores != 3 {
		t.Errorf("cores = %d, want 3 (the cgroup quota)", p.Cores)
	}
	if p.MemBytes != 4*gb {
		t.Errorf("mem = %d, want 4GB (the cgroup limit)", p.MemBytes)
	}
	if !p.Containerized {
		t.Error("want containerized")
	}
}

func TestResolve_FractionalQuotaRoundsUp(t *testing.T) {
	// 1.5-core quota → ceil to 2.
	if c := resolve(fakeProbe(8, 8*gb, 1.5, true, 0, false), 0, 0).Cores; c != 2 {
		t.Errorf("cores = %d, want 2 (ceil 1.5)", c)
	}
}

func TestResolve_OperatorOverrideWins(t *testing.T) {
	// Even inside a cgroup, an explicit override is authoritative and marks custom.
	p := resolve(fakeProbe(16, 64*gb, 8.0, true, 32*gb, true), 2, 4096<<20) // 4096 MB in bytes
	if p.Mode != "custom" {
		t.Fatalf("mode = %q, want custom", p.Mode)
	}
	if p.Cores != 2 {
		t.Errorf("cores = %d, want 2", p.Cores)
	}
	if p.MemBudgetMB() != 4096 {
		t.Errorf("mem MB = %d, want 4096", p.MemBudgetMB())
	}
}

func TestResolve_OverrideClampedToPhysical(t *testing.T) {
	if c := resolve(fakeProbe(4, 8*gb, 0, false, 0, false), 99, 0).Cores; c != 4 {
		t.Errorf("cores = %d, want 4 (clamped to physical)", c)
	}
}

func TestFitsMem(t *testing.T) {
	dir := t.TempDir()
	model := filepath.Join(dir, "m.gguf")
	// a 1GB model file
	if err := os.WriteFile(model, make([]byte, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(model, gb); err != nil {
		t.Fatal(err)
	}
	// need ≈ 1GB + 20% + 512MB ≈ 1.7GB
	small := Plan{MemBytes: gb} // 1GB budget → too small
	if ok, need := small.FitsMem(model); ok {
		t.Errorf("1GB model should not fit a 1GB budget (need %d)", need)
	}
	big := Plan{MemBytes: 4 * gb}
	if ok, _ := big.FitsMem(model); !ok {
		t.Error("1GB model should fit a 4GB budget")
	}
	// unbounded budget or unknown path always fits
	if ok, _ := (Plan{MemBytes: 0}).FitsMem(model); !ok {
		t.Error("unbounded budget must always fit")
	}
	if ok, _ := big.FitsMem(""); !ok {
		t.Error("empty path must always fit")
	}
}

func TestReadCgroupCPUQuota_V2(t *testing.T) {
	dir := t.TempDir()
	old := cgroupRoot
	cgroupRoot = dir
	defer func() { cgroupRoot = old }()

	os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("150000 100000\n"), 0o600)
	c, capped := readCgroupCPUQuota()
	if !capped || c != 1.5 {
		t.Errorf("cpu.max 150000/100000 → (%v, %v), want (1.5, true)", c, capped)
	}
	os.WriteFile(filepath.Join(dir, "cpu.max"), []byte("max 100000\n"), 0o600)
	if _, capped := readCgroupCPUQuota(); capped {
		t.Error("cpu.max 'max' must read as uncapped")
	}
}

func TestReadCgroupMemLimit_SentinelIsUncapped(t *testing.T) {
	dir := t.TempDir()
	oldC, oldP := cgroupRoot, procRoot
	cgroupRoot, procRoot = dir, dir
	defer func() { cgroupRoot, procRoot = oldC, oldP }()

	os.WriteFile(filepath.Join(dir, "meminfo"), []byte("MemTotal:       8000000 kB\n"), 0o600)
	// a real cap well below RAM
	os.WriteFile(filepath.Join(dir, "memory.max"), []byte("2147483648\n"), 0o600) // 2GB
	if v, capped := readCgroupMemLimit(); !capped || v != 2<<30 {
		t.Errorf("memory.max 2GB → (%d, %v), want (2GB, true)", v, capped)
	}
	// a sentinel >= RAM → uncapped
	os.WriteFile(filepath.Join(dir, "memory.max"), []byte("9223372036854771712\n"), 0o600)
	if _, capped := readCgroupMemLimit(); capped {
		t.Error("a limit >= physical RAM must read as uncapped")
	}
}
