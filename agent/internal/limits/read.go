package limits

import (
	"os"
	"strconv"
	"strings"
)

// Overridable roots so the readers are unit-testable against a fake filesystem.
var (
	cgroupRoot = "/sys/fs/cgroup"
	procRoot   = "/proc"
)

// readCgroupCPUQuota returns the effective cores a cgroup allows and whether a cap is set.
// cgroup v2: cpu.max = "<quota> <period>" (or "max <period>" = uncapped).
// cgroup v1: cpu.cfs_quota_us / cpu.cfs_period_us (quota -1 = uncapped).
func readCgroupCPUQuota() (float64, bool) {
	// v2
	if b, err := os.ReadFile(cgroupRoot + "/cpu.max"); err == nil {
		f := strings.Fields(strings.TrimSpace(string(b)))
		if len(f) == 2 && f[0] != "max" {
			quota, e1 := strconv.ParseFloat(f[0], 64)
			period, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && quota > 0 && period > 0 {
				return quota / period, true
			}
		}
		return 0, false // "max <period>" — uncapped
	}
	// v1
	q, e1 := readInt(cgroupRoot + "/cpu/cpu.cfs_quota_us")
	p, e2 := readInt(cgroupRoot + "/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil && q > 0 && p > 0 {
		return float64(q) / float64(p), true
	}
	return 0, false
}

// readCgroupMemLimit returns the memory limit a cgroup imposes (bytes) and whether one is set.
// A "limit" at/above total RAM (the common uncapped sentinel like 9223372036854771712) is treated
// as uncapped. cgroup v2: memory.max ("max" = uncapped); v1: memory/memory.limit_in_bytes.
func readCgroupMemLimit() (int64, bool) {
	sentinel := readMemTotalBytes() // treat limits >= physical RAM as "no real cap"
	try := func(path string) (int64, bool) {
		b, err := os.ReadFile(path)
		if err != nil {
			return 0, false
		}
		s := strings.TrimSpace(string(b))
		if s == "max" || s == "" {
			return 0, false
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return 0, false
		}
		if sentinel > 0 && n >= sentinel {
			return 0, false
		}
		return n, true
	}
	if v, ok := try(cgroupRoot + "/memory.max"); ok { // v2
		return v, true
	}
	if v, ok := try(cgroupRoot + "/memory/memory.limit_in_bytes"); ok { // v1
		return v, true
	}
	return 0, false
}

// readMemTotalBytes reads MemTotal from /proc/meminfo (kB) → bytes. 0 if unavailable (non-Linux).
func readMemTotalBytes() int64 {
	b, err := os.ReadFile(procRoot + "/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}

func readInt(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}
