//go:build linux

package limits

import "golang.org/x/sys/unix"

// PinCPU restricts this process (and the engine children it spawns, which inherit the mask) to the
// first p.Cores logical CPUs. When the plan allows every core (or is unset) it restores the FULL mask
// — so raising a cap live actually UN-pins, not just leaves the old narrower mask in place. Best-effort:
// a failure (e.g. a restrictive seccomp policy) is returned but not fatal — --threads still bounds compute.
func (p Plan) PinCPU() error {
	n := p.Cores
	if n <= 0 || n >= p.TotalCores {
		n = p.TotalCores // unpin: allow every core
	}
	if n <= 0 {
		return nil // unknown core count — leave affinity untouched
	}
	var set unix.CPUSet
	for i := 0; i < n; i++ {
		set.Set(i)
	}
	return unix.SchedSetaffinity(0, &set) // pid 0 = the calling thread group
}
