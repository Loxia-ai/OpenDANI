//go:build !linux

package limits

// PinCPU is a no-op off Linux (cpuset affinity is Linux-only). --threads still bounds engine compute,
// and Windows/macOS dev boxes don't run the production data plane.
func (p Plan) PinCPU() error { return nil }
