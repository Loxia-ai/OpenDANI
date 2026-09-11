// Package metrics is a dependency-free Prometheus exposition-format exporter
// (PRODUCTION-READINESS P1-2). It implements the three instrument kinds DANI needs — counters,
// histograms, and callback gauges, all label-aware — and renders the stable text format
// (`text/plain; version=0.0.4`) any Prometheus/Grafana/VictoriaMetrics scraper ingests.
//
// Hand-rolled on purpose, same reasoning as internal/wg using stdlib X25519: the exposition format
// is a small, frozen contract, and DANI's in-perimeter thesis favors a minimal dependency surface
// over importing the full client_golang tree for three instrument kinds.
package metrics

import (
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Registry holds metric families and renders them in name order.
type Registry struct {
	mu       sync.Mutex
	families []family // registration order preserved per family; rendered sorted by name
}

type family interface {
	name() string
	render(b *strings.Builder)
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// labelKey serializes label values into a map key (values cannot contain '\x00' in practice).
func labelKey(vals []string) string { return strings.Join(vals, "\x00") }

// renderLabels formats {a="x",b="y"} for a sample (empty when the metric has no labels).
func renderLabels(names, vals []string) string {
	if len(names) == 0 {
		return ""
	}
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s=%q", n, vals[i])
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ---- counter ----

// Counter is a monotonically increasing sample set, one series per label combination.
type Counter struct {
	mu         sync.Mutex
	fqName     string
	help       string
	labelNames []string
	series     map[string]*counterSeries
}

type counterSeries struct {
	vals []string
	n    float64
}

// Counter registers (or returns) a counter family.
func (r *Registry) Counter(name, help string, labelNames ...string) *Counter {
	c := &Counter{fqName: name, help: help, labelNames: labelNames, series: map[string]*counterSeries{}}
	r.mu.Lock()
	r.families = append(r.families, c)
	r.mu.Unlock()
	return c
}

// Inc adds 1 to the series identified by labelVals.
func (c *Counter) Inc(labelVals ...string) { c.Add(1, labelVals...) }

// Add adds v (>= 0) to the series identified by labelVals.
func (c *Counter) Add(v float64, labelVals ...string) {
	k := labelKey(labelVals)
	c.mu.Lock()
	s, ok := c.series[k]
	if !ok {
		s = &counterSeries{vals: append([]string(nil), labelVals...)}
		c.series[k] = s
	}
	s.n += v
	c.mu.Unlock()
}

// Value reads a series (tests + introspection).
func (c *Counter) Value(labelVals ...string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.series[labelKey(labelVals)]; ok {
		return s.n
	}
	return 0
}

func (c *Counter) name() string { return c.fqName }

func (c *Counter) render(b *strings.Builder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", c.fqName, c.help, c.fqName)
	for _, k := range sortedKeys(c.series) {
		s := c.series[k]
		fmt.Fprintf(b, "%s%s %g\n", c.fqName, renderLabels(c.labelNames, s.vals), s.n)
	}
}

// ---- gauge (callback) ----

// GaugeFunc reports a value computed at scrape time — the honest way to expose live state (fleet
// size, in-flight count) without a write on every mutation.
type GaugeFunc struct {
	fqName     string
	help       string
	labelNames []string
	fn         func() []GaugeSample
}

// GaugeSample is one scrape-time gauge reading.
type GaugeSample struct {
	LabelVals []string
	Value     float64
}

// GaugeFunc registers a callback gauge family.
func (r *Registry) GaugeFunc(name, help string, labelNames []string, fn func() []GaugeSample) *GaugeFunc {
	g := &GaugeFunc{fqName: name, help: help, labelNames: labelNames, fn: fn}
	r.mu.Lock()
	r.families = append(r.families, g)
	r.mu.Unlock()
	return g
}

func (g *GaugeFunc) name() string { return g.fqName }

func (g *GaugeFunc) render(b *strings.Builder) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n", g.fqName, g.help, g.fqName)
	for _, s := range g.fn() {
		fmt.Fprintf(b, "%s%s %g\n", g.fqName, renderLabels(g.labelNames, s.LabelVals), s.Value)
	}
}

// ---- histogram ----

// Histogram observes value distributions into cumulative buckets (Prometheus semantics: each bucket
// counts observations <= its upper bound; +Inf is implicit and equals _count).
type Histogram struct {
	mu         sync.Mutex
	fqName     string
	help       string
	labelNames []string
	buckets    []float64
	series     map[string]*histSeries
}

type histSeries struct {
	vals   []string
	counts []uint64 // one per bucket
	inf    uint64   // observations above the last bucket
	sum    float64
}

// DefBuckets suit request latencies in seconds (5ms .. 60s).
var DefBuckets = []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60}

// Histogram registers a histogram family. buckets must be sorted ascending (DefBuckets when nil).
func (r *Registry) Histogram(name, help string, buckets []float64, labelNames ...string) *Histogram {
	if buckets == nil {
		buckets = DefBuckets
	}
	h := &Histogram{fqName: name, help: help, labelNames: labelNames, buckets: buckets, series: map[string]*histSeries{}}
	r.mu.Lock()
	r.families = append(r.families, h)
	r.mu.Unlock()
	return h
}

// Observe records one value into the series identified by labelVals.
func (h *Histogram) Observe(v float64, labelVals ...string) {
	k := labelKey(labelVals)
	h.mu.Lock()
	s, ok := h.series[k]
	if !ok {
		s = &histSeries{vals: append([]string(nil), labelVals...), counts: make([]uint64, len(h.buckets))}
		h.series[k] = s
	}
	placed := false
	for i, ub := range h.buckets {
		if v <= ub {
			s.counts[i]++
			placed = true
			break
		}
	}
	if !placed {
		s.inf++
	}
	s.sum += v
	h.mu.Unlock()
}

// ObserveSince records the elapsed time since start, in seconds.
func (h *Histogram) ObserveSince(start time.Time, labelVals ...string) {
	h.Observe(time.Since(start).Seconds(), labelVals...)
}

func (h *Histogram) name() string { return h.fqName }

func (h *Histogram) render(b *strings.Builder) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", h.fqName, h.help, h.fqName)
	leNames := append(append([]string(nil), h.labelNames...), "le")
	for _, k := range sortedKeys(h.series) {
		s := h.series[k]
		cum := uint64(0)
		for i, ub := range h.buckets {
			cum += s.counts[i]
			fmt.Fprintf(b, "%s_bucket%s %d\n", h.fqName, renderLabels(leNames, append(append([]string(nil), s.vals...), fmt.Sprintf("%g", ub))), cum)
		}
		total := cum + s.inf
		fmt.Fprintf(b, "%s_bucket%s %d\n", h.fqName, renderLabels(leNames, append(append([]string(nil), s.vals...), "+Inf")), total)
		fmt.Fprintf(b, "%s_sum%s %g\n", h.fqName, renderLabels(h.labelNames, s.vals), s.sum)
		fmt.Fprintf(b, "%s_count%s %d\n", h.fqName, renderLabels(h.labelNames, s.vals), total)
	}
}

// ---- rendering ----

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Render produces the whole exposition payload, families sorted by name.
func (r *Registry) Render() string {
	r.mu.Lock()
	fams := append([]family(nil), r.families...)
	r.mu.Unlock()
	sort.SliceStable(fams, func(i, j int) bool { return fams[i].name() < fams[j].name() })
	var b strings.Builder
	for _, f := range fams {
		f.render(&b)
	}
	return b.String()
}

// RuntimeGauges registers Go runtime health gauges — cheap leak/soak signals an operator or a soak
// harness watches for unbounded growth (goroutines and heap should plateau under steady load).
func (r *Registry) RuntimeGauges() {
	r.GaugeFunc("go_goroutines", "Number of live goroutines.", nil, func() []GaugeSample {
		return []GaugeSample{{Value: float64(runtime.NumGoroutine())}}
	})
	r.GaugeFunc("go_heap_alloc_bytes", "Heap bytes allocated and still in use.", nil, func() []GaugeSample {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return []GaugeSample{{Value: float64(m.HeapAlloc)}}
	})
	r.GaugeFunc("go_gc_cycles_total", "Completed GC cycles.", nil, func() []GaugeSample {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return []GaugeSample{{Value: float64(m.NumGC)}}
	})
}

// Handler serves the registry as a Prometheus scrape target.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = rw.Write([]byte(r.Render()))
	})
}
