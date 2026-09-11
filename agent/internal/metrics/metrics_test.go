package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCounterRender(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("dani_test_total", "test counter", "route", "code")
	c.Inc("/v1", "200")
	c.Inc("/v1", "200")
	c.Add(3, "/v1", "503")
	if c.Value("/v1", "200") != 2 || c.Value("/v1", "503") != 3 || c.Value("/x", "0") != 0 {
		t.Fatalf("counter values wrong: %v %v", c.Value("/v1", "200"), c.Value("/v1", "503"))
	}
	out := r.Render()
	for _, want := range []string{
		"# HELP dani_test_total test counter",
		"# TYPE dani_test_total counter",
		`dani_test_total{route="/v1",code="200"} 2`,
		`dani_test_total{route="/v1",code="503"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestGaugeFuncRender(t *testing.T) {
	r := NewRegistry()
	r.Counter("dani_other_total", "forces family-name sorting through the gauge").Inc()
	v := 7.0
	r.GaugeFunc("dani_live", "live things", []string{"state"}, func() []GaugeSample {
		return []GaugeSample{{LabelVals: []string{"healthy"}, Value: v}, {LabelVals: []string{"stale"}, Value: 1}}
	})
	out := r.Render()
	if !strings.Contains(out, `dani_live{state="healthy"} 7`) || !strings.Contains(out, `dani_live{state="stale"} 1`) {
		t.Fatalf("gauge render wrong:\n%s", out)
	}
	v = 9 // scrape-time evaluation, not registration-time
	if !strings.Contains(r.Render(), `dani_live{state="healthy"} 9`) {
		t.Fatal("gauge not evaluated at scrape time")
	}
	// no labels renders bare
	r2 := NewRegistry()
	r2.GaugeFunc("dani_up", "up", nil, func() []GaugeSample { return []GaugeSample{{Value: 1}} })
	if !strings.Contains(r2.Render(), "dani_up 1") {
		t.Fatalf("bare gauge wrong:\n%s", r2.Render())
	}
}

func TestHistogramCumulativeBuckets(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("dani_dur_seconds", "durations", []float64{0.1, 1, 10}, "route")
	h.Observe(0.05, "/v1") // <= 0.1
	h.Observe(0.5, "/v1")  // <= 1
	h.Observe(5, "/v1")    // <= 10
	h.Observe(99, "/v1")   // +Inf
	out := r.Render()
	for _, want := range []string{
		`dani_dur_seconds_bucket{route="/v1",le="0.1"} 1`,
		`dani_dur_seconds_bucket{route="/v1",le="1"} 2`,
		`dani_dur_seconds_bucket{route="/v1",le="10"} 3`,
		`dani_dur_seconds_bucket{route="/v1",le="+Inf"} 4`,
		`dani_dur_seconds_count{route="/v1"} 4`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, `dani_dur_seconds_sum{route="/v1"} 104.55`) {
		t.Fatalf("sum wrong:\n%s", out)
	}
	// default buckets + ObserveSince
	h2 := r.Histogram("dani_d2_seconds", "d2", nil)
	h2.ObserveSince(time.Now().Add(-10 * time.Millisecond))
	if !strings.Contains(r.Render(), "dani_d2_seconds_count 1") {
		t.Fatal("ObserveSince/default buckets missing")
	}
}

func TestHandlerAndFamilyOrder(t *testing.T) {
	r := NewRegistry()
	r.Counter("zzz_total", "z").Inc()
	r.Counter("aaa_total", "a").Inc()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	body := rec.Body.String()
	if strings.Index(body, "aaa_total") > strings.Index(body, "zzz_total") {
		t.Fatalf("families not name-sorted:\n%s", body)
	}
}

func TestRuntimeGauges(t *testing.T) {
	r := NewRegistry()
	r.RuntimeGauges()
	out := r.Render()
	for _, want := range []string{"go_goroutines ", "go_heap_alloc_bytes ", "go_gc_cycles_total "} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing runtime gauge %q in:\n%s", want, out)
		}
	}
}

func TestConcurrentSafety(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("c_total", "c", "l")
	h := r.Histogram("h_seconds", "h", nil, "l")
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for j := 0; j < 500; j++ {
				c.Inc("x")
				h.Observe(0.01, "x")
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if c.Value("x") != 4000 {
		t.Fatalf("lost increments: %v", c.Value("x"))
	}
	if !strings.Contains(r.Render(), `h_seconds_count{l="x"} 4000`) {
		t.Fatal("lost observations")
	}
}
