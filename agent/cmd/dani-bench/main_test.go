package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMetricValueAndScrape(t *testing.T) {
	if v, ok := metricValue("go_goroutines 42", "go_goroutines "); !ok || v != 42 {
		t.Fatalf("parse: %v %v", v, ok)
	}
	if _, ok := metricValue("other 1", "go_goroutines "); ok {
		t.Fatal("wrong prefix must not match")
	}
	if _, ok := metricValue("go_goroutines notanumber", "go_goroutines "); ok {
		t.Fatal("non-numeric must not parse")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("# HELP x\ngo_goroutines 17\ngo_heap_alloc_bytes 1048576\n"))
	}))
	defer srv.Close()
	g, h := scrapeRuntime(srv.Client(), srv.URL)
	if g != 17 || h != 1048576 {
		t.Fatalf("scrape: g=%v h=%v", g, h)
	}
	// unreachable gateway -> zeros, no panic
	if g, h := scrapeRuntime(http.DefaultClient, "http://127.0.0.1:1"); g != 0 || h != 0 {
		t.Fatalf("unreachable: %v %v", g, h)
	}
}

func TestLeakVerdict(t *testing.T) {
	short := []soakSample{{0, 10, 5}, {10, 10, 5}}
	if got := leakVerdict(short); !contains(got, "inconclusive") {
		t.Fatalf("short: %s", got)
	}
	stable := []soakSample{{0, 40, 8}, {10, 20, 6}, {20, 21, 6.2}, {30, 20, 6.1}}
	if got := leakVerdict(stable); !contains(got, "STABLE") {
		t.Fatalf("stable: %s", got)
	}
	leaky := []soakSample{{0, 40, 8}, {10, 20, 6}, {20, 60, 9}, {30, 200, 20}}
	if got := leakVerdict(leaky); !contains(got, "POSSIBLE LEAK") {
		t.Fatalf("leaky: %s", got)
	}
}

func TestParseLevelsAndPct(t *testing.T) {
	if got := parseLevels("1, 4 ,x,16"); len(got) != 3 || got[2] != 16 {
		t.Fatalf("levels: %v", got)
	}
	if got := parseLevels("nope"); len(got) != 1 || got[0] != 1 {
		t.Fatalf("default level: %v", got)
	}
	if pct(nil, 50) != 0 {
		t.Fatal("pct empty")
	}
	if pct([]float64{1, 2, 3, 4}, 50) == 0 {
		t.Fatal("pct nonzero")
	}
	_ = time.Second
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
