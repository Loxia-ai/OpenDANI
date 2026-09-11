// Command dani-bench is the DEMO load generator + benchmark harness. It drives the DANI gateway with
// a growing number of concurrent "users" and records latency, throughput, tokens/sec, and how the
// fleet distributed the work — the data behind "measure it for a growing number of users."
//
// Usage:
//
//	dani-bench --gateway http://CTRL:8081 --model qwen2.5-1.5b \
//	           --concurrency 1,2,4,8,16,32 --requests 40 --max-tokens 128 --out bench.csv
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	gateway := flag.String("gateway", "http://127.0.0.1:8081", "DANI gateway base URL")
	model := flag.String("model", "stub-slm", "model id to request")
	concs := flag.String("concurrency", "1,2,4,8,16", "comma-separated concurrency levels to sweep")
	requests := flag.Int("requests", 40, "requests per concurrency level")
	maxTokens := flag.Int("max-tokens", 128, "max_tokens per request")
	prompt := flag.String("prompt", "Explain, in two sentences, why running a small language model inside the network perimeter matters.", "user prompt")
	classification := flag.String("classification", "unrestricted", "X-Dani-Classification header")
	timeout := flag.Duration("timeout", 5*time.Minute, "per-request timeout")
	outCSV := flag.String("out", "", "optional CSV output path")
	soak := flag.Duration("soak", 0, "SOAK mode: sustain load for this duration at the FIRST --concurrency level, sampling the controller's runtime health (goroutines/heap) to catch leaks")
	flag.Parse()

	levels := parseLevels(*concs)

	if *soak > 0 {
		runSoak(&http.Client{Timeout: *timeout}, *gateway, *model, *classification, *prompt, *maxTokens, levels[0], *soak)
		return
	}
	fmt.Printf("DANI benchmark → %s  model=%s  requests/level=%d  max_tokens=%d\n", *gateway, *model, *requests, *maxTokens)
	fmt.Printf("%-6s %-8s %-7s %-9s %-9s %-9s %-9s %-10s %-9s %-7s\n",
		"conc", "reqs", "errs", "p50ms", "p90ms", "p99ms", "req/s", "tok/s", "meanTok", "nodes")

	var rows [][]string
	rows = append(rows, []string{"concurrency", "requests", "errors", "p50_ms", "p90_ms", "p99_ms", "throughput_rps", "tokens_per_sec", "mean_completion_tokens", "distinct_workers"})

	client := &http.Client{Timeout: *timeout}
	for _, c := range levels {
		r := runLevel(client, *gateway, *model, *classification, *prompt, *maxTokens, c, *requests)
		fmt.Printf("%-6d %-8d %-7d %-9.0f %-9.0f %-9.0f %-9.1f %-10.1f %-9.1f %-7d\n",
			c, r.total, r.errors, r.p50, r.p90, r.p99, r.rps, r.tokPerSec, r.meanTok, r.nodes)
		rows = append(rows, []string{
			strconv.Itoa(c), strconv.Itoa(r.total), strconv.Itoa(r.errors),
			f(r.p50), f(r.p90), f(r.p99), f(r.rps), f(r.tokPerSec), f(r.meanTok), strconv.Itoa(r.nodes),
		})
	}

	if *outCSV != "" {
		writeCSV(*outCSV, rows)
		fmt.Printf("\nwrote %s\n", *outCSV)
	}
}

type levelResult struct {
	total, errors, nodes        int
	p50, p90, p99               float64
	rps, tokPerSec, meanTok     float64
}

func runLevel(client *http.Client, gateway, model, class, prompt string, maxTokens, conc, requests int) levelResult {
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens": maxTokens,
	})

	var (
		mu       sync.Mutex
		lat      []float64
		errs     int
		totTok   int
		workers  = map[string]int{}
		jobs     = make(chan int)
		wg       sync.WaitGroup
	)
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				t0 := time.Now()
				req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, gateway+"/v1/chat/completions", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Dani-Classification", class)
				resp, err := client.Do(req)
				ms := float64(time.Since(t0).Milliseconds())
				if err != nil {
					mu.Lock()
					errs++
					mu.Unlock()
					continue
				}
				servedBy := resp.Header.Get("X-Dani-Served-By")
				var out struct {
					Usage struct {
						CompletionTokens int `json:"completion_tokens"`
					} `json:"usage"`
				}
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				ok := resp.StatusCode == http.StatusOK
				_ = json.Unmarshal(raw, &out)
				mu.Lock()
				if ok {
					lat = append(lat, ms)
					totTok += out.Usage.CompletionTokens
					if servedBy != "" {
						workers[servedBy]++
					}
				} else {
					errs++
				}
				mu.Unlock()
			}
		}()
	}
	for i := 0; i < requests; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	sort.Float64s(lat)
	res := levelResult{total: requests, errors: errs, nodes: len(workers)}
	if len(lat) > 0 {
		res.p50 = pct(lat, 50)
		res.p90 = pct(lat, 90)
		res.p99 = pct(lat, 99)
		res.meanTok = float64(totTok) / float64(len(lat))
	}
	if elapsed > 0 {
		res.rps = float64(len(lat)) / elapsed
		res.tokPerSec = float64(totTok) / elapsed
	}
	return res
}

// runSoak sustains `conc` concurrent callers for `dur`, sampling the controller's runtime health so
// a slow leak (goroutines or heap growing without bound) shows up as a trend, not just a snapshot.
func runSoak(client *http.Client, gateway, model, class, prompt string, maxTokens, conc int, dur time.Duration) {
	body, _ := json.Marshal(map[string]any{
		"model": model, "messages": []map[string]string{{"role": "user", "content": prompt}}, "max_tokens": maxTokens,
	})
	fmt.Printf("DANI SOAK → %s  model=%s  concurrency=%d  duration=%s\n", gateway, model, conc, dur)

	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	var (
		mu      sync.Mutex
		lat     []float64
		ok, err int
		totTok  int
		workers = map[string]int{}
		wg      sync.WaitGroup
	)
	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				t0 := time.Now()
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, gateway+"/v1/chat/completions", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Dani-Classification", class)
				resp, e := client.Do(req)
				ms := float64(time.Since(t0).Milliseconds())
				if e != nil {
					mu.Lock()
					err++
					mu.Unlock()
					continue
				}
				var out struct {
					Usage struct {
						CompletionTokens int `json:"completion_tokens"`
					} `json:"usage"`
				}
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				served := resp.Header.Get("X-Dani-Served-By")
				good := resp.StatusCode == http.StatusOK
				_ = json.Unmarshal(raw, &out)
				mu.Lock()
				if good {
					ok++
					lat = append(lat, ms)
					totTok += out.Usage.CompletionTokens
					if served != "" {
						workers[served]++
					}
				} else {
					err++
				}
				mu.Unlock()
			}
		}()
	}

	// sample runtime health every 10s
	var samples []soakSample
	sampleTick := time.NewTicker(10 * time.Second)
	go func() {
		read := func() {
			g, h := scrapeRuntime(client, gateway)
			mu.Lock()
			samples = append(samples, soakSample{time.Since(start).Round(time.Second), g, h / (1 << 20)})
			mu.Unlock()
		}
		read() // baseline
		for {
			select {
			case <-ctx.Done():
				return
			case <-sampleTick.C:
				read()
			}
		}
	}()

	wg.Wait()
	sampleTick.Stop()
	elapsed := time.Since(start).Seconds()

	sort.Float64s(lat)
	fmt.Printf("\nrequests: %d ok, %d err   throughput: %.1f req/s, %.1f tok/s   nodes: %d\n",
		ok, err, float64(ok)/elapsed, float64(totTok)/elapsed, len(workers))
	if len(lat) > 0 {
		fmt.Printf("latency:  p50 %.0fms  p90 %.0fms  p99 %.0fms\n", pct(lat, 50), pct(lat, 90), pct(lat, 99))
	}
	fmt.Println("\nruntime health (leak watch — goroutines & heap should PLATEAU, not climb):")
	fmt.Printf("  %-8s %-12s %-10s\n", "t", "goroutines", "heapMB")
	for _, s := range samples {
		fmt.Printf("  %-8s %-12.0f %-10.1f\n", s.t, s.goroutines, s.heapMB)
	}
	fmt.Println(leakVerdict(samples))
}

// scrapeRuntime pulls go_goroutines + go_heap_alloc_bytes from the gateway /metrics.
func scrapeRuntime(client *http.Client, gateway string) (goroutines, heapBytes float64) {
	resp, err := client.Get(gateway + "/metrics")
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := metricValue(line, "go_goroutines "); ok {
			goroutines = v
		}
		if v, ok := metricValue(line, "go_heap_alloc_bytes "); ok {
			heapBytes = v
		}
	}
	return goroutines, heapBytes
}

func metricValue(line, prefix string) (float64, bool) {
	if !strings.HasPrefix(line, prefix) {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, prefix)), 64)
	return v, err == nil
}

// soakSample is one runtime-health reading during a soak.
type soakSample struct {
	t          time.Duration
	goroutines float64
	heapMB     float64
}

// leakVerdict compares the last sample to a post-warmup baseline. A steady system plateaus; a leak
// climbs. Uses the 2nd sample as the baseline (skip cold start) and flags >1.5x growth.
func leakVerdict(samples []soakSample) string {
	if len(samples) < 3 {
		return "\nleak verdict: inconclusive (soak too short — run >=30s for a trend)"
	}
	base := samples[1]
	last := samples[len(samples)-1]
	grewG := base.goroutines > 0 && last.goroutines > 1.5*base.goroutines
	grewH := base.heapMB > 0 && last.heapMB > 1.5*base.heapMB
	if grewG || grewH {
		return fmt.Sprintf("\nleak verdict: ⚠ POSSIBLE LEAK — goroutines %.0f→%.0f, heap %.1f→%.1fMB (grew >1.5x)",
			base.goroutines, last.goroutines, base.heapMB, last.heapMB)
	}
	return fmt.Sprintf("\nleak verdict: ✓ STABLE — goroutines %.0f→%.0f, heap %.1f→%.1fMB plateaued",
		base.goroutines, last.goroutines, base.heapMB, last.heapMB)
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(p / 100 * float64(len(sorted)-1))
	return sorted[i]
}

func parseLevels(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = []int{1}
	}
	return out
}

func f(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func writeCSV(path string, rows [][]string) {
	fh, err := os.Create(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "csv:", err)
		return
	}
	defer fh.Close()
	w := csv.NewWriter(fh)
	_ = w.WriteAll(rows)
	w.Flush()
}
