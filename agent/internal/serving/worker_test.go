package serving

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"dani.local/agent/internal/engine"
)

// slowEngine is a fixed-latency fake so requests pile up and exercise the admission queue.
type slowEngine struct{ d time.Duration }

func (s slowEngine) Name() string                    { return "slow" }
func (s slowEngine) Start(context.Context) error      { return nil }
func (s slowEngine) Close() error                     { return nil }
func (s slowEngine) Chat(ctx context.Context, _ engine.Request) (*engine.Result, error) {
	select {
	case <-time.After(s.d):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &engine.Result{Text: "ok", Engine: "slow", Model: "m", PromptTokens: 1, CompletionTokens: 1, TotalMs: s.d.Milliseconds()}, nil
}

// TestWorkerAdmissionQueue: with 1 serving slot + 1 queue slot, three concurrent requests should yield
// two served (one immediately, one after queueing) and exactly one back-pressured with a Retry-After.
func TestWorkerAdmissionQueue(t *testing.T) {
	w := NewWorker(WorkerConfig{
		Identity: Identity{UUID: "w"}, Engine: slowEngine{d: 250 * time.Millisecond}, ModelID: "m",
		MaxConcurrent: 1, QueueDepth: 1, SLOBudget: 3 * time.Second,
	})
	srv := httptest.NewServer(http.HandlerFunc(w.handleChat))
	defer srv.Close()

	body := `{"model":"m","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`
	var (
		mu       sync.Mutex
		ok, busy int
		retry    string
		eta      string
		wg       sync.WaitGroup
	)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(srv.URL, "application/json", strings.NewReader(body))
			if err != nil {
				return
			}
			defer resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			switch resp.StatusCode {
			case http.StatusOK:
				ok++
			case http.StatusTooManyRequests:
				busy++
				retry = resp.Header.Get("Retry-After")
				eta = resp.Header.Get("X-Dani-Estimated-Wait-Ms")
				if resp.Header.Get("X-Dani-Busy") != "true" {
					t.Errorf("busy response missing X-Dani-Busy header")
				}
			default:
				t.Errorf("unexpected status %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()

	if ok != 2 || busy != 1 {
		t.Fatalf("expected 2 served + 1 back-pressured, got ok=%d busy=%d", ok, busy)
	}
	if retry == "" || retry == "0" {
		t.Fatalf("busy response must carry a Retry-After hint, got %q", retry)
	}
	if eta == "" {
		t.Fatalf("busy response must carry X-Dani-Estimated-Wait-Ms")
	}
	t.Logf("served=%d busy=%d Retry-After=%ss eta=%sms", ok, busy, retry, eta)
}

// TestWorkerQueueDrains: with a generous queue, a burst all eventually serves (none rejected).
func TestWorkerQueueDrains(t *testing.T) {
	w := NewWorker(WorkerConfig{
		Identity: Identity{UUID: "w"}, Engine: slowEngine{d: 50 * time.Millisecond}, ModelID: "m",
		MaxConcurrent: 2, QueueDepth: 10, SLOBudget: 5 * time.Second,
	})
	srv := httptest.NewServer(http.HandlerFunc(w.handleChat))
	defer srv.Close()
	body := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`

	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Post(srv.URL, "application/json", strings.NewReader(body))
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 8 {
		t.Fatalf("expected all 8 to queue+serve, got %d", ok)
	}
}
