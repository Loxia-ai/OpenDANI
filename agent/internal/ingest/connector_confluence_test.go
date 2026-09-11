package ingest

// ConfluenceConnector against a FAKE Confluence Cloud: Basic auth, space resolve, page listing with
// version numbers, storage-format body download, then an incremental sync where one page's version
// advances (re-fetched), one page is removed (reported gone), and an unchanged page is NOT re-fetched.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeConfluence struct {
	t        *testing.T
	srv      *httptest.Server
	phase    int // 0 = initial crawl, 1 = incremental
	bodyHits map[string]int
}

func newFakeConfluence(t *testing.T) *fakeConfluence {
	g := &fakeConfluence{t: t, bodyHits: map[string]int{}}
	mux := http.NewServeMux()
	auth := func(r *http.Request) bool {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("dev@acme.com:tok-1"))
		return r.Header.Get("Authorization") == want
	}
	// space resolve (the probe path)
	mux.HandleFunc("/rest/api/space/ENG", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"name": "Engineering"})
	})
	// page listing (spaceKey + version); phase decides the set
	mux.HandleFunc("/rest/api/content", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		page := func(id, title string, ver int) map[string]any {
			return map[string]any{"id": id, "title": title, "version": map[string]any{"number": ver}}
		}
		var results []map[string]any
		if g.phase == 0 {
			results = []map[string]any{
				page("p1", "Onboarding", 1),
				page("p2", "Security Baseline", 2),
			}
		} else {
			// p1 unchanged (v1), p2 GONE, p3 new
			results = []map[string]any{
				page("p1", "Onboarding", 1),
				page("p3", "Runbook", 1),
			}
		}
		json.NewEncoder(rw).Encode(map[string]any{"results": results, "size": len(results)})
	})
	// storage-format body
	mux.HandleFunc("/rest/api/content/", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/rest/api/content/")
		g.bodyHits[id]++
		json.NewEncoder(rw).Encode(map[string]any{
			"body": map[string]any{"storage": map[string]any{
				"value": "<h1>" + id + "</h1><p>Welcome to <strong>Acme</strong> " + id + ".</p>",
			}},
		})
	})
	g.srv = httptest.NewServer(mux)
	return g
}

func TestConfluenceConnectorSync(t *testing.T) {
	g := newFakeConfluence(t)
	defer g.srv.Close()
	c := &ConfluenceConnector{
		BaseURL: "https://acme.atlassian.net/wiki", Space: "ENG", Email: "dev@acme.com", Token: "tok-1",
		ClassMap: map[string]string{"Security": "restricted"}, DefaultClass: "internal",
		APIBase: g.srv.URL + "/rest/api",
	}

	// initial crawl: 2 pages, both bodies fetched
	changed, gone, cursor, err := c.Sync(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 2 || len(gone) != 0 {
		t.Fatalf("initial: %d changed %d gone: %v", len(changed), len(gone), ids(changed))
	}
	byID := map[string]ConnectorDoc{}
	for _, d := range changed {
		byID[d.ID] = d
	}
	if d := byID["Security Baseline"]; d.SrcClass != "restricted" || !strings.Contains(d.Text, "Welcome to Acme") {
		t.Fatalf("title-prefix floor/content wrong: %+v", d)
	}
	if byID["Onboarding"].SrcClass != "internal" || byID["Onboarding"].Format != "html" {
		t.Fatalf("default floor/format wrong: %+v", byID["Onboarding"])
	}
	if g.bodyHits["p1"] != 1 || g.bodyHits["p2"] != 1 {
		t.Fatalf("initial body fetches: %v", g.bodyHits)
	}

	// incremental: p1 unchanged (NOT re-fetched), p2 removed, p3 new
	g.phase = 1
	changed, gone, cursor, err = c.Sync(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0].ID != "Runbook" {
		t.Fatalf("incremental changed: %v", ids(changed))
	}
	if len(gone) != 1 || gone[0] != "Security Baseline" {
		t.Fatalf("incremental gone: %v", gone)
	}
	if g.bodyHits["p1"] != 1 { // unchanged version → body NOT re-fetched
		t.Fatalf("unchanged page was re-fetched: p1 hits=%d", g.bodyHits["p1"])
	}
	if g.bodyHits["p3"] != 1 {
		t.Fatalf("new page p3 not fetched: %v", g.bodyHits)
	}
	if _, still := map[string]string(cursor)["id:p2"]; still {
		t.Fatal("removed page must be dropped from the cursor")
	}
}

func TestConfluenceProbeAndDefValidation(t *testing.T) {
	// def validation
	if err := (ConnectorDef{Kind: "confluence", Collection: "eng"}).Validate(); err == nil {
		t.Fatal("confluence def without url/space/email/secret must fail")
	}
	g := newFakeConfluence(t)
	defer g.srv.Close()
	c := &ConfluenceConnector{BaseURL: "https://acme.atlassian.net/wiki", Space: "ENG",
		Email: "dev@acme.com", Token: "tok-1", APIBase: g.srv.URL + "/rest/api"}
	if name, err := c.SpaceName(context.Background()); err != nil || name != "Engineering" {
		t.Fatalf("space resolve: %q %v", name, err)
	}
	// bad token → clean error
	bad := &ConfluenceConnector{BaseURL: "https://acme.atlassian.net/wiki", Space: "ENG",
		Email: "dev@acme.com", Token: "wrong", APIBase: g.srv.URL + "/rest/api"}
	if _, err := bad.SpaceName(context.Background()); err == nil {
		t.Fatal("bad token must fail the probe")
	}
}
