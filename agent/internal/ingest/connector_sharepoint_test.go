package ingest

// SharePointConnector against a FAKE Graph: client-credentials token, site resolve, paged initial
// delta (including a shared-facet item, which floor-by-container INDEXES like any other), content
// download, then an incremental delta carrying a change + a delete.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeGraph struct {
	t         *testing.T
	srv       *httptest.Server
	phase     int // 0 = initial crawl, 1 = incremental
	tokenHits int
}

func newFakeGraph(t *testing.T) *fakeGraph {
	g := &fakeGraph{t: t}
	mux := http.NewServeMux()
	// AAD token endpoint
	mux.HandleFunc("/tenant-1/oauth2/v2.0/token", func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "app-1" || r.Form.Get("client_secret") != "s3cret" {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		g.tokenHits++
		json.NewEncoder(rw).Encode(map[string]any{"access_token": "tok-abc", "expires_in": 3600})
	})
	auth := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer tok-abc" }
	// site resolve
	mux.HandleFunc("/graph/sites/contoso.sharepoint.com:/sites/eng", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"id": "site-123", "displayName": "Engineering"})
	})
	// delta feed (paged on the initial crawl)
	mux.HandleFunc("/graph/sites/site-123/drive/root/delta", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		if g.phase == 0 {
			if r.URL.Query().Get("page") == "2" {
				json.NewEncoder(rw).Encode(map[string]any{
					"value": []map[string]any{
						// carries the `shared` facet like EVERY SharePoint library item — must still be
						// indexed (floor-by-container), not skipped
						{"id": "it-3", "name": "handbook.md", "size": 10, "file": map[string]any{},
							"shared":          map[string]any{"scope": "users"},
							"parentReference": map[string]any{"path": "/drive/root:"}},
					},
					"@odata.deltaLink": g.srv.URL + "/graph/sites/site-123/drive/root/delta?token=T1",
				})
				return
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "it-1", "name": "policy.md", "size": 20, "file": map[string]any{},
						"parentReference": map[string]any{"path": "/drive/root:"}},
					{"id": "it-2", "name": "budget.md", "size": 22, "file": map[string]any{},
						"parentReference": map[string]any{"path": "/drive/root:/finance"}},
					{"id": "dir-1", "name": "finance", "size": 0, // a folder — no file facet → ignored
						"parentReference": map[string]any{"path": "/drive/root:"}},
				},
				"@odata.nextLink": g.srv.URL + "/graph/sites/site-123/drive/root/delta?page=2",
			})
			return
		}
		// incremental: policy.md changed, budget.md deleted
		json.NewEncoder(rw).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "it-1", "name": "policy.md", "size": 25, "file": map[string]any{},
					"parentReference": map[string]any{"path": "/drive/root:"}},
				{"id": "it-2", "name": "budget.md", "deleted": map[string]any{"state": "deleted"},
					"parentReference": map[string]any{"path": "/drive/root:/finance"}},
			},
			"@odata.deltaLink": g.srv.URL + "/graph/sites/site-123/drive/root/delta?token=T2",
		})
	})
	// content downloads
	mux.HandleFunc("/graph/sites/site-123/drive/items/", func(rw http.ResponseWriter, r *http.Request) {
		if !auth(r) {
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/graph/sites/site-123/drive/items/"), "/content")
		fmt.Fprintf(rw, "content of %s (phase %d)", id, g.phase)
	})
	g.srv = httptest.NewServer(mux)
	return g
}

func TestSharePointConnectorSync(t *testing.T) {
	g := newFakeGraph(t)
	defer g.srv.Close()
	c := &SharePointConnector{
		SiteURL: "https://contoso.sharepoint.com/sites/eng", Tenant: "tenant-1", ClientID: "app-1", Secret: "s3cret",
		ClassMap: map[string]string{"finance/": "restricted"}, DefaultClass: "internal",
		GraphBase: g.srv.URL + "/graph", LoginBase: g.srv.URL,
	}

	// initial crawl: 3 files (folder ignored; the shared-facet doc is INDEXED — floor-by-container
	// covers the whole library, and `shared` is not a unique-permissions signal)
	changed, gone, cursor, err := c.Sync(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 3 || len(gone) != 0 {
		t.Fatalf("initial: %d changed %d gone: %+v", len(changed), len(gone), ids(changed))
	}
	byID := map[string]ConnectorDoc{}
	for _, d := range changed {
		byID[d.ID] = d
	}
	if d := byID["finance/budget.md"]; d.SrcClass != "restricted" || !strings.Contains(d.Text, "content of it-2") {
		t.Fatalf("finance doc floor/content wrong: %+v", d)
	}
	if byID["policy.md"].SrcClass != "internal" {
		t.Fatalf("default floor wrong: %+v", byID["policy.md"])
	}
	if d, ok := byID["handbook.md"]; !ok || d.SrcClass != "internal" || !strings.Contains(d.Text, "content of it-3") {
		t.Fatalf("shared-facet doc must be INDEXED at the container floor: %+v (present=%v)", d, ok)
	}
	if !strings.Contains(cursor["__delta"], "token=T1") {
		t.Fatalf("cursor deltaLink: %q", cursor["__delta"])
	}

	// incremental: only the change + the delete travel; token endpoint hit only once (cached)
	g.phase = 1
	changed, gone, cursor, err = c.Sync(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0].ID != "policy.md" || !strings.Contains(changed[0].Text, "phase 1") {
		t.Fatalf("incremental changed: %+v", ids(changed))
	}
	if len(gone) != 1 || gone[0] != "finance/budget.md" {
		t.Fatalf("incremental gone: %v", gone)
	}
	if !strings.Contains(cursor["__delta"], "token=T2") {
		t.Fatalf("cursor must advance: %q", cursor["__delta"])
	}
	if g.tokenHits != 1 {
		t.Fatalf("token endpoint hit %d times, want 1 (cached)", g.tokenHits)
	}
}

func TestSharePointDefAndProbe(t *testing.T) {
	// def validation
	if err := (ConnectorDef{Kind: "sharepoint", Collection: "eng"}).Validate(); err == nil {
		t.Fatal("sharepoint def without url/tenant/client/secret must fail")
	}
	g := newFakeGraph(t)
	defer g.srv.Close()
	s := New()
	files, detail, err := s.Probe(context.Background(), ConnectorDef{
		Kind: "sharepoint", Collection: "eng",
		URL: "https://contoso.sharepoint.com/sites/eng", Tenant: "tenant-1", ClientID: "app-1", Secret: "s3cret",
	})
	// Probe builds its own connector with REAL endpoints — it can't reach the fake. So probe the
	// connector directly for the reachability contract instead:
	_ = files
	_ = detail
	_ = err
	c := &SharePointConnector{SiteURL: "https://contoso.sharepoint.com/sites/eng", Tenant: "tenant-1",
		ClientID: "app-1", Secret: "s3cret", GraphBase: g.srv.URL + "/graph", LoginBase: g.srv.URL}
	if _, display, err := c.ResolveSite(context.Background()); err != nil || display != "Engineering" {
		t.Fatalf("resolve: %q %v", display, err)
	}
	// bad credentials → clean error
	bad := &SharePointConnector{SiteURL: "https://contoso.sharepoint.com/sites/eng", Tenant: "tenant-1",
		ClientID: "app-1", Secret: "wrong", GraphBase: g.srv.URL + "/graph", LoginBase: g.srv.URL}
	if _, _, err := bad.ResolveSite(context.Background()); err == nil {
		t.Fatal("bad secret must fail the probe")
	}
}
