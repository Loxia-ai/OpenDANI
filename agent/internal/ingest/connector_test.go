package ingest

// P1-6 tests: the Azure Blob connector against a faithful fake of the List Blobs / Get Blob REST
// surface — proving the credentialed crawl, the INCREMENTAL contract (unchanged blobs are never
// re-fetched, across process restarts too), deletion propagation, pagination, the prefix→class
// map, and every error path.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeBlobService emulates one container: List (XML, paged) + per-blob GET, counting fetches.
type fakeBlobService struct {
	blobs    map[string]string // name -> content; etag derives from content
	fetches  atomic.Int64      // per-blob GETs (the incremental win is measured here)
	lists    atomic.Int64
	pageSize int  // 0 = everything on one page
	failList bool // return 403 on list
	failGet  string
	badXML   bool
}

func (f *fakeBlobService) etag(name string) string { return fmt.Sprintf("W/%d-%s", len(f.blobs[name]), name) }

func (f *fakeBlobService) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("comp") == "list" {
			f.lists.Add(1)
			if f.failList {
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			if f.badXML {
				_, _ = rw.Write([]byte("<not-xml"))
				return
			}
			names := make([]string, 0, len(f.blobs))
			for n := range f.blobs {
				names = append(names, n)
			}
			// deterministic order for paging
			for i := 1; i < len(names); i++ {
				for j := i; j > 0 && names[j] < names[j-1]; j-- {
					names[j-1], names[j] = names[j], names[j-1]
				}
			}
			start := 0
			if m := r.URL.Query().Get("marker"); m != "" {
				for i, n := range names {
					if n == m {
						start = i
						break
					}
				}
			}
			end, next := len(names), ""
			if f.pageSize > 0 && start+f.pageSize < len(names) {
				end = start + f.pageSize
				next = names[end]
			}
			var sb strings.Builder
			sb.WriteString(`<?xml version="1.0"?><EnumerationResults><Blobs>`)
			for _, n := range names[start:end] {
				fmt.Fprintf(&sb, "<Blob><Name>%s</Name><Properties><Etag>%s</Etag><Content-Length>%d</Content-Length></Properties></Blob>",
					n, f.etag(n), len(f.blobs[n]))
			}
			sb.WriteString("</Blobs><NextMarker>" + next + "</NextMarker></EnumerationResults>")
			_, _ = rw.Write([]byte(sb.String()))
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/container/")
		content, ok := f.blobs[name]
		if !ok || name == f.failGet {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		f.fetches.Add(1)
		_, _ = rw.Write([]byte(content))
	}
}

func newFakeConnector(t *testing.T, f *fakeBlobService) (*AzureBlobConnector, func()) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	c := &AzureBlobConnector{
		ContainerURL: srv.URL + "/container",
		SAS:          "sv=fake&sig=fake",
		ClassMap:     map[string]string{"finance/": "restricted", "finance/board/": "secret", "hr/": "internal"},
		HTTP:         srv.Client(),
	}
	return c, srv.Close
}

func TestConnectorIncrementalSync(t *testing.T) {
	f := &fakeBlobService{blobs: map[string]string{
		"hr/handbook.txt":        "The handbook covers onboarding. Leave policy is generous.",
		"finance/q3.txt":         "Q3 revenue grew nicely.",
		"finance/board/mins.txt": "Board minutes are classified material.",
	}}
	c, done := newFakeConnector(t, f)
	defer done()
	s := New()
	if err := s.RegisterConnector("cloud-docs", c); err != nil {
		t.Fatal(err)
	}

	// first sync fetches everything
	changed, gone, col, err := s.SyncConnector(context.Background(), "cloud-docs")
	if err != nil {
		t.Fatal(err)
	}
	if changed != 3 || gone != 0 || f.fetches.Load() != 3 {
		t.Fatalf("first sync: changed=%d gone=%d fetches=%d", changed, gone, f.fetches.Load())
	}
	// classification: prefix floors applied per doc, content can only raise
	classByDoc := map[string]string{}
	for _, ch := range col.Chunks {
		classByDoc[ch.DocID] = ch.Classification
	}
	if classByDoc["cloud-docs/hr/handbook.txt"] != "internal" {
		t.Fatalf("hr class: %v", classByDoc)
	}
	if classByDoc["cloud-docs/finance/q3.txt"] != "restricted" { // floor restricted, content "revenue" agrees
		t.Fatalf("finance class: %v", classByDoc)
	}
	if classByDoc["cloud-docs/finance/board/mins.txt"] != "secret" { // longest prefix wins; "classified" scan agrees
		t.Fatalf("board class: %v", classByDoc)
	}

	// unchanged re-sync: ZERO fetches (the incremental contract)
	changed, gone, _, err = s.SyncConnector(context.Background(), "cloud-docs")
	if err != nil || changed != 0 || gone != 0 {
		t.Fatalf("no-op sync: %v changed=%d gone=%d", err, changed, gone)
	}
	if f.fetches.Load() != 3 {
		t.Fatalf("no-op sync re-fetched: %d", f.fetches.Load())
	}

	// mutate ONE blob + delete another: exactly one fetch, one gone
	f.blobs["hr/handbook.txt"] = "The handbook covers onboarding. Remote work is default now."
	delete(f.blobs, "finance/q3.txt")
	changed, gone, col, err = s.SyncConnector(context.Background(), "cloud-docs")
	if err != nil || changed != 1 || gone != 1 {
		t.Fatalf("delta sync: %v changed=%d gone=%d", err, changed, gone)
	}
	if f.fetches.Load() != 4 {
		t.Fatalf("delta sync fetches: %d (want 4)", f.fetches.Load())
	}
	if strings.Contains(fmt.Sprint(col.Chunks), "q3") {
		t.Fatal("deleted doc still in the collection")
	}
	updated := false
	for _, ch := range col.Chunks {
		if strings.Contains(ch.Text, "Remote work") {
			updated = true
		}
	}
	if !updated {
		t.Fatal("mutated doc not updated")
	}

	// Ingest() routes connector-backed collections to the sync (console button just works)
	if _, err := s.Ingest("cloud-docs"); err != nil {
		t.Fatalf("Ingest routing: %v", err)
	}
	// retrieval works over the crawled collection with classification ceilings
	hits, err := s.Retrieve("cloud-docs", "onboarding handbook", 3, "internal")
	if err != nil || len(hits) == 0 {
		t.Fatalf("retrieve over connector collection: %v %d", err, len(hits))
	}
	for _, h := range hits {
		if rank(h.Classification) > rank("internal") {
			t.Fatalf("ceiling breached: %+v", h)
		}
	}
}

func TestConnectorCursorSurvivesRestart(t *testing.T) {
	f := &fakeBlobService{blobs: map[string]string{"a.txt": "alpha doc.", "b.txt": "beta doc."}}
	c, done := newFakeConnector(t, f)
	defer done()
	dsn := filepath.Join(t.TempDir(), "ingest.db")
	st, err := OpenStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New().WithStore(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterConnector("docs", c); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.SyncConnector(context.Background(), "docs"); err != nil {
		t.Fatal(err)
	}
	if f.fetches.Load() != 2 {
		t.Fatalf("first sync fetches: %d", f.fetches.Load())
	}
	_ = st.Close()

	// RESTART: fresh subsystem + store on the same DB; re-register the connector
	st2, err := OpenStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	s2, err := New().WithStore(context.Background(), st2)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := s2.Collection("docs"); !ok || len(got.Chunks) == 0 {
		t.Fatal("connector collection lost on restart")
	}
	if err := s2.RegisterConnector("docs", c); err != nil {
		t.Fatal(err)
	}
	// the durable cursor makes the post-restart sync fetch NOTHING
	changed, _, _, err := s2.SyncConnector(context.Background(), "docs")
	if err != nil || changed != 0 {
		t.Fatalf("post-restart sync: %v changed=%d", err, changed)
	}
	if f.fetches.Load() != 2 {
		t.Fatalf("post-restart sync re-fetched: %d", f.fetches.Load())
	}
}

func TestConnectorPagination(t *testing.T) {
	f := &fakeBlobService{blobs: map[string]string{}, pageSize: 2}
	for i := 0; i < 5; i++ {
		f.blobs[fmt.Sprintf("doc-%d.txt", i)] = fmt.Sprintf("document number %d.", i)
	}
	c, done := newFakeConnector(t, f)
	defer done()
	changed, _, next, err := c.Sync(context.Background(), nil)
	if err != nil || len(changed) != 5 || len(next) != 5 {
		t.Fatalf("paged sync: %v changed=%d next=%d", err, len(changed), len(next))
	}
	if f.lists.Load() < 3 { // 5 blobs / 2 per page = 3 pages
		t.Fatalf("expected >=3 list pages, got %d", f.lists.Load())
	}
}

func TestConnectorErrorsAndGuards(t *testing.T) {
	ctx := context.Background()
	// list refused (bad SAS)
	f := &fakeBlobService{blobs: map[string]string{"a": "x"}, failList: true}
	c, done := newFakeConnector(t, f)
	defer done()
	if _, _, _, err := c.Sync(ctx, nil); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("list 403 must surface: %v", err)
	}
	// bad XML
	f2 := &fakeBlobService{blobs: map[string]string{"a": "x"}, badXML: true}
	c2, done2 := newFakeConnector(t, f2)
	defer done2()
	if _, _, _, err := c2.Sync(ctx, nil); err == nil {
		t.Fatal("bad XML must surface")
	}
	// blob GET failure
	f3 := &fakeBlobService{blobs: map[string]string{"a.txt": "x"}, failGet: "a.txt"}
	c3, done3 := newFakeConnector(t, f3)
	defer done3()
	if _, _, _, err := c3.Sync(ctx, nil); err == nil {
		t.Fatal("blob GET failure must surface")
	}
	// oversize blob refused
	f4 := &fakeBlobService{blobs: map[string]string{"big.bin": strings.Repeat("x", 10)}}
	c4, done4 := newFakeConnector(t, f4)
	defer done4()
	c4.MaxBlobBytes = 5
	if _, _, _, err := c4.Sync(ctx, nil); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("oversize must be refused: %v", err)
	}
	// unreachable service
	c5 := &AzureBlobConnector{ContainerURL: "http://127.0.0.1:1/c", SAS: "s"}
	if _, _, _, err := c5.Sync(ctx, nil); err == nil {
		t.Fatal("unreachable must surface")
	}
	// name guards
	s := New()
	if err := s.RegisterConnector("", c); err == nil {
		t.Fatal("empty name must be refused")
	}
	if err := s.RegisterConnector("legal", c); err == nil {
		t.Fatal("built-in clash must be refused")
	}
	if _, err := s.AddCustom("docs", []string{"d"}, "internal"); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterConnector("docs", c); err == nil {
		t.Fatal("upload clash must be refused")
	}
	if err := s.RegisterConnector("blobcol", c); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddCustom("blobcol", []string{"d"}, "internal"); err == nil {
		t.Fatal("upload over a connector collection must be refused")
	}
	// sync of an unregistered collection
	if _, _, _, err := s.SyncConnector(ctx, "ghost"); err == nil {
		t.Fatal("unregistered sync must fail")
	}
	// connector collections are listed
	found := false
	for _, n := range s.AvailableCorpora() {
		if n == "blobcol" {
			found = true
		}
	}
	if !found {
		t.Fatal("connector collection missing from AvailableCorpora")
	}
	// default class + longest prefix
	c6 := &AzureBlobConnector{ClassMap: map[string]string{"a/": "restricted", "a/b/": "secret"}}
	if c6.classFor("a/b/x") != "secret" || c6.classFor("a/x") != "restricted" || c6.classFor("z") != "internal" {
		t.Fatalf("classFor wrong: %s %s %s", c6.classFor("a/b/x"), c6.classFor("a/x"), c6.classFor("z"))
	}
}

// errEmbedder fails on demand (SyncConnector's embed error branch).
type errEmbedder struct{}

func (errEmbedder) Embed([]string) ([][]float32, error) { return nil, fmt.Errorf("embedder down") }

func TestConnectorFaultInjection(t *testing.T) {
	ctx := context.Background()
	mk := func() (*Subsystem, *Store, *AzureBlobConnector, func()) {
		f := &fakeBlobService{blobs: map[string]string{"a.txt": "alpha."}}
		c, done := newFakeConnector(t, f)
		st, err := OpenStore(ctx, filepath.Join(t.TempDir(), "i.db"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := New().WithStore(ctx, st)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RegisterConnector("docs", c); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = st.Close() }) // Windows: an open DB handle blocks TempDir cleanup
		return s, st, c, done
	}

	// embed failure surfaces and nothing advances
	s1, _, _, d1 := mk()
	defer d1()
	s1.embedder = errEmbedder{}
	if _, _, _, err := s1.SyncConnector(ctx, "docs"); err == nil || !strings.Contains(err.Error(), "embed") {
		t.Fatalf("embed failure must surface: %v", err)
	}

	// saveConnectorSync statement failures: dropped docs table / unwritable docs view / dropped state
	s2, st2, _, d2 := mk()
	defer d2()
	if _, err := st2.db.Exec(`DROP TABLE ingest_connector_docs`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s2.SyncConnector(ctx, "docs"); err == nil {
		t.Fatal("missing docs table must fail sync")
	}
	s3, st3, _, d3 := mk()
	defer d3()
	breakTable(t, st3, "ingest_connector_docs", `'c' AS collection, 'i' AS id, 't' AS text, 'x' AS src_class`)
	if _, _, _, err := s3.SyncConnector(ctx, "docs"); err == nil {
		t.Fatal("unwritable docs table must fail sync")
	}
	s4, st4, _, d4 := mk()
	defer d4()
	if _, err := st4.db.Exec(`DROP TABLE ingest_connector_state`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s4.SyncConnector(ctx, "docs"); err == nil {
		t.Fatal("missing state table must fail sync")
	}
	s5, st5, _, d5 := mk()
	defer d5()
	breakTable(t, st5, "ingest_connector_state", `'c' AS collection, x'00' AS cursor`)
	if _, _, _, err := s5.SyncConnector(ctx, "docs"); err == nil {
		t.Fatal("unwritable state table must fail sync")
	}
	// collection persist failure AFTER connector-state persist succeeded
	s6, st6, _, d6 := mk()
	defer d6()
	if _, err := st6.db.Exec(`DROP TABLE ingest_chunks`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s6.SyncConnector(ctx, "docs"); err == nil {
		t.Fatal("collection persist failure must fail sync")
	}

	// loadConnectors read paths: scan NULL, bad cursor JSON, missing tables at WithStore
	st7, err := OpenStore(ctx, filepath.Join(t.TempDir(), "l1.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st7.Close() })
	nullify(t, st7, `DROP TABLE ingest_connector_docs`,
		`CREATE TABLE ingest_connector_docs (collection TEXT, id TEXT, text TEXT, src_class TEXT)`,
		`INSERT INTO ingest_connector_docs VALUES ('c', 'i', NULL, 'x')`)
	if _, err := New().WithStore(ctx, st7); err == nil {
		t.Fatal("NULL connector doc must fail load")
	}
	st8, err := OpenStore(ctx, filepath.Join(t.TempDir(), "l2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st8.Close() })
	if _, err := st8.db.Exec(`INSERT INTO ingest_connector_state VALUES ('c', 'not-json')`); err != nil {
		t.Fatal(err)
	}
	if _, err := New().WithStore(ctx, st8); err == nil {
		t.Fatal("bad cursor JSON must fail load")
	}
	st9, err := OpenStore(ctx, filepath.Join(t.TempDir(), "l3.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st9.Close() })
	if _, err := st9.db.Exec(`DROP TABLE ingest_connector_docs`); err != nil {
		t.Fatal(err)
	}
	if _, err := New().WithStore(ctx, st9); err == nil {
		t.Fatal("missing docs table must fail load")
	}
	st10, err := OpenStore(ctx, filepath.Join(t.TempDir(), "l4.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st10.Close() })
	if _, err := st10.db.Exec(`DROP TABLE ingest_connector_state`); err != nil {
		t.Fatal(err)
	}
	if _, err := New().WithStore(ctx, st10); err == nil {
		t.Fatal("missing state table must fail load")
	}
	st11, err := OpenStore(ctx, filepath.Join(t.TempDir(), "l5.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st11.Close() })
	nullify(t, st11, `DROP TABLE ingest_connector_state`,
		`CREATE TABLE ingest_connector_state (collection TEXT, cursor BLOB)`,
		`INSERT INTO ingest_connector_state VALUES (NULL, x'7b7d')`)
	if _, err := New().WithStore(ctx, st11); err == nil {
		t.Fatal("NULL cursor row must fail load")
	}

	// request-build errors (control character in the URL)
	cBad := &AzureBlobConnector{ContainerURL: "http://127.0.0.1/c\x7f", SAS: "s"}
	if _, _, _, err := cBad.Sync(ctx, nil); err == nil {
		t.Fatal("bad list URL must surface")
	}
	if _, err := cBad.fetch(ctx, "x"); err == nil {
		t.Fatal("bad fetch URL must surface")
	}
}

func TestConnectorDurableFirstRefusal(t *testing.T) {
	f := &fakeBlobService{blobs: map[string]string{"a.txt": "alpha."}}
	c, done := newFakeConnector(t, f)
	defer done()
	st, _ := OpenStore(context.Background(), filepath.Join(t.TempDir(), "i.db"))
	s, err := New().WithStore(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterConnector("docs", c); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	// a sync that cannot persist must FAIL and not advance the in-memory state
	if _, _, _, err := s.SyncConnector(context.Background(), "docs"); err == nil {
		t.Fatal("sync with a broken store must fail (durable-first)")
	}
}
