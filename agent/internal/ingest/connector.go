package ingest

// Real data connector (PRODUCTION-READINESS P1-6): until now the "connectors" (confluence/
// sharepoint/jdbc) were labels on synthetic corpora. AzureBlobConnector is the first REAL one —
// it crawls an Azure Blob container over the same SDK-free SAS-URL REST style the artifact store
// uses (Phase 1.4): credentialed via a scoped, time-limited SAS the operator provisions (a secret
// reference — never logged), INCREMENTAL via blob ETags (unchanged blobs are never re-fetched),
// and classification-mapped by blob-name prefix (the source floor; content scanning can only RAISE
// a doc's class — D-09 direction).

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync/atomic"
	"time"
)

// ConnectorDoc is one crawled document.
type ConnectorDoc struct {
	ID       string // stable id within the source (blob name / relative path)
	Text     string
	SrcClass string // source-mapped classification floor for THIS doc
	Format   string // what kind of file backed it (text|html|pdf|docx); "" = text
}

// Connector crawls an external source incrementally. state is the connector's opaque cursor from
// the previous sync (nil on first crawl); implementations return every NEW/CHANGED doc, the ids
// GONE from the source, and the next state.
type Connector interface {
	Name() string
	Sync(ctx context.Context, state map[string]string) (changed []ConnectorDoc, gone []string, next map[string]string, err error)
}

// AzureBlobConnector crawls one container. ContainerURL is "https://<acct>.blob.core.windows.net/
// <container>" and SAS the query string (no leading '?'), resolved from a secret reference by the
// caller — this struct never logs either.
type AzureBlobConnector struct {
	ContainerURL string
	SAS          string
	ClassMap     map[string]string // blob-name prefix -> classification floor (longest match wins)
	DefaultClass string            // floor when no prefix matches (default "internal")
	HTTP         *http.Client      // test seam; nil = 30s default
	MaxBlobBytes int64             // per-blob cap (default 1 MiB — ingest docs are text)
}

func (c *AzureBlobConnector) Name() string { return "azblob" }

func (c *AzureBlobConnector) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// listResult is the List Blobs REST response (flat listing).
type listResult struct {
	Blobs struct {
		Blob []struct {
			Name       string `xml:"Name"`
			Properties struct {
				Etag          string `xml:"Etag"`
				ContentLength int64  `xml:"Content-Length"`
			} `xml:"Properties"`
		} `xml:"Blob"`
	} `xml:"Blobs"`
	NextMarker string `xml:"NextMarker"`
}

// classFor picks the classification floor for a blob name (longest matching prefix wins;
// shared dialect with the folder/git connectors).
func (c *AzureBlobConnector) classFor(name string) string {
	return classForPrefix(name, c.ClassMap, c.DefaultClass)
}

// Sync lists the container (paged) and fetches only blobs whose ETag changed since state.
func (c *AzureBlobConnector) Sync(ctx context.Context, state map[string]string) ([]ConnectorDoc, []string, map[string]string, error) {
	maxBytes := c.MaxBlobBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	next := map[string]string{}
	var changed []ConnectorDoc
	marker := ""
	for {
		url := c.ContainerURL + "?restype=container&comp=list&" + c.SAS
		if marker != "" {
			url += "&marker=" + marker
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("azblob connector: %w", err)
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("azblob connector: list: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, nil, nil, fmt.Errorf("azblob connector: list HTTP %d (check the SAS grants List)", resp.StatusCode)
		}
		var lr listResult
		err = xml.NewDecoder(resp.Body).Decode(&lr)
		resp.Body.Close()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("azblob connector: list decode: %w", err)
		}
		for _, b := range lr.Blobs.Blob {
			next[b.Name] = b.Properties.Etag
			if state[b.Name] == b.Properties.Etag {
				continue // unchanged — the incremental win: never re-fetched
			}
			if b.Properties.ContentLength > maxBytes {
				return nil, nil, nil, fmt.Errorf("azblob connector: blob %q is %d bytes (cap %d) — not a text document", b.Name, b.Properties.ContentLength, maxBytes)
			}
			text, err := c.fetch(ctx, b.Name)
			if err != nil {
				return nil, nil, nil, err
			}
			changed = append(changed, ConnectorDoc{ID: b.Name, Text: text, SrcClass: c.classFor(b.Name)})
		}
		if lr.NextMarker == "" {
			break
		}
		marker = lr.NextMarker
	}
	var gone []string
	for name := range state {
		if _, still := next[name]; !still {
			gone = append(gone, name)
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i].ID < changed[j].ID })
	sort.Strings(gone)
	return changed, gone, next, nil
}

// ---- subsystem integration ----

// connectorEntry is a registered connector plus its synced state (docs by id + the cursor) and the
// live status the console's Connected-sources card shows.
type connectorEntry struct {
	conn   Connector
	docs   map[string]ConnectorDoc
	cursor map[string]string

	syncing     int32 // atomic: a sync is in flight
	lastSync    time.Time
	lastErr     string
	lastChanged int
	lastGone    int
}

// RegisterConnector binds a collection name to a live connector. If the durable store already holds
// synced docs + a cursor for this collection (a restart), they are used as the incremental baseline —
// the next sync fetches only what changed while we were down.
func (s *Subsystem) RegisterConnector(collection string, c Connector) error {
	if collection == "" {
		return fmt.Errorf("ingest: connector needs a collection name")
	}
	if _, builtin := corpora[collection]; builtin {
		return fmt.Errorf("ingest: %q is a built-in corpus — pick another name", collection)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.custom[collection]; dup {
		return fmt.Errorf("ingest: %q is an uploaded corpus — pick another name", collection)
	}
	e := &connectorEntry{conn: c, docs: map[string]ConnectorDoc{}, cursor: map[string]string{}}
	if prev, ok := s.connectors[collection]; ok { // rehydrated state from WithStore
		e.docs, e.cursor = prev.docs, prev.cursor
	}
	s.connectors[collection] = e
	return nil
}

// SyncConnector runs one incremental crawl for a connector-backed collection: fetch only
// changed/new docs, drop gone ones, persist docs + cursor durably, then rebuild + re-embed the
// collection (write-through, same durability contract as Ingest). Returns (changed, gone) counts.
func (s *Subsystem) SyncConnector(ctx context.Context, collection string) (int, int, Collection, error) {
	s.mu.Lock()
	e, ok := s.connectors[collection]
	s.mu.Unlock()
	if !ok || e.conn == nil {
		return 0, 0, Collection{}, fmt.Errorf("ingest: no connector registered for %q", collection)
	}
	atomic.StoreInt32(&e.syncing, 1)
	changed, gone, next, err := e.conn.Sync(ctx, e.cursor)
	if err != nil {
		s.recordSync(e, 0, 0, err)
		return 0, 0, Collection{}, err
	}
	// apply on a copy — the entry only advances if persistence succeeds (durable-first)
	docs := make(map[string]ConnectorDoc, len(e.docs)+len(changed))
	for id, d := range e.docs {
		docs[id] = d
	}
	for _, d := range changed {
		docs[d.ID] = d
	}
	for _, id := range gone {
		delete(docs, id)
	}
	col := s.buildConnectorCollection(collection, e.conn.Name(), docs)
	s.mu.Lock()
	prev := s.collections[collection]
	s.mu.Unlock()
	if err := s.embedChunks(prev, &col); err != nil { // incremental: unchanged chunks reuse vectors
		err = fmt.Errorf("ingest: embed %q: %w", collection, err)
		s.recordSync(e, 0, 0, err)
		return 0, 0, Collection{}, err
	}
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	if st != nil {
		if err := st.saveConnectorSync(ctx, collection, docs, next); err != nil {
			err = fmt.Errorf("ingest: persist connector %q: %w", collection, err)
			s.recordSync(e, 0, 0, err)
			return 0, 0, Collection{}, err
		}
		if err := st.saveCollection(ctx, col); err != nil {
			err = fmt.Errorf("ingest: persist %q: %w", collection, err)
			s.recordSync(e, 0, 0, err)
			return 0, 0, Collection{}, err
		}
	}
	s.mu.Lock()
	e.docs, e.cursor = docs, next
	s.collections[collection] = col
	s.mu.Unlock()
	s.recordSync(e, len(changed), len(gone), nil)
	return len(changed), len(gone), col, nil
}

// recordSync stamps a sync outcome onto the entry's status row (console health).
func (s *Subsystem) recordSync(e *connectorEntry, changed, gone int, err error) {
	s.mu.Lock()
	e.lastSync = time.Now()
	e.lastChanged, e.lastGone = changed, gone
	if err != nil {
		e.lastErr = err.Error()
	} else {
		e.lastErr = ""
	}
	s.mu.Unlock()
	atomic.StoreInt32(&e.syncing, 0)
}

// HasConnector reports whether a collection is connector-backed (Ingest routes it to SyncConnector).
func (s *Subsystem) HasConnector(collection string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.connectors[collection]
	return ok
}

// buildConnectorCollection renders the doc set as a classified, lineage-recorded collection
// (deterministic: docs sorted by id; sentence-chunked like built-in corpora; classification =
// max(per-doc source floor, content scan) — D-09).
func (s *Subsystem) buildConnectorCollection(collection, connector string, docs map[string]ConnectorDoc) Collection {
	ids := make([]string, 0, len(docs))
	for id := range docs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	col := Collection{Name: collection, Connector: connector}
	chunkID := 0
	for _, id := range ids {
		d := docs[id]
		class := classify(d.Text, d.SrcClass)
		format := d.Format
		if format == "" {
			format = "text"
		}
		for _, dc := range chunkDoc(d.ID, d.Text) {
			chunkID++
			col.Chunks = append(col.Chunks, Chunk{
				ID: fmt.Sprintf("%s#%d", collection, chunkID), DocID: collection + "/" + d.ID,
				Section: dc.Section, Text: dc.Text, Classification: class, Source: connector, Format: format,
			})
		}
	}
	return col
}

// fetch downloads one blob's text.
func (c *AzureBlobConnector) fetch(ctx context.Context, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ContainerURL+"/"+name+"?"+c.SAS, nil)
	if err != nil {
		return "", fmt.Errorf("azblob connector: %w", err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("azblob connector: get %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("azblob connector: get %s: HTTP %d", name, resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("azblob connector: read %s: %w", name, err)
	}
	return string(data), nil
}
