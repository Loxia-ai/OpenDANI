package ingest

// Console-connected sources ("Connect a source"): a ConnectorDef is a connector AS DATA — created
// through the governed API, persisted in the ingest store, rehydrated at boot, disconnectable —
// so an operator wires a folder/share, a git repo, or a blob container into DANI from the console:
// no flags, no SSH, no restart. Flag-configured connectors coexist and appear in the same list,
// marked static (they live in the process invocation, so the console cannot remove them).

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"dani.local/agent/internal/extract"
)

// ConnectorDef describes one source. Secret is write-only through the API (redacted on every read);
// it lands in the controller's protected state store.
type ConnectorDef struct {
	Kind         string            `json:"kind"` // folder | git | azblob | sharepoint | confluence | jdbc
	Collection   string            `json:"collection"`
	Path         string            `json:"path,omitempty"`   // folder: directory / mounted share
	URL          string            `json:"url,omitempty"`    // git: clone URL · azblob: container URL · sharepoint: site · confluence: base (…/wiki)
	Ref          string            `json:"ref,omitempty"`    // git: branch/tag ("" = default branch)
	Tenant       string            `json:"tenant,omitempty"`   // sharepoint: AAD tenant id/domain
	ClientID     string            `json:"clientId,omitempty"` // sharepoint: app registration (Sites.Selected)
	Space        string            `json:"space,omitempty"`    // confluence: space key
	Email        string            `json:"email,omitempty"`    // confluence: Atlassian account email (Basic auth with the token)
	Query        string            `json:"query,omitempty"`    // jdbc: SELECT — first column is the doc id, all columns become the text
	Secret       string            `json:"secret,omitempty"` // git token / azblob SAS / sharepoint|confluence secret / jdbc DSN — WRITE-ONLY
	ClassMap     map[string]string `json:"classMap,omitempty"`
	DefaultClass string            `json:"defaultClass,omitempty"` // floor when no prefix matches (default internal)
	SyncEvery    time.Duration     `json:"syncEvery,omitempty"`    // 0 = boot + manual sync only
	Static       bool              `json:"static,omitempty"`       // configured by flags — not persisted, not removable
}

// Validate rejects an unusable def before anything registers.
func (d ConnectorDef) Validate() error {
	if d.Collection == "" {
		return fmt.Errorf("connector needs a collection name")
	}
	switch d.Kind {
	case "folder":
		if d.Path == "" {
			return fmt.Errorf("folder connector needs a path")
		}
	case "git":
		if d.URL == "" {
			return fmt.Errorf("git connector needs a clone URL")
		}
	case "azblob":
		if d.URL == "" {
			return fmt.Errorf("azblob connector needs a container URL")
		}
		if d.Secret == "" {
			return fmt.Errorf("azblob connector needs a SAS")
		}
	case "sharepoint":
		if d.URL == "" || d.Tenant == "" || d.ClientID == "" || d.Secret == "" {
			return fmt.Errorf("sharepoint connector needs a site URL, tenant, client id and client secret (Sites.Selected)")
		}
	case "confluence":
		if d.URL == "" || d.Space == "" || d.Email == "" || d.Secret == "" {
			return fmt.Errorf("confluence connector needs a base URL (…/wiki), space key, account email and API token")
		}
	case "jdbc":
		if d.Secret == "" || d.Query == "" {
			return fmt.Errorf("jdbc connector needs a connection string (DSN) and a SELECT query")
		}
	default:
		return fmt.Errorf("unknown connector kind %q (folder | git | azblob | sharepoint | confluence | jdbc)", d.Kind)
	}
	for _, class := range d.ClassMap {
		if !validClass(class) {
			return fmt.Errorf("classification %q is not one of unrestricted|internal|restricted|secret", class)
		}
	}
	if d.DefaultClass != "" && !validClass(d.DefaultClass) {
		return fmt.Errorf("default classification %q is not one of unrestricted|internal|restricted|secret", d.DefaultClass)
	}
	return nil
}

func validClass(c string) bool {
	switch c {
	case "unrestricted", "internal", "restricted", "secret":
		return true
	}
	return false
}

// Redacted returns the def safe for any read path: the secret never leaves the controller.
func (d ConnectorDef) Redacted() ConnectorDef {
	if d.Secret != "" {
		d.Secret = "•redacted•"
	}
	return d
}

// buildConnector constructs the live connector for a def.
func (s *Subsystem) buildConnector(d ConnectorDef) (Connector, error) {
	switch d.Kind {
	case "folder":
		return &FolderConnector{Root: d.Path, ClassMap: d.ClassMap, DefaultClass: d.DefaultClass}, nil
	case "git":
		root := s.gitCacheRoot
		if root == "" {
			root = os.TempDir()
		}
		return &GitConnector{URL: d.URL, Ref: d.Ref, Token: d.Secret,
			CacheDir: filepath.Join(root, "git-cache", d.Collection), ClassMap: d.ClassMap, DefaultClass: d.DefaultClass}, nil
	case "azblob":
		return &AzureBlobConnector{ContainerURL: d.URL, SAS: d.Secret, ClassMap: d.ClassMap, DefaultClass: d.DefaultClass}, nil
	case "sharepoint":
		return &SharePointConnector{SiteURL: d.URL, Tenant: d.Tenant, ClientID: d.ClientID, Secret: d.Secret,
			ClassMap: d.ClassMap, DefaultClass: d.DefaultClass}, nil
	case "confluence":
		return &ConfluenceConnector{BaseURL: d.URL, Space: d.Space, Email: d.Email, Token: d.Secret,
			ClassMap: d.ClassMap, DefaultClass: d.DefaultClass}, nil
	case "jdbc":
		return &JDBCConnector{DSN: d.Secret, Query: d.Query, ClassMap: d.ClassMap, DefaultClass: d.DefaultClass}, nil
	}
	return nil, fmt.Errorf("unknown connector kind %q", d.Kind)
}

// SetGitCacheRoot points git working clones at the controller state dir (call once at boot).
func (s *Subsystem) SetGitCacheRoot(dir string) { s.gitCacheRoot = dir }

// ---- probe (the console's "Test connection" — reachability before commitment) ----

// Probe dry-runs a def without registering anything: is the source reachable, and roughly how many
// supported files does it hold?
func (s *Subsystem) Probe(ctx context.Context, d ConnectorDef) (files int, detail string, err error) {
	if err := d.Validate(); err != nil {
		return 0, "", err
	}
	switch d.Kind {
	case "folder":
		fi, err := os.Stat(d.Path)
		if err != nil || !fi.IsDir() {
			return 0, "", fmt.Errorf("%q is not a readable directory on the controller", d.Path)
		}
		n := 0
		_ = filepath.WalkDir(d.Path, func(path string, de os.DirEntry, err error) error {
			if err != nil || n >= 5000 {
				return filepath.SkipAll
			}
			if de.IsDir() {
				if strings.HasPrefix(de.Name(), ".") && path != d.Path {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasPrefix(de.Name(), ".") && extract.Supported(de.Name()) {
				n++
			}
			return nil
		})
		return n, fmt.Sprintf("directory reachable — %d supported file(s)", n), nil
	case "git":
		if _, err := exec.LookPath("git"); err != nil {
			return 0, "", fmt.Errorf("the git binary is not installed on this controller")
		}
		gc := &GitConnector{URL: d.URL, Token: d.Secret}
		ref := d.Ref
		if ref == "" {
			ref = "HEAD"
		}
		cmd := exec.CommandContext(ctx, "git", "ls-remote", gc.authURL(), ref)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return 0, "", fmt.Errorf("repository unreachable: %s", redactToken(tail(string(out), 200), d.Secret))
		}
		if strings.TrimSpace(string(out)) == "" {
			return 0, "", fmt.Errorf("ref %q not found in the repository", ref)
		}
		return 0, "repository reachable — ref resolves", nil
	case "azblob":
		ac := &AzureBlobConnector{ContainerURL: d.URL, SAS: d.Secret}
		changed, _, _, err := ac.Sync(ctx, nil) // one list+fetch pass IS the probe for a container
		if err != nil {
			return 0, "", err
		}
		return len(changed), fmt.Sprintf("container reachable — %d blob(s)", len(changed)), nil
	case "sharepoint":
		sp := &SharePointConnector{SiteURL: d.URL, Tenant: d.Tenant, ClientID: d.ClientID, Secret: d.Secret}
		_, display, err := sp.ResolveSite(ctx)
		if err != nil {
			return 0, "", err
		}
		if display == "" {
			display = "site"
		}
		return 0, fmt.Sprintf("site reachable — %s (Sites.Selected verified)", display), nil
	case "confluence":
		cf := &ConfluenceConnector{BaseURL: d.URL, Space: d.Space, Email: d.Email, Token: d.Secret}
		name, err := cf.SpaceName(ctx)
		if err != nil {
			return 0, "", err
		}
		if name == "" {
			name = d.Space
		}
		return 0, fmt.Sprintf("space reachable — %s (email/token verified)", name), nil
	case "jdbc":
		jc := &JDBCConnector{DSN: d.Secret, Query: d.Query}
		changed, _, _, err := jc.Sync(ctx, nil) // one query pass IS the probe for a result set
		if err != nil {
			return 0, "", err
		}
		return len(changed), fmt.Sprintf("database reachable — query returns %d row(s)", len(changed)), nil
	}
	return 0, "", fmt.Errorf("unknown connector kind %q", d.Kind)
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// ---- lifecycle: connect / disconnect / list, with per-source sync loops and status ----

// ConnectorStatus is one row of the console's Connected-sources card.
type ConnectorStatus struct {
	Def         ConnectorDef `json:"def"` // ALWAYS redacted by the caller-facing paths
	Docs        int          `json:"docs"`
	Chunks      int          `json:"chunks"`
	LastSync    time.Time    `json:"lastSync"`
	LastError   string       `json:"lastError,omitempty"`
	LastChanged int          `json:"lastChanged"`
	LastGone    int          `json:"lastGone"`
	Syncing     bool         `json:"syncing"`
}

// StartConnector validates, registers, persists (unless static) and starts the sync lifecycle for a
// def — the one entry point used by the console API, flag wiring, and boot rehydration alike.
// The first sync runs asynchronously; its outcome lands in the status row.
func (s *Subsystem) StartConnector(ctx context.Context, d ConnectorDef) error {
	if err := d.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	if _, exists := s.defs[d.Collection]; exists {
		s.mu.Unlock()
		return fmt.Errorf("a source named %q is already connected — disconnect it first or pick another collection name", d.Collection)
	}
	s.mu.Unlock()
	if d.DefaultClass == "" {
		d.DefaultClass = "internal"
	}
	conn, err := s.buildConnector(d)
	if err != nil {
		return err
	}
	if err := s.RegisterConnector(d.Collection, conn); err != nil {
		return err
	}
	s.mu.Lock()
	if !d.Static && s.store != nil {
		if err := s.store.saveConnectorDef(ctx, d); err != nil {
			delete(s.connectors, d.Collection) // roll the registration back — durable-first
			s.mu.Unlock()
			return err
		}
	}
	if s.defs == nil {
		s.defs = map[string]ConnectorDef{}
	}
	s.defs[d.Collection] = d
	loopCtx, cancel := context.WithCancel(context.Background())
	if s.syncCancel == nil {
		s.syncCancel = map[string]context.CancelFunc{}
	}
	s.syncCancel[d.Collection] = cancel
	s.mu.Unlock()

	go func() {
		syncOnce := func() {
			if _, _, _, err := s.SyncConnector(loopCtx, d.Collection); err != nil && loopCtx.Err() == nil {
				// the error is recorded on the status row by SyncConnector; nothing else to do
				_ = err
			}
		}
		syncOnce()
		if d.SyncEvery > 0 {
			t := time.NewTicker(d.SyncEvery)
			defer t.Stop()
			for {
				select {
				case <-loopCtx.Done():
					return
				case <-t.C:
					syncOnce()
				}
			}
		}
	}()
	return nil
}

// RemoveConnector disconnects a console-defined source: stops its loop, forgets the connector, and
// drops the synced data (the chunks came FROM the source — disconnect removes them, audited by the
// API layer). Static (flag-configured) connectors are refused.
func (s *Subsystem) RemoveConnector(ctx context.Context, collection string) error {
	s.mu.Lock()
	def, ok := s.defs[collection]
	if ok && def.Static {
		s.mu.Unlock()
		return fmt.Errorf("%q is configured by controller flags — remove the flag to disconnect it", collection)
	}
	if _, registered := s.connectors[collection]; !registered {
		s.mu.Unlock()
		return fmt.Errorf("no connected source named %q", collection)
	}
	if cancel := s.syncCancel[collection]; cancel != nil {
		cancel()
		delete(s.syncCancel, collection)
	}
	delete(s.connectors, collection)
	delete(s.defs, collection)
	delete(s.collections, collection)
	st := s.store
	s.mu.Unlock()
	if st != nil {
		return st.deleteConnectorDef(ctx, collection)
	}
	return nil
}

// RehydrateConnectors restarts every persisted console-defined connector (boot path; call after
// WithStore). Each resumes from its durable incremental cursor.
func (s *Subsystem) RehydrateConnectors(ctx context.Context) (int, error) {
	s.mu.Lock()
	st := s.store
	s.mu.Unlock()
	if st == nil {
		return 0, nil
	}
	defs, err := st.loadConnectorDefs(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range defs {
		if err := s.StartConnector(ctx, d); err != nil {
			return n, fmt.Errorf("rehydrate connector %q: %w", d.Collection, err)
		}
		n++
	}
	return n, nil
}

// ListConnectors returns every connected source with live status, secrets redacted, stable order.
func (s *Subsystem) ListConnectors() []ConnectorStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ConnectorStatus, 0, len(s.defs))
	for name, d := range s.defs {
		st := ConnectorStatus{Def: d.Redacted()}
		if e := s.connectors[name]; e != nil {
			st.Docs = len(e.docs)
			st.LastSync = e.lastSync
			st.LastError = e.lastErr
			st.LastChanged, st.LastGone = e.lastChanged, e.lastGone
			st.Syncing = atomic.LoadInt32(&e.syncing) == 1
		}
		if col, ok := s.collections[name]; ok {
			st.Chunks = len(col.Chunks)
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Def.Collection < out[j].Def.Collection })
	return out
}
