package ingest

// SharePointConnector — D-C1 slice 1 (floor-by-container, approved 2026-07-11): one DANI collection
// per SharePoint SITE; the operator sets the classification floor at connect time (plus optional
// folder-prefix floors inside the library, same classmap dialect as every other connector). SDK-free
// Microsoft Graph REST, credentialed by an app registration with the least-privilege Sites.Selected
// grant; INCREMENTAL via Graph delta queries (the cursor is the deltaLink — after the first crawl
// only changes travel).
//
// Permission fidelity (the honest slice-1 contract): the floor covers the WHOLE library, so pick it
// for the most sensitive document the site holds -- every file in the library is indexed at that
// floor. Detecting genuine broken-inheritance items (to skip or raise them) needs SharePoint's
// hasUniqueRoleAssignments; that, and full ACL-derived floors, are D-C1 option 2 (CONNECTORS-DESIGN.md).
// (Graph's `shared` facet is NOT that signal -- every item in a SharePoint library carries it.)

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"dani.local/agent/internal/extract"
)

// SharePointConnector crawls one site's default document library.
type SharePointConnector struct {
	SiteURL      string // https://contoso.sharepoint.com/sites/engineering
	Tenant       string // AAD tenant id (or domain)
	ClientID     string // app registration (Sites.Selected granted to this site)
	Secret       string // client secret — resolved by the caller, never logged
	ClassMap     map[string]string
	DefaultClass string
	MaxFileBytes int64 // per-file cap (default 4 MiB)

	GraphBase string       // test seam ("" = https://graph.microsoft.com/v1.0)
	LoginBase string       // test seam ("" = https://login.microsoftonline.com)
	HTTP      *http.Client // test seam; nil = 60s default

	mu     sync.Mutex
	token  string
	expiry time.Time
	siteID string
}

func (c *SharePointConnector) Name() string { return "sharepoint" }

func (c *SharePointConnector) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *SharePointConnector) graph() string {
	if c.GraphBase != "" {
		return strings.TrimSuffix(c.GraphBase, "/")
	}
	return "https://graph.microsoft.com/v1.0"
}

func (c *SharePointConnector) login() string {
	if c.LoginBase != "" {
		return strings.TrimSuffix(c.LoginBase, "/")
	}
	return "https://login.microsoftonline.com"
}

// bearer returns a cached client-credentials token, refreshing when within a minute of expiry.
func (c *SharePointConnector) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expiry) > time.Minute {
		return c.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {c.Secret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.login()+"/"+url.PathEscape(c.Tenant)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("sharepoint: token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sharepoint: token HTTP %d (check tenant/client id/secret)", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("sharepoint: token decode failed")
	}
	c.token = tok.AccessToken
	c.expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return c.token, nil
}

// get performs an authorized Graph GET.
func (c *SharePointConnector) get(ctx context.Context, u string) (*http.Response, error) {
	tok, err := c.bearer(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return c.client().Do(req)
}

// ResolveSite turns the operator's site URL into a Graph site id (also the Probe path).
func (c *SharePointConnector) ResolveSite(ctx context.Context) (id, display string, err error) {
	c.mu.Lock()
	cached := c.siteID
	c.mu.Unlock()
	if cached != "" {
		return cached, "", nil
	}
	u, err := url.Parse(c.SiteURL)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("sharepoint: site URL %q is not a valid https URL", c.SiteURL)
	}
	resp, err := c.get(ctx, c.graph()+"/sites/"+u.Host+":"+strings.TrimSuffix(u.Path, "/"))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("sharepoint: site resolve HTTP %d (is Sites.Selected granted for this site?)", resp.StatusCode)
	}
	var site struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&site); err != nil || site.ID == "" {
		return "", "", fmt.Errorf("sharepoint: site resolve decode failed")
	}
	c.mu.Lock()
	c.siteID = site.ID
	c.mu.Unlock()
	return site.ID, site.DisplayName, nil
}

// deltaItem is the slice of a Graph driveItem the connector needs.
type deltaItem struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	ETag    string          `json:"eTag"`
	Size    int64           `json:"size"`
	File    json.RawMessage `json:"file"`    // present for files
	Deleted json.RawMessage `json:"deleted"` // present when the item is gone
	Parent  struct {
		Path string `json:"path"` // ".../root:/sub/folder"
	} `json:"parentReference"`
}

// relPath renders the library-relative document path ("sub/folder/plan.docx").
func (it deltaItem) relPath() string {
	p := it.Parent.Path
	if i := strings.Index(p, "root:"); i >= 0 {
		p = strings.TrimPrefix(p[i+len("root:"):], "/")
	} else {
		p = ""
	}
	if p == "" {
		return it.Name
	}
	return p + "/" + it.Name
}

// Sync walks the delta feed. The cursor holds "__delta" (the deltaLink) plus id→docID mappings so
// deletions (which arrive as bare ids) can name the doc they remove.
func (c *SharePointConnector) Sync(ctx context.Context, state map[string]string) ([]ConnectorDoc, []string, map[string]string, error) {
	maxBytes := c.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	siteID, _, err := c.ResolveSite(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	next := make(map[string]string, len(state))
	for k, v := range state {
		next[k] = v
	}
	u := state["__delta"]
	if u == "" {
		u = c.graph() + "/sites/" + siteID + "/drive/root/delta"
	}
	var changed []ConnectorDoc
	var gone []string
	for u != "" {
		resp, err := c.get(ctx, u)
		if err != nil {
			return nil, nil, nil, err
		}
		if resp.StatusCode == http.StatusGone { // Graph expired the delta token — full resync
			resp.Body.Close()
			u = c.graph() + "/sites/" + siteID + "/drive/root/delta"
			next = map[string]string{}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, nil, nil, fmt.Errorf("sharepoint: delta HTTP %d", resp.StatusCode)
		}
		var page struct {
			Value     []deltaItem `json:"value"`
			NextLink  string      `json:"@odata.nextLink"`
			DeltaLink string      `json:"@odata.deltaLink"`
		}
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sharepoint: delta decode: %w", err)
		}
		for _, it := range page.Value {
			key := "id:" + it.ID
			if it.Deleted != nil {
				if docID, ok := next[key]; ok {
					gone = append(gone, docID)
					delete(next, key)
				}
				continue
			}
			if it.File == nil || !extract.Supported(it.Name) || it.Size > maxBytes {
				continue
			}
			// D-C1 floor-by-container: the operator's floor covers the WHOLE library, so every file
			// is indexed at that floor. (The `shared` facet is NOT a valid "unique permissions"
			// signal — every item in a SharePoint library carries it; detecting genuine broken
			// inheritance needs SharePoint's hasUniqueRoleAssignments, a documented future refinement.)
			docID := it.relPath()
			data, err := c.fetchItem(ctx, siteID, it.ID)
			if err != nil {
				continue // one bad item must not poison the sync; delta re-offers it next time
			}
			extracted, format, err := extract.Extract(it.Name, []byte(data))
			if err != nil {
				continue // undecodable content (scanned PDF etc.) — skip, not fatal
			}
			changed = append(changed, ConnectorDoc{
				ID: docID, Text: extracted, Format: format,
				SrcClass: classForPrefix(docID, c.ClassMap, c.DefaultClass),
			})
			next[key] = docID
		}
		if page.NextLink != "" {
			u = page.NextLink
			continue
		}
		if page.DeltaLink != "" {
			next["__delta"] = page.DeltaLink
		}
		u = ""
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i].ID < changed[j].ID })
	sort.Strings(gone)
	return changed, gone, next, nil
}

// fetchItem downloads one driveItem's raw content (Graph 302s to a pre-authorized URL; the client
// follows it).
func (c *SharePointConnector) fetchItem(ctx context.Context, siteID, itemID string) (string, error) {
	resp, err := c.get(ctx, c.graph()+"/sites/"+siteID+"/drive/items/"+itemID+"/content")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sharepoint: content HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
