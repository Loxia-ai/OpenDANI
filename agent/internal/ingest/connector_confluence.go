package ingest

// ConfluenceConnector — D-C1 slice 1 (floor-by-container): one DANI collection per Confluence SPACE;
// the operator sets the classification floor at connect time (plus optional title-prefix floors, the
// same classmap dialect as every other connector). SDK-free Confluence Cloud REST, credentialed by an
// Atlassian account email + API token (HTTP Basic). Confluence has no delta feed, so change detection
// is per-page VERSION numbers: each sync lists the space's pages (cheap — ids + version numbers) and
// only re-fetches a page's body when its version advanced, so unchanged pages are never re-downloaded;
// pages that dropped out of the listing are reported gone. (Confluence enforces unique page titles
// within a space, so the title is a stable, human-readable document id — good for citations.)
//
// Permission fidelity (the honest slice-1 contract): the floor covers the WHOLE space, exactly like
// SharePoint's floor-by-container — pick it for the most sensitive page the space holds. Per-page
// restriction-derived floors (Confluence content restrictions) are D-C1 option 2 (CONNECTORS-DESIGN.md).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"dani.local/agent/internal/extract"
)

// ConfluenceConnector crawls one space's current pages.
type ConfluenceConnector struct {
	BaseURL      string // https://your-site.atlassian.net/wiki
	Space        string // space key (e.g. "ENG")
	Email        string // Atlassian account email — the Basic-auth identity paired with the token
	Token        string // API token — resolved by the caller, never logged
	ClassMap     map[string]string
	DefaultClass string
	MaxBytes     int64 // per-page cap (default 4 MiB)

	APIBase string       // test seam ("" = BaseURL + /rest/api)
	HTTP    *http.Client // test seam; nil = 60s default
}

func (c *ConfluenceConnector) Name() string { return "confluence" }

func (c *ConfluenceConnector) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *ConfluenceConnector) api() string {
	if c.APIBase != "" {
		return strings.TrimSuffix(c.APIBase, "/")
	}
	return strings.TrimSuffix(c.BaseURL, "/") + "/rest/api"
}

// get performs an authorized Confluence GET (Basic email:token).
func (c *ConfluenceConnector) get(ctx context.Context, u string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Email+":"+c.Token)))
	req.Header.Set("Accept", "application/json")
	return c.client().Do(req)
}

// SpaceName resolves the space key to its display name (also the Probe path — reachability + auth).
func (c *ConfluenceConnector) SpaceName(ctx context.Context) (string, error) {
	resp, err := c.get(ctx, c.api()+"/space/"+url.PathEscape(c.Space))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("confluence: space resolve HTTP %d (check base URL, space key, and email/token)", resp.StatusCode)
	}
	var s struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return "", fmt.Errorf("confluence: space resolve decode failed")
	}
	return s.Name, nil
}

// Sync lists the space's current pages and re-fetches only those whose version advanced. The cursor
// maps "id:<pageID>" -> "<version>|<docID>" so an unchanged page is skipped and a vanished page can
// name the doc it removes.
func (c *ConfluenceConnector) Sync(ctx context.Context, state map[string]string) ([]ConnectorDoc, []string, map[string]string, error) {
	maxBytes := c.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	next := make(map[string]string, len(state))
	for k, v := range state {
		next[k] = v
	}
	seen := make(map[string]bool)
	var changed []ConnectorDoc

	const limit = 100
	for start := 0; ; start += limit {
		u := fmt.Sprintf("%s/content?spaceKey=%s&type=page&status=current&expand=version&limit=%d&start=%d",
			c.api(), url.QueryEscape(c.Space), limit, start)
		resp, err := c.get(ctx, u)
		if err != nil {
			return nil, nil, nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, nil, nil, fmt.Errorf("confluence: list HTTP %d", resp.StatusCode)
		}
		var pg struct {
			Results []struct {
				ID      string `json:"id"`
				Title   string `json:"title"`
				Version struct {
					Number int `json:"number"`
				} `json:"version"`
			} `json:"results"`
			Size int `json:"size"`
		}
		err = json.NewDecoder(resp.Body).Decode(&pg)
		resp.Body.Close()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("confluence: list decode: %w", err)
		}
		for _, p := range pg.Results {
			key := "id:" + p.ID
			seen[key] = true
			docID := p.Title
			if docID == "" {
				docID = p.ID
			}
			verKey := strconv.Itoa(p.Version.Number) + "|" + docID
			if next[key] == verKey {
				continue // unchanged since last sync — body not re-fetched
			}
			body, err := c.fetchBody(ctx, p.ID)
			if err != nil || int64(len(body)) > maxBytes {
				continue // transient/oversized — delta re-offers it next sync
			}
			text, format, err := extract.Extract(docID+".html", []byte(body)) // storage format is XHTML
			if err != nil {
				continue
			}
			changed = append(changed, ConnectorDoc{
				ID: docID, Text: text, Format: format,
				SrcClass: classForPrefix(docID, c.ClassMap, c.DefaultClass),
			})
			next[key] = verKey
		}
		if pg.Size < limit {
			break
		}
	}

	// deletions: a page we tracked that no longer appears in the space listing
	var gone []string
	for key, val := range state {
		if !strings.HasPrefix(key, "id:") || seen[key] {
			continue
		}
		docID := val
		if i := strings.IndexByte(val, '|'); i >= 0 {
			docID = val[i+1:]
		}
		gone = append(gone, docID)
		delete(next, key)
	}

	sort.Slice(changed, func(i, j int) bool { return changed[i].ID < changed[j].ID })
	sort.Strings(gone)
	return changed, gone, next, nil
}

// fetchBody downloads one page's storage-format (XHTML) body.
func (c *ConfluenceConnector) fetchBody(ctx context.Context, id string) (string, error) {
	resp, err := c.get(ctx, c.api()+"/content/"+url.PathEscape(id)+"?expand=body.storage")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("confluence: body HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Body struct {
			Storage struct {
				Value string `json:"value"`
			} `json:"storage"`
		} `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("confluence: body decode: %w", err)
	}
	return doc.Body.Storage.Value, nil
}
