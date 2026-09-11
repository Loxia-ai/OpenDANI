package artifact

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// BlobBackend stores artifacts in an Azure Blob container addressed by a container SAS URL. Each blob
// is PUT/GET/HEAD at <ContainerURL>/<name>?<SAS>. No SDK and NO account key in DANI — only the scoped,
// time-limited SAS the operator provisions. This makes artifacts reachable by EVERY controller/worker
// in an HA deployment, so a follower controller (D-18) can serve a replicated model's bytes.
type BlobBackend struct {
	Client       *http.Client // mTLS/HTTPS client (defaults to http.DefaultClient)
	ContainerURL string       // e.g. https://acct.blob.core.windows.net/artifacts (no trailing slash)
	SAS          string       // SAS query WITHOUT the leading '?' (sv=...&sig=...)
}

func (b *BlobBackend) client() *http.Client {
	if b.Client != nil {
		return b.Client
	}
	return http.DefaultClient
}

func (b *BlobBackend) url(name string) string {
	return strings.TrimRight(b.ContainerURL, "/") + "/" + name + "?" + b.SAS
}

// Put uploads data as a block blob (idempotent — content-addressed names dedupe; re-PUT overwrites
// identical bytes).
func (b *BlobBackend) Put(name string, data []byte) error {
	req, err := http.NewRequest(http.MethodPut, b.url(name), bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(data))
	resp, err := b.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("artifact/blob: PUT %s: HTTP %d: %s", name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Get downloads a blob's bytes (Store verifies the hash).
func (b *BlobBackend) Get(name string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, b.url(name), nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("artifact/blob: GET %s: HTTP %d", name, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// Has reports whether the blob exists (HEAD).
func (b *BlobBackend) Has(name string) bool {
	req, err := http.NewRequest(http.MethodHead, b.url(name), nil)
	if err != nil {
		return false
	}
	resp, err := b.client().Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// LocalPath is never local for a blob backend — Store materializes into its cache dir.
func (b *BlobBackend) LocalPath(string) (string, bool) { return "", false }

// OpenSpec builds a Store from an operator spec, materializing remote blobs into cacheDir for Path():
//
//	""  or  fs:<dir>  or  <dir>     local filesystem (DEMO default)
//	azblob:<containerURL>?<sas>     Azure Blob container via SAS URL
//
// fsDefault is the filesystem dir used for the fs backend and as the remote cache dir.
func OpenSpec(spec, fsDefault string) (*Store, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "" || spec == "fs" || spec == "fs:":
		return Open(fsDefault)
	case strings.HasPrefix(spec, "fs:"):
		return Open(strings.TrimPrefix(spec, "fs:"))
	case strings.HasPrefix(spec, "azblob:"):
		raw := strings.TrimPrefix(spec, "azblob:")
		i := strings.Index(raw, "?")
		if i < 0 || i == len(raw)-1 {
			return nil, fmt.Errorf("artifact: azblob spec needs <containerURL>?<sas>")
		}
		return OpenWith(&BlobBackend{ContainerURL: raw[:i], SAS: raw[i+1:]}, fsDefault)
	default:
		return nil, fmt.Errorf("artifact: unknown store spec %q (want fs:<dir> | azblob:<url>?<sas>)", spec)
	}
}
