package modelreg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// RemoteRoleSigner is a RoleSigner whose PRIVATE KEY LIVES OUTSIDE DANI — the faithful production
// shape of "each officer's key in their own HSM / cloud-KMS" (ROADMAP §2). DANI never holds the key;
// it signs by CALLING the officer's signing service over mTLS/HTTP. This is exactly the property the
// KeyStore contract promises for the HSM tier ("the bytes never enter DANI memory"), realized at the
// reviewer-signer seam so it composes with the three-party control from D-19.
//
// The officer's service implements a tiny contract:
//
//	GET  <base>/public          -> 200 {"pub": "<base64 SPKI DER public key>"}
//	POST <base>/sign  {"payload":"<b64>"} -> 200 {"sig": "<base64 signature>"}
//
// Both operations are fail-closed: any transport / status / decode error returns an error, which
// fails the Sign in the registry — a reachable-but-unauthorized officer cannot silently be skipped.
type RemoteRoleSigner struct {
	Client  *http.Client // mTLS client to the officer's signer (defaults to http.DefaultClient)
	BaseURL string       // the officer's signing service base URL
}

func (r RemoteRoleSigner) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return http.DefaultClient
}

// Public fetches the officer's public key (SPKI DER) from the signing service.
func (r RemoteRoleSigner) Public(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.BaseURL+"/public", nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("modelreg: remote signer %s: /public HTTP %d", r.BaseURL, resp.StatusCode)
	}
	var out struct {
		Pub string `json:"pub"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, fmt.Errorf("modelreg: remote signer %s: bad /public body: %w", r.BaseURL, err)
	}
	pub, err := base64.StdEncoding.DecodeString(out.Pub)
	if err != nil {
		return nil, fmt.Errorf("modelreg: remote signer %s: bad pub base64: %w", r.BaseURL, err)
	}
	return pub, nil
}

// Sign asks the officer's signing service to sign payload with its (external) private key.
func (r RemoteRoleSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	body, _ := json.Marshal(map[string]string{"payload": base64.StdEncoding.EncodeToString(payload)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+"/sign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("modelreg: remote signer %s: /sign HTTP %d", r.BaseURL, resp.StatusCode)
	}
	var out struct {
		Sig string `json:"sig"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return nil, fmt.Errorf("modelreg: remote signer %s: bad /sign body: %w", r.BaseURL, err)
	}
	sig, err := base64.StdEncoding.DecodeString(out.Sig)
	if err != nil {
		return nil, fmt.Errorf("modelreg: remote signer %s: bad sig base64: %w", r.BaseURL, err)
	}
	return sig, nil
}
