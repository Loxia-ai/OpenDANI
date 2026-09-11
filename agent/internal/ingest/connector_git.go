package ingest

// GitConnector: RAG over a repository. Clones (shallow) into a cache dir, then each sync fetches
// and diffs — the cursor holds the HEAD commit plus every file's git BLOB hash, so an unchanged
// file is never re-read and a push updates exactly what changed. Files go through the extract
// layer (code + md + html + pdf + docx), classification floors map by path prefix
// ("docs/internal/=internal,ops/=restricted"), and every doc records the commit it came from —
// citations carry file@commit lineage.
//
// SECURITY: the repo is DATA, never executed (no hooks, no checkout scripts: git is invoked with
// core.hooksPath=/dev/null and terminal prompts off). A token, when needed, is injected into the
// fetch URL in-memory and NEVER logged.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"dani.local/agent/internal/extract"
)

// GitConnector crawls one repository ref.
type GitConnector struct {
	URL          string            // https clone URL (https://github.com/org/repo.git)
	Ref          string            // branch/tag to track ("" = the remote default branch)
	Token        string            // optional bearer for private repos — resolved from a secret ref by the caller, never logged
	CacheDir     string            // where the working clone lives (under the controller state dir)
	ClassMap     map[string]string // path prefix -> classification floor (longest match wins)
	DefaultClass string            // floor when no prefix matches (default "internal")
	MaxFileBytes int64             // per-file cap (default 4 MiB)
}

func (c *GitConnector) Name() string { return "git" }

// authURL injects the token into the clone URL (in-memory only).
func (c *GitConnector) authURL() string {
	if c.Token == "" {
		return c.URL
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return c.URL
	}
	u.User = url.UserPassword("x-access-token", c.Token)
	return u.String()
}

// git runs one git command against the cache clone with hooks and prompts disabled.
func (c *GitConnector) git(ctx context.Context, args ...string) (string, error) {
	full := append([]string{"-c", "core.hooksPath=/dev/null"}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = c.CacheDir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// never echo the command line (it can carry the token) — only the tail of git's own output
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		return "", fmt.Errorf("git %s: %s", args[0], redactToken(msg, c.Token))
	}
	return strings.TrimSpace(string(out)), nil
}

func redactToken(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "***")
}

// Sync clones on first run, fetches after, and returns exactly the files whose blob hash changed.
func (c *GitConnector) Sync(ctx context.Context, state map[string]string) ([]ConnectorDoc, []string, map[string]string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, nil, nil, fmt.Errorf("git connector: the git binary is not installed on this controller")
	}
	maxBytes := c.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	if err := os.MkdirAll(c.CacheDir, 0o700); err != nil {
		return nil, nil, nil, fmt.Errorf("git connector: %w", err)
	}
	if _, err := os.Stat(filepath.Join(c.CacheDir, ".git")); err != nil { // first run: shallow clone
		args := []string{"clone", "--depth", "1", "--no-tags"}
		if c.Ref != "" {
			args = append(args, "--branch", c.Ref)
		}
		args = append(args, c.authURL(), ".")
		if _, err := c.git(ctx, args...); err != nil {
			return nil, nil, nil, fmt.Errorf("git connector: clone %s: %w", c.URL, err)
		}
	} else { // subsequent runs: fetch the tracked ref and hard-reset the worktree to it
		ref := c.Ref
		if ref == "" {
			ref = "HEAD"
		}
		if _, err := c.git(ctx, "fetch", "--depth", "1", "--no-tags", c.authURL(), ref); err != nil {
			return nil, nil, nil, fmt.Errorf("git connector: fetch: %w", err)
		}
		if _, err := c.git(ctx, "reset", "--hard", "FETCH_HEAD"); err != nil {
			return nil, nil, nil, fmt.Errorf("git connector: reset: %w", err)
		}
	}
	head, err := c.git(ctx, "rev-parse", "HEAD")
	if err != nil {
		return nil, nil, nil, err
	}
	short := head
	if len(short) > 8 {
		short = short[:8]
	}
	// unchanged commit → nothing to do (the cheap early exit)
	if state["__head"] == head {
		next := make(map[string]string, len(state))
		for k, v := range state {
			next[k] = v
		}
		return nil, nil, next, nil
	}
	// per-file blob hashes at HEAD: only files whose BLOB changed are re-read. The cursor value is
	// "blob:commitShort" — each file remembers the commit at which IT last changed, so its doc id
	// (path@commit) can be superseded precisely even when other files changed in between.
	// classic ls-tree output ("<mode> <type> <object>\t<path>") — works on every git version
	// (--format needs ≥2.36, which Ubuntu LTS controllers don't have).
	lsOut, err := c.git(ctx, "ls-tree", "-r", "HEAD")
	if err != nil {
		return nil, nil, nil, err
	}
	next := map[string]string{"__head": head}
	var changed []ConnectorDoc
	var gone []string
	for _, line := range strings.Split(lsOut, "\n") {
		meta, path, ok := strings.Cut(line, "\t")
		if !ok || path == "" || !extract.Supported(path) || strings.HasPrefix(filepath.Base(path), ".") {
			continue
		}
		f := strings.Fields(meta) // mode type object
		if len(f) < 3 || f[1] != "blob" {
			continue
		}
		blob := f[2]
		prevBlob, prevShort, _ := strings.Cut(state[path], ":")
		if prevBlob == blob { // same blob — never re-read; the doc keeps its file@commit id
			next[path] = state[path]
			continue
		}
		full := filepath.Join(c.CacheDir, filepath.FromSlash(path))
		info, err := os.Stat(full)
		if err != nil || info.Size() > maxBytes {
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		text, format, err := extract.Extract(path, data)
		if err != nil {
			continue // undecodable file must not poison the sync
		}
		next[path] = blob + ":" + short
		changed = append(changed, ConnectorDoc{
			ID: path + "@" + short, Text: text, Format: format,
			SrcClass: classForPrefix(path, c.ClassMap, c.DefaultClass),
		})
		if prevShort != "" { // the previous commit's version of this doc is superseded
			gone = append(gone, path+"@"+prevShort)
		}
	}
	// files removed from the repo entirely
	for key, val := range state {
		if key == "__head" {
			continue
		}
		if _, still := next[key]; !still {
			if _, prevShort, ok := strings.Cut(val, ":"); ok {
				gone = append(gone, key+"@"+prevShort)
			}
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i].ID < changed[j].ID })
	sort.Strings(gone)
	return changed, gone, next, nil
}
