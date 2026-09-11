package ingest

// GitConnector tests run against a REAL local repository built with the git CLI (skipped cleanly
// where git isn't installed): clone, incremental commit, per-file supersede lineage, deletion.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestGitConnectorSync(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	// build the upstream repo
	upstream := t.TempDir()
	gitCmd(t, upstream, "init", "-b", "main", ".")
	writeFile(t, upstream, "docs/policy.md", "Deployments require three signatures.")
	writeFile(t, upstream, "ops/runbook.md", "Restart the hub before any repair.")
	writeFile(t, upstream, "main.go", "package main // serve the mesh")
	writeFile(t, upstream, "logo.png", "\x89PNG")
	gitCmd(t, upstream, "add", "-A")
	gitCmd(t, upstream, "commit", "-m", "c1")

	c := &GitConnector{
		URL: upstream, CacheDir: filepath.Join(t.TempDir(), "clone"),
		ClassMap: map[string]string{"ops/": "restricted"}, DefaultClass: "internal",
	}
	changed, gone, cursor, err := c.Sync(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 3 || len(gone) != 0 { // png excluded
		t.Fatalf("first sync: %v / %v", ids(changed), gone)
	}
	short1 := shortOf(t, cursor["__head"])
	byID := map[string]ConnectorDoc{}
	for _, d := range changed {
		byID[d.ID] = d
	}
	if d, ok := byID["ops/runbook.md@"+short1]; !ok || d.SrcClass != "restricted" {
		t.Fatalf("ops doc missing or class wrong: %+v", byID)
	}
	if _, ok := byID["main.go@"+short1]; !ok {
		t.Fatalf("source code must be ingested: %v", ids(changed))
	}

	// same HEAD → cheap no-op
	changed, gone, cursor, err = c.Sync(context.Background(), cursor)
	if err != nil || len(changed) != 0 || len(gone) != 0 {
		t.Fatalf("no-op sync: %v/%v %v", changed, gone, err)
	}

	// a new commit: change one file, delete another, add one
	writeFile(t, upstream, "docs/policy.md", "Deployments require three signatures AND a gate.")
	os.Remove(filepath.Join(upstream, "main.go"))
	writeFile(t, upstream, "docs/faq.md", "Ask the mesh.")
	gitCmd(t, upstream, "add", "-A")
	gitCmd(t, upstream, "commit", "-m", "c2")

	changed, gone, cursor2, err := c.Sync(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	short2 := shortOf(t, cursor2["__head"])
	wantChanged := map[string]bool{"docs/policy.md@" + short2: true, "docs/faq.md@" + short2: true}
	if len(changed) != 2 || !wantChanged[changed[0].ID] || !wantChanged[changed[1].ID] {
		t.Fatalf("delta changed: %v", ids(changed))
	}
	// gone: the old policy doc (superseded at its own last-change commit) + the deleted main.go
	wantGone := map[string]bool{"docs/policy.md@" + short1: true, "main.go@" + short1: true}
	if len(gone) != 2 || !wantGone[gone[0]] || !wantGone[gone[1]] {
		t.Fatalf("delta gone: %v (want policy+main @%s)", gone, short1)
	}
	// unchanged file keeps its ORIGINAL commit lineage in the cursor
	if !strings.HasSuffix(cursor2["ops/runbook.md"], ":"+short1) {
		t.Fatalf("unchanged file lost its lineage: %q", cursor2["ops/runbook.md"])
	}
}

func TestGitConnectorMissingRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	c := &GitConnector{URL: filepath.Join(t.TempDir(), "nope"), CacheDir: filepath.Join(t.TempDir(), "clone")}
	if _, _, _, err := c.Sync(context.Background(), nil); err == nil {
		t.Fatal("cloning a missing repo must error")
	}
}

func shortOf(t *testing.T, head string) string {
	t.Helper()
	if head == "" {
		t.Fatal("cursor has no __head")
	}
	if len(head) > 8 {
		return head[:8]
	}
	return head
}
