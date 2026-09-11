package main

// `dani-agent ingest` — the NODE-SIDE ingest agent: push a folder of documents from THIS machine
// into a DANI collection, without the controller needing any access to the box. The complement of
// the controller-side folder connector: there, DANI reaches out to a path it can see; here, any
// machine in the org walks its own files (through the same extract layer — txt/md/code, HTML, PDF,
// DOCX, XLSX) and uploads the text over the gateway. Files never move; only extracted text does,
// classified at ingest with the classification floor you declare.
//
//	dani-agent ingest --path ./contracts --collection contracts-2026 --class restricted \
//	                  --gateway https://dani.corp.internal
//
// Identity: X-Dani-User is stamped from the logged-in OS user (or --user), so the upload is
// attributed in the audit trail like any operator action.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"dani.local/agent/internal/extract"
)

func cmdIngest(args []string) {
	fs2 := flag.NewFlagSet("ingest", flag.ExitOnError)
	path := fs2.String("path", "", "directory to ingest from THIS machine (required)")
	collection := fs2.String("collection", "", "collection name (default: the folder's name)")
	class := fs2.String("class", "internal", "source classification floor: unrestricted|internal|restricted|secret (content scanning can only RAISE it)")
	gateway := fs2.String("gateway", "", "DANI gateway base URL, e.g. https://dani.corp.internal (required)")
	asUser := fs2.String("user", "", "identity for X-Dani-User (default: the logged-in OS user)")
	maxBytes := fs2.Int64("max-file-bytes", 4<<20, "skip files larger than this")
	logJSON := fs2.Bool("log-json", false, "emit structured JSON logs instead of plain lines")
	_ = fs2.Parse(args)
	setupLogging(*logJSON)

	if *path == "" || *gateway == "" {
		fmt.Fprintln(os.Stderr, "ingest: --path and --gateway are required")
		os.Exit(2)
	}
	root, err := filepath.Abs(*path)
	check(err)
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "ingest: %q is not a readable directory\n", root)
		os.Exit(2)
	}
	name := *collection
	if name == "" {
		name = strings.ToLower(strings.ReplaceAll(filepath.Base(root), " ", "-"))
	}
	who := *asUser
	if who == "" {
		who = osUsername()
	}

	// walk + extract locally: only TEXT leaves this machine, each doc prefixed with its relative
	// path so citations point back to the real file.
	var docs []string
	var total int64
	skipped := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") || !extract.Supported(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > *maxBytes {
			skipped++
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			skipped++
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		text, format, err := extract.Extract(rel, data)
		if err != nil {
			logf("ingest: skipping %s: %v", rel, err)
			skipped++
			return nil
		}
		docs = append(docs, "FILE: "+rel+"\n"+text)
		total += int64(len(text))
		logf("ingest: + %s (%s, %d chars)", rel, format, len(text))
		return nil
	})
	check(err)
	if len(docs) == 0 {
		fmt.Fprintln(os.Stderr, "ingest: no supported documents found (txt/md/code, html, pdf, docx, xlsx)")
		os.Exit(1)
	}
	if total > 8<<20 {
		fmt.Fprintf(os.Stderr, "ingest: %d MB of text exceeds the gateway's default 10 MiB request cap — ingest subfolders separately\n", total>>20)
		os.Exit(1)
	}

	body, err := json.Marshal(map[string]any{"collection": name, "docs": docs, "classification": *class})
	check(err)
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(*gateway, "/")+"/dani/ingest", bytes.NewReader(body))
	check(err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Dani-User", who)
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	check(err)
	defer resp.Body.Close()
	var out struct {
		Name   string `json:"name"`
		Chunks []any  `json:"chunks"`
	}
	if resp.StatusCode != http.StatusOK {
		msg := new(bytes.Buffer)
		_, _ = msg.ReadFrom(resp.Body)
		fmt.Fprintf(os.Stderr, "ingest: gateway refused (%d): %s\n", resp.StatusCode, strings.TrimSpace(msg.String()))
		os.Exit(1)
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	logf("ingest: DONE — %d document(s) → collection %q (%d chunks indexed, %d skipped) as %s", len(docs), name, len(out.Chunks), skipped, who)
	logf("ingest: chat over it — create a RAG alias for %q in the console (Datasets → 💬), or POST /dani/rag/alias", name)
}
