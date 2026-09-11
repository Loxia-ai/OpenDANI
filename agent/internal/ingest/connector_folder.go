package ingest

// FolderConnector (the filesystem / shared-drive connector): crawls a directory tree — a local
// folder, or an SMB/NFS share mounted at a path — through the extract layer, so real files
// (txt/md/code, html, pdf, docx) become classified, chunked, embedded RAG data. INCREMENTAL via
// content hashes (an unchanged file is never re-read past its hash), classification-mapped by
// RELATIVE-path prefix exactly like the azblob connector ("hr/=internal,finance/=restricted";
// the source floor — content scanning can only RAISE a doc's class, D-09).
//
// The files never move: DANI reads them where they live and indexes chunks in the governed ingest
// store. Deleting a file removes its chunks on the next sync (the changed/gone contract).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"dani.local/agent/internal/extract"
)

// FolderConnector crawls Root recursively. Only files the extract layer supports are considered;
// hidden directories (.git, .cache, …) are skipped.
type FolderConnector struct {
	Root         string
	ClassMap     map[string]string // relpath prefix -> classification floor (longest match wins)
	DefaultClass string            // floor when no prefix matches (default "internal")
	MaxFileBytes int64             // per-file cap (default 4 MiB)
}

func (c *FolderConnector) Name() string { return "folder" }

// Sync walks the tree and extracts only files whose content hash changed since state.
func (c *FolderConnector) Sync(ctx context.Context, state map[string]string) ([]ConnectorDoc, []string, map[string]string, error) {
	maxBytes := c.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	root, err := filepath.Abs(c.Root)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("folder connector: %w", err)
	}
	next := map[string]string{}
	var changed []ConnectorDoc
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := d.Name()
		if d.IsDir() {
			if strings.HasPrefix(name, ".") && path != root { // .git, .cache, dotdirs
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") || !extract.Supported(name) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxBytes {
			return nil // unreadable or oversized files are skipped, not fatal — a share holds anything
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // vanished mid-walk / permission — skip, catch it next sync
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:8])
		next[rel] = hash
		if state[rel] == hash {
			return nil // unchanged — the incremental win
		}
		text, format, err := extract.Extract(rel, data)
		if err != nil {
			return nil // a corrupt/undecodable file must not poison the whole sync
		}
		changed = append(changed, ConnectorDoc{
			ID: rel, Text: text, Format: format,
			SrcClass: classForPrefix(rel, c.ClassMap, c.DefaultClass),
		})
		return nil
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("folder connector: walk %s: %w", root, err)
	}
	var gone []string
	for rel := range state {
		if _, still := next[rel]; !still {
			gone = append(gone, rel)
		}
	}
	sort.Slice(changed, func(i, j int) bool { return changed[i].ID < changed[j].ID })
	sort.Strings(gone)
	return changed, gone, next, nil
}

// classForPrefix picks the classification floor for a path/name (longest matching prefix wins) —
// shared by the folder, git, and azblob connectors so one classmap dialect rules them all.
func classForPrefix(name string, classMap map[string]string, def string) string {
	best, bestLen := def, -1
	for prefix, class := range classMap {
		if strings.HasPrefix(name, prefix) && len(prefix) > bestLen {
			best, bestLen = class, len(prefix)
		}
	}
	if best == "" {
		best = "internal"
	}
	return best
}
