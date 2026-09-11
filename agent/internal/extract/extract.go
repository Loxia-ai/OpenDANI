// Package extract turns real-world document FILES into plain text for ingest — the shared layer
// under every file-based connector (folder, git, azblob). SDK-free by project convention: DOCX is
// unzipped with archive/zip + encoding/xml, HTML is stripped with a small state machine, and PDF is
// a pragmatic stdlib reader (Flate content streams + BT/ET text operators) that handles the common
// office-generated text PDF; exotic encodings (CID/Type0 fonts) come out garbled and are the
// documented limitation — the extractor REFUSES output that doesn't look like text rather than
// indexing mojibake.
package extract

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// plainExts are ingested verbatim (source code included — the git connector feeds a coder model).
var plainExts = map[string]bool{
	".txt": true, ".md": true, ".markdown": true, ".rst": true, ".log": true, ".csv": true,
	".json": true, ".yaml": true, ".yml": true, ".toml": true, ".ini": true, ".conf": true,
	".go": true, ".py": true, ".js": true, ".ts": true, ".tsx": true, ".jsx": true, ".java": true,
	".c": true, ".h": true, ".cpp": true, ".hpp": true, ".cs": true, ".rb": true, ".rs": true,
	".sh": true, ".ps1": true, ".sql": true, ".proto": true, ".tf": true, ".xml": true,
}

// Supported reports whether Extract knows how to read this filename.
func Supported(name string) bool {
	switch ext(name) {
	case ".html", ".htm", ".pdf", ".docx", ".xlsx":
		return true
	}
	return plainExts[ext(name)]
}

// Extract converts one document's bytes to plain text. format names what was parsed
// ("text" | "html" | "pdf" | "docx") — it travels into chunk lineage so citations say what
// kind of source backed them.
func Extract(name string, data []byte) (text, format string, err error) {
	switch e := ext(name); {
	case e == ".html" || e == ".htm":
		return stripHTML(string(data)), "html", nil
	case e == ".pdf":
		t, err := pdfText(data)
		return t, "pdf", err
	case e == ".docx":
		t, err := docxText(data)
		return t, "docx", err
	case e == ".xlsx":
		t, err := xlsxText(data)
		return t, "xlsx", err
	case plainExts[e]:
		if !utf8.Valid(data) {
			return "", "text", fmt.Errorf("extract: %s is not valid UTF-8 text", name)
		}
		return string(data), "text", nil
	default:
		return "", "", fmt.Errorf("extract: unsupported file type %q (%s)", ext(name), name)
	}
}

func ext(name string) string { return strings.ToLower(filepath.Ext(name)) }

/* ---- HTML: a small state machine — drop tags, scripts and styles, decode the common entities. */

var htmlEntities = strings.NewReplacer(
	"&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "&apos;", "'", "&nbsp;", " ",
)

func stripHTML(s string) string {
	var b strings.Builder
	inTag, skipDepth := false, 0 // skipDepth>0 while inside <script>/<style>
	lower := strings.ToLower(s)
	for i := 0; i < len(s); i++ {
		if !inTag && s[i] == '<' {
			inTag = true
			rest := lower[i:]
			switch {
			case strings.HasPrefix(rest, "<script"), strings.HasPrefix(rest, "<style"):
				skipDepth++
			case strings.HasPrefix(rest, "</script"), strings.HasPrefix(rest, "</style"):
				if skipDepth > 0 {
					skipDepth--
				}
			// block-level closes read as sentence-ish boundaries
			case strings.HasPrefix(rest, "</p"), strings.HasPrefix(rest, "</div"), strings.HasPrefix(rest, "<br"),
				strings.HasPrefix(rest, "</h"), strings.HasPrefix(rest, "</li"), strings.HasPrefix(rest, "</tr"):
				b.WriteByte('\n')
			}
			continue
		}
		if inTag {
			if s[i] == '>' {
				inTag = false
			}
			continue
		}
		if skipDepth == 0 {
			b.WriteByte(s[i])
		}
	}
	return normalizeWS(htmlEntities.Replace(b.String()))
}

/* ---- DOCX: a zip holding word/document.xml; text lives in <w:t> runs, paragraphs in <w:p>. */

func docxText(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("extract: not a docx (zip): %w", err)
	}
	var doc *zip.File
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			doc = f
			break
		}
	}
	if doc == nil {
		return "", fmt.Errorf("extract: docx has no word/document.xml")
	}
	rc, err := doc.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	dec := xml.NewDecoder(rc)
	var b strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("extract: docx xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
		case xml.EndElement:
			if t.Name.Local == "p" { // paragraph boundary
				b.WriteByte('\n')
			}
		}
	}
	return normalizeWS(b.String()), nil
}

/* ---- PDF: pragmatic stdlib reader. Finds stream objects, inflates FlateDecode ones, then pulls
   the text-showing operators (Tj, TJ, ') out of BT..ET blocks. Handles the literal-string escapes
   of the PDF spec. Output that doesn't look like text (exotic font encodings) is refused. */

var streamRe = regexp.MustCompile(`(?s)stream\r?\n(.*?)endstream`)

func pdfText(data []byte) (string, error) {
	if !bytes.HasPrefix(data, []byte("%PDF")) {
		return "", fmt.Errorf("extract: not a PDF")
	}
	var b strings.Builder
	for _, m := range streamRe.FindAllSubmatch(data, -1) {
		raw := m[1]
		if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
			if inflated, err := io.ReadAll(zr); err == nil {
				raw = inflated
			}
			zr.Close()
		}
		b.WriteString(contentText(raw))
	}
	out := normalizeWS(b.String())
	if out == "" {
		return "", fmt.Errorf("extract: PDF contains no extractable text (scanned or unsupported encoding)")
	}
	if !looksLikeText(out) {
		return "", fmt.Errorf("extract: PDF text is not decodable (CID/Type0 font) — export it as text/docx instead")
	}
	return out, nil
}

// contentText walks one content stream and collects literal strings shown by Tj / ' / TJ.
func contentText(s []byte) string {
	var b strings.Builder
	inText := false
	for i := 0; i < len(s); i++ {
		if !inText {
			if s[i] == 'B' && i+1 < len(s) && s[i+1] == 'T' {
				inText = true
				i++
			}
			continue
		}
		switch s[i] {
		case 'E':
			if i+1 < len(s) && s[i+1] == 'T' {
				inText = false
				b.WriteByte('\n')
				i++
			}
		case '(':
			str, adv := pdfString(s[i:])
			b.WriteString(str)
			i += adv - 1
		}
	}
	return b.String()
}

// pdfString decodes one ( ... ) literal string starting at s[0]=='('; returns the text and the
// bytes consumed. Handles \) \( \\ \n \r \t and nested parens per the spec.
func pdfString(s []byte) (string, int) {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r', 't':
				b.WriteByte(' ')
			default:
				b.WriteByte(s[i]) // \( \) \\ and octal's first digit — good enough for text
			}
		case c == '(':
			depth++
			if depth > 1 {
				b.WriteByte(c)
			}
		case c == ')':
			depth--
			if depth == 0 {
				return b.String(), i + 1
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), len(s)
}

// looksLikeText: at least 85% printable-or-space runes → real text, not font-encoded bytes.
func looksLikeText(s string) bool {
	if s == "" {
		return false
	}
	printable, total := 0, 0
	for _, r := range s {
		total++
		if r == ' ' || r == '\n' || r == '\t' || (r >= 32 && r != 0xFFFD && r < 0x2FFF) || r > 0x3000 {
			printable++
		}
	}
	return printable*100 >= total*85
}

// normalizeWS collapses runs of blank lines/spaces so chunking sees clean sentences.
func normalizeWS(s string) string {
	lines := strings.Split(s, "\n")
	var out []string
	for _, ln := range lines {
		ln = strings.Join(strings.Fields(ln), " ")
		if ln != "" {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}
