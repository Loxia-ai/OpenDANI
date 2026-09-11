package extract

// The fixtures are GENERATED here with stdlib (a real zip for docx, real zlib streams for pdf), so
// the tests exercise the actual parse paths with zero binary blobs in the repo.

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
)

func TestSupported(t *testing.T) {
	for _, name := range []string{"a.txt", "b.md", "c.go", "d.html", "e.pdf", "f.docx", "G.PDF", "policy.Docx"} {
		if !Supported(name) {
			t.Errorf("Supported(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"a.exe", "b.png", "c.zip", "noext"} {
		if Supported(name) {
			t.Errorf("Supported(%q) = true, want false", name)
		}
	}
}

func TestExtractPlainAndInvalidUTF8(t *testing.T) {
	txt, format, err := Extract("notes.md", []byte("# Policy\nLiability caps apply."))
	if err != nil || format != "text" || !strings.Contains(txt, "Liability caps") {
		t.Fatalf("plain: %q %q %v", txt, format, err)
	}
	if _, _, err := Extract("bin.txt", []byte{0xff, 0xfe, 0x00, 0x81}); err == nil {
		t.Fatal("invalid UTF-8 must be refused")
	}
	if _, _, err := Extract("image.png", []byte("x")); err == nil {
		t.Fatal("unsupported extension must error")
	}
}

func TestExtractHTML(t *testing.T) {
	html := `<html><head><style>body{color:red}</style><script>alert("no")</script></head>
	<body><h1>Contract &amp; Terms</h1><p>Liability is capped.</p><p>Indemnity&nbsp;applies.</p></body></html>`
	txt, format, err := Extract("page.html", []byte(html))
	if err != nil || format != "html" {
		t.Fatalf("html: %v %q", err, format)
	}
	if !strings.Contains(txt, "Contract & Terms") || !strings.Contains(txt, "Liability is capped.") {
		t.Fatalf("html text lost content: %q", txt)
	}
	if strings.Contains(txt, "alert") || strings.Contains(txt, "color:red") {
		t.Fatalf("script/style leaked into text: %q", txt)
	}
	// block closes become line boundaries so the chunker sees separate sentences
	if !strings.Contains(txt, "\n") {
		t.Fatalf("expected paragraph boundaries: %q", txt)
	}
}

func makeDocx(t *testing.T, paragraphs ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	var doc strings.Builder
	doc.WriteString(`<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, p := range paragraphs {
		doc.WriteString(`<w:p><w:r><w:t>` + p + `</w:t></w:r></w:p>`)
	}
	doc.WriteString(`</w:body></w:document>`)
	f, err := zw.Create("word/document.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(doc.String())); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractDocx(t *testing.T) {
	data := makeDocx(t, "The master agreement caps liability.", "Indemnification survives termination.")
	txt, format, err := Extract("contract.docx", data)
	if err != nil || format != "docx" {
		t.Fatalf("docx: %v %q", err, format)
	}
	if !strings.Contains(txt, "caps liability") || !strings.Contains(txt, "Indemnification survives") {
		t.Fatalf("docx text: %q", txt)
	}
	if !strings.Contains(txt, "\n") {
		t.Fatalf("paragraphs must be newline-separated: %q", txt)
	}
	// not a zip → clean error
	if _, _, err := Extract("fake.docx", []byte("not a zip")); err == nil {
		t.Fatal("non-zip docx must error")
	}
	// zip without document.xml → clean error
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Close()
	if _, _, err := Extract("empty.docx", buf.Bytes()); err == nil {
		t.Fatal("docx without document.xml must error")
	}
}

// makePDF builds a minimal single-page PDF whose content stream shows `lines` — optionally
// Flate-compressed, exactly as office exporters write them.
func makePDF(t *testing.T, compressed bool, lines ...string) []byte {
	t.Helper()
	var content strings.Builder
	content.WriteString("BT /F1 12 Tf 72 720 Td ")
	for _, ln := range lines {
		fmt.Fprintf(&content, "(%s) Tj 0 -14 Td ", ln)
	}
	content.WriteString("ET")
	stream := []byte(content.String())
	filter := ""
	if compressed {
		var zbuf bytes.Buffer
		zw := zlib.NewWriter(&zbuf)
		zw.Write(stream)
		zw.Close()
		stream = zbuf.Bytes()
		filter = "/Filter /FlateDecode "
	}
	var pdf bytes.Buffer
	fmt.Fprintf(&pdf, "%%PDF-1.4\n1 0 obj\n<< %s/Length %d >>\nstream\n", filter, len(stream))
	pdf.Write(stream)
	pdf.WriteString("\nendstream\nendobj\ntrailer\n%%EOF")
	return pdf.Bytes()
}

func TestExtractPDF(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		data := makePDF(t, compressed, "Liability caps are governed", "by the master services agreement.")
		txt, format, err := Extract("contract.pdf", data)
		if err != nil || format != "pdf" {
			t.Fatalf("pdf(compressed=%v): %v %q", compressed, err, format)
		}
		if !strings.Contains(txt, "Liability caps are governed") || !strings.Contains(txt, "master services agreement") {
			t.Fatalf("pdf(compressed=%v) text: %q", compressed, txt)
		}
	}
	// escapes and nested parens per the string spec
	data := makePDF(t, false, `escaped \(parens\) and a \\ backslash`)
	txt, _, err := Extract("esc.pdf", data)
	if err != nil || !strings.Contains(txt, "escaped (parens) and a \\ backslash") {
		t.Fatalf("pdf escapes: %q %v", txt, err)
	}
	// not a pdf / no text → clean errors
	if _, _, err := Extract("fake.pdf", []byte("hello")); err == nil {
		t.Fatal("non-PDF must error")
	}
	if _, _, err := Extract("blank.pdf", []byte("%PDF-1.4\nno streams here\n%%EOF")); err == nil {
		t.Fatal("PDF without text must error")
	}
}

func TestLooksLikeTextGuard(t *testing.T) {
	if looksLikeText("\x01\x02\x03\x04\x05\x06\x07\x08") {
		t.Fatal("binary garbage must not pass the text guard")
	}
	if !looksLikeText("A perfectly ordinary sentence.") {
		t.Fatal("plain text must pass the guard")
	}
}
