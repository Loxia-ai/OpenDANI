package extract

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// makeXlsx builds a real two-row workbook: shared strings + a numeric + an inline string.
func makeXlsx(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, content string) {
		f, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(content))
	}
	add("xl/sharedStrings.xml", `<?xml version="1.0"?><sst><si><t>Server</t></si><si><t>Clearance</t></si><si><t>hub-01</t></si><si><t>restricted</t></si></sst>`)
	add("xl/worksheets/sheet1.xml", `<?xml version="1.0"?><worksheet><sheetData>`+
		`<row r="1"><c t="s"><v>0</v></c><c t="s"><v>1</v></c></row>`+
		`<row r="2"><c t="s"><v>2</v></c><c t="s"><v>3</v></c><c><v>42</v></c><c t="inlineStr"><is><t>gpu node</t></is></c></row>`+
		`</sheetData></worksheet>`)
	zw.Close()
	return buf.Bytes()
}

func TestExtractXlsx(t *testing.T) {
	txt, format, err := Extract("inventory.xlsx", makeXlsx(t))
	if err != nil || format != "xlsx" {
		t.Fatalf("xlsx: %v %q", err, format)
	}
	if !strings.Contains(txt, "Server · Clearance") {
		t.Fatalf("header row lost: %q", txt)
	}
	if !strings.Contains(txt, "hub-01 · restricted · 42 · gpu node") {
		t.Fatalf("data row lost: %q", txt)
	}
	if !Supported("Sheet.XLSX") {
		t.Fatal("xlsx must be Supported")
	}
	if _, _, err := Extract("bad.xlsx", []byte("not a zip")); err == nil {
		t.Fatal("non-zip xlsx must error")
	}
}
