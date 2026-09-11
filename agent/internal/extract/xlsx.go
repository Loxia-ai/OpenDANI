package extract

// XLSX: a zip of XML — shared strings in xl/sharedStrings.xml, cell values in xl/worksheets/
// sheet*.xml. The extractor walks each sheet row by row and emits one line per row (cells joined),
// resolving shared-string cells by index — so a spreadsheet of policies/inventory becomes clean,
// chunkable lines. Stdlib-only, same convention as docx.

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"encoding/xml"
)

func xlsxText(data []byte) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("extract: not an xlsx (zip): %w", err)
	}
	var shared []string
	var sheets []*zip.File
	for _, f := range zr.File {
		switch {
		case f.Name == "xl/sharedStrings.xml":
			shared, err = xlsxSharedStrings(f)
			if err != nil {
				return "", err
			}
		case strings.HasPrefix(f.Name, "xl/worksheets/sheet") && strings.HasSuffix(f.Name, ".xml"):
			sheets = append(sheets, f)
		}
	}
	if len(sheets) == 0 {
		return "", fmt.Errorf("extract: xlsx has no worksheets")
	}
	sort.Slice(sheets, func(i, j int) bool { return sheets[i].Name < sheets[j].Name })
	var b strings.Builder
	for _, sh := range sheets {
		if err := xlsxSheet(sh, shared, &b); err != nil {
			return "", err
		}
	}
	return normalizeWS(b.String()), nil
}

// xlsxSharedStrings loads the <si> entries (each may hold one <t> or rich-text runs of <t>).
func xlsxSharedStrings(f *zip.File) ([]string, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	dec := xml.NewDecoder(rc)
	var out []string
	var cur strings.Builder
	inSI, inT := false, false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("extract: xlsx sharedStrings: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "si":
				inSI = true
				cur.Reset()
			case "t":
				inT = true
			}
		case xml.CharData:
			if inSI && inT {
				cur.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inT = false
			case "si":
				inSI = false
				out = append(out, cur.String())
			}
		}
	}
	return out, nil
}

// xlsxSheet streams one worksheet: rows become lines, cells joined by " · ".
func xlsxSheet(f *zip.File, shared []string, b *strings.Builder) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	dec := xml.NewDecoder(rc)
	var row []string
	cellType := ""
	inV, inIS := false, false
	var val strings.Builder
	flushCell := func() {
		v := strings.TrimSpace(val.String())
		val.Reset()
		if v == "" {
			return
		}
		if cellType == "s" { // shared-string index
			if i, err := strconv.Atoi(v); err == nil && i >= 0 && i < len(shared) {
				v = shared[i]
			}
		}
		if v != "" {
			row = append(row, v)
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("extract: xlsx sheet %s: %w", f.Name, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "row":
				row = row[:0]
			case "c":
				cellType = ""
				for _, a := range t.Attr {
					if a.Name.Local == "t" {
						cellType = a.Value
					}
				}
			case "v":
				inV = true
			case "is":
				inIS = true
			case "t":
				if inIS {
					inV = true // inline string text collects like a value
				}
			}
		case xml.CharData:
			if inV {
				val.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "v", "t":
				if inV {
					inV = false
					if t.Name.Local == "v" || inIS {
						flushCell()
					}
				}
			case "is":
				inIS = false
			case "row":
				if len(row) > 0 {
					b.WriteString(strings.Join(row, " · "))
					b.WriteByte('\n')
				}
			}
		}
	}
	return nil
}
