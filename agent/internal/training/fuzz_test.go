package training

// P2-2 parser fuzzing: ParseMarkers decodes a REMOTE TRAINER's stdout/HTTP stream — a compromised
// or buggy trainer node must not be able to crash the controller with a malformed marker stream.

import (
	"strings"
	"testing"
)

func FuzzParseMarkers(f *testing.F) {
	for _, seed := range []string{
		"",
		"CKPT 1/3\nCKPT 2/3\nRESULT {\"artifact\":\"aGk=\",\"evals\":{\"loss\":1.5}}\n",
		"RESULT {\"artifact\":\"!!!not-base64\"}\n",
		"RESULT {not json}\n",
		"ERROR boom\n",
		"CKPT x/y\nRESULT {}\n",
		"noise\nCKPT 999999999999999999999/1\n",
		strings.Repeat("CKPT 1/1\n", 1000),
		"RESULT " + strings.Repeat("a", 4096) + "\n",
		"\x00\xff\nRESULT {\"artifact\":\"\"}\n",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, stream string) {
		ckpts := 0
		res, err := ParseMarkers(strings.NewReader(stream), func(done, total int) { ckpts++ })
		if err != nil {
			return // malformed streams must ERROR, never panic
		}
		_ = res // a successful parse produced a Result; malformed streams must ERROR, never panic
		_ = ckpts
	})
}

func FuzzSplitCommand(f *testing.F) {
	for _, seed := range []string{
		"", `python train.py`, `"C:/Program Files/py/python.exe" train.py --epochs 3`,
		`'single quoted' arg`, `unterminated "quote`, "tabs\tand  spaces",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		parts := SplitCommand(cmd)
		for _, p := range parts {
			if p == "" {
				t.Fatalf("empty part from %q -> %q", cmd, parts)
			}
		}
	})
}
