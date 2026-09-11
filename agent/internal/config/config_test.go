package config

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func set(t *testing.T, s *Store, scope, val, key, value string) {
	t.Helper()
	if err := s.Set(context.Background(), Entry{Scope: scope, ScopeVal: val, Key: key, Value: value}); err != nil {
		t.Fatalf("set %s/%s %s=%s: %v", scope, val, key, value, err)
	}
}

func TestFourScopeResolution(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	set(t, s, ScopeFleet, "", "worker.queue-depth", "8")
	set(t, s, ScopeSite, "site-b", "worker.queue-depth", "4")
	set(t, s, ScopeRole, "trainer", "worker.queue-depth", "2")
	set(t, s, ScopeNode, "w-9", "worker.queue-depth", "1")
	set(t, s, ScopeFleet, "", "worker.slo-budget", "20s")

	cases := []struct {
		attrs     NodeAttrs
		want      string
		wantScope string
	}{
		{NodeAttrs{UUID: "w-1", Site: "site-a", Roles: []string{"worker"}}, "8", ScopeFleet},          // only fleet matches
		{NodeAttrs{UUID: "w-2", Site: "site-b", Roles: []string{"worker"}}, "4", ScopeSite},           // site beats fleet
		{NodeAttrs{UUID: "w-3", Site: "site-b", Roles: []string{"trainer"}}, "2", ScopeRole},          // role beats site
		{NodeAttrs{UUID: "w-9", Site: "site-b", Roles: []string{"trainer"}}, "1", ScopeNode},          // node beats all
		{NodeAttrs{UUID: "w-4", Site: "", Roles: nil}, "8", ScopeFleet},                               // bare node gets fleet
	}
	for i, c := range cases {
		got, err := s.ResolveAll(ctx, c.attrs)
		if err != nil {
			t.Fatal(err)
		}
		r := got["worker.queue-depth"]
		if r.Value != c.want || r.Scope != c.wantScope {
			t.Fatalf("case %d: got %+v want %s@%s", i, r, c.want, c.wantScope)
		}
		if got["worker.slo-budget"].Value != "20s" {
			t.Fatalf("case %d: slo-budget missing", i)
		}
	}

	// among multiple matching ROLE entries: first role in sorted order wins (deterministic, D-37)
	set(t, s, ScopeRole, "worker", "worker.queue-depth", "6")
	got, err := s.ResolveAll(ctx, NodeAttrs{UUID: "w-5", Roles: []string{"worker", "trainer"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := got["worker.queue-depth"]; r.Value != "2" || r.ScopeVal != "trainer" { // "trainer" < "worker"
		t.Fatalf("role tie-break wrong: %+v", r)
	}
}

func TestValidationRefusesBadWrites(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	bad := []Entry{
		{Scope: "galaxy", Key: "x-a", Value: "1"},                                  // unknown scope
		{Scope: ScopeFleet, ScopeVal: "oops", Key: "x-a", Value: "1"},              // fleet takes no scope val
		{Scope: ScopeSite, Key: "x-a", Value: "1"},                                 // site needs a value
		{Scope: ScopeFleet, Key: "", Value: "1"},                                   // empty key
		{Scope: ScopeFleet, Key: "worker.qeue-depth", Value: "4"},                  // TYPO'd built-in — hard error
		{Scope: ScopeFleet, Key: "worker.queue-depth", Value: "banana"},            // not an int
		{Scope: ScopeFleet, Key: "worker.queue-depth", Value: "9999"},              // out of range
		{Scope: ScopeFleet, Key: "worker.slo-budget", Value: "0s"},                 // below min
		{Scope: ScopeFleet, Key: "worker.slo-budget", Value: "soon"},               // not a duration
		{Scope: ScopeFleet, Key: "policy.rate-max", Value: "-1"},                   // negative
	}
	for i, e := range bad {
		if err := s.Set(ctx, e); err == nil {
			t.Fatalf("bad entry %d accepted: %+v", i, e)
		}
	}
	// operator-defined keys need the x- prefix; with it they're free-form
	if err := s.Set(ctx, Entry{Scope: ScopeFleet, Key: "x-team-tag", Value: "blue"}); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Version(ctx); err != nil || v != 1 {
		t.Fatalf("only the one valid write may bump the version: v=%d err=%v", v, err)
	}
	if !strings.Contains(KnownKeys()["worker.slo-budget"], "admission") {
		t.Fatalf("KnownKeys: %v", KnownKeys())
	}
}

func TestVersionListDeleteAndPersistence(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "config.db")
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Version(ctx); v != 0 {
		t.Fatalf("fresh version: %d", v)
	}
	set(t, s, ScopeFleet, "", "worker.queue-depth", "8")
	set(t, s, ScopeNode, "w-1", "worker.queue-depth", "2")
	set(t, s, ScopeFleet, "", "worker.queue-depth", "6") // upsert replaces
	if v, _ := s.Version(ctx); v != 3 {
		t.Fatalf("version after 3 writes: %d", v)
	}
	l, err := s.List(ctx)
	if err != nil || len(l) != 2 {
		t.Fatalf("list: %v %d", err, len(l))
	}
	if err := s.Delete(ctx, ScopeNode, "w-1", "worker.queue-depth"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Version(ctx); v != 4 {
		t.Fatalf("version after delete: %d", v)
	}
	_ = s.Close()

	// restart: entries + version survive
	s2, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v, _ := s2.Version(ctx); v != 4 {
		t.Fatalf("version lost on restart: %d", v)
	}
	got, err := s2.ResolveAll(ctx, NodeAttrs{UUID: "w-1"})
	if err != nil || got["worker.queue-depth"].Value != "6" {
		t.Fatalf("resolution after restart: %v %+v", err, got)
	}
}

func TestStoreFaults(t *testing.T) {
	ctx := context.Background()
	// unreachable postgres / unwritable path fail at Open
	if _, err := Open(ctx, "postgres://u:p@127.0.0.1:1/db"); err == nil {
		t.Fatal("unreachable postgres must fail Open")
	}
	if _, err := Open(ctx, filepath.Join(t.TempDir(), "no", "dir", "x.db")); err == nil {
		t.Fatal("unwritable path must fail Open")
	}
	// read-only DB missing a table: the DDL must WRITE and fails
	roDir := t.TempDir()
	roPath := filepath.Join(roDir, "ro.db")
	seed, err := Open(ctx, roPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.db.Exec(`DROP TABLE config_entries`); err != nil {
		t.Fatal(err)
	}
	_ = seed.Close()
	if _, err := Open(ctx, "sqlite:file:"+filepath.ToSlash(roPath)+"?mode=ro"); err == nil {
		t.Fatal("read-only DDL must fail Open")
	}
	// read-only DB with tables but NO version row: the seed insert must WRITE and fails
	ro2 := filepath.Join(t.TempDir(), "ro2.db")
	seed2, err := Open(ctx, ro2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed2.db.Exec(`DELETE FROM config_version`); err != nil {
		t.Fatal(err)
	}
	_ = seed2.Close()
	if _, err := Open(ctx, "sqlite:file:"+filepath.ToSlash(ro2)+"?mode=ro"); err == nil {
		t.Fatal("read-only version seed must fail Open")
	}
	// closed store: every op surfaces
	s := open(t)
	_ = s.Close()
	if err := s.Set(ctx, Entry{Scope: ScopeFleet, Key: "x-a", Value: "1"}); err == nil {
		t.Fatal("Set on closed store must fail")
	}
	if err := s.Delete(ctx, ScopeFleet, "", "x-a"); err == nil {
		t.Fatal("Delete on closed store must fail")
	}
	if _, err := s.Version(ctx); err == nil {
		t.Fatal("Version on closed store must fail")
	}
	if _, err := s.List(ctx); err == nil {
		t.Fatal("List on closed store must fail")
	}
	if _, err := s.ResolveAll(ctx, NodeAttrs{}); err == nil {
		t.Fatal("ResolveAll on closed store must fail")
	}
	// statement-level faults: broken tables
	s2 := open(t)
	if _, err := s2.db.Exec(`DROP TABLE config_entries`); err != nil {
		t.Fatal(err)
	}
	if err := s2.Set(ctx, Entry{Scope: ScopeFleet, Key: "x-a", Value: "1"}); err == nil {
		t.Fatal("missing entries table must fail Set")
	}
	if err := s2.Delete(ctx, ScopeFleet, "", "x-a"); err == nil {
		t.Fatal("missing entries table must fail Delete")
	}
	s3 := open(t)
	if _, err := s3.db.Exec(`DROP TABLE config_entries; CREATE VIEW config_entries AS SELECT 'fleet' AS scope_kind, '' AS scope_val, 'k' AS key, 'v' AS value; CREATE TRIGGER ce_del INSTEAD OF DELETE ON config_entries BEGIN SELECT 1; END`); err != nil {
		t.Fatal(err)
	}
	if err := s3.Set(ctx, Entry{Scope: ScopeFleet, Key: "x-a", Value: "1"}); err == nil {
		t.Fatal("unwritable entries table must fail Set")
	}
	// scan fault: NULL value
	s4 := open(t)
	if _, err := s4.db.Exec(`DROP TABLE config_entries; CREATE TABLE config_entries (scope_kind TEXT, scope_val TEXT, key TEXT, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s4.db.Exec(`INSERT INTO config_entries VALUES ('fleet', '', 'x-a', NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s4.List(ctx); err == nil {
		t.Fatal("NULL row must fail List")
	}
	// version-update fault: version table gone mid-Set
	s5 := open(t)
	if _, err := s5.db.Exec(`DROP TABLE config_version`); err != nil {
		t.Fatal(err)
	}
	if err := s5.Set(ctx, Entry{Scope: ScopeFleet, Key: "x-a", Value: "1"}); err == nil {
		t.Fatal("missing version table must fail Set")
	}
	if err := s5.Delete(ctx, ScopeFleet, "", "x-a"); err == nil {
		t.Fatal("missing version table must fail Delete")
	}
}
