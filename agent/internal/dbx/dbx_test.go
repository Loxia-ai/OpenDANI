package dbx

import (
	"context"
	"testing"
)

func TestResolve(t *testing.T) {
	cases := []struct {
		dsn, driver string
		d           Dialect
	}{
		{"", "sqlite", SQLite},
		{":memory:", "sqlite", SQLite},
		{"sqlite:/tmp/x.db", "sqlite", SQLite},
		{"/var/lib/x.db", "sqlite", SQLite},
		{"postgres://u:p@h:5432/db", "pgx", Postgres},
		{"postgresql://u@h/db", "pgx", Postgres},
	}
	for _, c := range cases {
		driver, _, d := resolve(c.dsn)
		if driver != c.driver || d != c.d {
			t.Fatalf("resolve(%q)=(%s,%s) want (%s,%s)", c.dsn, driver, d, c.driver, c.d)
		}
	}
	// sqlite: strips the prefix; bare "" becomes :memory:
	if _, conn, _ := resolve("sqlite:/a/b"); conn != "/a/b" {
		t.Fatalf("sqlite conn strip wrong: %q", conn)
	}
	if _, conn, _ := resolve(""); conn != ":memory:" {
		t.Fatalf("empty dsn must default :memory:, got %q", conn)
	}
}

func TestRebind(t *testing.T) {
	if got := SQLite.Rebind("SELECT * WHERE a=? AND b=?"); got != "SELECT * WHERE a=? AND b=?" {
		t.Fatalf("sqlite must passthrough, got %q", got)
	}
	if got := Postgres.Rebind("INSERT (a,b,c) VALUES (?,?,?)"); got != "INSERT (a,b,c) VALUES ($1,$2,$3)" {
		t.Fatalf("postgres rebind wrong: %q", got)
	}
	if got := Postgres.Rebind("no placeholders"); got != "no placeholders" {
		t.Fatalf("no-placeholder passthrough: %q", got)
	}
}

func TestItoa(t *testing.T) {
	for _, c := range []struct {
		n int
		s string
	}{{0, "0"}, {7, "7"}, {42, "42"}, {100, "100"}} {
		if got := itoa(c.n); got != c.s {
			t.Fatalf("itoa(%d)=%q want %q", c.n, got, c.s)
		}
	}
}

func TestOpenSQLite(t *testing.T) {
	db, d, err := Open(context.Background(), ":memory:")
	if err != nil || d != SQLite {
		t.Fatalf("open sqlite: %v %s", err, d)
	}
	db.Close()
}

func TestOpenPostgresUnreachable(t *testing.T) {
	// a well-formed Postgres DSN that cannot connect -> Ping fails at Open (fast, no external dep)
	if _, _, err := Open(context.Background(), "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1"); err == nil {
		t.Fatal("unreachable postgres must fail at Open")
	}
}

func TestOpenSQLiteBadPath(t *testing.T) {
	// modernc sqlite opens lazily; the Ping/first-use against an unwritable path errors
	if _, _, err := Open(context.Background(), "sqlite:/no-such-dir/deeper/x.db"); err == nil {
		t.Fatal("unwritable sqlite path must fail at Open")
	}
}
