# OpenDANI Go runtime

This Go module contains the development runtime for the OpenDANI community fork.
See the [OpenDANI README](../README.md) for its current status, trust boundary,
requirements and build instructions. Historical phase checklists are not release
validation.

From this directory:

```sh
go mod verify
go vet ./...
go build ./...
go test -count=1 -timeout 900s ./...
```

The module declares Go 1.25. The default suite runs against local fixtures and SQLite;
it does not need a model or GPU. Tests for a real Postgres instance use `DANI_TEST_PG`.
Live calibration uses `DANI_CALIB_BIN` and `DANI_CALIB_MODEL`. Those tests skip when
their dependencies are not configured. Linux CI also runs the race detector.

`cmd/dani-agent` builds the controller/worker binary; `cmd/dani-ctl` is the operator
client, `cmd/dani-bench` the benchmark client, and `cmd/dani-verify` the offline audit
tool. `cmd/dani-econsim` and `cmd/mockidp` are simulation/development tools. This is
an implementation inventory, not a decision to include every command in a public
release.

Generated enrollment Go bindings and the console bundle are checked in, so `buf`
and Node.js are not needed for an ordinary Go build. Changes to the protocol require
regenerating the bindings using `buf.gen.yaml`. Changes to the console require a
separate console build and deliberate refresh of `internal/serving/webapp/console`.

No model weights or inference backend are bundled. Real inference can use a
separately installed llama.cpp server or a configured OpenAI-compatible backend.
Review model and backend licenses before distributing either.
