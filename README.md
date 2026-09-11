# OpenDANI

OpenDANI is an experimental community inference network for computers that contribute
capacity. The Go runtime contains workers, a controller/router, an OpenAI-compatible
chat gateway and an embedded browser console. The intended first workload is
repeatable processing of public or synthetic data.

## Preview status

This is the public source preview of OpenDANI, maintained by
[Loxia.ai](https://github.com/Loxia-ai). DANI, the organizational product, remains
private. This repository has independent history and contains the community runtime
and console.

The first-party license is still being selected. Public visibility does not grant
an open-source license; third-party components retain their own licenses. This
preview does not establish a public service, supported installer or public-network
security assurance.

The runtime includes inherited organizational features: data ingestion/connectors,
model governance, training, audit, backup and SSO. They are coupled to the current
Go entrypoint and have not yet been separated into a minimal community-only core.
They are included in this source preview; their availability here does not imply
production support or parity with the private DANI product.

| Component | Source and current limits |
| --- | --- |
| Controller and workers | `agent/cmd/dani-agent`; enrollment, mTLS transport, gateway and routing. |
| Public enrollment | `agent/internal/openid` and `agent/internal/enrollment`; experimental self-minted identities and proof-of-work. |
| Outbound worker transport | `agent/internal/serving/reverse.go`; requests can reach workers through an outbound connection. |
| Contribution priority | `agent/internal/ledger`; implemented policy, without measured public-network sustainability. |
| Seed cross-checks | `agent/internal/serving/verify.go`; token overlap rather than semantic embeddings or guaranteed correctness. |
| Browser console | Source in `console/`, with a checked-in bundle embedded by the Go runtime. |

## Build and test

Requirements: Git and Go 1.25 or newer, with network access to download dependencies.
The Go build and default test suite use local fixtures and the checked-in console
bundle; no model weights, GPU or Node.js installation are required for those checks.

From this repository root:

```sh
cd agent
go mod download
go mod verify
go vet ./...
go build ./...
go test -count=1 -timeout 900s ./...
```

Build and inspect the node binary on Linux:

```sh
go build -o ./dist/dani-agent ./cmd/dani-agent
./dist/dani-agent version
./dist/dani-agent controller --help
./dist/dani-agent worker --help
```

In Windows PowerShell:

```powershell
go build -o .\dist\dani-agent.exe ./cmd/dani-agent
.\dist\dani-agent.exe version
.\dist\dani-agent.exe controller --help
.\dist\dani-agent.exe worker --help
```

The current inherited version string is `dani-agent demo 0.1.0`; a release version
has not been assigned. Help commands do not start a node. Real inference requires
a separately installed compatible backend and appropriately licensed model.
The default worker engine is a stub.

To check console source, use Node.js 22 and npm from `console/`:

```sh
npm ci
npm test
npm run build
```

That produces `console/dist/`. It does not automatically replace the checked-in
Go embed directory. `console/build-embed.sh` performs that separate refresh in
a shell environment; review its generated changes before committing.

[Third-party notices](THIRD_PARTY_NOTICES.md) preserve the separate dependency
licenses, including MPL-covered components and their versioned source links.
The embed refresh also copies these notices into the served console assets at
`/console/THIRD_PARTY_NOTICES.md`. Include the notices alongside binary packages;
the application's own license remains a separate release decision.

`.github/workflows/ci.yml` runs the Go module on Linux and Windows, including the
Linux race detector, plus console tests and build on Linux. Postgres parity and live calibration tests require explicitly
configured dependencies and otherwise skip. These checks do not establish GPU
support, Internet deployment safety, installer support or browser E2E behavior.

## Public-network trust

A volunteer executing a request can see its inputs and may return incorrect output.
Transport encryption does not hide inputs from the computer processing them.
Use public or synthetic data for evaluation and keep organizational identities,
private collections and enterprise credentials in the organizational deployment.

Controller defaults are for development: some listeners bind all interfaces,
and gateway/console authentication require explicit configuration. Do not expose
a default controller to the Internet. Optional `--demo` mode contains a
code-executing verification endpoint. Public enrollment needs a reviewed operating
profile, trustworthy worker/seed authorization and abuse controls before launch.
The inherited `connect --user` relay stamps a supplied name; it does not prove
an authenticated operating-system user.

## Release work

The remaining work includes a first-party license, a minimal self-hosting recipe, safe enrollment defaults,
resource controls, signed distribution/updates, model policy, clean-machine
validation and contribution terms.

See [contribution guidance](CONTRIBUTING.md) and [security reporting status](SECURITY.md).
Use [GitHub issues](https://github.com/Loxia-ai/OpenDANI/issues) for reproducible
non-sensitive bugs and focused proposals. Private vulnerability reporting is
enabled; follow the security guidance for sensitive findings.
