# Contributing to OpenDANI

OpenDANI is a public source preview. Bug reports and focused design proposals are
welcome. The first-party license and contributor terms are still being selected;
please wait for those terms before submitting code contributions.

## Preparing a change

Keep changes focused and explain the user-visible problem, the resulting behavior
and the checks you ran. Include a regression test when fixing runtime behavior.
Use synthetic fixtures rather than private prompts, customer data or credentials.

Run the Go checks from `agent/`:

```sh
go vet ./...
go build ./...
go test -count=1 -timeout 900s ./...
```

For console changes, run `npm ci`, `npm test` and `npm run build` in `console/`.
Keep generated enrollment bindings and embedded console assets consistent with
their source. Do not edit third-party copyright or license notices.

Use [GitHub issues](https://github.com/Loxia-ai/OpenDANI/issues) for reproducible
non-sensitive bugs and focused proposals. Include the operating system, toolchain, reproduction
steps and expected/actual behavior. Redact private data and access tokens.

Security-sensitive findings belong in a private reporting channel. See
[SECURITY.md](SECURITY.md); do not publish an exploit or private credentials in an issue.

## Maintainer setup still required

Before accepting code contributions, maintainers will publish the license,
contributor terms and community participation guidance. GitHub private vulnerability
reporting is enabled. No response-time commitment is established for this preview.
