# Contributing

Bug reports and pull requests are welcome.

## Working on the code

Requires Go 1.26 or later.

```sh
go build -o bin/sec1-mcp .
go vet ./...
go test -race ./...
gofmt -l .          # must print nothing
```

The tests need no network: the advisory services are replaced by a local
fake. To run the tools against the real services:

```sh
SEC1_LIVE=1 go test ./internal/server -run TestLive -v
```

## What a change should keep true

- **A failed or missing lookup is never reported as clean.** If a source
  cannot be asked, the status is `unknown` and the source appears as `failed`
  in `coverage`.
- **No guessing.** A product the catalog does not know is `unrecognised`.
  Do not add fuzzy name matching.
- **Tools stay read-only**, and the hosts the server calls stay fixed in the
  code.
- **Third-party text goes through `clean`** before it is returned, and its
  schema description says it is untrusted.

## Adding a product to the catalog

See [docs/catalog.md](docs/catalog.md). Add only identifiers you have
confirmed, and say in the pull request how you confirmed them.

## Pull requests

Describe what changes for someone using the server, add or update tests, and
add a line under `Unreleased` in `CHANGELOG.md`.
