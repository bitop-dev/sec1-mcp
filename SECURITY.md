# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue.

Use GitHub's private reporting: open the repository's **Security** tab and
choose **Report a vulnerability**. Include what you found, how to reproduce
it, and the version or commit you tested.

You should get a first response within a week. Once a fix is released, the
advisory is published with credit to the reporter unless you ask otherwise.

## Supported versions

Only the latest release, and the `main` branch, receive fixes.

## What this server trusts, and what it does not

These points describe the design, so that a report can say which of them
does not hold.

- **Tool inputs are untrusted.** Each value is validated against a pattern
  before use. The services the server calls are fixed in the code; no input
  is ever used as a host name.
- **Advisory text is untrusted.** Titles, summaries and reference URLs are
  written by third parties and are passed on to the calling agent as data.
  The server strips control characters and limits their length, and marks
  the fields as untrusted in its tool schemas. It does not try to detect
  hostile text, so an agent reading the output must not act on instructions
  found in it.
- **The HTTP transport is unauthenticated unless `SEC1_HTTP_TOKEN` is set.**
  Without a token, anyone who can reach the port can use the server. It
  refuses requests from other browser origins in either case.
- **All tools are read-only.** The server writes nothing except its own
  response cache.
- **Credentials** (`GITHUB_TOKEN`, `NVD_API_KEY`, `SEC1_HTTP_TOKEN`) are read
  from the environment and are never written to logs or to the cache.
