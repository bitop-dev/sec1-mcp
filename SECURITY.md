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
  before use. No tool input is ever used as a host name: the services the
  server calls are fixed in the code, apart from vendor feed URLs, which
  come only from the catalog and from the catalog file the operator supplies.
- **The catalog file is trusted.** Whoever can write the file named by
  `-catalog` can make the server fetch the `https` URLs listed in it as
  feeds. Protect it as you would the server's own configuration.
- **Advisory text is untrusted.** Titles, summaries and reference URLs are
  written by third parties and are passed on to the calling agent as data.
  The server strips control characters and limits their length, and marks
  the fields as untrusted in its tool schemas. It does not try to detect
  hostile text, so an agent reading the output must not act on instructions
  found in it.
- **The HTTP transport is unauthenticated unless a token is configured**,
  with `SEC1_HTTP_TOKEN` or `SEC1_HTTP_TOKEN_FILE`. Without one, anyone who
  can reach the port can use the server. It refuses requests from other
  browser origins in either case. Tokens are shared secrets, not user
  logins: whoever holds a team's token is that team.
- **The metrics endpoint is unauthenticated.** It is served on a listener of
  its own so that it can be kept off the network that reaches the MCP
  endpoint. It exposes tool names, team names and request counts, and never
  what was looked up.
- **The audit log holds no lookup data.** It records who called which tool
  and how it went, not the arguments or the answer.
- **All tools are read-only.** The server writes nothing except its own
  response cache.
- **Credentials** (`GITHUB_TOKEN`, `NVD_API_KEY`, `SEC1_HTTP_TOKEN`, and the
  tokens in the token file) are read from the environment or that file and
  are never written to logs or to the cache. An error in the token file
  names the line and never shows its contents.
