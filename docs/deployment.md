# Running the server

## Choosing a transport

| | stdio | Streamable HTTP |
| --- | --- | --- |
| Who starts the server | The agent, as a child process | You, as a service |
| Where the agent is | Same machine | Anywhere that can reach it |
| Authentication | None needed; only the parent process can talk to it | Bearer token, optional but recommended |
| Good for | One person's agent | A team, or agents running in a cluster |

Both follow MCP specification revision 2026-07-28.

## Settings

| Flag | Environment variable | Meaning |
| --- | --- | --- |
| `-catalog <path>` | `SEC1_CATALOG` | A catalog file of your own products, added to the built-in catalog. See [catalog.md](catalog.md). |
| `-http <addr>` | `SEC1_HTTP_ADDR` | Serve Streamable HTTP on this address, such as `127.0.0.1:8080`. Without it, the server uses stdio. |
| `-http-json` | | Answer HTTP requests with plain JSON bodies instead of event streams. |
| `-http-token-file <path>` | `SEC1_HTTP_TOKEN_FILE` | A file of named bearer tokens, one `name token` per line, so that callers can be told apart. |
| `-http-rate <n>` | `SEC1_HTTP_RATE` | The most requests each client may make in a minute over HTTP. 0, the default, means no limit. |
| `-metrics <addr>` | `SEC1_METRICS_ADDR` | Serve Prometheus metrics at `http://<addr>/metrics`, on a listener of its own. |
| `-log-format <format>` | | `text`, the default, or `json`. |
| `-cache-dir <dir>` | | Where lookups are cached. Defaults to the user cache directory; `""` keeps the cache in memory only. |
| `-version` | | Print the version and exit. |
| | `SEC1_HTTP_TOKEN` | Require this bearer token on every MCP request over HTTP. One token for everyone; see `-http-token-file` for one per team. |
| | `GITHUB_TOKEN` | Raises GitHub's limit of 60 requests an hour. Needs no scopes for public repositories. |
| | `NVD_API_KEY` | Raises NVD's limit of one request every six seconds. |

Tokens are read from the environment only, so they never appear in a
process listing, and they are never logged or cached.

None of them is required. The server needs no account anywhere: `GITHUB_TOKEN`
and `NVD_API_KEY` only raise rate limits, and `SEC1_HTTP_TOKEN` is a secret
you choose yourself.

## stdio

```sh
bin/sec1-mcp
```

The server reads requests from stdin, writes responses to stdout, and logs
to stderr. It exits when stdin closes. See [agents.md](agents.md) for how to
register the command with an agent.

## Streamable HTTP

```sh
SEC1_HTTP_TOKEN="$(openssl rand -hex 32)" bin/sec1-mcp -http 127.0.0.1:8080
```

| Path | Method | Purpose |
| --- | --- | --- |
| `/mcp` | `POST` | The MCP endpoint. |
| `/healthz` | `GET` | Returns `200 ok`. Needs no token. For load balancers and probes. |

How the endpoint behaves:

- **Responses are event streams by default** (`text/event-stream`). With
  `-http-json` each response is a single `application/json` body, which
  suits proxies that buffer responses. MCP clients accept either.
- **There are no sessions.** The server does not issue or read
  `Mcp-Session-Id`, so any replica can answer any request, and it can sit
  behind an ordinary load balancer.
- **`GET` and `DELETE` on `/mcp` return 405.**
- **Requests from other browser origins are refused** with 403, whether or
  not a token is set.

### Authentication

When `SEC1_HTTP_TOKEN` or `SEC1_HTTP_TOKEN_FILE` is set, every request to
`/mcp` must carry `Authorization: Bearer <token>`; anything else gets 401.

When neither is set, the server logs a warning at start-up and accepts every
request. That is reasonable when the server is bound to localhost, when
something in front of it authenticates callers, or when it sits on a network
that only your own staff can reach; see
[Running without authentication](shared-service.md#running-without-authentication).

`SEC1_HTTP_TOKEN` is one secret for everyone. `SEC1_HTTP_TOKEN_FILE` gives
each team its own named token, which is what you want for a service several
teams share; see [shared-service.md](shared-service.md). Both are shared
secrets, not user logins: the server does not implement MCP's OAuth
authorization. If you need per-person identity, put it behind a proxy that
provides it.

Use TLS for anything that crosses a network: the token is sent on every
request. The server speaks plain HTTP, so terminate TLS at a proxy or
ingress.

## Container

Images are published to the GitHub Container Registry for `linux/amd64` and
`linux/arm64`:

| Tag | Built from |
| --- | --- |
| `0.3.0`, `0.3`, `latest` | A release. `0.3` follows the newest 0.3 release, and `latest` the newest of all. |
| `main` | The latest commit on `main`, which may be ahead of the release. |
| `sha-<commit>` | One specific commit. |

The image holds a single static binary on a base with no shell or package
manager, and runs as an unprivileged user.

stdio, for an agent on the same machine:

```sh
docker run -i --rm ghcr.io/bitop-dev/sec1-mcp:latest
```

HTTP. Inside a container the server must listen on all interfaces for the
published port to reach it:

```sh
docker run -d --name sec1-mcp -p 127.0.0.1:8080:8080 \
  -e SEC1_HTTP_TOKEN \
  ghcr.io/bitop-dev/sec1-mcp:latest -http 0.0.0.0:8080
```

To build the image yourself:

```sh
docker build -t sec1-mcp .
```

### Keeping the cache

The cache lives in the container user's cache directory,
`/home/nonroot/.cache/sec1-mcp`. It is lost when the container is removed,
which only costs slower first lookups. Mount a volume there to keep it.

## Kubernetes

For a service several teams share, start from
[`deploy/kubernetes.yaml`](../deploy/kubernetes.yaml) and
[shared-service.md](shared-service.md) instead of the manifest below.

A minimal deployment. The token comes from a Secret you create separately:

```sh
kubectl create secret generic sec1-mcp --from-literal=token="$(openssl rand -hex 32)"
```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sec1-mcp
spec:
  replicas: 1
  selector:
    matchLabels: {app: sec1-mcp}
  template:
    metadata:
      labels: {app: sec1-mcp}
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: sec1-mcp
          image: ghcr.io/bitop-dev/sec1-mcp:0.3.0
          args: ["-http", "0.0.0.0:8080"]
          ports:
            - {name: http, containerPort: 8080}
          env:
            - name: SEC1_HTTP_TOKEN
              valueFrom:
                secretKeyRef: {name: sec1-mcp, key: token}
          readinessProbe:
            httpGet: {path: /healthz, port: http}
          livenessProbe:
            httpGet: {path: /healthz, port: http}
          resources:
            requests: {cpu: 50m, memory: 64Mi}
            limits: {memory: 256Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts:
            - {name: cache, mountPath: /home/nonroot/.cache}
      volumes:
        - name: cache
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: sec1-mcp
spec:
  selector: {app: sec1-mcp}
  ports:
    - {name: http, port: 80, targetPort: http}
```

Things to decide for your cluster:

- **Your own catalog.** Mount it from a ConfigMap and point `SEC1_CATALOG`
  at the file.
- **Outbound access.** The pod needs HTTPS to `api.osv.dev`,
  `api.github.com`, `raw.githubusercontent.com`, `services.nvd.nist.gov`,
  `www.cisa.gov`, `api.first.org`, `endoflife.date`, `pypi.org`,
  `registry.npmjs.org`, `gitlab.com` and `about.gitlab.com`, plus the host
  of any feed in your own catalog file. If you restrict egress, allow
  those. A host that is blocked shows up as a failed source in `coverage`.
- **Who can reach it.** Keep the Service cluster-internal, and use a
  NetworkPolicy to limit which pods may call it. Expose it outside the
  cluster only through an ingress with TLS.
- **Replicas.** More than one works, since there are no sessions. Each
  replica keeps its own cache and its own NVD queue, so more replicas use up
  the NVD and GitHub rate limits faster. Set `NVD_API_KEY` and
  `GITHUB_TOKEN` if you scale out.
- **Pin the image.** `latest` and `main` move. Use a version tag, as above,
  or a digest.
