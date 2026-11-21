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
| `-cache-dir <dir>` | | Where lookups are cached. Defaults to the user cache directory; `""` keeps the cache in memory only. |
| `-version` | | Print the version and exit. |
| | `SEC1_HTTP_TOKEN` | Require this bearer token on every MCP request over HTTP. |
| | `GITHUB_TOKEN` | Raises GitHub's limit of 60 requests an hour. Needs no scopes for public repositories. |
| | `NVD_API_KEY` | Raises NVD's limit of one request every six seconds. |

Tokens are read from the environment only, so they never appear in a
process listing, and they are never logged or cached.

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

When `SEC1_HTTP_TOKEN` is set, every request to `/mcp` must carry
`Authorization: Bearer <token>`; anything else gets 401.

When it is not set, the server logs a warning at start-up and accepts every
request. That is only reasonable when the server is bound to localhost, or
when something in front of it authenticates callers.

The token is a single shared secret. The server does not implement MCP's
OAuth authorization. If you need per-user access or audit trails, put it
behind a proxy that provides them.

Use TLS for anything that crosses a network: the token is sent on every
request. The server speaks plain HTTP, so terminate TLS at a proxy or
ingress.

## Container

Images are published to the GitHub Container Registry for `linux/amd64` and
`linux/arm64`:

| Tag | Built from |
| --- | --- |
| `main` | The latest commit on `main`. |
| `1.2.3`, `1.2`, `latest` | Version tags, once a release has been made. |
| `sha-<commit>` | One specific commit. |

The image holds a single static binary on a base with no shell or package
manager, and runs as an unprivileged user.

stdio, for an agent on the same machine:

```sh
docker run -i --rm ghcr.io/bitop-dev/sec1-mcp:main
```

HTTP. Inside a container the server must listen on all interfaces for the
published port to reach it:

```sh
docker run -d --name sec1-mcp -p 127.0.0.1:8080:8080 \
  -e SEC1_HTTP_TOKEN \
  ghcr.io/bitop-dev/sec1-mcp:main -http 0.0.0.0:8080
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
          image: ghcr.io/bitop-dev/sec1-mcp:main
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
  `api.github.com`, `services.nvd.nist.gov`, `www.cisa.gov`, `api.first.org`,
  `pypi.org`, `registry.npmjs.org` and `gitlab.com`. If you restrict egress,
  allow those.
- **Who can reach it.** Keep the Service cluster-internal, and use a
  NetworkPolicy to limit which pods may call it. Expose it outside the
  cluster only through an ingress with TLS.
- **Replicas.** More than one works, since there are no sessions. Each
  replica keeps its own cache and its own NVD queue, so more replicas use up
  the NVD and GitHub rate limits faster. Set `NVD_API_KEY` and
  `GITHUB_TOKEN` if you scale out.
- **Pin the image.** `main` moves. Use a version tag or a digest once a
  release exists.
