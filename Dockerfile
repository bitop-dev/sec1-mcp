# syntax=docker/dockerfile:1

# The build stage runs on the builder's own architecture and cross-compiles,
# so building for another platform needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.1.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags="-s -w -X github.com/bitop-dev/sec1-mcp/internal/server.Version=${VERSION}" \
      -o /out/sec1-mcp .

# A static binary on an image with no shell or package manager, running as
# an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sec1-mcp /usr/local/bin/sec1-mcp
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sec1-mcp"]
