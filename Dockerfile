FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /gatehouse ./cmd/gatehouse

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /gatehouse /gatehouse
COPY LICENSE /LICENSE
USER 65532:65532
ENTRYPOINT ["/gatehouse"]
CMD ["version"]
LABEL org.opencontainers.image.source="https://github.com/zekihan/gatehouse" \
      org.opencontainers.image.licenses="AGPL-3.0" \
      org.opencontainers.image.title="gatehouse" \
      org.opencontainers.image.description="Gatehouse edge proxy and operator configuration validator"
