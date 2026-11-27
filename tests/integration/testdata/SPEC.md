# Edge proxy benchmark spec

Build a TLS-terminating reverse proxy that reproduces the subset of Traefik the homelab
actually uses (measured from cluster-1 on 2026-11-27). Three implementations (Go, Rust,
Zig) and Traefik v3.8.0 with the real plugins are benchmarked on identical work. The
implementation must be written as you would write the production version: idiomatic,
best ecosystem libraries, release build, no shortcuts that a production edge could not
take (no response caching, no skipping verification, no hardcoded responses).

`$B` below is the bench root (the directory containing this file).

## Interface

- Binary: `$B/impl/<lang>/edge-<lang>`, run as `edge-<lang> --config <path>`.
- Config: JSON at `$B/config/bench.json` (bench), `$B/config/bench-<lang>.json`
  (your development copy, same content but your own listen ports). Read everything from
  the config; hardcode nothing that appears there.
- Readiness: start serving only after certificates, routes and the CrowdSec startup
  decision stream are loaded (Traefik's `streamStartupBlock: true`).
- Access log: one line per request on **stdout** (the bench redirects it to a file).
- Use every CPU in the process affinity mask (the bench pins the proxy to 2 CPUs);
  do not hardcode thread counts.

## Config schema (`bench.json`)

- `listen`: TLS listener address. `metricsListen`: plain-HTTP Prometheus `/metrics`.
- `tls.minVersion` `"1.2"`; `tls.alpn` `["h2","http/1.1"]`; `tls.hosts[]`: `{name, cert, key, mtls}`.
  `cert` is a PEM chain (leaf + intermediate), RSA-2048 leaf like the Let's Encrypt certs in
  production. `tls.defaultHost`: certificate served when SNI is missing or unknown.
  `tls.clientCa`: PEM CA for client certificates.
- `timeouts`: `readSeconds`, `writeSeconds`, `idleSeconds` (all 300), `keepAliveMaxRequests` (1000).
- `crowdsec`: `lapiUrl`, `apiKey`, `updateIntervalSeconds` (60).
- `forwardAuth.<name>`: `address`, `authRequestHeaders`, `stripAfterAuth`, `maxResponseBodyBytes`.
- `mtlsPolicies.<name>`: `trustedIssuers` (SHA-256 hex of the DER trust-anchor cert),
  `identityPrefix`, `identities`, `disabledIdentities`, `blockedFingerprints` (SHA-256 hex
  of leaf DER), `forwardIdentityHeader`.
- `routes[]` (90): `name`, `host`, `path` (nullable), `pathType` (`prefix`|`exact`|null),
  `method` (nullable), `action` (`proxy`|`deny`), `backend` (base URL), `middlewares`
  (`realIp`, `crowdsec`, `inFlight{perClientIp,perHost}`, `rateLimit{average,periodSeconds,burst}`,
  `securityHeaders`, `compress{encodings,minBytes}`), `mtlsPolicy` (nullable), `forwardAuth` (nullable).

## TLS

1. TLS 1.2 and 1.3. Choose the certificate by SNI; unknown or absent SNI gets `defaultHost`'s cert.
2. Hosts with `mtls: true` require and verify a client certificate against `tls.clientCa`
   (Traefik `RequireAndVerifyClientCert`, `sniStrict`, session tickets disabled). A missing or
   unverifiable certificate fails the handshake. Hosts without `mtls` must not request one.
   This requires choosing a per-SNI server configuration during the handshake.
3. ALPN `h2` and `http/1.1`. HTTP/2 is required for Go and Rust; for Zig it is optional
   (report if absent). HTTP/1.1 keep-alive is required everywhere.
4. Request `Host` (port ignored) must equal SNI when either side is an mTLS host; otherwise
   respond `421`.

## Routing

Match `Host` (case-insensitive, port ignored), then the route with an `exact` path equal to
the request path, else the longest matching `prefix`. A route's `method`, when set, must
match; a route whose method does not match is skipped. No match: `404`. `action: deny`
responds `403` (still after real IP).

## Middleware order (per request)

1. **Real IP** (entrypoint middleware, `traefik-real-ip` scoped direct mode): client IP is
   the TCP peer. Delete `Cf-Connecting-Ip`, `Cf-Connecting-Ipv6`, `Cf-Pseudo-Ipv4`,
   `Eo-Connecting-Ip`, `True-Client-Ip`, `X-Client-Ip`, `X-Cluster-Client-Ip`,
   `X-Original-Forwarded-For`, `Fastly-Client-Ip`, `Forwarded`, `X-Is-Trusted`; set
   `X-Real-IP` and `X-Forwarded-For` to the peer IP (replacing any client values).
2. **mTLS authorization** (routes with `mtlsPolicy`, `traefik-mtls-authz` semantics): from the
   verified chain, the trust anchor fingerprint must be in `trustedIssuers` and every chain
   cert valid now (±60 s). Leaf fingerprint not in `blockedFingerprints`. The leaf SAN must
   contain exactly one entry and it must be a URI, matching
   `^urn:noqer:mtls:[a-z0-9]+(-[a-z0-9]+)*:[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, ≤128 chars, with
   `identityPrefix`, not in `disabledIdentities`, and in `identities`. Deny: `403`, headers
   `Cache-Control: no-store` and `X-Mtls-Authz-Reason: <reason>`. Allow: delete every request
   header whose lowercase name starts with `x-mtls-` (plus `x-forwarded-tls-client-cert`,
   `x-forwarded-tls-client-cert-info`), then set `forwardIdentityHeader` to the identity.
3. **Standard chain** (every non-deny route):
   - `X-Forwarded-Proto: https`; `X-Forwarded-Host:` the request `Host` header verbatim.
   - **CrowdSec** stream bouncer: on startup `GET {lapiUrl}/v1/decisions/stream?startup=true`
     with header `X-Api-Key`; then every `updateIntervalSeconds` `?startup=false`, applying
     `new` and `deleted` (both may be null). Keep `type: ban`, `scope: Ip` decisions in memory
     (~40k entries). Client IP banned → `403`.
   - **In-flight limits**: concurrent requests per client IP ≤ `perClientIp` and per request
     host ≤ `perHost`, else `429`.
   - **Rate limit**: token bucket per client IP, `average` requests per `periodSeconds`,
     `burst` capacity, else `429`. (Bench routes use a huge limit so it computes without
     triggering; host `rl.bench.test` uses 60/min burst 5.)
   - **Forward auth** (routes with `forwardAuth`): before proxying, `GET` the auth `address`
     with only the listed `authRequestHeaders` plus `X-Forwarded-Method`, `X-Forwarded-Proto`,
     `X-Forwarded-Host`, `X-Forwarded-Uri` (path+query), `X-Forwarded-For`. 2xx → continue
     and delete `stripAfterAuth` headers from the proxied request. Otherwise return the auth
     response status and body (cap body at `maxResponseBodyBytes`) to the client. Reuse
     connections to the auth server.
   - **Proxy** to `backend` over HTTP/1.1 with a keep-alive connection pool, request and
     response bodies **streamed** (a 64 MB upload or download must not be buffered in memory),
     hop-by-hop headers handled per RFC 9110. Upstream failure before a response → `502`.
   - **Security response headers** (overwrite): `Strict-Transport-Security: max-age=31536000;
     includeSubDomains; preload`, `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options:
     nosniff`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy:
     strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), midi=(), camera=(),
     usb=(), magnetometer=(), accelerometer=(), gyroscope=(), microphone=()`,
     `Cross-Origin-Embedder-Policy: unsafe-none`, `Cross-Origin-Opener-Policy: same-origin`,
     `Cross-Origin-Resource-Policy: same-site`, `X-Robots-Tag:
     none,noarchive,nosnippet,notranslate,noimageindex`, `X-Forwarded-Proto: https`;
     delete `Server` and `X-Powered-By`.
   - **Compression**: gzip (library default level) when the client accepts gzip, the
     response has no `Content-Encoding`, and the body is ≥ `minBytes` (use `Content-Length`
     when present; for unknown length buffer at most `minBytes` to decide). Add
     `Vary: Accept-Encoding`, drop `Content-Length` when compressing. Stream the compressor
     output; never compress `HEAD`, `204` or `304`.
4. **Access log** line, Traefik CLF (`common`) format, written after the response:
   `<clientip> - - [02/Jan/2006:15:04:05 -0700] "<METHOD> <path?query> <HTTP/1.1|HTTP/2.0>" <status> <bytes-sent> "<Referer or ->" "<User-Agent or ->" <request-count> "<route-name>" "<backend-url>" <duration-ms>ms`
5. **Metrics** on `metricsListen` `/metrics`, Prometheus text: per route a request counter
   by `code` and `method`, and a duration histogram with buckets
   `0.05,0.1,0.25,0.5,1,2.5,5,10,30`; label `router="<route-name>"`.

## Out of scope

Kubernetes watching and hot reload, ACME, HTTP→HTTPS redirect, UDP/TCP routing, brotli and
zstd, OIDC. Note them in your report if your design has implications for them.

## Gatehouse integration

This is the original benchmark contract. Gatehouse's operator design supersedes
the old fallback certificate, CrowdSec deltas, CLF logs and metric names. The
portable bench fixture describes routes and test certificates for a driver to
translate to Gatehouse resources. See [the conformance runner](../README.md).
