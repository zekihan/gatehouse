# Gatehouse conformance

Run `make test/integration`. The harness builds the real Gatehouse binary,
generates disposable certificates and routes, and starts loopback app,
Authelia and LAPI mocks. The default driver converts the fixtures to an
operator configuration and a file snapshot. It waits for a real HTTPS route
to be ready through the CrowdSec check, then runs all 53 wire checks.
The limiter fault tests separately exercise three encrypted memberlist nodes
and deterministic loss, reordering, restart and partition schedules.

## Using a different driver

Set `GATEHOUSE_BENCH_DRIVER` to the absolute path to an executable. It runs
in `$BENCH_DIR`, which holds `bench.json` and the relative certificate paths.
It must bind loopback ports `$BENCH_TLS_PORT` and `$BENCH_METRICS_PORT` and
create `$BENCH_READY` when ready. The proxy binary path is in
`$GATEHOUSE_BINARY`. The mocks are at `$BENCH_APP_URL`, `$BENCH_AUTH_URL`
and `$BENCH_LAPI_URL`. Write request logs to stdout and diagnostics to stderr.
The driver runs every group by default. Set `GATEHOUSE_BENCH_FEATURES` to
a comma-separated list of groups to limit coverage.

## Wire check groups

- **proxy** (14). page status, page gzip, page gunzip size, hsts, frame options, nosniff, xss, referrer, permissions, coop, corp, robots, server stripped, powered-by stripped.
- **identity** (5). x-real-ip, x-forwarded-for, x-forwarded-proto, x-forwarded-host, spoof headers stripped.
- **streaming** (7). s3 get status, s3 get bytes, s3 identity, s3 head length, s3 big download, small not compressed, health body.
- **routing** (1). deny route.
- **tls** (1). unknown SNI alert.
- **mtls** (8). mtls no cert refused, mtls no cert no response, mtls identity forwarded, mtls spoof stripped, mtls other identity, mtls blocked fp, mtls rogue CA refused, sni host mismatch.
- **crowdsec** (1). crowdsec ban.
- **limits** (2). rate limit 429, rate limit first ok.
- **forward-auth** (6). forward auth deny, forward auth allow, bearer stripped, auth x-forwarded-uri, auth x-forwarded-method, auth x-forwarded-host.
- **uploads** (3). vm write, journald stream upload, journald method.
- **alpn** (3). h2, h2 mtls, h1.
- **observability** (2). JSON access log, metrics.

`make test/controller` runs the Kubernetes suite in a disposable, privileged
Docker container using the pinned k3s image. It installs the matching Gateway
API and generated Gatehouse CRDs and runs the controller with a service account
token scoped to the generated RBAC. The harness uses synthetic certificates,
credentials, replica readiness, and upstream endpoints.

The OIDC suite starts two Gatehouse replicas against a disposable Authelia
container. It saves pre-configured consent and verifies silent re-login,
navigation and form POST expiry, rejection of altered cookies and unlisted
return destinations, cookie and Authelia signing-key rotation, and logout.
The fixture uses seconds for session expiry. The operator example uses one
hour and eight hours.
