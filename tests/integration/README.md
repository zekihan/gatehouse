# Gatehouse conformance

Run `make test/integration`. CI launches the real Gatehouse binary to validate
operator configuration, creates disposable certificate and route fixtures, and
starts loopback app, Authelia and LAPI mocks. All 53 wire assertions run through
the integration harness. The current scaffold reports the wire assertions
below as skips until the corresponding server features are available.

## Running wire checks

Set `GATEHOUSE_BENCH_DRIVER` to the absolute path to an executable that
translates `$BENCH_DIR/bench.json` into server resources and runs the
`$GATEHOUSE_BINARY` supplied by the test. The driver runs in `$BENCH_DIR`, where
certificate paths are relative. It must bind loopback ports `$BENCH_TLS_PORT`
and `$BENCH_METRICS_PORT` and signal readiness by creating `$BENCH_READY` once
the proxy is ready to serve. The runner captures stdout and stderr in the
fixture directory. Keep request logs on stdout and diagnostics on stderr.
The app, auth and LAPI URLs are also passed in `$BENCH_APP_URL`,
`$BENCH_AUTH_URL` and `$BENCH_LAPI_URL`.

The driver runs all suites by default. To enable suites as features land, set
`GATEHOUSE_BENCH_FEATURES` to a comma-separated list of the names below. The
runner accounts for every check and fails on a mismatch.

## Wire checks skipped in the scaffold

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
