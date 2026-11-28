# Gatehouse conformance

Run `make test/integration`. The harness builds the real Gatehouse binary,
generates disposable certificates and routes, and starts loopback app,
Authelia and LAPI mocks. The default driver converts the fixtures to an
operator configuration and a file snapshot. It waits for a real HTTPS route
to be ready through the CrowdSec check, then runs all 56 wire checks.
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
- **streaming** (9). s3 get status, s3 get bytes, s3 identity, s3 head length, s3 put status, s3 put body received, s3 big download, small not compressed, health body.
- **routing** (1). deny route.
- **tls** (2). unknown SNI alert, missing SNI alert.
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

## Release gate

The Checks workflow and the pre-publication checks run unit and race tests,
the wire and controller integration tests, the tagged Gateway API subset,
and four bounded fuzz targets. Use `make audit` to run the same suites locally
along with module verification.

| Trust boundary | Required coverage |
| --- | --- |
| Listener identity | Untrusted and missing PROXY v2, invalid Cloudflare identity assertions, absent and unknown SNI, mTLS SNI and authority mismatch, and reserved request headers. |
| Registry and authorization | All six storage denies at cold start, with a catch-all route, and after route removal. Invalid route policy and absent, revoked, untrusted, or out-of-ceiling mTLS identities. Exact constraints and mandatory forward-auth for delegates and exceptions. |
| Kubernetes references | Namespace label removal, conflicting policies, named RBAC, backend CA rotation, EndpointSlice changes, invalid operator config, outage recovery, and replica acknowledgements. |
| Browser and machine auth | The Gatus sign-in request with `Accept: text/html`, rejection of invalid and altered session cookies, machine `401`, callback and return validation, expiry, rotation, and logout. |
| Abuse limits | Full CrowdSec snapshot recovery, three encrypted gossip peers, loss, duplicate and reordered state, partition healing, restart, slot-boundary limits, and high-cardinality state. |
| Request handling | Malformed request and log input, unconditional redaction, S3 byte counts, method matching, and non-idempotent request protections. |

### Gateway API v1.6.3 subset

`make test/conformance` runs the following upstream test functions under the
`conformance` build tag with the controller and a disposable k3s API.

- `HTTPRouteInvalidParentRefNotMatchingListenerPort`
- `HTTPRouteInvalidParentRefNotMatchingSectionName`
- `HTTPRouteInvalidParentRefSectionNameNotMatchingPort`
- `ListenerSetAllowedNamespaceNone`
- `ListenerSetDefaultNotAllowed`

The test harness provides a redirect Gateway and a Service for the first two
tests. The two ListenerSet manifests use a host-independent HTTP redirect
listener, as required by Gatehouse's operator model. Their upstream assertions
run unmodified. See the [Gateway API Implementer's Guide](https://gateway-api.sigs.k8s.io/guides/implementers-guide/)
for the requirements for a full conformance claim.

`make test/fuzz` runs bounded Go fuzzing for ClientHello replay, PROXY v2
address parsing, request path normalization, and query redaction. The normal
unit and race jobs also run the fuzz seeds.
