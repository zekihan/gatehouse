# Access log schema

Gatehouse writes newline-delimited JSON access records to standard output. A
matched RoutePolicy with `accessLog: off` suppresses the record, including a
refusal on that route. `accessLog: full` is the default. Requests rejected
before route selection and listener redirects use the default. Request metrics
are collected in both modes.

| Field | Type | Meaning |
| --- | --- | --- |
| `time` | string | UTC request start time in RFC 3339 format. |
| `request_id` | string | Gatehouse-generated identifier for correlating an access record. |
| `listener` | integer | Configured listening port. |
| `client_ip` | string | Address resolved by the listener's source policy. Empty when unavailable. |
| `client_identity` | string, optional | Validated identity reported by an authentication policy. |
| `tls.version` | integer, optional | Negotiated TLS wire version, such as 772 for TLS 1.3. |
| `tls.sni` | string, optional | TLS server name sent by the client. |
| `method` | string | Incoming HTTP method. |
| `host` | string | Incoming HTTP authority, including the port when present. |
| `path` | string | Escaped incoming path before routing and rewrites. |
| `query` | string, optional | Redacted incoming query without the leading `?`. |
| `proto` | string | HTTP protocol, for example `HTTP/2.0`. |
| `user_agent` | string, optional | Incoming User-Agent. |
| `referer` | string, optional | Incoming Referer with credentials removed. |
| `status` | integer | Response status. Gatehouse uses 499 when handling ended without a final response. |
| `bytes_in` | integer | Request body bytes read for the backend. |
| `bytes_out` | integer | Response body bytes written, after any compression. |
| `duration_ms` | number | Elapsed handling time in milliseconds. |
| `upstream_ms` | number | Elapsed upstream round-trip time through response headers or transport error, including dial retries. Zero when no backend round trip was attempted. |
| `route` | string | Matched `namespace/name` for a Kubernetes HTTPRoute. File snapshots without a namespace use the route name. Empty before a route matches. |
| `backend` | string | Selected service and port, in the form `namespace/name:port`. Empty before a backend is selected. |
| `deny_reason` | string, optional | Fixed Gatehouse reason when handling rejected the request. |

The values of `code`, `state`, `id_token`, `access_token`, `token`,
`X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Security-Token`, `Signature`, and
`AWSAccessKeyId` become `[redacted]` in the query and the Referer query. Gatehouse
checks each occurrence, compares names case-insensitively after percent
decoding, and checks both `&` and `;` separators. A malformed parameter name,
malformed Referer, or opaque Referer redacts the whole affected field. Referer
userinfo and fragments are removed. Cookies, Authorization, and response
Location headers are excluded from the access record. Redaction applies to
successful responses, errors, and redirects.

When the HTTP/1.x parser sends an error before routing, Gatehouse records the
status and `http_parse_error` with available connection metadata. Unparsed
request fields are empty and parser diagnostic text is discarded. TLS and HTTP/2
protocol failures that do not reach a request handler have no request access
record. TLS handshake results are available in `gatehouse_tls_handshakes_total`.

```json
{"time":"2026-11-28T00:00:00Z","request_id":"18ebf01956c40000-1","listener":8443,"client_ip":"192.0.2.1","tls.version":772,"tls.sni":"app.example.test","method":"GET","host":"app.example.test","path":"/objects","query":"Signature=[redacted]&page=1","proto":"HTTP/2.0","status":200,"bytes_in":0,"bytes_out":42,"duration_ms":3.1,"upstream_ms":2.5,"route":"app/web","backend":"app/web:8080"}
```
