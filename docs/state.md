# State and metrics

`GET /state` on the management listener returns the local replica's JSON state
with `Cache-Control: no-store`. A valid response is HTTP 200 even before the
replica is ready. `GET /readyz` also tests the configured route probe when present. The management address comes from `--management` in Kubernetes and
`--metrics` when serving a file snapshot.

Publish only the state route at `gatehouse-cluster-1.noqer.com` through the
named admin mTLS policy. Restrict direct access to the management port with
NetworkPolicy. The management listener uses plain HTTP for traffic from the
authorized ingress, monitoring, and probe clients.

| Field | Type | Meaning |
| --- | --- | --- |
| `snapshot_digest` | string | Digest of the active data-plane snapshot. Empty before a snapshot is installed. |
| `ready` | boolean | The local snapshot and listening sockets are ready and policy prerequisites have passed. |
| `device_tls_exceptions` | integer | Number of device TLS exceptions configured in the active snapshot. Expired entries are still counted until removed from configuration. |
| `listeners` | array | Configured listeners, sorted by ascending port. Empty before a snapshot is installed. |
| `listeners[].port` | integer | Configured port. |
| `listeners[].mode` | string | Configured mode. Empty means the default TLS mode. |
| `listeners[].open_connections` | integer | Currently accepted TCP connections, including handshakes, keep-alive, upgraded streams, and TLS passthrough. |
| `controller` | object, Kubernetes only | Local controller status. |
| `controller.operator_config_generation` | string | Resource version of the last accepted operator ConfigMap. Empty before acceptance. |
| `controller.operator_config_rejected` | boolean | The latest observed operator configuration was rejected. |
| `controller.config_errors` | integer | Operator configuration rejection count since process startup. |
| `controller.api_last_sync_timestamp` | integer | Unix timestamp in seconds of the last successful Kubernetes API probe. Zero before the first success. |

```json
{
  "snapshot_digest": "b90d86e66eb4c8272e917d10243a775ed36ed7d30ab71616e73403113ab065b87",
  "ready": true,
  "device_tls_exceptions": 0,
  "listeners": [{"port": 8443, "mode": "", "open_connections": 2}],
  "controller": {
    "operator_config_generation": "541",
    "operator_config_rejected": false,
    "config_errors": 0,
    "api_last_sync_timestamp": 1795824000
  }
}
```

The same listener serves `GET /metrics` using Prometheus text exposition.

| Metric | Type | Labels |
| --- | --- | --- |
| `gatehouse_requests_total` | counter | `listener, route, backend, code, method` |
| `gatehouse_request_duration_seconds` | histogram | Same request labels |
| `gatehouse_upstream_duration_seconds` | histogram | Same request labels. Only records requests that attempt a backend round trip. |
| `gatehouse_request_bytes_total` | counter | Same request labels |
| `gatehouse_response_bytes_total` | counter | Same request labels |
| `gatehouse_certificate_expiry_timestamp_seconds` | gauge | `listener, host`, local certificate expiry as a Unix timestamp |
| `gatehouse_tls_handshakes_total` | counter | `result`, including `unrecognized_name` |
| `gatehouse_denies_total` | counter | `reason` |
| `gatehouse_crowdsec_decisions` | gauge | None |
| `gatehouse_crowdsec_staleness_seconds` | gauge | None |
| `gatehouse_gossip_peers` | gauge | None |
| `gatehouse_gossip_peer_staleness_seconds` | gauge | `peer` |
| `gatehouse_limiter_isolated` | gauge | None, 1 when counting alone |
| `gatehouse_limiter_capacity_overflow_total` | counter | None |
| `gatehouse_limiter_resync_pending` | gauge | None, 1 when waiting to resynchronize |
| `gatehouse_limiter_pressure` | gauge | `route`, highest utilization as a ratio over one minute |
| `gatehouse_snapshot_digest_info` | gauge | `digest`, value 1 for the active snapshot |
| `gatehouse_config_errors` | counter | None, Kubernetes only |
| `gatehouse_api_last_sync_timestamp` | gauge | None, Kubernetes only |
| `gatehouse_device_tls_exceptions` | gauge | None |
| `gatehouse_open_connections` | gauge | `listener` |

Unrecognized HTTP methods are grouped under `OTHER` in metrics. Traffic and
denial series appear after the first matching observation. When a policy
component is absent, its unlabeled samples are zero and its per-peer or
per-route series are absent.
