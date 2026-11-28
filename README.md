# Gatehouse

Gatehouse is a Go edge proxy for the homelab. It validates operator
configuration and serves resolved snapshots.

```sh
make build
dist/gatehouse validate examples/operator.yaml
dist/gatehouse schema > gatehouse.schema.json
make lint test test/race test/integration
```

`gatehouse validate <file>` accepts one YAML or JSON document. It checks the
operator schema and references between ports, hosts and classes. On error it
exits with status 1 and identifies the invalid field. The full example expands
the placeholders in the operator design. See
[conformance coverage](tests/integration/README.md) for the wire assertions and
fixture driver.

The file-based data plane uses the same listener and request code as the
controller. For disposable fixtures, run:

```sh
dist/gatehouse serve --config operator.yaml --snapshot snapshot.json \
  --bind 127.0.0.1 --metrics 127.0.0.1:9101
```

The snapshot JSON uses the [resolved snapshot fields](internal/snapshot/dataplane.go).
The optional management listener serves `GET /metrics` and `GET /state`. See the
[state and metrics schema](docs/state.md) and [access log schema](docs/access-log.md).
The conformance tests
generate both input files and their disposable certificates.

### CrowdSec and shared limits

Both serving commands accept `--crowdsec-lapi` and `--crowdsec-key-file`.
Use Gatehouse's dedicated bouncer key. With `defaults.crowdsec` enabled,
readiness requires a complete LAPI snapshot. A failed refresh leaves the last
set in service until decisions individually expire. Each replica polls the full
stream every 60 seconds. Preparation measures live LAPI capacity at that rate.
If capacity is insufficient, the design switches to one lease-held delta
consumer that publishes versioned full state. That fallback needs its own
implementation and validation before use.

Set `--gossip-discover <headless-service>:7946` to share rate and in-flight
limits. The Service must publish unready addresses so replicas can exchange
state during startup. Allow TCP and UDP gossip only between Gatehouse pods.
Set `POD_NAME` or `--gossip-name` and put `--gossip-incarnation-file` on a
writable pod-local volume that persists across container restarts. The
`--gossip-key-dir` must contain a base64-encoded 32-byte `gossip-current` key
and can contain `gossip-previous`. To rotate, first load both keys everywhere
while the existing key remains primary, then roll with the new key as primary.
Without peer discovery the process enforces limits locally.

Configure `--ready-route` with an HTTPS URL for a public route on a direct
listener. The management `GET /readyz` endpoint uses that hostname for TLS and
HTTP and connects to the local listener. It requires a successful response
through the proxy after CrowdSec initialization and peer resync. Provide
`--ready-route-ca-file` if the route uses a private CA.

The edge image is published as `ghcr.io/zekihan/gatehouse:edge` and
`docker.io/zekihan/gatehouse:edge`. To validate a local file with a read-only
container, mount the file so the image's unprivileged user can read it.

```sh
docker run --rm --read-only --network none \
  -v "$PWD/examples:/config:ro" ghcr.io/zekihan/gatehouse:edge \
  validate /config/operator.yaml
```
