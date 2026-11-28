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
The optional metrics listener serves `GET /metrics`. The conformance tests
generate both input files and their disposable certificates.

The edge image is published as `ghcr.io/zekihan/gatehouse:edge` and
`docker.io/zekihan/gatehouse:edge`. To validate a local file with a read-only
container, mount the file so the image's unprivileged user can read it.

```sh
docker run --rm --read-only --network none \
  -v "$PWD/examples:/config:ro" ghcr.io/zekihan/gatehouse:edge \
  validate /config/operator.yaml
```
