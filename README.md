# Gatehouse

Gatehouse is a Go edge proxy for the homelab. The scaffold ships the operator
configuration validator, JSON Schema, snapshot digest, and conformance harness.

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

The edge image is published as `ghcr.io/zekihan/gatehouse:edge` and
`docker.io/zekihan/gatehouse:edge`. To validate a local file with a read-only
container, mount the file so the image's unprivileged user can read it.

```sh
docker run --rm --read-only --network none \
  -v "$PWD/examples:/config:ro" ghcr.io/zekihan/gatehouse:edge \
  validate /config/operator.yaml
```
