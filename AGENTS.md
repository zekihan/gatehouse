# Gatehouse

Gatehouse is the homelab edge proxy. Follow `docs/gatehouse-design.md` on
`zekihan/homelab` main for operator configuration, trust boundaries, routing
and status. Keep the config types, JSON schema and example in sync. Changes
to snapshot inputs must preserve digest stability across replicas and include
changes to dependencies that affect behavior. Use disposable test material.

Run `make lint test test/race test/integration release-check` before publishing
changes, and `make container-test` for image changes. Use scoped conventional
commits. Push or publish only when explicitly authorized.
