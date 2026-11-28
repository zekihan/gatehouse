# Kubernetes controller

Install the Gateway API v1.6.3 standard CRDs and the Gatehouse CRDs in
`deploy/crds`. Create the operator and trust namespaces before applying the
RBAC manifests. The included service account is `gatehouse/gatehouse`.

Set `POD_NAME`, `POD_UID`, and `POD_NAMESPACE` from the Downward API. Label
replica Pods `app.kubernetes.io/name=gatehouse`. The default Gateway is
`gatehouse/gatehouse`, using controller name `gatehouse.noqer.com/controller`.
Run `gatehouse serve-kubernetes` and probe `GET /readyz` on its management
listener (port 8080). Keep that listener on the operator network.

Place the operator YAML in the `operator.yaml` key of the `gatehouse-operator`
ConfigMap. The generated role permits the standard three bootstrap Secrets
and two public trust ConfigMaps described in the design. Each app namespace
must grant the Gatehouse service account `get`, `list`, and `watch` for its
specific certificate Secret names through a Role with `resourceNames` and
a RoleBinding. Apply the same pattern for additional public trust ConfigMaps.
For a cross-namespace Gateway API reference, the target namespace also
needs a ReferenceGrant.

For each OIDC class, `gatehouse-bootstrap` supplies
`oidc-<class>-client-secret`, `cookie-<class>-current`, and
`cookie-<class>-previous`. Cookie keys are base64-encoded 32-byte values.
Register each callback as a Gatehouse-owned HTTPS listener with its
certificate. Gatehouse handles the configured callback path directly.
Browser probes can send `Accept: text/html` to `/oauth2/sign_in` on a
protected host to check the login redirect. The session cookie is named
`__Secure-gatehouse-session-<class>`. `POST /oauth2/sign_out` clears the
class session in the browser.

The generated controller Role permits Lease operations in the Gatehouse
namespace. Keep that namespace and its replica label under operator control.
Gatehouse writes acknowledgements named `gatehouse-ack-<pod>` every ten
seconds. A leader publishes Programmed only when every ready Pod has
acknowledged the current digest in the past 30 seconds.

Use `make generate` after changing policy types or controller permissions.
