#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$root"
scratch=$(mktemp -d)
container="gatehouse-k3s-${scratch##*.}"
cleanup() {
    docker container rm --force "$container" >/dev/null 2>&1 || true
    rm -r -- "$scratch"
}
trap cleanup EXIT

image=rancher/k3s:v1.37.2-k3s1@sha256:21ea6e0fac4e3930c2ce8aa40ddd41a8b18cb3e9a0222c030dc005e7e88c4332
docker run -d --name "$container" --privileged -p 127.0.0.1::6443 "$image" server \
    --disable=traefik,servicelb,metrics-server,local-storage,coredns,network-policy \
    --flannel-backend=none >/dev/null

kubectl() {
    docker exec -i "$container" kubectl "$@"
}

for ((attempt = 0; attempt < 90; attempt++)); do
    if kubectl get --raw=/readyz >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
kubectl get --raw=/readyz >/dev/null

go_cmd=${GO:-go}
"$go_cmd" mod download sigs.k8s.io/gateway-api
gateway=$("$go_cmd" list -m -f '{{.Dir}}' sigs.k8s.io/gateway-api)
for crd in gatewayclasses gateways listenersets httproutes tlsroutes referencegrants backendtlspolicies; do
    kubectl apply -f - < "$gateway/config/crd/standard/gateway.networking.k8s.io_$crd.yaml" >/dev/null
done
for namespace in gatehouse external-ingress external-secrets bazarr; do
    kubectl create namespace "$namespace" >/dev/null
done
for file in deploy/crds/*.yaml deploy/rbac/role.yaml deploy/rbac/bindings.yaml \
    tests/integration/testdata/controller/objects.yaml; do
    kubectl apply -f - < "$file" >/dev/null
done

port=$(docker port "$container" 6443/tcp)
(umask 077 && docker exec "$container" cat /etc/rancher/k3s/k3s.yaml \
    | sed "s|https://127.0.0.1:6443|https://$port|" > "$scratch/kubeconfig")
GATEHOUSE_TEST_KUBECONFIG="$scratch/kubeconfig" "$go_cmd" test -tags=integration -run '^TestKubernetesController$' \
    -count=1 -timeout=4m -v ./internal/controller
