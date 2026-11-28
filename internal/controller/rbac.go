package controller

// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses;gateways;listenersets;httproutes;tlsroutes;backendtlspolicies;referencegrants,verbs=get;list;watch
// +kubebuilder:rbac:groups=gateway.networking.k8s.io,resources=gatewayclasses/status;gateways/status;listenersets/status;httproutes/status;tlsroutes/status;backendtlspolicies/status,verbs=update
// +kubebuilder:rbac:groups=gatehouse.noqer.com,resources=routepolicies;backendpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=gatehouse.noqer.com,resources=routepolicies/status;backendpolicies/status,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces;services,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:namespace=gatehouse,groups="",resources=pods,verbs=list
// +kubebuilder:rbac:namespace=gatehouse,groups="",resources=configmaps,resourceNames=gatehouse-operator,verbs=get;list;watch
// +kubebuilder:rbac:namespace=gatehouse,groups="",resources=secrets,resourceNames=gatehouse-bootstrap;mtls-clients-v1-trust;cloudflare-edge-auth,verbs=get;list;watch
// +kubebuilder:rbac:namespace=gatehouse,groups=coordination.k8s.io,resources=leases,verbs=create;get;list;update
// +kubebuilder:rbac:namespace=external-ingress,groups="",resources=configmaps,resourceNames=device-ca,verbs=get;list;watch
// +kubebuilder:rbac:namespace=external-secrets,groups="",resources=configmaps,resourceNames=external-secrets-sops-ca,verbs=get;list;watch
