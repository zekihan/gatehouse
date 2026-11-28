// Package v1alpha1 defines the Gatehouse policy API.
//
// +groupName=gatehouse.noqer.com
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const Group = "gatehouse.noqer.com"

// RoutePolicy is the namespaced policy resource.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type RoutePolicy struct {
	metav1.TypeMeta   `json:",inline"` //nolint:revive // Kubernetes API embedding used by controller-gen.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RoutePolicySpec `json:"spec"`
	Status PolicyStatus    `json:"status,omitempty"`
}

// BackendPolicy is the namespaced policy resource.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type BackendPolicy struct {
	metav1.TypeMeta   `json:",inline"` //nolint:revive // Kubernetes API embedding used by controller-gen.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackendPolicySpec `json:"spec"`
	Status PolicyStatus      `json:"status,omitempty"`
}

type TargetRef struct {
	// +kubebuilder:validation:MaxLength=253
	Group string `json:"group"`
	// +kubebuilder:validation:Enum=HTTPRoute;Service
	Kind string `json:"kind"`
	// +kubebuilder:validation:Pattern="^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$"
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:Pattern="^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
	// +kubebuilder:validation:MaxLength=63
	SectionName string `json:"sectionName,omitempty"`
}

// RoutePolicySpec applies additional restrictions and overrides to local HTTPRoute rules.
//
// +kubebuilder:validation:XValidation:rule="self.targetRefs.all(r, r.group == 'gateway.networking.k8s.io' && r.kind == 'HTTPRoute')",message="RoutePolicy targets local HTTPRoutes or their named rules"
type RoutePolicySpec struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	TargetRefs []TargetRef `json:"targetRefs"`
	MTLS       *MTLS       `json:"mtls,omitempty"`
	Auth       *Auth       `json:"auth,omitempty"`
	Deny       *Deny       `json:"deny,omitempty"`
	// +kubebuilder:validation:MaxProperties=32
	ResponseHeaders map[string]string `json:"responseHeaders,omitempty"`
	Compression     *Compression      `json:"compression,omitempty"`
	Limits          *Limits           `json:"limits,omitempty"`
	Deadlines       *Deadlines        `json:"deadlines,omitempty"`
	// +kubebuilder:validation:Enum=on;off
	AccessLog string `json:"accessLog,omitempty"`
	// +kubebuilder:validation:Enum=exempt
	CrowdSec string `json:"crowdsec,omitempty"`
}

type MTLS struct {
	// +kubebuilder:validation:MaxLength=253
	IdentityPrefix string `json:"identityPrefix,omitempty"`
	// +kubebuilder:validation:MaxItems=128
	// +listType=set
	Identities []string `json:"identities,omitempty"`
	// +kubebuilder:validation:MaxProperties=128
	Constraints map[string]Constraint `json:"constraints,omitempty"`
	// +kubebuilder:validation:MaxItems=128
	// +listType=set
	BlockedFingerprints []string `json:"blockedFingerprints,omitempty"`
	// +kubebuilder:validation:MaxItems=128
	// +listType=set
	DisabledIdentities []string `json:"disabledIdentities,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	// +listType=set
	TrustedAnchors []string `json:"trustedAnchors,omitempty"`
	// +kubebuilder:validation:MaxItems=8
	// +listType=set
	ForwardHeaders []string `json:"forwardHeaders,omitempty"`
}

type Constraint struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=set
	Methods []string `json:"methods"`
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=set
	Paths []string `json:"paths"`
}

// Auth selects a class within the limits of the host registry.
//
// +kubebuilder:validation:XValidation:rule="has(self.oidc) != has(self.forwardAuth)",message="choose exactly one authentication class"
type Auth struct {
	// +kubebuilder:validation:MinLength=1
	OIDC string `json:"oidc,omitempty"`
	// +kubebuilder:validation:MinLength=1
	ForwardAuth string `json:"forwardAuth,omitempty"`
}

type Deny struct {
	// +kubebuilder:validation:MaxItems=32
	// +listType=set
	Prefixes []string `json:"prefixes,omitempty"`
	// +kubebuilder:validation:MaxItems=32
	// +listType=set
	Exact []string `json:"exact,omitempty"`
}

type Compression struct {
	// +kubebuilder:validation:MaxItems=3
	// +listType=set
	Encodings []string `json:"encodings"`
	// +kubebuilder:validation:Minimum=0
	MinBytes int `json:"minBytes"`
}

type Limits struct {
	PerRouteClient ClientLimits `json:"perRouteClient"`
	PerRouteHost   HostLimits   `json:"perRouteHost"`
}

type ClientLimits struct {
	// +kubebuilder:validation:Minimum=1
	PerMinute int `json:"perMinute"`
	// +kubebuilder:validation:Minimum=1
	PerSecondSlot int `json:"perSecondSlot"`
	// +kubebuilder:validation:Minimum=1
	InFlight int `json:"inFlight"`
}

type HostLimits struct {
	// +kubebuilder:validation:Minimum=1
	InFlight int `json:"inFlight"`
}

type Deadlines struct {
	Dial           string `json:"dial,omitempty"`
	TLS            string `json:"tls,omitempty"`
	RequestBody    string `json:"requestBody,omitempty"`
	ResponseHeader string `json:"responseHeader,omitempty"`
	ResponseBody   string `json:"responseBody,omitempty"`
	UpgradeIdle    string `json:"upgradeIdle,omitempty"`
}

// BackendPolicySpec configures transport for named Service ports.
//
// +kubebuilder:validation:XValidation:rule="self.targetRefs.all(r, size(r.group) == 0 && r.kind == 'Service' && has(r.sectionName))",message="BackendPolicy targets named ports of local Services"
// +kubebuilder:validation:XValidation:rule="!has(self.sni) || (has(self.tls) && self.tls == 'required')",message="sni requires TLS"
type BackendPolicySpec struct {
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	TargetRefs []TargetRef `json:"targetRefs"`
	// +kubebuilder:validation:Enum=required
	TLS string `json:"tls,omitempty"`
	// +kubebuilder:validation:MaxLength=253
	SNI string `json:"sni,omitempty"`
	// +kubebuilder:validation:MaxLength=63
	StickyCookie string `json:"stickyCookie,omitempty"`
	ClusterIP    bool   `json:"clusterIP,omitempty"`
	// +kubebuilder:validation:Enum=IPv4;IPv6
	AddressFamily string `json:"addressFamily,omitempty"`
	DialTimeout   string `json:"dialTimeout,omitempty"`
	ProxyV2       bool   `json:"proxyV2,omitempty"`
}

type PolicyStatus struct {
	// +kubebuilder:validation:MaxItems=16
	Ancestors []Ancestor `json:"ancestors,omitempty"`
}

type Ancestor struct {
	AncestorRef    AncestorRef `json:"ancestorRef"`
	ControllerName string      `json:"controllerName"`
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions"`
}

type AncestorRef struct {
	Group       string `json:"group"`
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	SectionName string `json:"sectionName,omitempty"`
}
