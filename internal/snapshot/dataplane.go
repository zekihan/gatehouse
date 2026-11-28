package snapshot

import (
	"strings"
	"time"

	"github.com/zekihan/gatehouse/internal/config"
)

// DataPlane contains resolved inputs. The controller must publish it as
// immutable and include every dependency used to produce it in the digest.
type DataPlane struct {
	Ports       map[uint16]map[string]Host   `json:"ports,omitempty"`
	Hosts       map[string]Host              `json:"hosts"`
	EdgeSecrets map[string]map[string]string `json:"edgeSecrets,omitempty"`
}

// Host is keyed by the exact registry hostname. A missing certificate or
// passthrough backend makes the host unavailable for TLS.
type Host struct {
	Certificate *KeyPair `json:"certificate,omitempty"`
	ClientCA    []byte   `json:"clientCA,omitempty"`
	Passthrough *Backend `json:"passthrough,omitempty"`
	Routes      []Route  `json:"routes,omitempty"`
}

type KeyPair struct {
	CertPEM []byte `json:"certPEM"`
	KeyPEM  []byte `json:"keyPEM"`
}

// Route is one match from a Gateway API rule. A nil or invalid backend
// produces a terminal error after matching.
type Route struct {
	Namespace           string              `json:"namespace"`
	Name                string              `json:"name"`
	Created             time.Time           `json:"created"`
	HostnameSpecificity int                 `json:"hostnameSpecificity,omitempty"`
	Path                string              `json:"path"`
	Exact               bool                `json:"exact,omitempty"`
	Method              string              `json:"method,omitempty"`
	Headers             []Match             `json:"headers,omitempty"`
	Query               []Match             `json:"query,omitempty"`
	Deny                *config.Deny        `json:"deny,omitempty"`
	InvalidPolicy       bool                `json:"invalidPolicy,omitempty"`
	MTLS                *MTLSPolicy         `json:"mtls,omitempty"`
	ForwardAuth         string              `json:"forwardAuth,omitempty"`
	Rewrite             *Rewrite            `json:"rewrite,omitempty"`
	RequestHeaders      HeaderFilter        `json:"requestHeaders,omitzero"`
	ResponseHeaders     HeaderFilter        `json:"responseHeaders,omitzero"`
	Backends            []WeightedBackend   `json:"backends,omitempty"`
	Limits              *config.Limits      `json:"limits,omitempty"`
	Backend             *Backend            `json:"backend,omitempty"`
	Compression         *config.Compression `json:"compression,omitempty"`
	Deadlines           Deadlines           `json:"deadlines,omitzero"`
	AccessLogOff        bool                `json:"accessLogOff,omitempty"`
	CrowdSecExempt      bool                `json:"crowdSecExempt,omitempty"`
}

type WeightedBackend struct {
	Weight  uint32   `json:"weight"`
	Backend *Backend `json:"backend"`
}

type Match struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Regex bool   `json:"regex,omitempty"`
}

type MTLSPolicy struct {
	IdentityPrefix      string                               `json:"identityPrefix"`
	Identities          []string                             `json:"identities"`
	Constraints         map[string]config.IdentityConstraint `json:"constraints,omitempty"`
	BlockedFingerprints []string                             `json:"blockedFingerprints,omitempty"`
	DisabledIdentities  []string                             `json:"disabledIdentities,omitempty"`
	TrustedAnchors      []string                             `json:"trustedAnchors"`
	ForwardHeaders      []string                             `json:"forwardHeaders,omitempty"`
}

type Rewrite struct {
	Path   string `json:"path,omitempty"`
	Prefix bool   `json:"prefix,omitempty"`
	Host   string `json:"host,omitempty"`
}

type HeaderFilter struct {
	Set    map[string]string `json:"set,omitempty"`
	Add    map[string]string `json:"add,omitempty"`
	Remove []string          `json:"remove,omitempty"`
}

type Deadlines struct {
	Dial           time.Duration `json:"dial,omitempty"`
	TLS            time.Duration `json:"tls,omitempty"`
	RequestBody    time.Duration `json:"requestBody,omitempty"`
	ResponseHeader time.Duration `json:"responseHeader,omitempty"`
	ResponseBody   time.Duration `json:"responseBody,omitempty"`
	UpgradeIdle    time.Duration `json:"upgradeIdle,omitempty"`
}

// Backend contains controller-selected IP endpoints. DNS names belong in the
// server name field of the trust policy. Service is namespace/name.
type Backend struct {
	Service      string      `json:"service"`
	Port         uint16      `json:"port"`
	Endpoints    []string    `json:"endpoints"` // IP:port, deduplicated again at runtime
	LAN          bool        `json:"lan,omitempty"`
	ClusterIP    string      `json:"clusterIP,omitempty"` // IP:port, when ClusterIP mode is selected
	StickyCookie string      `json:"stickyCookie,omitempty"`
	TLSRequired  bool        `json:"tlsRequired,omitempty"`
	TLS          *BackendTLS `json:"tls,omitempty"`
	ProxyV2      bool        `json:"proxyV2,omitempty"`
}

type BackendTLS struct {
	ServerName string `json:"serverName"`
	CAPEM      []byte `json:"caPEM"`
}

// MTLSHeaderSource maps the forwarding header names used by Gatehouse routes
// to their verified certificate fact. An empty result means unsupported.
func MTLSHeaderSource(name string) string {
	switch strings.ToLower(name) {
	case "x-mtls-identity", "x-mtls-viewer", "x-mtls-mesh-viewer":
		return "X-Mtls-Identity"
	case "x-mtls-fingerprint", "x-mtls-mesh-fingerprint":
		return "X-Mtls-Fingerprint"
	case "x-mtls-not-after", "x-mtls-mesh-not-after":
		return "X-Mtls-Not-After"
	}
	return ""
}
