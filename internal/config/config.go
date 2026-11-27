// Package config loads the operator-owned configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"

	_ "embed"
)

type Config struct {
	Ports              map[uint16]Port              `json:"ports"`
	ClientCertProfiles map[string]ClientCertProfile `json:"clientCertProfiles"`
	ForwardAuthClasses map[string]ForwardAuthClass  `json:"forwardAuthClasses"`
	Hosts              map[string]Host              `json:"hosts"`
	DNSGroups          map[string]*string           `json:"dnsGroups"`
	LANBackends        []LANBackend                 `json:"lanBackends"`
	AuthClasses        map[string]AuthClass         `json:"authClasses"`
	DeviceTrust        DeviceTrust                  `json:"deviceTrust"`
	Defaults           Defaults                     `json:"defaults"`
}

type Port struct {
	Identity     string      `json:"identity"`
	TrustedCIDRs []string    `json:"trustedCIDRs,omitempty"`
	Mode         string      `json:"mode,omitempty"`
	EdgeSecret   *EdgeSecret `json:"edgeSecret,omitempty"`
}

type EdgeSecret struct {
	Header string   `json:"header"`
	Secret string   `json:"secret"`
	Keys   []string `json:"keys"`
}

type ClientCertProfile struct {
	CASecret       string `json:"caSecret"`
	MinVersion     string `json:"minVersion"`
	SessionTickets bool   `json:"sessionTickets"`
}

type ForwardAuthClass struct {
	Address          string   `json:"address"`
	RequestHeaders   []string `json:"requestHeaders"`
	StripAfter       []string `json:"stripAfter"`
	MaxResponseBytes int      `json:"maxResponseBytes"`
}

type Host struct {
	Namespace           string                        `json:"namespace"`
	DNSGroup            string                        `json:"dnsGroup"`
	Proxied             bool                          `json:"proxied"`
	Ports               []uint16                      `json:"ports"`
	Protection          string                        `json:"protection"`
	Deny                *Deny                         `json:"deny,omitempty"`
	Identities          []string                      `json:"identities,omitempty"`
	IdentityConstraints map[string]IdentityConstraint `json:"identityConstraints,omitempty"`
	Exceptions          []Exception                   `json:"exceptions,omitempty"`
	Delegate            []Delegation                  `json:"delegate,omitempty"`
	CrowdSecExemptPaths []string                      `json:"crowdsecExemptPaths,omitempty"`
}

type Deny struct {
	Prefixes []string `json:"prefixes,omitempty"`
	Exact    []string `json:"exact,omitempty"`
}

type IdentityConstraint struct {
	Methods []string `json:"methods"`
	Paths   []string `json:"paths"`
}

type Exception struct {
	Path        string   `json:"path"`
	Methods     []string `json:"methods"`
	ForwardAuth string   `json:"forwardAuth"`
}

type Delegation struct {
	Namespace   string   `json:"namespace"`
	Paths       []string `json:"paths"`
	Methods     []string `json:"methods"`
	ForwardAuth string   `json:"forwardAuth"`
	Rewrite     string   `json:"rewrite,omitempty"`
}

type LANBackend struct {
	CIDR  string   `json:"cidr"`
	Ports []uint16 `json:"ports"`
}

type AuthClass struct {
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"clientID"`
	Scopes        []string `json:"scopes"`
	Callback      string   `json:"callback"`
	Groups        []string `json:"groups"`
	SoftExpiry    string   `json:"softExpiry"`
	HardExpiry    string   `json:"hardExpiry"`
	CookieDomain  string   `json:"cookieDomain"`
	RedirectHosts []string `json:"redirectHosts"`
}

type DeviceTrust struct {
	CAConfigMap string            `json:"caConfigMap"`
	Exceptions  []DeviceException `json:"exceptions"`
}

type DeviceException struct {
	Service string `json:"service"`
	Port    uint16 `json:"port"`
	Expires string `json:"expires"`
}

type Defaults struct {
	CrowdSec    bool        `json:"crowdsec"`
	Limits      Limits      `json:"limits"`
	Compression Compression `json:"compression"`
}

type Limits struct {
	PerRouteClient ClientLimits `json:"perRouteClient"`
	PerRouteHost   HostLimits   `json:"perRouteHost"`
}

type ClientLimits struct {
	PerMinute     int `json:"perMinute"`
	PerSecondSlot int `json:"perSecondSlot"`
	InFlight      int `json:"inFlight"`
}

type HostLimits struct {
	InFlight int `json:"inFlight"`
}

type Compression struct {
	Encodings []string `json:"encodings"`
	MinBytes  int      `json:"minBytes"`
}

//go:embed schema.json
var schemaJSON []byte

var compiledSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	const resource = "gatehouse-config.json"
	var schema any
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(resource, schema); err != nil {
		return nil, err
	}
	return compiler.Compile(resource)
})

// Schema returns a copy of the operator configuration JSON Schema.
func Schema() []byte {
	return bytes.Clone(schemaJSON)
}

// Parse validates one YAML or JSON document before returning typed configuration.
func Parse(data []byte) (*Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("decode operator configuration: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("decode trailing document: %w", err)
		}
		return nil, errors.New("operator configuration must contain exactly one document")
	}

	// YAML resolves an unquoted port property to an integer map key.
	document, err := decodeNode(root.Content[0], "")
	if err != nil {
		return nil, err
	}
	schema, err := compiledSchema()
	if err != nil {
		return nil, fmt.Errorf("compile operator configuration schema: %w", err)
	}
	if err := schema.Validate(document); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode operator configuration: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(encoded, &cfg); err != nil {
		return nil, fmt.Errorf("decode validated operator configuration: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func decodeNode(node *yaml.Node, path string) (any, error) {
	switch node.Kind {
	case yaml.MappingNode:
		return decodeMapping(node, path)
	case yaml.SequenceNode:
		out := make([]any, len(node.Content))
		for i, item := range node.Content {
			value, err := decodeNode(item, fmt.Sprintf("%s/%d", path, i))
			if err != nil {
				return nil, err
			}
			out[i] = value
		}
		return out, nil
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!str", "!!timestamp":
			return node.Value, nil
		case "!!bool", "!!int", "!!float", "!!null":
			var value any
			if err := node.Decode(&value); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			return value, nil
		}
	case yaml.DocumentNode, yaml.AliasNode:
	default:
	}
	return nil, fmt.Errorf("%s (line %d): unsupported YAML tag or alias", path, node.Line)
}

func decodeMapping(node *yaml.Node, path string) (any, error) {
	out := make(map[string]any, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.ShortTag() != "!!str" && (path != "/ports" || key.ShortTag() != "!!int") {
			return nil, fmt.Errorf("%s (line %d): expected a string property name", path, key.Line)
		}
		name := key.Value
		next := path + "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(name)
		if _, exists := out[name]; exists {
			return nil, fmt.Errorf("%s (line %d): duplicate property", next, key.Line)
		}
		value, err := decodeNode(node.Content[i+1], next)
		if err != nil {
			return nil, err
		}
		out[name] = value
	}
	return out, nil
}
