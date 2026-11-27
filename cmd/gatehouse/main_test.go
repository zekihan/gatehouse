package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zekihan/gatehouse/internal/config"
)

func TestValidate(t *testing.T) {
	example := filepath.Join("..", "..", "examples", "operator.yaml")
	data, err := os.ReadFile(example)
	if err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"validate", example}, &out, &stderr); code != 0 {
		t.Fatalf("valid example exited %d: %s", code, &stderr)
	}
	tests := []struct{ name, old, new, diagnostic string }{
		{
			"duplicate field",
			"  crowdsec: true",
			"  crowdsec: true\n  crowdsec: false",
			"/defaults/crowdsec",
		},
		{
			"duplicate numeric and quoted key",
			"  8443: {identity: direct}",
			"  8443: {identity: direct}\n  '8443': {identity: direct}",
			"/ports/8443",
		},
		{"unknown field", "  crowdsec: true", "  crowdsecs: true", "crowdsecs"},
		{
			"missing edge secret",
			"    edgeSecret: {header: X-Noqer-Edge-Auth, secret: cloudflare-edge-auth, keys: [current, previous]}\n",
			"",
			"edgeSecret",
		},
		{"bad trusted CIDR", "10.42.0.0/16", "10.42.0.1/16", "/ports/8445/trustedCIDRs/0"},
		{"out of range listener", "  8443: {identity", "  65536: {identity", "65536"},
		{
			"unconfigured listener",
			"ports: [8443, 8445]",
			"ports: [8443, 443]",
			"/hosts/bazarr.noqer.com/ports/1",
		},
		{
			"unknown profile",
			"protection: mtls:clients",
			"protection: mtls:absent",
			"/hosts/bazarr.noqer.com/protection",
		},
		{
			"unknown DNS group",
			"dnsGroup: frps",
			"dnsGroup: absent",
			"/hosts/bazarr.noqer.com/dnsGroup",
		},
		{
			"identity outside ceiling",
			"identities: [urn:noqer:mtls:clients:gatus-cluster-1]",
			"identities: []",
			"identity is outside the host ceiling",
		},
		{
			"relative deny",
			"[/minio/admin, /rustfs/admin",
			"[minio/admin, /rustfs/admin",
			"/deny/prefixes/0",
		},
		{
			"unknown exception class",
			"forwardAuth: gatus-bearer}",
			"forwardAuth: absent}",
			"/exceptions/0/forwardAuth",
		},
		{
			"unknown delegation class",
			"forwardAuth: machine-bearer",
			"forwardAuth: absent",
			"/delegate/0/forwardAuth",
		},
		{
			"missing OIDC callback host",
			"callback: https://auth-user-cluster-1.noqer.com",
			"callback: https://wrong.noqer.com",
			"/authClasses/user/callback",
		},
		{
			"negative session duration",
			"hardExpiry: 8h",
			"hardExpiry: -1h",
			"/authClasses/admin/hardExpiry",
		},
		{"malformed LAN subnet", "192.168.2.50/32", "192.168.2.50/33", "/lanBackends/0/cidr"},
		{
			"malformed device expiry",
			"  exceptions: []",
			"  exceptions: [{service: external-ingress/pve, port: 8006, expires: someday}]",
			"/deviceTrust/exceptions/0/expires",
		},
		{
			"unknown encoding",
			"[zstd, br, gzip]",
			"[zstd, br, unknown]",
			"/defaults/compression/encodings/2",
		},
		{
			"second document",
			"minBytes: 1024}",
			"minBytes: 1024}\n---\nnull",
			"exactly one document",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broken := strings.Replace(string(data), test.old, test.new, 1)
			if broken == string(data) {
				t.Fatal("test mutation did not change the example")
			}
			path := filepath.Join(t.TempDir(), "broken.yaml")
			if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			code := run([]string{"validate", path}, &out, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), test.diagnostic) {
				t.Fatalf("wanted exit 1 and %q, got %d: %s", test.diagnostic, code, &stderr)
			}
		})
	}
}

func TestSchemaCommand(t *testing.T) {
	var out bytes.Buffer
	if code := run(
		[]string{"schema"},
		&out,
		os.Stderr,
	); code != 0 ||
		!bytes.Equal(out.Bytes(), config.Schema()) {
		t.Fatalf("schema command did not emit embedded schema (exit %d)", code)
	}
}
