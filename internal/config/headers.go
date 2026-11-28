package config

import "strings"

func FoldHeader(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// ReservedHeader recognizes the built-in identity headers. Callers also check
// the edge-secret names configured on all listeners.
func ReservedHeader(folded string) bool {
	switch folded {
	case "x-real-ip", "remote-user", "remote-email", "remote-groups", "remote-name",
		"forwarded", "cf-connecting-ip", "cf-connecting-ipv6", "cf-pseudo-ipv4",
		"eo-connecting-ip", "true-client-ip", "x-client-ip", "x-cluster-client-ip",
		"x-original-forwarded-for", "fastly-client-ip", "x-is-trusted",
		"x-noqer-edge-auth":
		return true
	}
	return strings.HasPrefix(folded, "x-forwarded-") ||
		strings.HasPrefix(folded, "x-auth-request-") ||
		strings.HasPrefix(folded, "x-authentik-") ||
		strings.HasPrefix(folded, "x-mtls-")
}
