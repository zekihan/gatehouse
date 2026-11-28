package dataplane

import (
	"cmp"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/zekihan/gatehouse/internal/config"
	"github.com/zekihan/gatehouse/internal/snapshot"
)

type route struct {
	rule     snapshot.Route
	headers  []matcher
	query    []matcher
	mtls     *mtlsPolicy
	position int
	backends []weighted
	total    uint64
	index    atomicCounter
}

type matcher struct {
	key   string
	value string
	regex *regexp.Regexp
}

func makeMatchers(in []snapshot.Match, canonicalize func(string) string) ([]matcher, bool) {
	out := make([]matcher, 0, len(in))
	for _, match := range in {
		m := matcher{key: canonicalize(match.Name), value: match.Value}
		if match.Regex {
			var err error
			m.regex, err = regexp.Compile(match.Value)
			if err != nil {
				return nil, false
			}
		}
		out = append(out, m)
	}
	return out, true
}

func (s *compiled) compileRoute(cfg *config.Config, host config.Host, rule snapshot.Route) *route {
	r := &route{rule: rule}
	if r.rule.Path == "" {
		r.rule.Path = "/"
	}
	if !r.rule.Exact {
		r.rule.Path = strings.TrimRight(r.rule.Path, "/")
	}
	headers, headersOK := makeMatchers(rule.Headers, http.CanonicalHeaderKey)
	query, queryOK := makeMatchers(rule.Query, func(s string) string { return s })
	r.headers, r.query = headers, query
	r.rule.InvalidPolicy = rule.InvalidPolicy || !headersOK || !queryOK
	if strings.HasPrefix(host.Protection, "mtls:") {
		r.mtls = compileMTLS(host, rule)
	}
	if len(rule.Backends) == 0 {
		r.addBackend(s, cfg, rule.Backend, 1)
	} else {
		for _, b := range rule.Backends {
			r.addBackend(s, cfg, b.Backend, b.Weight)
		}
	}
	return r
}

func sortRoutes(routes []*route) {
	slices.SortStableFunc(routes, func(a, b *route) int {
		x, y := &a.rule, &b.rule
		return cmp.Or(
			cmp.Compare(y.HostnameSpecificity, x.HostnameSpecificity),
			prefer(x.Exact, y.Exact),
			cmp.Compare(len(y.Path), len(x.Path)),
			prefer(x.Method != "", y.Method != ""),
			cmp.Compare(len(y.Headers), len(x.Headers)),
			cmp.Compare(len(y.Query), len(x.Query)),
			x.Created.Compare(y.Created),
			cmp.Compare(x.Namespace, y.Namespace),
			cmp.Compare(x.Name, y.Name),
		)
	})
}

func prefer(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	default:
		return 1
	}
}

func matchRoute(routes []*route, r *http.Request, p string) *route {
	var query url.Values
	for _, route := range routes {
		rule := &route.rule
		if rule.Exact && rule.Path != p || !rule.Exact && !prefixMatch(p, rule.Path) ||
			rule.Method != "" && rule.Method != r.Method || !matchValues(r.Header, route.headers) {
			continue
		}
		if len(route.query) != 0 {
			if query == nil {
				query = r.URL.Query()
			}
			if !matchValues(query, route.query) {
				continue
			}
		}
		return route
	}
	return nil
}

func matchValues(fields map[string][]string, matches []matcher) bool {
	for _, m := range matches {
		if !slices.ContainsFunc(fields[m.key], func(v string) bool {
			if m.regex == nil {
				return v == m.value
			}
			return m.regex.MatchString(v)
		}) {
			return false
		}
	}
	return true
}

func prefixMatch(p, prefix string) bool {
	return p == prefix ||
		strings.HasPrefix(p, prefix) && len(p) > len(prefix) && p[len(prefix)] == '/'
}

func denied(deny *config.Deny, p string) bool {
	return deny != nil &&
		(slices.Contains(deny.Exact, p) || slices.ContainsFunc(deny.Prefixes, func(prefix string) bool {
			return prefixMatch(p, strings.TrimRight(prefix, "/"))
		}))
}

func normalizedPath(r *http.Request) (string, bool) {
	if r.Method == http.MethodConnect || !strings.HasPrefix(r.RequestURI, "/") ||
		strings.ContainsAny(r.URL.Path, "\\%;?#\x00") {
		return "", false
	}
	escaped := r.URL.EscapedPath()
	for i := 0; i < len(escaped); i++ {
		if escaped[i] == '%' {
			// URL parsing already checked the escape syntax. Encoded separators,
			// controls and encoded percent signs have ambiguous upstream meanings.
			if i+2 >= len(escaped) {
				return "", false
			}
			part := strings.ToLower(escaped[i+1 : i+3])
			if part == "2f" || part[0] < '2' || part == "7f" {
				return "", false
			}
			i += 2
		}
	}
	clean := path.Clean(r.URL.Path)
	if clean != "/" && strings.HasSuffix(r.URL.Path, "/") {
		clean += "/"
	}
	return clean, true
}

func hostname(authority string) string {
	if host, _, err := net.SplitHostPort(authority); err == nil {
		authority = host
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(authority, "[]"), "."))
}

func rewritePath(r *http.Request, target string) {
	r.URL.Path, r.URL.RawPath = target, ""
}
