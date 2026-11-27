package config

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

func (c *Config) validate() error {
	var problems []error
	for _, port := range slices.Sorted(maps.Keys(c.Ports)) {
		problems = append(problems, validatePrefixes(fmt.Sprintf("/ports/%d/trustedCIDRs", port),
			c.Ports[port].TrustedCIDRs))
	}
	for _, name := range slices.Sorted(maps.Keys(c.ForwardAuthClasses)) {
		prefix := "/forwardAuthClasses/" + name
		class := c.ForwardAuthClasses[name]
		_, err := endpoint(prefix+"/address", class.Address)
		problems = append(
			problems,
			err,
			validateHeaders(prefix+"/requestHeaders", class.RequestHeaders),
			validateHeaders(prefix+"/stripAfter", class.StripAfter),
		)
	}
	for index, backend := range c.LANBackends {
		problems = append(
			problems,
			validatePrefixes(fmt.Sprintf("/lanBackends/%d/cidr", index), []string{backend.CIDR}),
		)
	}
	for _, name := range slices.Sorted(maps.Keys(c.Hosts)) {
		problems = append(problems, c.validateHost(name, c.Hosts[name]))
	}
	for _, name := range slices.Sorted(maps.Keys(c.AuthClasses)) {
		problems = append(problems, c.validateAuthClass(name, c.AuthClasses[name]))
	}
	seen := make(map[struct {
		service string
		port    uint16
	}]bool)
	for i, exception := range c.DeviceTrust.Exceptions {
		key := struct {
			service string
			port    uint16
		}{exception.Service, exception.Port}
		if seen[key] {
			problems = append(
				problems,
				fmt.Errorf("/deviceTrust/exceptions/%d: duplicate service and port", i),
			)
		}
		seen[key] = true
	}
	limits := c.Defaults.Limits.PerRouteClient
	if limits.PerSecondSlot > limits.PerMinute {
		problems = append(
			problems,
			errors.New("/defaults/limits/perRouteClient/perSecondSlot: exceeds perMinute"),
		)
	}
	return errors.Join(problems...)
}

func validatePrefixes(path string, prefixes []string) error {
	var problems []error
	for index, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		where := fmt.Sprintf("%s/%d", path, index)
		if strings.HasSuffix(path, "/cidr") {
			where = path
		}
		if err != nil || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			problems = append(
				problems,
				fmt.Errorf("%s: expected a canonical IPv4 or IPv6 network prefix", where),
			)
		}
	}
	return errors.Join(problems...)
}

func validateHeaders(path string, headers []string) error {
	seen := make(map[string]bool, len(headers))
	for index, header := range headers {
		name := strings.ToLower(header)
		if seen[name] {
			return fmt.Errorf("%s/%d: duplicate header name", path, index)
		}
		seen[name] = true
	}
	return nil
}

func endpoint(path, value string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || strings.Contains(value, "#") {
		return nil, fmt.Errorf(
			"%s: expected an absolute URL without credentials or fragments",
			path,
		)
	}
	return parsed, nil
}

func (c *Config) validateHost(name string, host Host) error {
	path := "/hosts/" + name
	var problems []error
	if _, ok := c.DNSGroups[host.DNSGroup]; !ok {
		problems = append(
			problems,
			fmt.Errorf("%s/dnsGroup: unknown group %q", path, host.DNSGroup),
		)
	}
	if host.DNSGroup == "none" && host.Proxied {
		problems = append(problems, fmt.Errorf("%s/proxied: requires a publishing DNS group", path))
	}
	for i, number := range host.Ports {
		if _, ok := c.Ports[number]; !ok {
			problems = append(
				problems,
				fmt.Errorf("%s/ports/%d: port %d is not configured", path, i, number),
			)
		}
	}
	kind, class, _ := strings.Cut(host.Protection, ":")
	switch kind {
	case "mtls":
		if _, ok := c.ClientCertProfiles[class]; !ok {
			problems = append(
				problems,
				fmt.Errorf("%s/protection: unknown client certificate profile %q", path, class),
			)
		}
	case "oidc", "oidcCallback":
		if _, ok := c.AuthClasses[class]; !ok {
			problems = append(
				problems,
				fmt.Errorf("%s/protection: unknown auth class %q", path, class),
			)
		}
		if kind == "oidcCallback" && host.Namespace != "gatehouse" {
			problems = append(
				problems,
				fmt.Errorf("%s/namespace: callback hosts must belong to gatehouse", path),
			)
		}
	}
	for _, identity := range slices.Sorted(maps.Keys(host.IdentityConstraints)) {
		if !slices.Contains(host.Identities, identity) {
			problems = append(
				problems,
				fmt.Errorf("%s/identityConstraints/%s: identity is outside the host ceiling",
					path, identity),
			)
		}
	}
	return errors.Join(append(problems, c.validateHostPaths(path, host))...)
}

func (c *Config) validateHostPaths(path string, host Host) error {
	var problems []error
	seen := make(map[[2]string]string)
	add := func(where, auth string, paths, methods []string) {
		if _, ok := c.ForwardAuthClasses[auth]; !ok {
			problems = append(
				problems,
				fmt.Errorf("%s/forwardAuth: unknown forward-auth class %q", where, auth),
			)
		}
		for _, exact := range paths {
			for _, method := range methods {
				key := [2]string{method, exact}
				if previous, ok := seen[key]; ok {
					problems = append(
						problems,
						fmt.Errorf(
							"%s: %s %s already assigned by %s",
							where,
							method,
							exact,
							previous,
						),
					)
					continue
				}
				seen[key] = where
			}
		}
	}
	for i, exception := range host.Exceptions {
		add(
			fmt.Sprintf("%s/exceptions/%d", path, i),
			exception.ForwardAuth,
			[]string{exception.Path},
			exception.Methods,
		)
	}
	for i, delegate := range host.Delegate {
		where := fmt.Sprintf("%s/delegate/%d", path, i)
		add(where, delegate.ForwardAuth, delegate.Paths, delegate.Methods)
		if delegate.Namespace == host.Namespace {
			problems = append(
				problems,
				fmt.Errorf("%s/namespace: delegation must name another namespace", where),
			)
		}
	}
	return errors.Join(problems...)
}

func (c *Config) validateAuthClass(name string, class AuthClass) error {
	where := "/authClasses/" + name
	var problems []error
	_, issuerErr := endpoint(where+"/issuer", class.Issuer)
	callback, callbackErr := endpoint(where+"/callback", class.Callback)
	problems = append(problems, issuerErr, callbackErr, validateExpiry(where, class))
	domain := strings.TrimPrefix(class.CookieDomain, ".")
	if callbackErr == nil {
		host := callback.Hostname()
		if c.Hosts[host].Protection != "oidcCallback:"+name {
			problems = append(
				problems,
				fmt.Errorf(
					"%s/callback: hostname must be registered with protection oidcCallback:%s",
					where,
					name,
				),
			)
		}
		if callback.Path == "" || callback.RawQuery != "" || callback.ForceQuery ||
			!inDomain(host, domain) {
			problems = append(
				problems,
				fmt.Errorf(
					"%s/callback: requires a path on the cookie domain without a query",
					where,
				),
			)
		}
	}
	for index, host := range class.RedirectHosts {
		if c.Hosts[host].Protection != "oidc:"+name || !inDomain(host, domain) {
			problems = append(
				problems,
				fmt.Errorf("%s/redirectHosts/%d: must be an oidc:%s host in the cookie domain",
					where, index, name),
			)
		}
	}
	return errors.Join(problems...)
}

func validateExpiry(where string, class AuthClass) error {
	soft, softErr := time.ParseDuration(class.SoftExpiry)
	hard, hardErr := time.ParseDuration(class.HardExpiry)
	switch {
	case softErr != nil || soft <= 0:
		return fmt.Errorf("%s/softExpiry: expected a positive Go duration", where)
	case hardErr != nil || hard <= 0:
		return fmt.Errorf("%s/hardExpiry: expected a positive Go duration", where)
	case soft >= hard:
		return fmt.Errorf("%s/hardExpiry: must exceed softExpiry", where)
	default:
		return nil
	}
}

func inDomain(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}
