package platform

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// NormalizeDomain lowercases and strips a trailing dot.
func NormalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// FQDN turns a relative record name ("www", "@", "") into a FQDN under zone.
// Names that already end with the zone are returned normalized unchanged.
func FQDN(name, zone string) string {
	zone = NormalizeDomain(zone)
	name = NormalizeDomain(name)
	if name == "" || name == "@" || name == zone {
		return zone
	}
	if strings.HasSuffix(name, "."+zone) {
		return name
	}
	return name + "." + zone
}

// RelativeName turns a FQDN into the name relative to zone ("@" for apex).
func RelativeName(fqdn, zone string) string {
	fqdn = NormalizeDomain(fqdn)
	zone = NormalizeDomain(zone)
	if fqdn == zone || fqdn == "" {
		return "@"
	}
	return strings.TrimSuffix(fqdn, "."+zone)
}

// Candidates returns the domain and each of its parents, longest first,
// excluding the bare TLD: www.a.example.com -> [www.a.example.com a.example.com example.com].
func Candidates(domain string) []string {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return nil
	}
	parts := strings.Split(domain, ".")
	var out []string
	for i := 0; i < len(parts)-1; i++ {
		out = append(out, strings.Join(parts[i:], "."))
	}
	return out
}

// TTLLabel renders a record's TTL for human-readable output. Values that a
// platform uses as a marker rather than a number of seconds are shown by
// name, so they cannot be mistaken for a real duration:
//
//   - Cloudflare: 1 means "automatic" and is shown as "auto".
//   - Route 53: alias records carry no TTL of their own (the target's
//     applies) and are shown as "alias".
//   - GoDaddy: 0 is never a real TTL (the minimum is 600). It only appears
//     on a record that polyctl just wrote without --ttl, where GoDaddy
//     applied its own default, and is shown as "default".
//
// Every other value is a TTL in seconds on all supported platforms and is
// shown as the number. Machine-readable output keeps the raw value.
func TTLLabel(p ID, r Record) string {
	switch p {
	case Cloudflare:
		if r.TTL == 1 {
			return "auto"
		}
	case AWS:
		if r.TTL == 0 && extraFlag(r.Extra, "alias") {
			return "alias"
		}
	case GoDaddy:
		if r.TTL == 0 {
			return "default"
		}
	}
	return strconv.Itoa(r.TTL)
}

// extraFlag reads a boolean from Extra, tolerating the string form.
func extraFlag(extra map[string]any, key string) bool {
	switch v := extra[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// Nameservers turns the positional <nameserver>... arguments of an
// `ns set` command into a list of normalized host names. Each argument may
// itself be a comma-separated list, so a pasted "ns1.example.com,ns2.example.com"
// works as well as two arguments. An empty entry is an error, and so is an
// empty list.
func Nameservers(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		for _, n := range strings.Split(a, ",") {
			n = NormalizeDomain(n)
			if n == "" {
				return nil, fmt.Errorf("empty nameserver in %q", a)
			}
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("at least one nameserver is required")
	}
	return out, nil
}
