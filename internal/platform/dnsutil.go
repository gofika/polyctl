package platform

import "strings"

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
