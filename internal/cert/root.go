// Package cert issues and keeps Let's Encrypt certificates: the local
// certificate store, the ACME account, the DNS-01 challenge written through
// the DNS account that hosts a domain, and the `cert ensure` flow that
// renews a certificate when it gets close to its expiry.
package cert

import (
	"fmt"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
)

// RootDomain returns the registered domain (eTLD+1 by the Public Suffix
// List, private suffixes included) that a certificate of host is issued
// and stored under: www.example.com, *.example.com and example.com all give
// example.com. The name is lowercased, a trailing dot and a leading "*."
// are dropped and an internationalized name is converted to punycode. A
// name without a registered domain (a bare public suffix, localhost, an IP
// address) or that is not a host name is invalid input (exit code 2).
func RootDomain(host string) (string, error) {
	h := strings.TrimSpace(host)
	h = strings.TrimPrefix(h, "*.")
	root, err := platform.RegisteredDomain(h)
	if err != nil {
		return "", fmt.Errorf("%w: %v", platform.ErrInvalidInput, err)
	}
	return root, nil
}

// Names are the names of the certificate of root: the root itself and its
// wildcard, in the order polyctl shows them.
func Names(root string) []string { return []string{root, "*." + root} }
