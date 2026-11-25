package creds

import (
	"errors"
	"sort"

	"github.com/zalando/go-keyring"
)

// LimitKeyring makes the keyring refuse, as Windows Credential Manager does,
// values longer than limit bytes. It returns a function that lists the
// entries of service written since that are still there, and one that
// undoes the change.
func LimitKeyring(limit int) (present func(service string) []string, restore func()) {
	set := keyringSet
	written := map[[2]string]bool{}
	keyringSet = func(service, user, password string) error {
		if len(password) > limit {
			return keyring.ErrSetDataTooBig
		}
		written[[2]string{service, user}] = true
		return set(service, user, password)
	}
	present = func(service string) []string {
		var out []string
		for k := range written {
			if k[0] != service {
				continue
			}
			if _, err := keyring.Get(k[0], k[1]); !errors.Is(err, keyring.ErrNotFound) {
				out = append(out, k[1])
			}
		}
		sort.Strings(out)
		return out
	}
	return present, func() { keyringSet = set }
}
