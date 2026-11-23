package cloudflare

import (
	"testing"
	"time"
)

// E2E gives the external tests of this package (which run the whole command
// line, and so cannot live in the package itself) the fake API and the fake
// authorization server, with the registered provider pointed at both.
type E2E struct {
	env *oauthEnv
	t   *testing.T
}

// NewE2E starts the fakes and redirects the registered provider to them for
// the duration of the test.
func NewE2E(t *testing.T) *E2E {
	t.Helper()
	env := newOAuthEnv(t)
	old := apiBaseURL
	apiBaseURL = env.srv.URL
	t.Cleanup(func() { apiBaseURL = old })
	return &E2E{env: env, t: t}
}

// AuthEndpoint is the authorization endpoint the login prints a URL of.
func (x *E2E) AuthEndpoint() string { return oauthEP.Auth }

// Approve plays the person in the browser for the given authorization URL.
func (x *E2E) Approve(authURL string) { _ = x.env.browser(x.t, nil)(authURL) }

// Grant limits what the person approves at the next logins (nil: all).
func (x *E2E) Grant(scopes []string) { x.env.as.granted = scopes }

// Issue returns the secret of a finished browser login whose access token
// expires at expiry.
func (x *E2E) Issue(expiry time.Time) map[string]string { return x.env.grant(nil, expiry).get() }

// Secrets lists every code and token issued so far.
func (x *E2E) Secrets() []string { return x.env.secrets() }

// Refreshes counts the refresh grants.
func (x *E2E) Refreshes() int {
	_, n := x.env.as.counts()
	return n
}

// Revoked lists the revocation requests as "<hint>:<token>".
func (x *E2E) Revoked() []string {
	x.env.as.mu.Lock()
	defer x.env.as.mu.Unlock()
	return append([]string(nil), x.env.as.revoked...)
}

// FailRevocation makes the revocation endpoint answer with status.
func (x *E2E) FailRevocation(status int) {
	x.env.as.mu.Lock()
	defer x.env.as.mu.Unlock()
	x.env.as.revokeStatus = status
}

// Secret keys, for assertions on the stored secret.
const (
	SecretAccessToken  = secretAccessToken
	SecretRefreshToken = secretRefreshToken
	SecretExpiry       = secretExpiry
	SecretScopes       = secretScopes
)

// UseBaseURL points the registered provider at a fake API for the duration
// of the test.
func UseBaseURL(t *testing.T, url string) {
	t.Helper()
	old := apiBaseURL
	apiBaseURL = url
	t.Cleanup(func() { apiBaseURL = old })
}
