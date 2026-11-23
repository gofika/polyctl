package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofika/polyctl/internal/httpx"
	"github.com/gofika/polyctl/internal/loopback"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// oauthClientPublic says whether everybody can authorize polyctl's OAuth
// client. Flip it to true once the client is published in the Cloudflare
// dashboard: the interactive `auth login cloudflare` then uses the browser
// by default. While it is false only members of the publisher's account can
// approve, so the browser is used only on --set method=oauth.
var oauthClientPublic = false

// oauthClientID identifies polyctl at Cloudflare. It is a public identifier:
// the client has no secret and authenticates each login with PKCE.
const oauthClientID = "4fca7aad480603e808aabf9b2acfe87a"

// oauthCallbackPath is the path of the registered loopback redirect URIs
// (http://127.0.0.1/oauth/callback). Cloudflare accepts any port there, but
// the path has to match exactly.
const oauthCallbackPath = "/oauth/callback"

// oauthEndpoints are the endpoints of Cloudflare's authorization server.
type oauthEndpoints struct {
	Auth, Token, Revoke, Userinfo string
}

// oauthEP is what the provider talks to. Only tests replace it.
var oauthEP = oauthEndpoints{
	Auth:     "https://dash.cloudflare.com/oauth2/auth",
	Token:    "https://dash.cloudflare.com/oauth2/token",
	Revoke:   "https://dash.cloudflare.com/oauth2/revoke",
	Userinfo: "https://dash.cloudflare.com/oauth2/userinfo",
}

// Scope ids, as listed by GET /client/v4/oauth/scopes. They carry the names
// of the API token permissions.
const (
	scopeZoneRead          = "zone.read"
	scopeDNSRead           = "dns.read"
	scopeDNSWrite          = "dns.write"
	scopeOfflineAccess     = "offline_access"
	scopeCachePurge        = "cache.purge"
	scopeZoneSettingsRead  = "zone-settings.read"
	scopeZoneSettingsWrite = "zone-settings.write"
	scopeAccountRead       = "account-settings.read"
	scopeUserRead          = "user-details.read"
)

// OAuthRequiredScopes is what every browser login asks for and cannot be
// declined: listing zones, reading and writing DNS records, and a refresh
// token. The OAuth client must declare the same list as its "scopes".
var OAuthRequiredScopes = []string{scopeZoneRead, scopeDNSRead, scopeDNSWrite, scopeOfflineAccess}

// OAuthOptionalScopes is what the extra commands of the cloudflare tree
// need; the person may decline any of them on the consent page, and the
// command that needs a declined one says so (see scopeFor). The OAuth client
// must declare the same list as its "optional_scopes".
//
//	cache.purge            POST  /zones/{id}/purge_cache        cloudflare cache purge
//	zone-settings.read     GET   /zones/{id}/settings/{name}    cloudflare dev-mode / ssl-mode (show)
//	zone-settings.write    PATCH /zones/{id}/settings/{name}    cloudflare dev-mode / ssl-mode (set)
//	account-settings.read  GET   /accounts                      cloudflare account list, account choice at login
//	user-details.read      GET   /user                          the e-mail shown by whoami and auth list
var OAuthOptionalScopes = []string{scopeCachePurge, scopeZoneSettingsRead, scopeZoneSettingsWrite, scopeAccountRead, scopeUserRead}

// scopeFor names the scope a request of the v4 API needs, or "" when the
// request is not one polyctl maps.
func scopeFor(method, path string) string {
	read := method == http.MethodGet || method == http.MethodHead
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch parts[0] {
	case "accounts":
		if len(parts) >= 3 && parts[2] == "r2" {
			// R2 is not among the scopes of polyctl's OAuth client.
			return ""
		}
		return scopeAccountRead
	case "user":
		return scopeUserRead
	case "zones":
		if len(parts) < 3 {
			return scopeZoneRead
		}
		switch parts[2] {
		case "dns_records":
			if read {
				return scopeDNSRead
			}
			return scopeDNSWrite
		case "purge_cache":
			return scopeCachePurge
		case "settings":
			if read {
				return scopeZoneSettingsRead
			}
			return scopeZoneSettingsWrite
		}
	}
	return ""
}

// oauthWait bounds the wait for the approval in the browser. Tests shorten
// it.
var oauthWait = 5 * time.Minute

// expirySkew is how long before its expiry an access token is replaced.
const expirySkew = 60 * time.Second

// oauthHTTP talks to the authorization server. Its endpoints do not
// redirect; following one would send a code or a refresh token elsewhere.
var oauthHTTP = &http.Client{
	Timeout:       30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// oauthToken is the secret of a browser login.
type oauthToken struct {
	Access  string
	Refresh string
	// Expiry of the access token; zero when the server did not say.
	Expiry time.Time
	// Scopes granted; nil when the server did not say.
	Scopes []string
}

func tokenFromSecret(s map[string]string) oauthToken {
	t := oauthToken{Access: strings.TrimSpace(s[secretAccessToken]), Refresh: strings.TrimSpace(s[secretRefreshToken])}
	if exp, err := time.Parse(time.RFC3339, s[secretExpiry]); err == nil {
		t.Expiry = exp
	}
	t.Scopes = strings.Fields(s[secretScopes])
	return t
}

// secret writes the token over base, keeping whatever else base holds.
func (t oauthToken) secret(base map[string]string) map[string]string {
	out := make(map[string]string, len(base)+4)
	for k, v := range base {
		out[k] = v
	}
	out[secretAccessToken] = t.Access
	out[secretRefreshToken] = t.Refresh
	delete(out, secretExpiry)
	if !t.Expiry.IsZero() {
		out[secretExpiry] = t.Expiry.UTC().Format(time.RFC3339)
	}
	out[secretScopes] = strings.Join(t.Scopes, " ")
	return out
}

// expiring reports whether the access token is missing, expired or about
// to expire. A token without a known expiry counts as valid: the API says
// when it is not.
func (t oauthToken) expiring() bool {
	if t.Access == "" {
		return true
	}
	return !t.Expiry.IsZero() && time.Until(t.Expiry) < expirySkew
}

func (t oauthToken) expired() bool {
	return t.Access == "" || (!t.Expiry.IsZero() && !time.Now().Before(t.Expiry))
}

func (t oauthToken) has(scope string) bool {
	for _, s := range t.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// tokenError is a refusal of the token or revocation endpoint. It carries
// the OAuth error code and never the request.
type tokenError struct {
	Status      int
	Code        string
	Description string
}

func (e *tokenError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d", e.Status)
	if e.Code != "" {
		b.WriteString(": " + e.Code)
	}
	if e.Description != "" {
		b.WriteString(" (" + e.Description + ")")
	}
	return b.String()
}

// printable reduces a server-supplied text to printable ASCII of a bounded
// length.
func printable(v string, max int) string {
	var b strings.Builder
	for _, r := range v {
		if b.Len() >= max {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// postForm sends a form to an endpoint of the authorization server, without
// client authentication (the client is public), and returns the decoded
// JSON object of a 2xx answer. Any other answer is a *tokenError; values of
// the form are removed from the texts it carries.
func postForm(ctx context.Context, endpoint string, form url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", httpx.UserAgent)
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			// Without the URL: it is fixed, and the text stays short.
			err = ue.Err
		}
		return nil, fmt.Errorf("reach the Cloudflare authorization server: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return body, nil
	}
	te := &tokenError{Status: resp.StatusCode}
	if s, ok := body["error"].(string); ok {
		te.Code = s
	}
	if s, ok := body["error_description"].(string); ok {
		te.Description = s
	}
	if te.Code == "" {
		// The envelope of the v4 API, in case the endpoint answers with it.
		if list, ok := body["errors"].([]any); ok && len(list) > 0 {
			if m, ok := list[0].(map[string]any); ok {
				te.Description, _ = m["message"].(string)
			}
		}
	}
	for _, vals := range form {
		for _, v := range vals {
			if len(v) >= 8 {
				te.Code = strings.ReplaceAll(te.Code, v, "[redacted]")
				te.Description = strings.ReplaceAll(te.Description, v, "[redacted]")
			}
		}
	}
	te.Code, te.Description = printable(te.Code, 64), printable(te.Description, 200)
	return nil, te
}

// requestToken runs a grant at the token endpoint. prev supplies what the
// answer may leave out: the refresh token (a server that does not rotate it
// returns none) and the scopes.
func requestToken(ctx context.Context, form url.Values, prev oauthToken) (oauthToken, error) {
	form.Set("client_id", oauthClientID)
	body, err := postForm(ctx, oauthEP.Token, form)
	if err != nil {
		return oauthToken{}, err
	}
	t := oauthToken{Refresh: prev.Refresh, Scopes: prev.Scopes}
	t.Access, _ = body["access_token"].(string)
	if t.Access == "" {
		return oauthToken{}, errors.New("the Cloudflare authorization server returned no access token")
	}
	if r, _ := body["refresh_token"].(string); r != "" {
		t.Refresh = r
	}
	// expires_in is a number of seconds; some servers send it as a string.
	var secs float64
	switch v := body["expires_in"].(type) {
	case float64:
		secs = v
	case string:
		secs, _ = strconv.ParseFloat(strings.TrimSpace(v), 64)
	}
	if secs > 0 {
		t.Expiry = time.Now().Add(time.Duration(secs * float64(time.Second))).UTC().Truncate(time.Second)
	}
	// scope is a space-separated string; a list is accepted too.
	switch v := body["scope"].(type) {
	case string:
		if f := strings.Fields(v); len(f) > 0 {
			t.Scopes = f
		}
	case []any:
		var f []string
		for _, s := range v {
			if s, ok := s.(string); ok && s != "" {
				f = append(f, s)
			}
		}
		if len(f) > 0 {
			t.Scopes = f
		}
	}
	t.Scopes = append([]string(nil), t.Scopes...)
	sort.Strings(t.Scopes)
	return t, nil
}

// pkceChallenge is the S256 code challenge of a verifier (RFC 7636).
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorize runs the authorization-code flow with PKCE on a loopback
// listener and returns the tokens. The person approves in a browser on this
// machine: polyctl opens it when it may, and prints the URL in any case.
func authorize(ctx context.Context, in platform.LoginInput, pio *prompt.IO) (oauthToken, error) {
	lb, err := loopback.Listen(oauthCallbackPath)
	if err != nil {
		return oauthToken{}, err
	}
	defer lb.Close()
	verifier, err := loopback.RandomToken()
	if err != nil {
		return oauthToken{}, err
	}
	scopes := append(append([]string{}, OAuthRequiredScopes...), OAuthOptionalScopes...)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClientID},
		"redirect_uri":          {lb.RedirectURL()},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {lb.State},
		"code_challenge":        {pkceChallenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	authURL := oauthEP.Auth + "?" + q.Encode()

	fmt.Fprintln(pio.Err, "Cloudflare authorizes polyctl in the browser: choose the account and approve the access there.")
	if !oauthClientPublic {
		fmt.Fprintln(pio.Err, "note: polyctl's OAuth client is not published yet, so only members of its publisher's Cloudflare account can approve; everybody else logs in with an API token (--set method=token)")
	}
	fmt.Fprintln(pio.Err, "Open this URL in a browser on this machine:")
	fmt.Fprintln(pio.Err)
	fmt.Fprintln(pio.Err, "    "+authURL)
	fmt.Fprintln(pio.Err)
	if in.MayOpenBrowser() {
		if err := in.OpenBrowser(authURL); err != nil {
			fmt.Fprintln(pio.Err, "could not open a browser; open the URL above manually")
		}
	}
	fmt.Fprintf(pio.Err, "Waiting up to %s for the approval (Ctrl-C to cancel)...\n", oauthWait)

	code, err := lb.Wait(ctx, oauthWait)
	var denied *loopback.DeniedError
	switch {
	case err == nil:
	case errors.Is(err, loopback.ErrTimeout):
		return oauthToken{}, fmt.Errorf("%w: no approval arrived within %s", platform.ErrLoginCancelled, oauthWait)
	case errors.As(err, &denied):
		return oauthToken{}, fmt.Errorf("%w: %v", platform.ErrLoginCancelled, err)
	case ctx.Err() != nil:
		// Ctrl-C: left like any other question of the login.
		return oauthToken{}, prompt.ErrAborted
	default:
		return oauthToken{}, fmt.Errorf("%w: %v", platform.ErrLoginCancelled, err)
	}
	// The listener has done its part; the browser has its page.
	lb.Close()

	tok, err := requestToken(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {lb.RedirectURL()},
	}, oauthToken{})
	if err != nil {
		if ctx.Err() != nil {
			return oauthToken{}, prompt.ErrAborted
		}
		var te *tokenError
		if errors.As(err, &te) {
			return oauthToken{}, fmt.Errorf("%w: Cloudflare refused the authorization code: %v", platform.ErrUnauthorized, err)
		}
		return oauthToken{}, fmt.Errorf("exchange the authorization code: %w", err)
	}
	if tok.Refresh == "" {
		fmt.Fprintln(pio.Err, "note: Cloudflare returned no refresh token; this login ends when its access token expires")
	}
	return tok, nil
}

// oauthSession is the token of an opened browser-login account. It hands
// out the access token, replaces it when it expires and keeps the stored
// secret in step.
type oauthSession struct {
	prof platform.Profile

	mu  sync.Mutex
	tok oauthToken
	// futile401 and futileOther are set once a renewed token was refused
	// like the one before it, with HTTP 401 or with another authentication
	// failure: such refusals are not about expiry, and renewing again would
	// only spend refresh tokens.
	futile401, futileOther bool
}

func newOAuthSession(prof platform.Profile) *oauthSession {
	return &oauthSession{prof: prof, tok: tokenFromSecret(prof.Secret)}
}

func (s *oauthSession) loginAgain() string {
	cmd := "polyctl auth login cloudflare"
	if s.prof.Name != "" {
		cmd += " --profile " + s.prof.Name
	}
	return cmd
}

// current returns the access token in use, without the network.
func (s *oauthSession) current() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tok.Access
}

func (s *oauthSession) token() oauthToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tok
}

// fresh returns an access token that is not about to expire, renewing it
// first when needed.
func (s *oauthSession) fresh(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok.expiring() {
		if err := s.renewLocked(ctx, ""); err != nil {
			// A token that is still valid outlives a renewal that could not
			// be made (no network for a moment); a revoked one does not.
			if errors.Is(err, platform.ErrUnauthorized) || s.tok.expired() {
				return "", err
			}
		}
	}
	return s.tok.Access, nil
}

// renew replaces the access token after the API refused rejected.
func (s *oauthSession) renew(ctx context.Context, rejected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewLocked(ctx, rejected)
}

// renewLocked replaces the access token through the refresh token. It runs
// under the lock of the credential store and starts from the secret as it
// is stored now: another polyctl process may have renewed it already, and
// with rotating refresh tokens the one this process loaded is then spent.
// rejected is the access token the API just refused ("" when the renewal is
// about the expiry): a stored token is taken over only when it is another
// one.
func (s *oauthSession) renewLocked(ctx context.Context, rejected string) error {
	if rejected != "" && s.tok.Access != rejected && !s.tok.expiring() {
		// Renewed already, by another request of this process.
		return nil
	}
	var called bool
	var renewErr error
	step := func(cur map[string]string) (map[string]string, error) {
		called = true
		stored := tokenFromSecret(cur)
		if stored.Access != rejected && !stored.expiring() {
			s.tok = stored
			return nil, nil
		}
		if stored.Refresh == "" {
			stored.Refresh = s.tok.Refresh
		}
		if stored.Refresh == "" {
			renewErr = fmt.Errorf("%w: the Cloudflare authorization has expired and holds no refresh token; run `%s` again", platform.ErrUnauthorized, s.loginAgain())
			return nil, renewErr
		}
		if len(stored.Scopes) == 0 {
			stored.Scopes = s.tok.Scopes
		}
		next, err := requestToken(ctx, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {stored.Refresh},
		}, stored)
		if err != nil {
			var te *tokenError
			if errors.As(err, &te) && te.Status >= 400 && te.Status < 500 && te.Status != http.StatusTooManyRequests {
				// invalid_grant, or a refusal in a form polyctl does not
				// know: the authorization was revoked or has expired.
				renewErr = fmt.Errorf("%w: the Cloudflare authorization was revoked or has expired (%v); run `%s` again", platform.ErrUnauthorized, err, s.loginAgain())
			} else {
				renewErr = fmt.Errorf("renew the Cloudflare authorization: %w", err)
			}
			return nil, renewErr
		}
		s.tok = next
		return next.secret(cur), nil
	}

	var storeErr error
	switch {
	case s.prof.RefreshSecret != nil:
		storeErr = s.prof.RefreshSecret(step)
		if !called && storeErr != nil {
			// The store could not be read: renew from what was loaded.
			if next, err := step(s.prof.Secret); err == nil && next != nil && s.prof.UpdateSecret != nil {
				storeErr = s.prof.UpdateSecret(next)
			}
		}
	default:
		next, err := step(s.prof.Secret)
		if err == nil && next != nil && s.prof.UpdateSecret != nil {
			storeErr = s.prof.UpdateSecret(next)
		}
	}
	if renewErr != nil {
		return renewErr
	}
	if storeErr != nil {
		// The new token works for this run. If the refresh token rotated,
		// the stored one is spent and the next run asks for a new login.
		warnf("cloudflare/%s: the renewed authorization could not be stored: %v", s.prof.Name, storeErr)
	}
	return nil
}

// mayBeExpired reports whether an API failure can mean that the access
// token is no longer accepted, so that renewing it is worth one try. HTTP
// 401 always can. Other authentication failures (a missing permission is
// reported as one too) only when the token's expiry is not known.
func (s *oauthSession) mayBeExpired(err error) bool {
	var ce *Error
	if !errors.As(err, &ce) || !errors.Is(err, platform.ErrUnauthorized) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ce.Status == http.StatusUnauthorized {
		return !s.futile401
	}
	return s.tok.Expiry.IsZero() && !s.futileOther
}

// setFutile records that renewing did not help against err.
func (s *oauthSession) setFutile(err error) {
	var ce *Error
	if !errors.As(err, &ce) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ce.Status == http.StatusUnauthorized {
		s.futile401 = true
	} else {
		s.futileOther = true
	}
}

// mayHave reports whether the login may hold a scope: it was granted, or
// Cloudflare did not say what was.
func (s *oauthSession) mayHave(scope string) bool {
	tok := s.token()
	return len(tok.Scopes) == 0 || tok.has(scope)
}

// scopeError is an API refusal explained by a scope the login does not
// have. It unwraps to the API error.
type scopeError struct {
	err error
	msg string
}

func (e *scopeError) Error() string { return e.err.Error() + ": " + e.msg }
func (e *scopeError) Unwrap() error { return e.err }

// explain adds to a permission failure the scope the request needs, when
// the login does not have it.
func (s *oauthSession) explain(method, path string, err error) error {
	var ce *Error
	if err == nil || !errors.As(err, &ce) || !errors.Is(err, platform.ErrUnauthorized) {
		return err
	}
	scope := scopeFor(method, path)
	if scope == "" {
		return err
	}
	tok := s.token()
	switch {
	case len(tok.Scopes) == 0:
		// Cloudflare did not say what was granted.
		return &scopeError{err: err, msg: fmt.Sprintf("this needs the %q scope; if it was declined at the login, run `%s` again and approve it", scope, s.loginAgain())}
	case !tok.has(scope):
		return &scopeError{err: err, msg: fmt.Sprintf("the %q scope was not granted to this login; run `%s` again and approve it", scope, s.loginAgain())}
	}
	return err
}

// userinfo is what the OpenID userinfo endpoint may report. Its fields are
// not documented by Cloudflare: polyctl reads the standard claims and takes
// nothing for granted.
type userinfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
}

// getUserinfo asks the userinfo endpoint who the access token belongs to.
// It is best effort: callers treat an error as "not known".
func getUserinfo(ctx context.Context, accessToken string) (*userinfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oauthEP.Userinfo, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", httpx.UserAgent)
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return nil, errors.New("userinfo: request failed")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo: HTTP %d", resp.StatusCode)
	}
	var u userinfo
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, errors.New("userinfo: not a JSON object")
	}
	u.Email = printable(u.Email, 254)
	return &u, nil
}

// CanRevoke reports whether the profile is a browser login: only those
// leave an authorization at Cloudflare. An API token stays the person's own
// to delete in the dashboard.
func (*provider) CanRevoke(p platform.Profile) bool {
	if !isOAuth(p) {
		return false
	}
	t := tokenFromSecret(p.Secret)
	return t.Refresh != "" || t.Access != ""
}

// Revoke withdraws the authorization at Cloudflare: the refresh token, so
// that no new access token can be obtained, then the access token. Both are
// tried; the first failure is returned.
func (p *provider) Revoke(ctx context.Context, prof platform.Profile) error {
	if !p.CanRevoke(prof) {
		return nil
	}
	t := tokenFromSecret(prof.Secret)
	var first error
	for _, tk := range []struct{ value, hint string }{{t.Refresh, "refresh_token"}, {t.Access, "access_token"}} {
		if tk.value == "" {
			continue
		}
		_, err := postForm(ctx, oauthEP.Revoke, url.Values{
			"token":           {tk.value},
			"token_type_hint": {tk.hint},
			"client_id":       {oauthClientID},
		})
		if err != nil && first == nil {
			first = fmt.Errorf("revoke the %s: %w", strings.ReplaceAll(tk.hint, "_", " "), err)
		}
	}
	return first
}

var _ platform.Revoker = (*provider)(nil)
