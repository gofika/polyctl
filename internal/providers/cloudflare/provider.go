// Package cloudflare implements the Cloudflare provider: login with an API
// token or through the browser (OAuth), zone and DNS record management
// through the v4 REST API, inventory sync and the `polyctl cloudflare` native
// command tree.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

func init() { platform.Register(&provider{}) }

// DefaultBaseURL is the Cloudflare v4 API endpoint.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// apiBaseURL is the API endpoint of the registered provider. Only tests
// replace it.
var apiBaseURL = DefaultBaseURL

// tokenPageURL is where users create API tokens.
const tokenPageURL = "https://dash.cloudflare.com/profile/api-tokens"

// tokenEnv is the environment variable read for non-interactive logins. It is
// the name the official Cloudflare tooling (Terraform provider, wrangler)
// understands, so a token exported once serves every tool.
const tokenEnv = "CLOUDFLARE_API_TOKEN"

// warnf reports non-fatal conditions (skipped zones during sync). Tests
// replace it to capture the output.
var warnf = func(format string, args ...any) { fmt.Fprintln(os.Stderr, output.Clean(fmt.Sprintf(format, args...))) }

// Login methods, as given with --set method=.
const (
	methodToken = "token"
	methodOAuth = "oauth"
)

// storedToken is the method metadata of an API-token account. It is the
// value polyctl has always written for them; an account stored by 0.1.x
// without a method is an API-token account as well.
const storedToken = "api_token"

// Secret keys (stored in the credential store).
//
// API-token accounts:
//
//	api_token      the Cloudflare API token (Bearer)
//
// Browser logins (method oauth):
//
//	access_token   the OAuth access token (Bearer)
//	refresh_token  the OAuth refresh token
//	expiry         when the access token expires (RFC 3339); absent when
//	               Cloudflare did not say
//	scopes         the granted scopes, separated by spaces; empty when
//	               Cloudflare did not say
//
// Metadata keys (stored in plaintext config.yaml, never sensitive):
//
//	method        "api_token" or "oauth"
//	account_id    the id of the default account (absent when the accounts cannot be listed)
//	account_name  the display name of the default account
//	accounts      the ids of the selected accounts, separated by commas, when
//	              there are several (see accounts.go)
//	email         the user's email when it can be read (optional)
//	token_id      API token: its public id, as reported by the token verify endpoint
//	scopes        oauth: the granted scopes, separated by spaces
const (
	secretToken        = "api_token"
	secretAccessToken  = "access_token"
	secretRefreshToken = "refresh_token"
	secretExpiry       = "expiry"
	secretScopes       = "scopes"
	metaMethod         = "method"
	metaAccountID      = "account_id"
	metaAccountName    = "account_name"
	metaEmail          = "email"
	metaTokenID        = "token_id"
	metaScopes         = "scopes"
)

type provider struct {
	// baseURL overrides apiBaseURL (tests).
	baseURL string
}

func (p *provider) base() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return apiBaseURL
}

func (*provider) ID() platform.ID     { return platform.Cloudflare }
func (*provider) DisplayName() string { return "Cloudflare" }
func (*provider) LoginHelp() string {
	browser := "--set method=oauth approves polyctl in the browser instead, for a whole account\n" +
		"(interactive flow only). polyctl's OAuth client is not published yet: for now\n" +
		"this works only for members of its publisher's Cloudflare account."
	if oauthClientPublic {
		browser = "The interactive flow approves polyctl in the browser, for a whole account\n" +
			"(--set method=oauth, the default there); --set method=token uses an API token\n" +
			"instead, which is what the non-interactive flow always needs."
	}
	return "API token created in the dashboard (--set method=token). Non-interactive: export\n" +
		tokenEnv + " or pass --set token=- with the token on stdin.\n" +
		browser + "\n" +
		"--set account_id=<id> names the default account and --set accounts=<id>,<id>,...\n" +
		"the accounts the login works on, when the credentials see several; the\n" +
		"non-interactive flow requires one of them then."
}

// LoginOptions lists the --set keys of the login (see LoginHelp).
func (*provider) LoginOptions() []string {
	return []string{metaMethod, "token", metaAccountID, metaAccounts}
}

// RecordTypes are the record types Cloudflare creates through the API
// (SPF and SOA are refused there; DNSKEY only at the apex and DS only next
// to NS records, which the API reports).
func (*provider) RecordTypes() []string {
	return []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "PTR", "NAPTR", "TLSA", "URI", "CERT", "DNSKEY", "DS"}
}

func (*provider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResR2Bucket}
}

var _ platform.CoverageChanger = (*provider)(nil)

// CoverageChange compares the selections of a login before and after a new
// login: the accounts that left it are dropped from the inventory (their
// zones, the records of those, their R2 buckets), and any change of the
// selection makes the cached sets due. A login that only changes its
// default account covers what it covered.
func (*provider) CoverageChange(before, after map[string]string) (dropped []string, changed bool) {
	was, is := selectedAccounts(before), selectedAccounts(after)
	for _, a := range was {
		if !slices.Contains(is, a) {
			dropped = append(dropped, a)
		}
	}
	for _, a := range is {
		if !slices.Contains(was, a) {
			changed = true
		}
	}
	return dropped, changed || len(dropped) > 0
}

var _ platform.OwnerHinter = (*provider)(nil)

// OwnerHint says how to choose among several zones of one login that hold
// the same name: they are zones of different accounts of its selection
// (Cloudflare holds a name once per account), told apart by --account of
// the cloudflare commands, or by their zone id.
func (*provider) OwnerHint(kind platform.ResourceType, _ []string) string {
	if kind != platform.ResZone {
		return ""
	}
	return "the login holds zones of this name in several of its Cloudflare accounts: use `polyctl cloudflare ... --account <id or name>`, or the zone id, to choose"
}

// isOAuthMethod reads the method metadata of a stored account.
func isOAuthMethod(stored string) bool {
	return strings.EqualFold(strings.TrimSpace(stored), methodOAuth)
}

// isOAuth reports whether a profile is a browser login. The metadata says
// so; a secret that holds OAuth tokens and no API token says so as well.
func isOAuth(p platform.Profile) bool {
	if isOAuthMethod(p.Meta(metaMethod)) {
		return true
	}
	return strings.TrimSpace(p.Secret[secretToken]) == "" &&
		(p.Secret[secretAccessToken] != "" || p.Secret[secretRefreshToken] != "")
}

// loginMethod decides how to log in and, for the API-token method, returns
// the token when it was supplied.
//
// --set method= decides when given. Without it, a token supplied through
// --set token or CLOUDFLARE_API_TOKEN selects the API-token method; then an
// account that is logged in again keeps its method; then the interactive
// flow uses the browser once polyctl's OAuth client is public, and
// everything else an API token. The browser needs a person, so it is never
// chosen, and is refused when asked for, in the non-interactive flow.
func loginMethod(in platform.LoginInput, pio *prompt.IO) (method, token string, err error) {
	method = strings.ToLower(strings.TrimSpace(in.Opt(metaMethod, "")))
	optToken := strings.TrimSpace(in.Opt("token", ""))
	envToken := strings.TrimSpace(os.Getenv(tokenEnv))
	const tokenWays = "set " + tokenEnv + " or pass --set token=- with the token on stdin"
	switch method {
	case "", methodToken:
	case methodOAuth:
		if optToken != "" {
			return "", "", app.UsageErrf("--set method=%s does not take --set token: the browser login stores its own credentials; leave one of them out", methodOAuth)
		}
		if !in.Interactive {
			return "", "", app.UsageErrf("cloudflare login with method=%s needs a person to approve it in a browser, so it runs in the interactive flow only; in the non-interactive flow log in with an API token: %s", methodOAuth, tokenWays)
		}
		if envToken != "" {
			fmt.Fprintf(pio.Err, "note: %s is set and is not used by --set method=%s\n", tokenEnv, methodOAuth)
		}
		return methodOAuth, "", nil
	default:
		return "", "", app.UsageErrf("unknown cloudflare login method %q (expected %s or %s)", method, methodOAuth, methodToken)
	}
	if optToken != "" {
		return methodToken, optToken, nil
	}
	if envToken != "" {
		fmt.Fprintf(pio.Err, "using the API token from %s\n", tokenEnv)
		return methodToken, envToken, nil
	}
	if method == "" {
		switch {
		case in.Existing != nil:
			// Kept from the previous login: stored metadata, not input.
			if isOAuthMethod(in.Existing[metaMethod]) {
				method = methodOAuth
			}
		case oauthClientPublic && in.Interactive:
			method = methodOAuth
		}
		if method == methodOAuth {
			if !in.Interactive {
				return "", "", app.UsageErrf("this cloudflare account was authorized in a browser, which needs the interactive flow; log in there, or switch the account to an API token: %s", tokenWays)
			}
			return methodOAuth, "", nil
		}
	}
	if !in.Interactive {
		return "", "", app.UsageErrf("cloudflare login needs an API token: %s (create one at %s)", tokenWays, tokenPageURL)
	}
	return methodToken, "", nil
}

// Login authenticates with an API token or through the browser (see
// loginMethod for which).
//
// The API token comes from --set token (the CLI warns about argv exposure
// and accepts `--set token=-` for stdin), then from CLOUDFLARE_API_TOKEN.
// After that the interactive flow asks for it; the non-interactive flow
// fails with a usage error. It does not fall back to reading stdin on its
// own: a pipe that stays open without data (ssh without -n, docker run -i,
// some CI runners) would block the command forever, and a script fed to a
// shell on stdin would lose its next line.
func (p *provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	io := in.IO(ctx)
	method, token, err := loginMethod(in, io)
	if err != nil {
		return nil, err
	}
	if method == methodOAuth {
		return p.loginOAuth(ctx, in, io)
	}
	return p.loginToken(ctx, in, io, token)
}

// loginToken obtains and verifies an API token.
func (p *provider) loginToken(ctx context.Context, in platform.LoginInput, io *prompt.IO, token string) (*platform.LoginResult, error) {
	if token == "" {
		fmt.Fprintln(io.Err, "Cloudflare authenticates polyctl with an API token.")
		fmt.Fprintln(io.Err, "Create one at:", tokenPageURL)
		fmt.Fprintln(io.Err, `  - the "Edit zone DNS" template is a good starting point`)
		fmt.Fprintln(io.Err, "  - required permissions: Zone:Read, DNS:Edit; add Account:Read to list accounts")
		fmt.Fprintln(io.Err, "  - optional: Zone:Edit (cache purge, dev mode, SSL mode), User:Read (shows your email)")
		if in.MayOpenBrowser() {
			if err := in.OpenBrowser(tokenPageURL); err != nil {
				fmt.Fprintln(io.Err, "could not open a browser; open the URL above manually")
			}
		}
		var err error
		token, err = io.RequiredSecret("API token")
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(token)
	}

	a := newAPI(p.base(), token, "")
	tok, err := a.verifyToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	if tok.Status != "" && tok.Status != "active" {
		return nil, fmt.Errorf("%w: token status is %q", platform.ErrUnauthorized, tok.Status)
	}

	meta := map[string]string{metaMethod: storedToken, metaTokenID: tok.ID}
	accounts, accErr := a.listAccounts(ctx)
	if accErr != nil {
		fmt.Fprintf(io.Err, "note: the token cannot list accounts (%v); zones will be listed across all accounts it can see\n", accErr)
	}
	chosen, err := chooseAccounts(in, io, accounts, accErr == nil, accErr == nil, "token", true)
	if err != nil {
		return nil, err
	}
	if chosen != nil {
		chosen.store(meta)
	}

	// User details are optional (needs User:Read).
	if u, err := a.getUser(ctx); err == nil && u.Email != "" {
		meta[metaEmail] = u.Email
	}
	return &platform.LoginResult{
		Secret:   map[string]string{secretToken: token},
		Metadata: meta,
		Label:    loginLabel(meta, chosen, "token "+tok.ID),
	}, nil
}

// loginOAuth authorizes polyctl in the browser. /user/tokens/verify is for
// API tokens, so the login is verified by listing zones, which the required
// scopes always allow.
func (p *provider) loginOAuth(ctx context.Context, in platform.LoginInput, io *prompt.IO) (*platform.LoginResult, error) {
	if !in.Interactive {
		// loginMethod refuses this already; nothing must start a listener
		// that nobody will answer.
		return nil, app.UsageErrf("cloudflare login with method=%s runs in the interactive flow only", methodOAuth)
	}
	tok, err := authorize(ctx, in, io)
	if err != nil {
		return nil, err
	}
	// The session has no store yet: a renewal during the login stays in
	// memory and is part of what the login returns.
	sess := &oauthSession{prof: platform.Profile{Name: in.ProfileName}, tok: tok}
	a := newOAuthAPI(p.base(), sess, "")
	if err := a.probe(ctx); err != nil {
		return nil, fmt.Errorf("verify the authorization: %w", err)
	}

	// The accounts the authorization covers. Listing them is an optional
	// scope; without it they are read off the zones, which every login can
	// list.
	var accounts []account
	accErr := errors.New("the " + scopeAccountRead + " scope was not granted")
	if sess.mayHave(scopeAccountRead) {
		accounts, accErr = a.listAccounts(ctx)
	}
	complete := accErr == nil && len(accounts) > 0
	if !complete {
		if derived, err := a.accountsOfZones(ctx); err == nil {
			accounts, accErr = derived, nil
		}
	}
	if accErr != nil {
		fmt.Fprintf(io.Err, "note: the accounts of this authorization cannot be listed (%v); zones will be listed across all accounts it covers\n", accErr)
	}
	// The default account of the previous login is a preference here: the
	// person may have approved another one in the browser.
	chosen, err := chooseAccounts(in, io, accounts, accErr == nil, complete, "authorization", false)
	if err != nil {
		return nil, err
	}

	tok = sess.token()
	meta := map[string]string{metaMethod: methodOAuth}
	if len(tok.Scopes) > 0 {
		meta[metaScopes] = strings.Join(tok.Scopes, " ")
		var declined []string
		for _, s := range OAuthOptionalScopes {
			if !tok.has(s) {
				declined = append(declined, s)
			}
		}
		if len(declined) > 0 {
			fmt.Fprintf(io.Err, "note: not granted: %s; the commands that need them will say so\n", strings.Join(declined, ", "))
		}
	}
	if chosen != nil {
		chosen.store(meta)
	}
	// The e-mail is optional: the user details scope, else the userinfo
	// endpoint, else none.
	if email := oauthEmail(ctx, a); email != "" {
		meta[metaEmail] = email
	}
	tok = sess.token()
	return &platform.LoginResult{
		Secret:   tok.secret(nil),
		Metadata: meta,
		Label:    loginLabel(meta, chosen, "browser authorization"),
	}, nil
}

// loginLabel is the short description shown after a login: the e-mail,
// else the default account, with the number of other selected accounts.
func loginLabel(meta map[string]string, sel *selection, fallback string) string {
	acct, more := "", 0
	if sel != nil {
		if acct = sel.def.Name; acct == "" {
			acct = sel.def.ID
		}
		more = len(sel.accounts) - 1
	}
	switch e := meta[metaEmail]; {
	case e != "" && more > 0:
		return fmt.Sprintf("%s (account %s, +%d more)", e, acct, more)
	case e != "":
		return e
	case acct != "" && more > 0:
		return fmt.Sprintf("%s (+%d more)", acct, more)
	case acct != "":
		return acct
	}
	return fallback
}

// selection is the accounts of a login: the default one and the selected
// set, the default first.
type selection struct {
	def      account
	accounts []string
}

func newSelection(def account, accounts []string) *selection {
	return &selection{def: def, accounts: selectedAccounts(map[string]string{metaAccountID: def.ID, metaAccounts: strings.Join(accounts, ",")})}
}

// store writes the selection into the metadata of the login.
func (s *selection) store(meta map[string]string) { setSelection(meta, s.def, s.accounts) }

// accountChooser resolves the accounts of a login among those its
// credentials see.
type accountChooser struct {
	in  platform.LoginInput
	pio *prompt.IO
	// accounts are the accounts the credentials see. listed says the list
	// could be read at all (a token without Account:Read cannot; that is
	// tolerated), complete that it is the list of the accounts and was not
	// read off the zones, which shows the accounts with a zone only.
	accounts         []account
	listed, complete bool
	// what names the credential in messages.
	what string
	// prev is the selection stored by the previous login.
	prev []string
}

func (c *accountChooser) find(id string) *account {
	for i := range c.accounts {
		if c.accounts[i].ID == id {
			return &c.accounts[i]
		}
	}
	return nil
}

// visible reports whether there is a list to check an account against.
func (c *accountChooser) visible() bool { return c.listed && len(c.accounts) > 0 }

// named is the account of an id: as the credentials list it, else with
// the name the previous login stored for it.
func (c *accountChooser) named(id string) account {
	if a := c.find(id); a != nil {
		return *a
	}
	name := ""
	if c.in.Existing != nil && c.in.Existing[metaAccountID] == id {
		name = c.in.Existing[metaAccountName]
	}
	return account{ID: id, Name: name}
}

// kept is the selection of the previous login without the accounts the
// credentials no longer see, which is said. An account missing from a list
// read off the zones stays: it may only have no zone.
func (c *accountChooser) kept() []string {
	var out []string
	for _, id := range c.prev {
		if c.find(id) == nil && c.visible() && c.complete {
			fmt.Fprintf(c.pio.Err, "note: account %s of the previous selection is not visible to this %s and was left out\n", id, c.what)
			continue
		}
		out = append(out, id)
	}
	c.prev = out
	return out
}

// keptSelection is the selection of a login that names def as the default
// account and says nothing else: the selection stored before, with def.
func (c *accountChooser) keptSelection(def account) *selection {
	return newSelection(def, c.kept())
}

// optSelection is the selection --set gives, if it gives one:
//
//   - account_id=X makes X the default account; the selection is the one
//     stored before, with X;
//   - accounts=a,b,c is the selection, with the default account. Without
//     account_id, the default is the one stored before when it is still
//     selected, else the first account listed, which is said on stderr.
//
// Every account named must be one the credentials see, when they can list
// their accounts.
func (c *accountChooser) optSelection() (sel *selection, given bool, err error) {
	def := strings.TrimSpace(c.in.Opt(metaAccountID, ""))
	list := splitAccounts(c.in.Opt(metaAccounts, ""))
	for _, id := range append([]string{def}, list...) {
		if id == "" {
			continue
		}
		if err := checkAccountID(id); err != nil {
			return nil, false, app.UsageErrf("%v (--set account_id=<id>, --set accounts=<id>,<id>,...)", err)
		}
		if c.visible() && c.find(id) == nil {
			return nil, false, fmt.Errorf("account %q is not visible to this %s (visible: %s)", id, c.what, accountNames(c.accounts))
		}
	}
	switch {
	case len(list) > 0:
		if def == "" {
			if len(c.prev) > 0 && slices.Contains(list, c.prev[0]) {
				def = c.prev[0]
			} else {
				def = list[0]
				fmt.Fprintf(c.pio.Err, "using %s as the default account (pass --set account_id=<id> to choose another)\n", def)
			}
		}
		return newSelection(c.named(def), list), true, nil
	case def != "":
		// The default of before is checked like the rest of the selection.
		return c.keptSelection(c.named(def)), true, nil
	}
	return nil, false, nil
}

// chooseAccounts resolves the accounts of a login: --set (see
// optSelection), then, in the interactive flow of credentials that see
// several accounts, a multi-select of them with the selection stored
// before ticked (a first login ticks none) and, when several are selected,
// the question which one is the default. Credentials that see one account
// work on it without a question.
//
// The non-interactive flow asks nothing: the selection stored before is
// kept, else the only visible account is used, and several are a usage
// error.
//
// listed and complete describe the list (see accountChooser), what names
// the credential in messages. With strictExisting the default account of
// the previous login must still be visible; otherwise it is only
// preferred. A nil selection is that of credentials whose accounts cannot
// be listed and are not named: the login is not bound to an account.
func chooseAccounts(in platform.LoginInput, pio *prompt.IO, accounts []account, listed, complete bool, what string, strictExisting bool) (*selection, error) {
	c := &accountChooser{in: in, pio: pio, accounts: accounts, listed: listed, complete: complete, what: what}
	if in.Existing != nil {
		c.prev = selectedAccounts(in.Existing)
	}
	if sel, given, err := c.optSelection(); given || err != nil {
		return sel, err
	}
	def := ""
	if len(c.prev) > 0 {
		def = c.prev[0]
		switch {
		case c.find(def) != nil:
		case !c.visible():
			// Nothing to check against: the selection stays as it is.
			return newSelection(c.named(def), c.prev), nil
		case strictExisting:
			return nil, fmt.Errorf("account %q is not visible to this %s (visible: %s)", def, what, accountNames(accounts))
		default:
			fmt.Fprintf(pio.Err, "note: the account of the previous login (%s) is not covered by this %s\n", def, what)
			def, c.prev = "", c.prev[1:]
		}
	}
	if !in.Interactive {
		switch {
		case def != "":
			return c.keptSelection(c.named(def)), nil
		case len(accounts) == 1:
			return newSelection(accounts[0], nil), nil
		case len(accounts) > 1:
			return nil, app.UsageErrf("the %s sees %d accounts; pass --set account_id=<id> to choose one (and --set accounts=<id>,<id>,... to select more) of: %s", what, len(accounts), accountNames(accounts))
		}
		return nil, nil
	}
	opts := make([]prompt.Option, 0, len(accounts))
	for _, acc := range accounts {
		opts = append(opts, prompt.Option{Label: fmt.Sprintf("%s (%s)", acc.Name, acc.ID), Value: acc.ID})
	}
	preset := c.kept()
	for _, id := range preset {
		// A selected account the list does not show stays offered.
		if c.find(id) == nil {
			opts = append(opts, prompt.Option{Label: id, Value: id})
		}
	}
	switch len(opts) {
	case 0:
		return nil, nil
	case 1:
		return newSelection(c.named(opts[0].Value), nil), nil
	}
	chosen, err := in.MultiSelect(pio, "Cloudflare accounts to work on (the inventory covers them all)", opts, preset)
	if err != nil {
		return nil, err
	}
	switch len(chosen) {
	case 0:
		return nil, fmt.Errorf("%w: no account was selected", platform.ErrInvalidInput)
	case 1:
		return newSelection(c.named(chosen[0]), nil), nil
	}
	if !slices.Contains(chosen, def) {
		def = chosen[0]
	}
	var defOpts []prompt.Option
	for _, o := range opts {
		if slices.Contains(chosen, o.Value) {
			defOpts = append(defOpts, o)
		}
	}
	if def, err = in.Select(pio, "Default account (where new zones are created)", defOpts, def); err != nil {
		return nil, err
	}
	return newSelection(c.named(def), chosen), nil
}

func accountNames(accounts []account) string {
	parts := make([]string, len(accounts))
	for i, a := range accounts {
		parts[i] = fmt.Sprintf("%s=%s", a.ID, a.Name)
	}
	return strings.Join(parts, ", ")
}

// probe makes the cheapest request the required scopes allow: one zone.
func (a *api) probe(ctx context.Context) error {
	q := a.zoneQuery()
	q.Set("per_page", "1")
	_, err := a.do(ctx, http.MethodGet, "/zones", q, nil, nil)
	return err
}

// accountsOfZones reads the accounts off the zones the credentials can see.
func (a *api) accountsOfZones(ctx context.Context) ([]account, error) {
	zones, err := paginate[apiZone](ctx, a, "/zones", url.Values{}, zonesPerPage)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []account
	for _, z := range zones {
		if z.Account.ID == "" || seen[z.Account.ID] {
			continue
		}
		seen[z.Account.ID] = true
		out = append(out, account{ID: z.Account.ID, Name: z.Account.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Open returns a client bound to the profile's credentials, its selected
// accounts and its default account. Nothing is requested here: an expired
// access token of a browser login is renewed by the first request that
// needs it.
func (p *provider) Open(ctx context.Context, prof platform.Profile) (platform.Client, error) {
	sel := selectedAccounts(prof.Metadata)
	def := ""
	if len(sel) > 0 {
		def = sel[0]
	}
	if isOAuth(prof) {
		sess := newOAuthSession(prof)
		if sess.tok.Access == "" && sess.tok.Refresh == "" {
			return nil, fmt.Errorf("%w: profile %q holds no Cloudflare authorization; run `%s`", platform.ErrUnauthorized, prof.Name, sess.loginAgain())
		}
		a := newOAuthAPI(p.base(), sess, def)
		a.accounts = sel
		return &Client{api: a, profile: prof}, nil
	}
	token := strings.TrimSpace(prof.Secret[secretToken])
	if token == "" {
		return nil, fmt.Errorf("%w: profile %q has no %s", platform.ErrUnauthorized, prof.Name, secretToken)
	}
	a := newAPI(p.base(), token, def)
	a.accounts = sel
	return &Client{api: a, profile: prof}, nil
}

// Client is an authenticated Cloudflare session. It implements
// platform.Client and platform.DNSService.
type Client struct {
	api     *api
	profile platform.Profile
	// peers opens the other Cloudflare accounts (set by the runtime).
	peers func(ctx context.Context) ([]platform.Peer, error)
	// r2AccountID caches the account R2 requests go to when the profile
	// pins none.
	r2AccountID string
}

var (
	_ platform.Client     = (*Client)(nil)
	_ platform.DNSService = (*Client)(nil)
)

// Verify checks the credentials and reports the principal.
func (c *Client) Verify(ctx context.Context) (*platform.Identity, error) {
	if c.api.oauth != nil {
		return c.verifyOAuth(ctx)
	}
	tok, err := c.api.verifyToken(ctx)
	if err != nil {
		return nil, err
	}
	id := &platform.Identity{
		Account: c.api.accountID,
		User:    c.profile.Meta(metaEmail),
		Extra:   map[string]string{"token_id": tok.ID, "token_status": tok.Status},
	}
	c.identifyAccounts(id)
	if tok.ExpiresOn != "" {
		id.Extra["token_expires_on"] = tok.ExpiresOn
	}
	if tok.Status != "active" {
		return id, fmt.Errorf("%w: token status is %q", platform.ErrUnauthorized, tok.Status)
	}
	return id, nil
}

// identifyAccounts adds the name of the default account and, when the
// login works on several accounts, its selection to an identity.
func (c *Client) identifyAccounts(id *platform.Identity) {
	if n := c.profile.Meta(metaAccountName); n != "" {
		id.Extra["account_name"] = n
	}
	if len(c.api.accounts) > 1 {
		id.Extra[metaAccounts] = strings.Join(c.api.accounts, ",")
	}
}

// verifyOAuth checks a browser login. The token verify endpoint is for API
// tokens, so the check is a request the required scopes allow (one zone),
// which also renews an expired access token. What is reported comes from
// the login's metadata and the token itself; the e-mail is looked up only
// when the login could not read it, and its absence is not an error.
func (c *Client) verifyOAuth(ctx context.Context) (*platform.Identity, error) {
	if err := c.api.probe(ctx); err != nil {
		return nil, err
	}
	tok := c.api.oauth.token()
	id := &platform.Identity{
		Account: c.api.accountID,
		User:    c.profile.Meta(metaEmail),
		Extra:   map[string]string{"method": methodOAuth},
	}
	c.identifyAccounts(id)
	if len(tok.Scopes) > 0 {
		id.Extra["scopes"] = strings.Join(tok.Scopes, " ")
	}
	if !tok.Expiry.IsZero() {
		id.Extra["access_token_expires_on"] = tok.Expiry.UTC().Format(time.RFC3339)
	}
	if id.User == "" {
		id.User = oauthEmail(ctx, c.api)
	}
	return id, nil
}

// oauthEmail looks up the e-mail behind a browser login: through the user
// details scope when the login has it, else at the userinfo endpoint. ""
// means it is not known, which is not an error.
func oauthEmail(ctx context.Context, a *api) string {
	if a.oauth.mayHave(scopeUserRead) {
		if u, err := a.getUser(ctx); err == nil && u.Email != "" {
			return u.Email
		}
	}
	if ui, err := getUserinfo(ctx, a.oauth.current()); err == nil && ui.Email != "" {
		return ui.Email
	}
	return ""
}

// Sync fetches every resource of the given type, in every selected account
// of the login. A sync that fails for some accounts only returns the rows
// of the others with a *platform.RegionSyncError: the rows stored for the
// failed accounts are kept.
func (c *Client) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	switch rt {
	case platform.ResZone:
		return c.eachAccount(ctx, func(ctx context.Context, ac *Client) ([]platform.Resource, error) {
			zs, err := ac.api.listZonesOf(ctx, ac.api.accountID)
			if err != nil {
				return nil, err
			}
			return zoneResources(toZones(zs)), nil
		})
	case platform.ResDNSRecord:
		return c.syncRecords(ctx)
	case platform.ResR2Bucket:
		return c.syncBuckets(ctx)
	}
	return nil, fmt.Errorf("%s: %w", rt, platform.ErrNotSupported)
}

// syncRecords lists the records of every visible zone. A token commonly has
// Zone:Read on all zones but DNS:Read on a subset; the API answers 403 for
// the others, and zones in moved/initializing state may answer 404. Such
// zones are skipped with a warning so the readable ones still get indexed.
// Only when every zone fails (or a non-permission error occurs) is the error
// returned, so a token without any DNS permission still surfaces as
// ErrUnauthorized.
//
// With several accounts selected, an account whose zones cannot be listed
// (or one of whose zones fails for another reason) is a failure of that
// account: its stored records are kept. The skipped zones are counted
// across all the accounts, so an account in which the token reads no
// records at all does not fail as long as another account has some.
func (c *Client) syncRecords(ctx context.Context) ([]platform.Resource, error) {
	var (
		skipped []error
		okZones int
	)
	out, err := c.eachAccount(ctx, func(ctx context.Context, ac *Client) ([]platform.Resource, error) {
		zs, err := ac.api.listZonesOf(ctx, ac.api.accountID)
		if err != nil {
			return nil, err
		}
		var out []platform.Resource
		var skip []error
		ok := 0
		for _, z := range toZones(zs) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			recs, err := ac.ListRecords(ctx, z.ID)
			if err != nil {
				if errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrNotFound) {
					skip = append(skip, fmt.Errorf("zone %s: %w", z.Name, err))
					continue
				}
				return nil, fmt.Errorf("zone %s: %w", z.Name, err)
			}
			ok++
			out = append(out, app.RecordResources(z.ID, z.Name, recs)...)
		}
		// Counted only for an account that was read to its end: a failed
		// account keeps its stored rows, whatever was skipped in it.
		skipped = append(skipped, skip...)
		okZones += ok
		return out, nil
	})
	if err != nil && platform.AsRegionSyncError(err) == nil {
		return nil, err
	}
	if len(skipped) > 0 && okZones == 0 {
		if err != nil {
			skipped = append(skipped, err)
		}
		return nil, errors.Join(skipped...)
	}
	for _, e := range skipped {
		warnf("cloudflare/%s: skipped %v", c.profile.Name, e)
	}
	return out, err
}

// ListZones returns the zones of every selected account of the login (all
// the zones the credentials see when it has none).
func (c *Client) ListZones(ctx context.Context) ([]platform.Zone, error) {
	zs, err := c.api.listZones(ctx)
	if err != nil {
		return nil, err
	}
	return toZones(zs), nil
}

// GetZone returns one zone by id or name, among the selected accounts.
func (c *Client) GetZone(ctx context.Context, idOrName string) (*platform.Zone, error) {
	z, err := c.api.findZone(ctx, idOrName)
	if err != nil {
		return nil, err
	}
	out := toZone(*z)
	return &out, nil
}

// ListRecords returns every DNS record of a zone.
func (c *Client) ListRecords(ctx context.Context, zoneID string) ([]platform.Record, error) {
	rs, err := c.api.listRecords(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Record, 0, len(rs))
	for _, r := range rs {
		out = append(out, recordIn(zoneID, r))
	}
	return out, nil
}

// recordIn converts a record of zoneID. Cloudflare no longer returns zone_id
// in DNS record responses (deprecated 2024-11-30), so the zone the request
// named fills it in.
func recordIn(zoneID string, r apiRecord) platform.Record {
	out := toRecord(r)
	if out.ZoneID == "" {
		out.ZoneID = zoneID
	}
	return out
}

// CreateRecord creates a record; r.Name is the FQDN.
func (c *Client) CreateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	res, err := c.api.createRecord(ctx, zoneID, toBody(r))
	if err != nil {
		return nil, err
	}
	out := recordIn(zoneID, *res)
	return &out, nil
}

// UpdateRecord replaces the record identified by r.ID.
func (c *Client) UpdateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	if r.ID == "" {
		return nil, errors.New("record id is required")
	}
	res, err := c.api.updateRecord(ctx, zoneID, r.ID, toBody(r))
	if err != nil {
		return nil, err
	}
	out := recordIn(zoneID, *res)
	return &out, nil
}

// PatchRecord changes only the fields named in p (PATCH): ttl, proxied,
// comment and tags of the record stay as they are unless p names them.
// A value of a data type (SRV, CAA, ...) is sent as its components.
func (c *Client) PatchRecord(ctx context.Context, zoneID string, cur platform.Record, p platform.RecordPatch) (*platform.Record, error) {
	if cur.ID == "" {
		return nil, errors.New("record id is required")
	}
	body := map[string]any{}
	if p.Value != nil {
		if isDataType(cur.Type) {
			d, prio, err := dataFromText(cur.Type, *p.Value, p.Priority)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", platform.ErrInvalidInput, err)
			}
			body["data"] = d
			if prio != nil {
				body["priority"] = *prio
			}
		} else {
			body["content"] = *p.Value
		}
	}
	if p.TTL != nil {
		ttl := *p.TTL
		if ttl <= 0 {
			ttl = 1
		}
		body["ttl"] = ttl
	}
	if p.Proxied != nil {
		body["proxied"] = *p.Proxied
	}
	if p.Priority != nil {
		body["priority"] = *p.Priority
	}
	res, err := c.api.patchRecord(ctx, zoneID, cur.ID, body)
	if err != nil {
		return nil, err
	}
	out := recordIn(zoneID, *res)
	return &out, nil
}

var (
	_ platform.RecordPatcher = (*Client)(nil)
	_ platform.RecordTyper   = (*provider)(nil)
)

// DeleteRecord deletes a record.
func (c *Client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	return c.api.deleteRecord(ctx, zoneID, recordID)
}
