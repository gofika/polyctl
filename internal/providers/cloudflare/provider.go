// Package cloudflare implements the Cloudflare provider: API-token login,
// zone and DNS record management through the v4 REST API, inventory sync
// and the `polyctl cf` native command tree.
package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

func init() { platform.Register(&provider{}) }

// DefaultBaseURL is the Cloudflare v4 API endpoint.
const DefaultBaseURL = "https://api.cloudflare.com/client/v4"

// tokenPageURL is where users create API tokens.
const tokenPageURL = "https://dash.cloudflare.com/profile/api-tokens"

// tokenEnv is the environment variable read for non-interactive logins. It is
// the name the official Cloudflare tooling (Terraform provider, wrangler)
// understands, so a token exported once serves every tool.
const tokenEnv = "CLOUDFLARE_API_TOKEN"

// warnf reports non-fatal conditions (skipped zones during sync). Tests
// replace it to capture the output.
var warnf = func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }

// Secret keys (stored in the credential store):
//
//	api_token  the Cloudflare API token (Bearer)
//
// Metadata keys (stored in plaintext config.yaml, never sensitive):
//
//	method        always "api_token"
//	account_id    the pinned account id (may be empty when the token cannot list accounts)
//	account_name  the account's display name
//	email         the user's email when the token has User:Read (optional)
//	token_id      the public id of the token, as reported by /user/tokens/verify
const (
	secretToken     = "api_token"
	metaMethod      = "method"
	metaAccountID   = "account_id"
	metaAccountName = "account_name"
	metaEmail       = "email"
	metaTokenID     = "token_id"
)

type provider struct {
	// baseURL overrides DefaultBaseURL (tests).
	baseURL string
}

func (p *provider) base() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return DefaultBaseURL
}

func (*provider) ID() platform.ID     { return platform.Cloudflare }
func (*provider) DisplayName() string { return "Cloudflare" }
func (*provider) LoginHelp() string {
	return "API token created in the dashboard (non-interactive: export " + tokenEnv + " or pipe the token on stdin; --set account_id=... pins an account)"
}
func (*provider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord}
}

// Login obtains and verifies an API token. Cloudflare has no public OAuth
// flow for third-party CLIs, so the user creates a token in the dashboard
// and pastes it here. Non-interactive callers export CLOUDFLARE_API_TOKEN or
// pipe the token on stdin. `--set token=...` still works for compatibility
// but is discouraged: argv is visible in process listings and shell history.
func (p *provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	io := prompt.New(in.Stdin, in.Stdout, in.Stderr)
	token := strings.TrimSpace(in.Opt("token", ""))
	if token != "" {
		fmt.Fprintln(io.Err, "warning: a token passed with --set token=... is exposed in process listings and shell history; prefer "+tokenEnv+" or stdin")
	}
	if token == "" {
		if v := strings.TrimSpace(os.Getenv(tokenEnv)); v != "" {
			token = v
			fmt.Fprintf(io.Err, "using the API token from %s\n", tokenEnv)
		}
	}
	if token == "" {
		fmt.Fprintln(io.Err, "Cloudflare authenticates polyctl with an API token.")
		fmt.Fprintln(io.Err, "Create one at:", tokenPageURL)
		fmt.Fprintln(io.Err, `  - the "Edit zone DNS" template is a good starting point`)
		fmt.Fprintln(io.Err, "  - required permissions: Zone:Read, DNS:Edit; add Account:Read to list accounts")
		fmt.Fprintln(io.Err, "  - optional: Zone:Edit (cache purge, dev mode, SSL mode), User:Read (shows your email)")
		if !in.NoBrowser && in.OpenBrowser != nil {
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

	meta := map[string]string{metaMethod: "api_token", metaTokenID: tok.ID}

	// Account selection: --set account_id > previous profile metadata > the
	// only account > interactive choice. Tokens without Account:Read cannot
	// list accounts; that is tolerated.
	wantID := in.Opt(metaAccountID, "")
	if wantID == "" && in.Existing != nil {
		wantID = in.Existing[metaAccountID]
	}
	accounts, accErr := a.listAccounts(ctx)
	if accErr != nil {
		fmt.Fprintf(io.Err, "note: the token cannot list accounts (%v); zones will be listed across all accounts it can see\n", accErr)
	}
	var chosen *account
	switch {
	case wantID != "":
		for i := range accounts {
			if accounts[i].ID == wantID {
				chosen = &accounts[i]
			}
		}
		if chosen == nil {
			if accErr == nil && len(accounts) > 0 {
				return nil, fmt.Errorf("account %q is not visible to this token (visible: %s)", wantID, accountNames(accounts))
			}
			name := ""
			if in.Existing != nil && in.Existing[metaAccountID] == wantID {
				name = in.Existing[metaAccountName]
			}
			chosen = &account{ID: wantID, Name: name}
		}
	case len(accounts) == 1:
		chosen = &accounts[0]
	case len(accounts) > 1:
		if !io.IsTerminal() {
			return nil, fmt.Errorf("the token sees %d accounts; pass --set account_id=<id> to choose one of: %s", len(accounts), accountNames(accounts))
		}
		opts := make([]string, len(accounts))
		for i, acc := range accounts {
			opts[i] = fmt.Sprintf("%s (%s)", acc.Name, acc.ID)
		}
		pick, err := io.Choose("Account", opts, opts[0])
		if err != nil {
			return nil, err
		}
		for i, o := range opts {
			if o == pick {
				chosen = &accounts[i]
			}
		}
	}
	if chosen != nil {
		meta[metaAccountID] = chosen.ID
		meta[metaAccountName] = chosen.Name
	}

	// User details are optional (needs User:Read).
	if u, err := a.getUser(ctx); err == nil && u.Email != "" {
		meta[metaEmail] = u.Email
	}

	label := meta[metaEmail]
	if label == "" && chosen != nil {
		label = chosen.Name
		if label == "" {
			label = chosen.ID
		}
	}
	if label == "" {
		label = "token " + tok.ID
	}
	return &platform.LoginResult{
		Secret:   map[string]string{secretToken: token},
		Metadata: meta,
		Label:    label,
	}, nil
}

func accountNames(accounts []account) string {
	parts := make([]string, len(accounts))
	for i, a := range accounts {
		parts[i] = fmt.Sprintf("%s=%s", a.ID, a.Name)
	}
	return strings.Join(parts, ", ")
}

// Open returns a client bound to the profile's token and pinned account.
func (p *provider) Open(ctx context.Context, prof platform.Profile) (platform.Client, error) {
	token := strings.TrimSpace(prof.Secret[secretToken])
	if token == "" {
		return nil, fmt.Errorf("%w: profile %q has no %s", platform.ErrUnauthorized, prof.Name, secretToken)
	}
	return &Client{api: newAPI(p.base(), token, prof.Meta(metaAccountID)), profile: prof}, nil
}

// Client is an authenticated Cloudflare session. It implements
// platform.Client and platform.DNSService.
type Client struct {
	api     *api
	profile platform.Profile
}

var (
	_ platform.Client     = (*Client)(nil)
	_ platform.DNSService = (*Client)(nil)
)

// Verify checks the token and reports the principal.
func (c *Client) Verify(ctx context.Context) (*platform.Identity, error) {
	tok, err := c.api.verifyToken(ctx)
	if err != nil {
		return nil, err
	}
	id := &platform.Identity{
		Account: c.profile.Meta(metaAccountID),
		User:    c.profile.Meta(metaEmail),
		Extra:   map[string]string{"token_id": tok.ID, "token_status": tok.Status},
	}
	if n := c.profile.Meta(metaAccountName); n != "" {
		id.Extra["account_name"] = n
	}
	if tok.ExpiresOn != "" {
		id.Extra["token_expires_on"] = tok.ExpiresOn
	}
	if tok.Status != "active" {
		return id, fmt.Errorf("%w: token status is %q", platform.ErrUnauthorized, tok.Status)
	}
	return id, nil
}

// Sync fetches every resource of the given type.
func (c *Client) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	switch rt {
	case platform.ResZone:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		return app.ZoneResources(zones), nil
	case platform.ResDNSRecord:
		return c.syncRecords(ctx)
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
func (c *Client) syncRecords(ctx context.Context) ([]platform.Resource, error) {
	zones, err := c.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	var (
		out     []platform.Resource
		skipped []error
		okZones int
	)
	for _, z := range zones {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		recs, err := c.ListRecords(ctx, z.ID)
		if err != nil {
			if errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrNotFound) {
				skipped = append(skipped, fmt.Errorf("zone %s: %w", z.Name, err))
				continue
			}
			return nil, fmt.Errorf("zone %s: %w", z.Name, err)
		}
		okZones++
		out = append(out, app.RecordResources(z.ID, z.Name, recs)...)
	}
	if len(skipped) > 0 && okZones == 0 {
		return nil, errors.Join(skipped...)
	}
	for _, e := range skipped {
		warnf("cloudflare/%s: skipped %v", c.profile.Name, e)
	}
	return out, nil
}

// ListZones returns all zones visible to the token (restricted to the pinned
// account when one is configured).
func (c *Client) ListZones(ctx context.Context) ([]platform.Zone, error) {
	zs, err := c.api.listZones(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Zone, 0, len(zs))
	for _, z := range zs {
		out = append(out, toZone(z))
	}
	return out, nil
}

// GetZone returns one zone by id or name.
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
		out = append(out, toRecord(r))
	}
	return out, nil
}

// CreateRecord creates a record; r.Name is the FQDN.
func (c *Client) CreateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	res, err := c.api.createRecord(ctx, zoneID, toBody(r))
	if err != nil {
		return nil, err
	}
	out := toRecord(*res)
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
	out := toRecord(*res)
	return &out, nil
}

// DeleteRecord deletes a record.
func (c *Client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	return c.api.deleteRecord(ctx, zoneID, recordID)
}
