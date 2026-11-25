// Package gcp implements the Google Cloud provider: Cloud DNS managed zones
// and records, Compute Engine instances, and the login flows that produce
// a profile.
//
// Profile metadata keys (stored in plaintext config.yaml, never sensitive):
//
//	method       "adc", "service_account" or "oauth"
//	project      the default Google Cloud project id: the one a command
//	             works on when nothing else names a project
//	disabled_projects
//	             the projects kept out of every sync, list and lookup,
//	             comma-separated; absent when none is disabled. Every
//	             other project the credentials see is enabled
//	email        the user account email (adc / oauth), when known
//	client_email the service account email (service_account)
//	oauth_client "builtin" when the account was logged in with the OAuth
//	             client built into polyctl (oauth); absent with a client
//	             of the user
//
// Profile secret keys (stored in the credential store):
//
//	service_account_json  the full JSON key file (service_account)
//	client_id             OAuth client id (oauth, client of the user)
//	client_secret         OAuth client secret (oauth, client of the user)
//	refresh_token         OAuth refresh token (oauth)
//
// An account of the built-in OAuth client stores the refresh token only:
// the client comes from the binary (see oauth_builtin.go).
//
// The adc method stores no secret: credentials stay in the Application
// Default Credentials file written by `gcloud auth application-default login`.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/gofika/polyctl/internal/platform"
)

func init() { platform.Register(&provider{}) }

const (
	scopeCloudPlatform = "https://www.googleapis.com/auth/cloud-platform"
	scopeUserinfoEmail = "https://www.googleapis.com/auth/userinfo.email"

	methodADC            = "adc"
	methodServiceAccount = "service_account"
	methodOAuth          = "oauth"
)

type provider struct{}

func (*provider) ID() platform.ID     { return platform.GCP }
func (*provider) DisplayName() string { return "Google Cloud" }
func (*provider) LoginHelp() string {
	return `Google Cloud: without --set method, a terminal login opens the browser and
signs in with polyctl's built-in OAuth client (gcloud is not needed); a build
without that client uses Application Default Credentials when there are any
and asks which way to log in otherwise. Methods: method=oauth is the browser
login, with the built-in client or, with --set client_id=... --set
client_secret=- (the secret read from stdin), an OAuth client of your own
(type "Desktop app"); method=service_account stores a JSON key file (--set
key_file=PATH); method=adc uses Application Default Credentials from "gcloud
auth application-default login". A re-login keeps the method of the account.
One account works on every project its credentials see, the ones created
later included; "polyctl gcp project disable" keeps the ones that are not used
out of every sync. A login chooses the default project only, the one new
resources are created in: on a terminal it is asked when several projects are
visible, and a re-login keeps the one it had. --set project=ID sets it without
prompting; change it later with "polyctl gcp project use". --set
disabled_projects=ID,ID,... sets the disabled projects (an empty value enables
all of them again); without it a re-login keeps them. --set projects=..., which
chose the projects of an account in polyctl 0.4.0, is accepted and no longer
used, apart from naming the default project when project is not given.
Non-interactive: nothing is asked and the default method is adc; key_file, the
project (for oauth, or when several are visible) and, without a built-in
client, client_id and client_secret must be given, and the oauth flow prints
the URL and waits up to 5 minutes for the browser to return.`
}

// LoginOptions lists the --set keys of the login (see LoginHelp).
func (*provider) LoginOptions() []string {
	return []string{"method", "project", "disabled_projects", "projects", "key_file", "client_id", "client_secret"}
}

// RecordTypes are the record types Cloud DNS can write.
func (*provider) RecordTypes() []string {
	return []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "PTR", "NAPTR", "SPF", "TLSA", "DNSKEY", "DS"}
}

var _ platform.RecordTyper = (*provider)(nil)
var _ platform.OwnerHinter = (*provider)(nil)

// OwnerHint says how to choose among several managed zones of one account
// that hold the same DNS name: zones of different projects are told apart
// by --project of the gcp dns commands, any zones by their id.
func (*provider) OwnerHint(kind platform.ResourceType, ids []string) string {
	if kind != platform.ResZone {
		return ""
	}
	projects := map[string]bool{}
	for _, id := range ids {
		p, _ := splitZoneID(id)
		projects[p] = true
	}
	if len(projects) > 1 {
		return "the managed zones are in different projects: use `polyctl gcp dns ... --project <id>`, or `polyctl gcp dns ...` with the zone id <project>/<managed zone>, to choose"
	}
	return "the project holds several managed zones of this DNS name: use `polyctl gcp dns ...` with the zone id <project>/<managed zone> to choose"
}

var _ platform.CoverageChanger = (*provider)(nil)

// CoverageChange compares what an account covers before and after a
// re-login: the projects disabled by it are dropped from the inventory,
// and a change of the default project or of the disabled projects makes
// the cached sets due, as does the first login after every visible
// project became enabled (the stored selection is gone).
func (*provider) CoverageChange(before, after map[string]string) (dropped []string, changed bool) {
	was, is := disabledProjects(before), disabledProjects(after)
	for _, p := range is {
		if !slices.Contains(was, p) {
			dropped = append(dropped, p)
		}
	}
	_, legacyWas := before[legacyProjects]
	_, legacyIs := after[legacyProjects]
	changed = len(dropped) > 0 || len(was) != len(is) || legacyWas != legacyIs ||
		strings.TrimSpace(before[metaProject]) != strings.TrimSpace(after[metaProject])
	return dropped, changed
}

func (*provider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResInstance, platform.ResLoadBalancer, platform.ResEIP, platform.ResCertificate}
}

// Open builds an authenticated client for the profile.
func (*provider) Open(ctx context.Context, p platform.Profile) (platform.Client, error) {
	project := p.Meta("project")
	if project == "" {
		return nil, fmt.Errorf("%w: profile %q has no project (re-run `polyctl auth login gcp --profile %s`)", platform.ErrUnauthorized, p.Name, p.Name)
	}
	method := storedMethod(p.Meta("method"))
	if method == "" {
		method = methodADC
	}
	var (
		ts    oauth2.TokenSource
		email string
	)
	switch method {
	case methodADC:
		creds, err := google.FindDefaultCredentials(ctx, scopeCloudPlatform)
		if err != nil {
			return nil, fmt.Errorf("%w: application default credentials not found (run `gcloud auth application-default login`): %v", platform.ErrUnauthorized, err)
		}
		ts = creds.TokenSource
		email = p.Meta("email")
	case methodServiceAccount:
		raw := p.Secret["service_account_json"]
		if raw == "" {
			return nil, fmt.Errorf("%w: profile %q has no stored service account key", platform.ErrUnauthorized, p.Name)
		}
		creds, err := google.CredentialsFromJSON(ctx, []byte(raw), scopeCloudPlatform)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid service account key: %v", platform.ErrUnauthorized, err)
		}
		ts = creds.TokenSource
		email = p.Meta("client_email")
	case methodOAuth:
		cfg, tok, err := oauthFromSecret(p.Secret, p.Meta("oauth_client"))
		if err != nil {
			return nil, fmt.Errorf("%w: profile %q: %v (re-run `polyctl auth login gcp --profile %s`)", platform.ErrUnauthorized, p.Name, err, p.Name)
		}
		ts = cfg.TokenSource(ctx, tok)
		email = p.Meta("email")
	default:
		return nil, fmt.Errorf("unknown gcp login method %q in profile %q", method, p.Name)
	}
	c, err := newClient(ctx, project, email, method, clientOptions(ts)...)
	if err != nil {
		return nil, err
	}
	c.cov.profile, c.cov.disabled = p.Name, disabledProjects(p.Metadata)
	return c, nil
}

// oauthFromSecret rebuilds the OAuth config and token of a stored account.
// The client is the one stored with the account, or, for an account marked
// as logged in with the built-in client (clientKind "builtin"), the one of
// this binary.
func oauthFromSecret(secret map[string]string, clientKind string) (*oauth2.Config, *oauth2.Token, error) {
	client := oauthClient{ID: secret["client_id"], Secret: secret["client_secret"]}
	rt := secret["refresh_token"]
	if client.ID == "" && clientKind == oauthClientBuiltin {
		if !builtinClient.set() {
			return nil, nil, errors.New("the account uses polyctl's built-in OAuth client, which this build of polyctl does not have")
		}
		client = builtinClient
	}
	if client.ID == "" || rt == "" {
		return nil, nil, errors.New("stored OAuth credentials are incomplete")
	}
	return oauthConfig(client, ""), &oauth2.Token{RefreshToken: rt}, nil
}

// oauthEndpoint is Google's OAuth endpoint; tests point it at a fake.
var oauthEndpoint = google.Endpoint

// oauthConfig is the OAuth configuration of a client, for the login (with
// the redirect URL of the loopback listener) or the token refresh.
func oauthConfig(client oauthClient, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Endpoint:     oauthEndpoint,
		RedirectURL:  redirectURL,
		Scopes:       []string{scopeCloudPlatform, scopeUserinfoEmail},
	}
}
