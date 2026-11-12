// Package gcp implements the Google Cloud provider: Cloud DNS managed zones
// and records, Compute Engine instances, and the login flows that produce
// a profile.
//
// Profile metadata keys (stored in plaintext config.yaml, never sensitive):
//
//	method       "adc", "service_account" or "oauth"
//	project      the Google Cloud project id every command operates on
//	email        the user account email (adc / oauth), when known
//	client_email the service account email (service_account)
//
// Profile secret keys (stored in the credential store):
//
//	service_account_json  the full JSON key file (service_account)
//	client_id             OAuth client id (oauth)
//	client_secret         OAuth client secret (oauth)
//	refresh_token         OAuth refresh token (oauth)
//
// The adc method stores no secret: credentials stay in the Application
// Default Credentials file written by `gcloud auth application-default login`.
package gcp

import (
	"context"
	"fmt"

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
	return `Google Cloud: --set method=adc (default) uses Application Default Credentials
from "gcloud auth application-default login"; method=service_account stores a
JSON key file (--set key_file=PATH); method=oauth runs a browser OAuth flow
with your own Desktop-app OAuth client (--set client_id=...
--set client_secret=-, the secret read from stdin).
Use --set project=ID to pick the project without prompting. Non-interactive:
nothing is asked; key_file, client_id, client_secret and (for oauth, or when
several projects are visible) project must be given, and the oauth flow prints
the URL and waits up to 5 minutes for the browser to return.`
}

// LoginOptions lists the --set keys of the login (see LoginHelp).
func (*provider) LoginOptions() []string {
	return []string{"method", "project", "key_file", "client_id", "client_secret"}
}

func (*provider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResInstance}
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
		cfg, tok, err := oauthFromSecret(p.Secret)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", platform.ErrUnauthorized, err)
		}
		ts = cfg.TokenSource(ctx, tok)
		email = p.Meta("email")
	default:
		return nil, fmt.Errorf("unknown gcp login method %q in profile %q", method, p.Name)
	}
	return newClient(ctx, project, email, method, clientOptions(ts)...)
}

// oauthFromSecret rebuilds the OAuth config and token from stored secrets.
func oauthFromSecret(secret map[string]string) (*oauth2.Config, *oauth2.Token, error) {
	id, sec, rt := secret["client_id"], secret["client_secret"], secret["refresh_token"]
	if id == "" || rt == "" {
		return nil, nil, fmt.Errorf("stored OAuth credentials are incomplete")
	}
	cfg := &oauth2.Config{
		ClientID:     id,
		ClientSecret: sec,
		Endpoint:     google.Endpoint,
		Scopes:       []string{scopeCloudPlatform, scopeUserinfoEmail},
	}
	return cfg, &oauth2.Token{RefreshToken: rt}, nil
}
