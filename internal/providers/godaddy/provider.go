// Package godaddy implements the GoDaddy provider: Personal Access Token
// (or legacy API-key) authentication, registrar operations, the DNS zone
// GoDaddy hosts for every domain, and the `polyctl godaddy` native command
// tree.
package godaddy

import (
	"context"
	"fmt"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

func init() { platform.Register(&provider{}) }

// Profile storage layout.
//
// Secret (credential store), one of two layouts:
//
//	token  GoDaddy Personal Access Token (method "pat", recommended)
//	key    GoDaddy API key    } legacy sso-key pair (method "api_key",
//	secret GoDaddy API secret } deprecated by GoDaddy for Domains)
//
// Metadata (config.yaml, non-sensitive):
//
//	env        "production" or "ote"
//	method     "pat" or "api_key"
//	key_prefix fingerprint of the token (sha256 prefix) or first characters of the API key id
//	base_url   only when overridden with --set base_url=... (custom endpoint)
const (
	secretToken  = "token"
	secretKey    = "key"
	secretSecret = "secret"
	metaEnv      = "env"
	metaMethod   = "method"
	metaKeyPref  = "key_prefix"
	metaBaseURL  = "base_url"

	methodPAT    = "pat"
	methodAPIKey = "api_key"
)

// accessRequirement is GoDaddy's documented precondition for using the
// domain-management API with a production credential.
const accessRequirement = "the account must hold at least one domain or be on a plan that grants API management access; paid operations need a billing method on file"

type provider struct{}

func (*provider) ID() platform.ID     { return platform.GoDaddy }
func (*provider) DisplayName() string { return "GoDaddy" }

func (*provider) LoginHelp() string {
	return "Personal Access Token created at " + keysURL + " (" + accessRequirement + "; use --set env=ote for the test environment). Non-interactive: --set token=- reads the token from stdin (legacy API key pair: --set key=... --set secret=- or --set method=api_key)"
}

func (*provider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResDomain, platform.ResZone, platform.ResDNSRecord}
}

// Login guides the user through creating a Personal Access Token (or,
// when asked for, a legacy API key pair) and verifies it.
func (*provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	env := strings.ToLower(strings.TrimSpace(in.Opt(metaEnv, in.Existing[metaEnv])))
	switch env {
	case "":
		env = envProduction
	case "prod", "production":
		env = envProduction
	case "ote", "test":
		env = envOTE
	default:
		return nil, fmt.Errorf("unknown GoDaddy environment %q (expected production or ote)", env)
	}
	baseURL := strings.TrimRight(in.Opt(metaBaseURL, in.Existing[metaBaseURL]), "/")

	cred := credentials{
		token:  strings.TrimSpace(in.Opt(secretToken, "")),
		key:    strings.TrimSpace(in.Opt(secretKey, "")),
		secret: strings.TrimSpace(in.Opt(secretSecret, "")),
	}
	method := strings.ToLower(strings.TrimSpace(in.Opt(metaMethod, "")))
	switch {
	case cred.token != "":
		method = methodPAT
	case cred.key != "" || cred.secret != "":
		method = methodAPIKey
	case method == "":
		// Re-authenticating a legacy profile keeps its method unless the
		// user asks otherwise; everything else defaults to a PAT.
		if in.Existing[metaMethod] == methodAPIKey {
			method = methodAPIKey
		} else {
			method = methodPAT
		}
	}
	switch method {
	case methodPAT, "token":
		method = methodPAT
	case methodAPIKey, "key", "sso-key", "sso_key":
		method = methodAPIKey
	default:
		return nil, fmt.Errorf("unknown GoDaddy auth method %q (expected pat or api_key)", method)
	}

	if !cred.complete() {
		io := prompt.New(in.Stdin, in.Stdout, in.Stderr)
		if method == methodPAT {
			fmt.Fprintf(in.Stderr, "GoDaddy (%s) uses Personal Access Tokens; create a %s token at:\n  %s\n", env, env, keysURL)
		} else {
			fmt.Fprintf(in.Stderr, "GoDaddy (%s) legacy API key pair (deprecated by GoDaddy; prefer a Personal Access Token). Keys were created at:\n  %s\n", env, keysURL)
		}
		if env == envProduction {
			fmt.Fprintln(in.Stderr, "Note: for production API access "+accessRequirement+".")
		}
		if !in.NoBrowser && in.OpenBrowser != nil {
			if err := in.OpenBrowser(keysURL); err != nil {
				fmt.Fprintf(in.Stderr, "could not open a browser (%v); open the URL above manually\n", err)
			}
		}
		var err error
		if method == methodPAT {
			if cred.token, err = io.RequiredSecret("Personal Access Token"); err != nil {
				return nil, err
			}
		} else {
			if cred.key == "" {
				if cred.key, err = io.Required("API key"); err != nil {
					return nil, err
				}
			}
			if cred.secret == "" {
				if cred.secret, err = io.RequiredSecret("API secret"); err != nil {
					return nil, err
				}
			}
		}
	}

	c := newClient(baseURL, env, cred)
	id, err := c.Verify(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify GoDaddy credentials: %w", err)
	}
	meta := map[string]string{metaEnv: env, metaMethod: method, metaKeyPref: cred.prefix()}
	if baseURL != "" {
		meta[metaBaseURL] = baseURL
	}
	label := fmt.Sprintf("GoDaddy %s, %s", env, cred.label())
	if d := id.Extra["first_domain"]; d != "" {
		label += " (domains include " + d + ")"
	} else {
		label += " (no domains in account)"
	}
	return &platform.LoginResult{
		Secret:   cred.secretMap(),
		Metadata: meta,
		Label:    label,
	}, nil
}

// Open creates an authenticated client for the profile. Both secret
// layouts (token, or key+secret) are accepted.
func (*provider) Open(ctx context.Context, p platform.Profile) (platform.Client, error) {
	cred := credentials{token: p.Secret[secretToken], key: p.Secret[secretKey], secret: p.Secret[secretSecret]}
	if !cred.complete() {
		return nil, fmt.Errorf("%w: profile %q has no GoDaddy Personal Access Token (or API key/secret) stored (run `polyctl auth login godaddy --profile %s`)", platform.ErrUnauthorized, p.Name, p.Name)
	}
	env := p.Meta(metaEnv)
	if env == "" {
		env = envProduction
	}
	return newClient(p.Meta(metaBaseURL), env, cred), nil
}

// credentials is one of the two GoDaddy credential layouts. A token wins
// over a key pair when both are set.
type credentials struct {
	token       string
	key, secret string
}

// complete reports whether the layout can authenticate a request.
func (c credentials) complete() bool {
	return c.token != "" || (c.key != "" && c.secret != "")
}

// method is the metadata method name of the layout.
func (c credentials) method() string {
	if c.token != "" {
		return methodPAT
	}
	return methodAPIKey
}

// describe is a short human name of the layout.
func (c credentials) describe() string {
	if c.token != "" {
		return "personal access token"
	}
	return "API key"
}

// prefix returns a non-sensitive identifier of the credential: a one-way
// fingerprint for a PAT (every character of it is secret) and the leading
// characters of an API key id (which is not secret on its own).
func (c credentials) prefix() string {
	if c.token != "" {
		return fingerprint(c.token)
	}
	return keyPrefix(c.key)
}

// label is the human description of the credential used in labels and
// identities, e.g. "personal access token fingerprint 1a2b3c4d".
func (c credentials) label() string {
	if c.token != "" {
		return c.describe() + " fingerprint " + c.prefix()
	}
	return c.describe() + " " + c.prefix() + "..."
}

// authorization is the value of the Authorization header.
func (c credentials) authorization() string {
	if c.token != "" {
		return "Bearer " + c.token
	}
	return "sso-key " + c.key + ":" + c.secret
}

// secretMap is the layout as stored in the credential store.
func (c credentials) secretMap() map[string]string {
	if c.token != "" {
		return map[string]string{secretToken: c.token}
	}
	return map[string]string{secretKey: c.key, secretSecret: c.secret}
}
