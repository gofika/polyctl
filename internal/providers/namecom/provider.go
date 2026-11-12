// Package namecom implements the name.com provider: registrar operations and
// the DNS zones name.com hosts for each registered domain, via the Core API v4.
package namecom

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func init() { platform.Register(&provider{}) }

// Profile keys.
//
// Metadata (persisted in config.yaml, non-sensitive):
//   - username: the name.com account username used for HTTP Basic auth
//   - env:      "production" (api.name.com) or "test" (api.dev.name.com)
//   - method:   always "api_token"
//
// Secret (persisted in the credential store):
//   - token: the API token created at https://www.name.com/account/settings/api
const (
	metaUsername = "username"
	metaEnv      = "env"
	metaMethod   = "method"
	secretToken  = "token"

	methodAPIToken = "api_token"
)

type provider struct{}

func (*provider) ID() platform.ID     { return platform.NameCom }
func (*provider) DisplayName() string { return "name.com" }
func (*provider) LoginHelp() string {
	return "API token (HTTP Basic): create a token at " + apiTokenURL + ", then enter your username and token. " +
		"Non-interactive: --set username=<user> --set token=- (token read from stdin); use --set env=test for api.dev.name.com " +
		"(the test environment needs your username with " + testUserSuffix + " appended, added automatically, and a token created for that environment)."
}

// testUserSuffix is appended to the production username when talking to
// api.dev.name.com, as name.com's API documentation requires.
const testUserSuffix = "-test"

// testEnvUsername returns the username to use for env: in the test
// environment it carries the "-test" suffix, added when missing.
func testEnvUsername(env, username string) (string, bool) {
	if env != envTest || strings.HasSuffix(username, testUserSuffix) {
		return username, false
	}
	return username + testUserSuffix, true
}
func (*provider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResDomain, platform.ResZone, platform.ResDNSRecord}
}

// Login collects a username and API token, verifies them against GET
// /v4/hello and returns the profile. The interactive flow asks for what
// --set did not give; the non-interactive flow asks nothing and reads
// nothing: a missing value is a usage error naming its --set key.
func (*provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	io := in.IO(ctx)

	env, err := normalizeEnv(in.Opt("env", in.Existing[metaEnv]))
	if err != nil {
		return nil, err
	}
	username := in.Opt("username", in.Existing[metaUsername])
	token := in.Opt("token", "")

	if !in.Interactive && (username == "" || token == "") {
		var missing []string
		if username == "" {
			missing = append(missing, "--set username=<user>")
		}
		if token == "" {
			missing = append(missing, "--set token=- (the API token on stdin)")
		}
		return nil, app.UsageErrf("name.com login needs a username and an API token: pass %s (create a token at %s)", strings.Join(missing, " and "), apiTokenURL)
	}
	if token == "" {
		fmt.Fprintf(io.Err, "name.com login (%s environment)\n", env)
		fmt.Fprintf(io.Err, "Create an API token in your account settings:\n  %s\n", apiTokenURL)
		fmt.Fprintln(io.Err, "API access must be enabled for the account; name.com may also require your IP address to be whitelisted there.")
		if env == envTest {
			fmt.Fprintf(io.Err, "The test environment (api.dev.name.com) requires your username with %s appended and a token generated for that environment; the suffix is added for you if missing.\n", testUserSuffix)
		}
		if in.MayOpenBrowser() {
			if err := in.OpenBrowser(apiTokenURL); err == nil {
				fmt.Fprintln(io.Err, "(opened in your browser)")
			}
		}
	}
	if username == "" {
		if username, err = io.Required("name.com username"); err != nil {
			return nil, err
		}
	} else if token == "" {
		fmt.Fprintf(io.Err, "Username: %s\n", username)
	}
	if token == "" {
		if token, err = io.RequiredSecret("API token"); err != nil {
			return nil, err
		}
	}
	if u, added := testEnvUsername(env, username); added {
		fmt.Fprintf(io.Err, "Using username %q for the test environment (name.com requires the %s suffix there).\n", u, testUserSuffix)
		username = u
	}

	c := newClient(baseURLs[env], env, username, token)
	h, err := c.hello(ctx)
	if err != nil {
		if errors.Is(err, platform.ErrUnauthorized) {
			hint := "check that API access is enabled and your IP address is whitelisted"
			if env == envTest {
				hint += "; the test environment needs a token generated for api.dev.name.com and the username with " + testUserSuffix + " appended"
			}
			return nil, fmt.Errorf("%w: name.com rejected the username/token for user %q (%s)", platform.ErrUnauthorized, username, hint)
		}
		return nil, fmt.Errorf("verify name.com credentials: %w", err)
	}
	label := h.Username
	if label == "" {
		label = username
	}
	return &platform.LoginResult{
		Secret:   map[string]string{secretToken: token},
		Metadata: map[string]string{metaUsername: username, metaEnv: env, metaMethod: methodAPIToken},
		Label:    fmt.Sprintf("%s (%s)", label, env),
	}, nil
}

// Open builds an authenticated client from a stored profile.
func (*provider) Open(ctx context.Context, p platform.Profile) (platform.Client, error) {
	env, err := normalizeEnv(p.Meta(metaEnv))
	if err != nil {
		return nil, err
	}
	username := p.Meta(metaUsername)
	token := p.Secret[secretToken]
	if username == "" || token == "" {
		return nil, fmt.Errorf("%w: profile %q has no name.com username/token (run `polyctl auth login namecom --profile %s`)", platform.ErrUnauthorized, p.Name, p.Name)
	}
	return newClient(baseURLs[env], env, username, token), nil
}
