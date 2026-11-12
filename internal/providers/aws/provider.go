// Package aws implements the Amazon Web Services provider: IAM Identity
// Center (SSO), access-key and shared-profile authentication, Route 53
// hosted zones and records, Route 53 Domains and EC2 instances.
//
// Profile metadata keys (stored in plaintext in config.yaml, never sensitive):
//
//	method       "sso" | "keys" | "profile"
//	region       default region for regional API calls; only written when
//	             given explicitly for method=profile, whose region otherwise
//	             comes from ~/.aws/config (default us-east-1)
//	start_url    (sso) IAM Identity Center start URL
//	sso_region   (sso) region of the Identity Center instance
//	account_id   (sso) selected AWS account id
//	role_name    (sso) selected permission set / role name
//	aws_profile  (profile) name of the profile in ~/.aws/config
//
// Secret keys (stored in the credential store):
//
//	sso:      client_id, client_secret, access_token, refresh_token (optional),
//	          token_expires_at (RFC3339)
//	keys:     access_key_id, secret_access_key, session_token (optional)
//	profile:  none (credentials are resolved from the shared AWS files)
package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

func init() { platform.Register(&provider{}) }

const (
	methodSSO     = "sso"
	methodKeys    = "keys"
	methodProfile = "profile"

	defaultRegion = "us-east-1"

	metaMethod     = "method"
	metaRegion     = "region"
	metaStartURL   = "start_url"
	metaSSORegion  = "sso_region"
	metaAccountID  = "account_id"
	metaRoleName   = "role_name"
	metaAWSProfile = "aws_profile"

	secretClientID        = "client_id"
	secretClientSecret    = "client_secret"
	secretAccessToken     = "access_token"
	secretRefreshToken    = "refresh_token"
	secretTokenExpiresAt  = "token_expires_at"
	secretAccessKeyID     = "access_key_id"
	secretSecretAccessKey = "secret_access_key"
	secretSessionToken    = "session_token"
)

type provider struct{}

func (*provider) ID() platform.ID     { return platform.AWS }
func (*provider) DisplayName() string { return "Amazon Web Services" }
func (*provider) LoginHelp() string {
	return "IAM Identity Center device login (--set method=sso, recommended), static access keys (--set method=keys) or a named profile from ~/.aws/config (--set method=profile --set aws_profile=<name>). Options: --set region=<default region>, --set start_url=..., --set sso_region=..., --set account_id=..., --set role_name=...; keys: --set access_key_id=... --set secret_access_key=- [--set session_token=-], or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN. Non-interactive: --set method is required; sso needs --set start_url, prints the URL and code and waits for the approval, and needs --set account_id / --set role_name when several are accessible"
}
func (*provider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResDomain, platform.ResInstance}
}

// Environment variables read by the keys method, the names the AWS SDKs and
// CLI use.
const (
	envAccessKeyID     = "AWS_ACCESS_KEY_ID"
	envSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	envSessionToken    = "AWS_SESSION_TOKEN"
)

// Login runs one of the authentication flows. The interactive flow asks for
// what --set did not give. The non-interactive flow (in.Interactive false)
// asks nothing: a missing value or an open choice is a usage error naming
// the --set key.
func (p *provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	io := in.IO(ctx)
	method := in.Opt("method", "")
	if method == "" && in.Existing != nil {
		method = in.Existing[metaMethod]
	}
	if method == "" && !in.Interactive {
		return nil, app.UsageErrf("aws login needs a method: pass --set method=sso, --set method=keys or --set method=profile")
	}
	if method == "" {
		fmt.Fprintln(io.Err, "How do you want to authenticate to AWS?")
		fmt.Fprintln(io.Err, "  sso     - IAM Identity Center browser login (recommended)")
		fmt.Fprintln(io.Err, "  keys    - static access key id + secret access key")
		fmt.Fprintln(io.Err, "  profile - a named profile from ~/.aws/config and ~/.aws/credentials")
		var err error
		method, err = io.Choose("Method", []string{methodSSO, methodKeys, methodProfile}, methodSSO)
		if err != nil {
			return nil, err
		}
	}
	region := in.Opt(metaRegion, existingOr(in.Existing, metaRegion, defaultRegion))
	switch strings.ToLower(method) {
	case methodSSO:
		return loginSSO(ctx, in, io, region)
	case methodKeys:
		return loginKeys(ctx, in, io, region)
	case methodProfile:
		return loginProfile(ctx, in, io, region)
	}
	return nil, fmt.Errorf("unknown login method %q (expected sso, keys or profile)", method)
}

func existingOr(m map[string]string, key, def string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return def
}

func loginKeys(ctx context.Context, in platform.LoginInput, io *prompt.IO, region string) (*platform.LoginResult, error) {
	// --set first; then the environment, as a whole and only when --set gave
	// none of the pair, so that halves of two key pairs are never mixed.
	keyID := strings.TrimSpace(in.Opt(secretAccessKeyID, ""))
	secret := strings.TrimSpace(in.Opt(secretSecretAccessKey, ""))
	session := strings.TrimSpace(in.Opt(secretSessionToken, ""))
	_, sessionSet := in.Options[secretSessionToken]
	if keyID == "" && secret == "" {
		envID, envSecret := strings.TrimSpace(os.Getenv(envAccessKeyID)), strings.TrimSpace(os.Getenv(envSecretAccessKey))
		if envID != "" && envSecret != "" {
			keyID, secret = envID, envSecret
			if !sessionSet {
				session, sessionSet = strings.TrimSpace(os.Getenv(envSessionToken)), true
			}
			fmt.Fprintf(io.Err, "using the access key from %s / %s\n", envAccessKeyID, envSecretAccessKey)
		}
	}
	if keyID == "" || secret == "" {
		if !in.Interactive {
			var missing []string
			if keyID == "" {
				missing = append(missing, "--set access_key_id=<id>")
			}
			if secret == "" {
				missing = append(missing, "--set secret_access_key=- (the secret on stdin)")
			}
			return nil, app.UsageErrf("aws login with method=keys needs an access key: pass %s, or set %s and %s (and %s for temporary credentials)",
				strings.Join(missing, " and "), envAccessKeyID, envSecretAccessKey, envSessionToken)
		}
		fmt.Fprintln(io.Err, "Create an access key in the IAM console: https://console.aws.amazon.com/iam/home#/security_credentials")
		var err error
		if keyID == "" {
			if keyID, err = io.Required("Access key id"); err != nil {
				return nil, err
			}
		}
		if secret == "" {
			if secret, err = io.RequiredSecret("Secret access key"); err != nil {
				return nil, err
			}
		}
		// The optional token is asked for only along with the key itself,
		// and never in the non-interactive flow.
		if !sessionSet {
			if session, err = io.Secret("Session token (optional, for temporary credentials)"); err != nil {
				return nil, err
			}
		}
	}
	cfg := awssdk.Config{
		Region:      region,
		Credentials: credentials.NewStaticCredentialsProvider(keyID, secret, session),
	}
	id, err := verifyLogin(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sec := map[string]string{secretAccessKeyID: keyID, secretSecretAccessKey: secret}
	if session != "" {
		sec[secretSessionToken] = session
	}
	return &platform.LoginResult{
		Secret:   sec,
		Metadata: map[string]string{metaMethod: methodKeys, metaRegion: region},
		Label:    identityLabel(id),
	}, nil
}

func loginProfile(ctx context.Context, in platform.LoginInput, io *prompt.IO, region string) (*platform.LoginResult, error) {
	name := in.Opt(metaAWSProfile, existingOr(in.Existing, metaAWSProfile, "default"))
	if _, set := in.Options[metaAWSProfile]; !set {
		if in.Interactive {
			var err error
			name, err = io.Line("AWS profile name (from ~/.aws/config)", name)
			if err != nil {
				return nil, err
			}
		} else {
			// The default of the question, taken without asking.
			fmt.Fprintf(io.Err, "using AWS profile %q (pass --set aws_profile=<name> to choose another)\n", name)
		}
	}
	// The region of the shared profile wins unless --set region was given;
	// the metadata records only an explicit choice.
	_, regionSet := in.Options[metaRegion]
	cfg, err := loadSharedConfig(ctx, name, region, regionSet)
	if err != nil {
		return nil, err
	}
	id, err := verifyLogin(ctx, cfg)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{metaMethod: methodProfile, metaAWSProfile: name}
	if regionSet {
		meta[metaRegion] = region
	}
	return &platform.LoginResult{
		Secret:   map[string]string{},
		Metadata: meta,
		Label:    identityLabel(id),
	}, nil
}

// loadSharedConfig loads the named profile from the shared AWS files. The
// region is forced to region only when override is set; otherwise the
// profile's own region is used, falling back to defaultRegion when the
// profile has none.
func loadSharedConfig(ctx context.Context, name, region string, override bool) (awssdk.Config, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithSharedConfigProfile(name)}
	if override && region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("load AWS profile %q: %w", name, err)
	}
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}
	return cfg, nil
}

// verifyLogin checks the credentials a login flow ended up with. Tests
// replace it: the flows themselves need no network up to this point.
var verifyLogin = verifyIdentity

// verifyIdentity calls sts GetCallerIdentity with cfg.
func verifyIdentity(ctx context.Context, cfg awssdk.Config) (*platform.Identity, error) {
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("verify credentials: %w", mapErr(err))
	}
	return identityFromCaller(awssdk.ToString(out.Account), awssdk.ToString(out.Arn), awssdk.ToString(out.UserId)), nil
}

func identityFromCaller(account, arn, userID string) *platform.Identity {
	id := &platform.Identity{Account: account, User: arn}
	if userID != "" {
		id.Extra = map[string]string{"user_id": userID}
	}
	return id
}

func identityLabel(id *platform.Identity) string {
	if id.User != "" {
		return id.User
	}
	return id.Account
}

// Open creates an authenticated client for the profile.
func (p *provider) Open(ctx context.Context, prof platform.Profile) (platform.Client, error) {
	region := prof.Meta(metaRegion)
	var cfg awssdk.Config
	switch prof.Meta(metaMethod) {
	case methodKeys:
		region = regionOrDefault(region)
		keyID, secret := prof.Secret[secretAccessKeyID], prof.Secret[secretSecretAccessKey]
		if keyID == "" || secret == "" {
			return nil, fmt.Errorf("%w: stored access keys are incomplete; run `polyctl auth login aws --profile %s`", platform.ErrUnauthorized, prof.Name)
		}
		cfg = awssdk.Config{Region: region, Credentials: credentials.NewStaticCredentialsProvider(keyID, secret, prof.Secret[secretSessionToken])}
	case methodProfile:
		name := prof.Meta(metaAWSProfile)
		if name == "" {
			name = "default"
		}
		var err error
		// Without an explicit region in the metadata the profile's own
		// region (from ~/.aws/config) applies, like the aws CLI.
		cfg, err = loadSharedConfig(ctx, name, region, region != "")
		if err != nil {
			return nil, err
		}
		region = cfg.Region
	case methodSSO:
		region = regionOrDefault(region)
		creds, err := ssoRoleCredentials(ctx, prof)
		if err != nil {
			return nil, err
		}
		cfg = awssdk.Config{Region: region, Credentials: creds}
	default:
		return nil, fmt.Errorf("%w: profile %q has no AWS login method recorded; run `polyctl auth login aws --profile %s`", platform.ErrUnauthorized, prof.Name, prof.Name)
	}
	return newClient(cfg, region), nil
}

func regionOrDefault(region string) string {
	if region == "" {
		return defaultRegion
	}
	return region
}

// ssoRoleCredentials exchanges the stored Identity Center access token for
// role credentials. When the access token has expired and a refresh token
// is present, a fresh token is obtained and persisted through
// Profile.UpdateSecret when available; the user must run `polyctl auth login`
// again once the refresh token itself expires.
func ssoRoleCredentials(ctx context.Context, prof platform.Profile) (awssdk.CredentialsProvider, error) {
	ssoRegion := prof.Meta(metaSSORegion)
	if ssoRegion == "" {
		ssoRegion = defaultRegion
	}
	accountID, roleName := prof.Meta(metaAccountID), prof.Meta(metaRoleName)
	token := prof.Secret[secretAccessToken]
	if token == "" || accountID == "" || roleName == "" {
		return nil, fmt.Errorf("%w: SSO session is incomplete; run `polyctl auth login aws --profile %s`", platform.ErrUnauthorized, prof.Name)
	}
	anon := awssdk.Config{Region: ssoRegion, Credentials: awssdk.AnonymousCredentials{}}
	expired := false
	if exp := prof.Secret[secretTokenExpiresAt]; exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil && time.Now().After(t.Add(-time.Minute)) {
			expired = true
		}
	}
	if expired {
		rt, cid, csec := prof.Secret[secretRefreshToken], prof.Secret[secretClientID], prof.Secret[secretClientSecret]
		if rt == "" || cid == "" || csec == "" {
			return nil, fmt.Errorf("%w: the SSO session has expired; run `polyctl auth login aws --profile %s`", platform.ErrUnauthorized, prof.Name)
		}
		out, err := ssooidc.NewFromConfig(anon).CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     awssdk.String(cid),
			ClientSecret: awssdk.String(csec),
			GrantType:    awssdk.String("refresh_token"),
			RefreshToken: awssdk.String(rt),
		})
		if err != nil {
			return nil, fmt.Errorf("%w: the SSO session has expired and could not be refreshed (%v); run `polyctl auth login aws --profile %s`", platform.ErrUnauthorized, err, prof.Name)
		}
		token = awssdk.ToString(out.AccessToken)
		if prof.UpdateSecret != nil {
			secret := make(map[string]string, len(prof.Secret)+2)
			for k, v := range prof.Secret {
				secret[k] = v
			}
			secret[secretAccessToken] = token
			if out.RefreshToken != nil && *out.RefreshToken != "" {
				secret[secretRefreshToken] = *out.RefreshToken
			}
			secret[secretTokenExpiresAt] = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
			_ = prof.UpdateSecret(secret) // best effort: a failure only means re-login sooner
		}
	}
	out, err := sso.NewFromConfig(anon).GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: awssdk.String(token),
		AccountId:   awssdk.String(accountID),
		RoleName:    awssdk.String(roleName),
	})
	if err != nil {
		err = mapErr(err)
		if errors.Is(err, platform.ErrUnauthorized) {
			return nil, fmt.Errorf("%w; run `polyctl auth login aws --profile %s`", err, prof.Name)
		}
		return nil, fmt.Errorf("get SSO role credentials: %w", err)
	}
	rc := out.RoleCredentials
	if rc == nil || rc.AccessKeyId == nil {
		return nil, fmt.Errorf("%w: Identity Center returned no role credentials", platform.ErrUnauthorized)
	}
	return credentials.NewStaticCredentialsProvider(awssdk.ToString(rc.AccessKeyId), awssdk.ToString(rc.SecretAccessKey), awssdk.ToString(rc.SessionToken)), nil
}
