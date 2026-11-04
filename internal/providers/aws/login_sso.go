package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

const (
	grantDeviceCode   = "urn:ietf:params:oauth:grant-type:device_code"
	grantRefreshToken = "refresh_token"
	ssoScope          = "sso:account:access"
)

// loginSSO performs the IAM Identity Center device authorization flow.
func loginSSO(ctx context.Context, in platform.LoginInput, io *prompt.IO, region string) (*platform.LoginResult, error) {
	startURL := in.Opt(metaStartURL, existingOr(in.Existing, metaStartURL, ""))
	if _, set := in.Options[metaStartURL]; !set {
		fmt.Fprintln(io.Err, "The start URL is shown in the IAM Identity Center console, e.g. https://d-0123456789.awsapps.com/start")
		var err error
		if startURL != "" {
			startURL, err = io.Line("Identity Center start URL", startURL)
		} else {
			startURL, err = io.Required("Identity Center start URL")
		}
		if err != nil {
			return nil, err
		}
	}
	ssoRegion := in.Opt(metaSSORegion, existingOr(in.Existing, metaSSORegion, defaultRegion))
	if _, set := in.Options[metaSSORegion]; !set {
		var err error
		if ssoRegion, err = io.Line("Identity Center region", ssoRegion); err != nil {
			return nil, err
		}
	}

	anon := awssdk.Config{Region: ssoRegion, Credentials: awssdk.AnonymousCredentials{}}
	oidc := ssooidc.NewFromConfig(anon)

	reg, err := registerClient(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("register OIDC client: %w", mapErr(err))
	}
	auth, err := oidc.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     reg.ClientId,
		ClientSecret: reg.ClientSecret,
		StartUrl:     awssdk.String(startURL),
	})
	if err != nil {
		return nil, fmt.Errorf("start device authorization: %w", mapErr(err))
	}
	verifyURL := awssdk.ToString(auth.VerificationUriComplete)
	if verifyURL == "" {
		verifyURL = awssdk.ToString(auth.VerificationUri)
	}
	fmt.Fprintf(io.Err, "\nOpen the following URL in your browser and confirm the code %s:\n  %s\n\n", awssdk.ToString(auth.UserCode), verifyURL)
	if !in.NoBrowser && in.OpenBrowser != nil {
		if err := in.OpenBrowser(verifyURL); err != nil {
			fmt.Fprintf(io.Err, "could not open the browser automatically (%v); open the URL manually\n", err)
		}
	}
	fmt.Fprintln(io.Err, "Waiting for authorization...")

	token, err := pollDeviceToken(ctx, oidc, reg, auth)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	accessToken := awssdk.ToString(token.AccessToken)

	ssoc := sso.NewFromConfig(anon)
	accountID, accountLabel, err := chooseAccount(ctx, ssoc, accessToken, in, io)
	if err != nil {
		return nil, err
	}
	roleName, err := chooseRole(ctx, ssoc, accessToken, accountID, in, io)
	if err != nil {
		return nil, err
	}

	rc, err := ssoc.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: awssdk.String(accessToken),
		AccountId:   awssdk.String(accountID),
		RoleName:    awssdk.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("get role credentials: %w", mapErr(err))
	}
	if rc.RoleCredentials == nil {
		return nil, errors.New("Identity Center returned no role credentials")
	}
	cfg := awssdk.Config{
		Region: region,
		Credentials: credentials.NewStaticCredentialsProvider(
			awssdk.ToString(rc.RoleCredentials.AccessKeyId),
			awssdk.ToString(rc.RoleCredentials.SecretAccessKey),
			awssdk.ToString(rc.RoleCredentials.SessionToken)),
	}
	id, err := verifyIdentity(ctx, cfg)
	if err != nil {
		return nil, err
	}

	secret := map[string]string{
		secretClientID:       awssdk.ToString(reg.ClientId),
		secretClientSecret:   awssdk.ToString(reg.ClientSecret),
		secretAccessToken:    accessToken,
		secretTokenExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	}
	if rt := awssdk.ToString(token.RefreshToken); rt != "" {
		secret[secretRefreshToken] = rt
	}
	label := fmt.Sprintf("%s / %s", accountLabel, roleName)
	if id.Account != "" && accountLabel == "" {
		label = fmt.Sprintf("%s / %s", id.Account, roleName)
	}
	return &platform.LoginResult{
		Secret: secret,
		Metadata: map[string]string{
			metaMethod:    methodSSO,
			metaStartURL:  startURL,
			metaSSORegion: ssoRegion,
			metaAccountID: accountID,
			metaRoleName:  roleName,
			metaRegion:    region,
		},
		Label: label,
	}, nil
}

// registerClient registers a public OIDC client that may use the device
// code and refresh token grants. Older Identity Center deployments reject
// the grant type / scope parameters, so it falls back to a bare registration.
func registerClient(ctx context.Context, oidc *ssooidc.Client) (*ssooidc.RegisterClientOutput, error) {
	out, err := oidc.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: awssdk.String("polyctl"),
		ClientType: awssdk.String("public"),
		GrantTypes: []string{grantDeviceCode, grantRefreshToken},
		Scopes:     []string{ssoScope},
	})
	if err == nil {
		return out, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	return oidc.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: awssdk.String("polyctl"),
		ClientType: awssdk.String("public"),
	})
}

// pollDeviceToken polls CreateToken until the user has authorized the
// device, honouring the interval and slow_down responses.
func pollDeviceToken(ctx context.Context, oidc *ssooidc.Client, reg *ssooidc.RegisterClientOutput, auth *ssooidc.StartDeviceAuthorizationOutput) (*ssooidc.CreateTokenOutput, error) {
	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	if auth.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", platform.ErrLoginCancelled, ctx.Err())
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: the device code expired before the login was confirmed", platform.ErrLoginCancelled)
		}
		out, err := oidc.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     reg.ClientId,
			ClientSecret: reg.ClientSecret,
			GrantType:    awssdk.String(grantDeviceCode),
			DeviceCode:   auth.DeviceCode,
		})
		if err == nil {
			return out, nil
		}
		var pending *oidctypes.AuthorizationPendingException
		var slow *oidctypes.SlowDownException
		var expired *oidctypes.ExpiredTokenException
		var denied *oidctypes.AccessDeniedException
		switch {
		case errors.As(err, &pending):
			continue
		case errors.As(err, &slow):
			interval += 5 * time.Second
			continue
		case errors.As(err, &expired):
			return nil, fmt.Errorf("%w: the device code expired before the login was confirmed", platform.ErrLoginCancelled)
		case errors.As(err, &denied):
			return nil, fmt.Errorf("%w: authorization was denied", platform.ErrLoginCancelled)
		}
		return nil, fmt.Errorf("create token: %w", mapErr(err))
	}
}

type ssoAccount struct {
	ID, Name, Email string
}

func (a ssoAccount) label() string {
	switch {
	case a.Name != "" && a.Email != "":
		return fmt.Sprintf("%s (%s, %s)", a.Name, a.ID, a.Email)
	case a.Name != "":
		return fmt.Sprintf("%s (%s)", a.Name, a.ID)
	}
	return a.ID
}

func listAccounts(ctx context.Context, c *sso.Client, token string) ([]ssoAccount, error) {
	var out []ssoAccount
	pg := sso.NewListAccountsPaginator(c, &sso.ListAccountsInput{AccessToken: awssdk.String(token)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list accounts: %w", mapErr(err))
		}
		for _, a := range page.AccountList {
			out = append(out, ssoAccount{ID: awssdk.ToString(a.AccountId), Name: awssdk.ToString(a.AccountName), Email: awssdk.ToString(a.EmailAddress)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].label() < out[j].label() })
	return out, nil
}

func listRoles(ctx context.Context, c *sso.Client, token, accountID string) ([]string, error) {
	var out []string
	pg := sso.NewListAccountRolesPaginator(c, &sso.ListAccountRolesInput{AccessToken: awssdk.String(token), AccountId: awssdk.String(accountID)})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list roles for account %s: %w", accountID, mapErr(err))
		}
		for _, r := range page.RoleList {
			out = append(out, awssdk.ToString(r.RoleName))
		}
	}
	sort.Strings(out)
	return out, nil
}

// chooseAccount returns the account id and a human label.
func chooseAccount(ctx context.Context, c *sso.Client, token string, in platform.LoginInput, io *prompt.IO) (string, string, error) {
	accounts, err := listAccounts(ctx, c, token)
	if err != nil {
		return "", "", err
	}
	want := in.Opt(metaAccountID, "")
	if want != "" {
		for _, a := range accounts {
			if a.ID == want {
				return a.ID, a.label(), nil
			}
		}
		return "", "", fmt.Errorf("account %s is not accessible with this login (accessible: %d account(s))", want, len(accounts))
	}
	if len(accounts) == 0 {
		return "", "", errors.New("this Identity Center user has no account assignments")
	}
	def := existingOr(in.Existing, metaAccountID, "")
	if len(accounts) == 1 {
		a := accounts[0]
		fmt.Fprintf(io.Err, "Using the only accessible account: %s\n", a.label())
		return a.ID, a.label(), nil
	}
	labels := make([]string, len(accounts))
	defLabel := ""
	for i, a := range accounts {
		labels[i] = a.label()
		if a.ID == def {
			defLabel = labels[i]
		}
	}
	if defLabel == "" {
		defLabel = labels[0]
	}
	chosen, err := io.Choose("Account", labels, defLabel)
	if err != nil {
		return "", "", err
	}
	for i, l := range labels {
		if l == chosen {
			return accounts[i].ID, l, nil
		}
	}
	return "", "", errors.New("no account selected")
}

func chooseRole(ctx context.Context, c *sso.Client, token, accountID string, in platform.LoginInput, io *prompt.IO) (string, error) {
	roles, err := listRoles(ctx, c, token, accountID)
	if err != nil {
		return "", err
	}
	want := in.Opt(metaRoleName, "")
	if want != "" {
		for _, r := range roles {
			if r == want {
				return r, nil
			}
		}
		return "", fmt.Errorf("role %s is not available in account %s (available: %v)", want, accountID, roles)
	}
	switch len(roles) {
	case 0:
		return "", fmt.Errorf("no roles are available in account %s", accountID)
	case 1:
		fmt.Fprintf(io.Err, "Using the only available role: %s\n", roles[0])
		return roles[0], nil
	}
	def := existingOr(in.Existing, metaRoleName, roles[0])
	found := false
	for _, r := range roles {
		if r == def {
			found = true
		}
	}
	if !found {
		def = roles[0]
	}
	return io.Choose("Role", roles, def)
}
