package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	oauth2api "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/httpx"
	"github.com/gofika/polyctl/internal/loopback"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

const adcDocsURL = "https://cloud.google.com/docs/authentication/provide-credentials-adc"

// extraOptions are appended to every API service; tests point them at a
// fake server.
var extraOptions []option.ClientOption

// clientOptions combines credentials with the shared options.
func clientOptions(ts oauth2.TokenSource) []option.ClientOption {
	opts := []option.ClientOption{option.WithUserAgent(httpx.UserAgent)}
	if ts != nil {
		opts = append(opts, option.WithTokenSource(ts))
	}
	return append(opts, extraOptions...)
}

// oauthWait bounds the wait for the browser to return in the
// non-interactive flow, where nobody may be there to interrupt it. Tests
// shorten it.
var oauthWait = 5 * time.Minute

// Login runs the authentication flow for the selected method. The
// interactive flow asks for what --set did not give. The non-interactive
// flow (in.Interactive false) asks nothing: a missing value or an open
// choice is a usage error naming the --set key.
func (p *provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	pio := in.IO(ctx)
	method := strings.ToLower(strings.TrimSpace(in.Opt("method", "")))
	if method == "" && in.Existing != nil {
		// Kept from the previous login: stored metadata, not input. An
		// account without the metadata is one of Application Default
		// Credentials, as Open reads it.
		if method = storedMethod(in.Existing["method"]); method == "" {
			method = methodADC
		}
	}
	if method == "" {
		var err error
		if method, err = defaultMethod(ctx, in, pio); err != nil {
			return nil, err
		}
	}
	switch method {
	case methodADC:
		return loginADC(ctx, in, pio)
	case methodServiceAccount:
		return loginServiceAccount(ctx, in, pio)
	case methodOAuth:
		return loginOAuth(ctx, in, pio)
	}
	return nil, app.UsageErrf("unknown gcp login method %q (expected %s, %s or %s)", method, methodADC, methodServiceAccount, methodOAuth)
}

// storedMethod reads the method metadata of a stored account. Besides the
// three method names it accepts the spellings polyctl 0.1.x took as login
// input for a service account (service-account, sa), so that a config.yaml
// carrying one of them still loads. They are not accepted as input any
// more.
func storedMethod(s string) string {
	switch m := strings.ToLower(strings.TrimSpace(s)); m {
	case "service-account", "sa":
		return methodServiceAccount
	default:
		return m
	}
}

// Choices of the question defaultMethod asks. The first two are methods.
const choiceGcloud = "gcloud"

// defaultMethod is the method of a login that names none and has no
// previous login to take it from.
//
// On a terminal it is the browser login with the built-in OAuth client,
// which needs nothing installed. A build without that client uses
// Application Default Credentials when the machine has them and asks which
// way to log in when it has not, instead of failing. The non-interactive
// flow asks nothing and opens no browser: it stays with Application
// Default Credentials.
func defaultMethod(ctx context.Context, in platform.LoginInput, pio *prompt.IO) (string, error) {
	if !in.Interactive {
		return methodADC, nil
	}
	if builtinClient.set() {
		return methodOAuth, nil
	}
	if _, err := google.FindDefaultCredentials(ctx, scopeCloudPlatform); err == nil {
		return methodADC, nil
	}
	fmt.Fprintln(pio.Err, "No Application Default Credentials were found on this machine.")
	choice, err := in.Select(pio, "How do you want to log in to Google Cloud?", []prompt.Option{
		{Label: "Service account key file (JSON)", Value: methodServiceAccount},
		{Label: "Browser login with an OAuth client of your own", Value: methodOAuth},
		{Label: "Application Default Credentials: show how to create them with gcloud", Value: choiceGcloud},
	}, methodServiceAccount)
	if err != nil {
		return "", err
	}
	if choice != choiceGcloud {
		return choice, nil
	}
	fmt.Fprintln(pio.Err)
	printADCHowTo(pio)
	return "", fmt.Errorf("%w: no account was added; create the Application Default Credentials, then run `polyctl auth login gcp --set method=adc`", platform.ErrNothingToDo)
}

// lookPath finds a program on PATH; tests replace it.
var lookPath = exec.LookPath

// printADCHowTo says how Application Default Credentials are created, and
// that gcloud is missing when it is.
func printADCHowTo(pio *prompt.IO) {
	if _, err := lookPath("gcloud"); err != nil {
		fmt.Fprintln(pio.Err, "They are created with gcloud (the Google Cloud CLI), which is not installed on this machine (not found on PATH).")
		fmt.Fprintln(pio.Err, "Install it (https://cloud.google.com/sdk/docs/install), then run the following command and complete the browser login:")
	} else {
		fmt.Fprintln(pio.Err, "Run the following command and complete the browser login:")
	}
	fmt.Fprintln(pio.Err)
	fmt.Fprintln(pio.Err, "    gcloud auth application-default login")
	fmt.Fprintln(pio.Err)
	fmt.Fprintf(pio.Err, "Documentation: %s\n", adcDocsURL)
}

// oauthAlternative is the command line of the browser login, as the
// messages about missing credentials print it.
func oauthAlternative() string {
	if builtinClient.set() {
		return "polyctl auth login gcp --set method=oauth --set project=<id>"
	}
	return "polyctl auth login gcp --set method=oauth --set client_id=<id> --set client_secret=- --set project=<id>"
}

// loginADC uses Application Default Credentials; nothing sensitive is stored.
func loginADC(ctx context.Context, in platform.LoginInput, pio *prompt.IO) (*platform.LoginResult, error) {
	creds, err := google.FindDefaultCredentials(ctx, scopeCloudPlatform)
	if err != nil {
		fmt.Fprintln(pio.Err, "No Application Default Credentials were found on this machine.")
		printADCHowTo(pio)
		fmt.Fprintln(pio.Err)
		fmt.Fprintln(pio.Err, "Then re-run `polyctl auth login gcp`. The other ways to log in need no gcloud:")
		fmt.Fprintln(pio.Err)
		fmt.Fprintln(pio.Err, "    polyctl auth login gcp --set method=service_account --set key_file=<path to the JSON key>")
		fmt.Fprintln(pio.Err, "    "+oauthAlternative())
		if in.MayOpenBrowser() {
			_ = in.OpenBrowser(adcDocsURL)
		}
		return nil, fmt.Errorf("%w: application default credentials not found (alternatives: --set method=service_account, --set method=oauth): %v", platform.ErrUnauthorized, err)
	}
	email := lookupEmail(ctx, creds.TokenSource)
	project, err := chooseProject(ctx, in, pio, creds.TokenSource, creds.ProjectID)
	if err != nil {
		return nil, err
	}
	c, err := verifyAccess(ctx, creds.TokenSource, project, email, methodADC)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{"method": methodADC, "project": project}
	if email != "" {
		meta["email"] = email
	}
	return &platform.LoginResult{Secret: map[string]string{}, Metadata: meta, Label: label(c.email, project)}, nil
}

// serviceAccountKey is the subset of a JSON key file polyctl inspects.
type serviceAccountKey struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	ClientEmail string `json:"client_email"`
}

// loginServiceAccount stores a JSON key file in the credential store.
func loginServiceAccount(ctx context.Context, in platform.LoginInput, pio *prompt.IO) (*platform.LoginResult, error) {
	path := in.Opt("key_file", "")
	if path == "" && !in.Interactive {
		return nil, app.UsageErrf("gcp login with method=service_account needs the key file: pass --set key_file=<path to the JSON key>")
	}
	if path == "" {
		fmt.Fprintln(pio.Err, "Create a service account key (JSON) in the Google Cloud console under IAM & Admin > Service Accounts,")
		fmt.Fprintln(pio.Err, "grant it DNS Administrator and/or Compute roles, download it, and enter the file path below.")
		var err error
		if path, err = pio.Required("Path to the service account JSON key file"); err != nil {
			return nil, err
		}
	}
	path = platform.ExpandHome(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	key, err := parseServiceAccountKey(data)
	if err != nil {
		return nil, err
	}
	creds, err := google.CredentialsFromJSON(ctx, data, scopeCloudPlatform)
	if err != nil {
		return nil, fmt.Errorf("invalid service account key: %w", err)
	}
	project := in.Opt("project", "")
	if project == "" && in.Existing != nil {
		project = in.Existing["project"]
	}
	if project == "" {
		project = key.ProjectID
	}
	if project == "" && !in.Interactive {
		return nil, app.UsageErrf("the service account key names no project: pass --set project=<id>")
	}
	if project == "" {
		if project, err = pio.Required("Google Cloud project id"); err != nil {
			return nil, err
		}
	}
	c, err := verifyAccess(ctx, creds.TokenSource, project, key.ClientEmail, methodServiceAccount)
	if err != nil {
		return nil, err
	}
	return &platform.LoginResult{
		Secret:   map[string]string{"service_account_json": string(data)},
		Metadata: map[string]string{"method": methodServiceAccount, "project": project, "client_email": key.ClientEmail},
		Label:    label(c.email, project),
	}, nil
}

// parseServiceAccountKey validates the key file shape.
func parseServiceAccountKey(data []byte) (*serviceAccountKey, error) {
	var key serviceAccountKey
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("key file is not valid JSON: %w", err)
	}
	if key.Type != "service_account" {
		return nil, fmt.Errorf("key file type is %q, expected \"service_account\"", key.Type)
	}
	if key.ClientEmail == "" {
		return nil, errors.New("key file has no client_email")
	}
	return &key, nil
}

// loginOAuth runs the browser login of an installed application: with the
// client given by client_id and client_secret, or else with the built-in
// client of polyctl.
//
// The built-in client is used when neither value is given and the binary
// has one. A re-login of an account that holds a client of the user keeps
// to such a client: its id and secret are asked for again (they are not
// kept as metadata), so that the account does not change its client
// without being told to.
func loginOAuth(ctx context.Context, in platform.LoginInput, pio *prompt.IO) (*platform.LoginResult, error) {
	client := oauthClient{ID: in.Opt("client_id", ""), Secret: in.Opt("client_secret", "")}
	ownAccount := in.Existing != nil && storedMethod(in.Existing["method"]) == methodOAuth && in.Existing["oauth_client"] != oauthClientBuiltin
	builtin := client.ID == "" && client.Secret == "" && builtinClient.set() && !ownAccount
	if builtin {
		client = builtinClient
	}
	if !in.Interactive {
		// Everything that would be asked is checked before the listener
		// starts, so that nobody goes through the browser for nothing.
		var missing []string
		if client.ID == "" {
			missing = append(missing, "--set client_id=<id>")
		}
		if client.Secret == "" {
			missing = append(missing, "--set client_secret=- (the secret on stdin)")
		}
		if in.Opt("project", "") == "" && in.Existing["project"] == "" {
			missing = append(missing, "--set project=<id>")
		}
		if len(missing) > 0 {
			hint := ""
			if ownAccount && builtinClient.set() && (client.ID == "" || client.Secret == "") {
				hint = " (" + ownClientNote(in.ProfileName) + ")"
			}
			return nil, app.UsageErrf("gcp login with method=oauth needs %s%s", strings.Join(missing, ", "), hint)
		}
	}
	if builtin {
		fmt.Fprintln(pio.Err, "Logging in to Google Cloud in the browser (the consent screen names \"Google Auth Library\").")
	} else if client.ID == "" || client.Secret == "" {
		fmt.Fprintln(pio.Err, "polyctl needs an OAuth client of your own: in the Google Cloud console open APIs & Services > Credentials,")
		fmt.Fprintln(pio.Err, "create an OAuth client ID of type \"Desktop app\", and enter its id and secret below.")
		if ownAccount && builtinClient.set() {
			fmt.Fprintln(pio.Err, "Note: "+ownClientNote(in.ProfileName)+".")
		}
	}
	var err error
	if client.ID == "" {
		if client.ID, err = pio.Required("OAuth client id"); err != nil {
			return nil, err
		}
	}
	if client.Secret == "" {
		if client.Secret, err = pio.RequiredSecret("OAuth client secret"); err != nil {
			return nil, err
		}
	}
	tok, cfg, err := runLoopbackFlow(ctx, in, pio, client)
	if err != nil {
		return nil, err
	}
	ts := cfg.TokenSource(ctx, tok)
	email := lookupEmail(ctx, ts)
	project, err := chooseProject(ctx, in, pio, ts, "")
	if err != nil {
		return nil, err
	}
	c, err := verifyAccess(ctx, ts, project, email, methodOAuth)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{"method": methodOAuth, "project": project}
	if email != "" {
		meta["email"] = email
	}
	// The built-in client is not stored: the marker tells Open to take it
	// from the binary, whatever client that binary carries by then.
	secret := map[string]string{"refresh_token": tok.RefreshToken}
	if builtin {
		meta["oauth_client"] = oauthClientBuiltin
	} else {
		secret["client_id"], secret["client_secret"] = client.ID, client.Secret
	}
	return &platform.LoginResult{Secret: secret, Metadata: meta, Label: label(c.email, project)}, nil
}

// ownClientNote says why a re-login of an account that holds an OAuth
// client of the user does not use the built-in client, and how to move the
// account to it.
func ownClientNote(profile string) string {
	logout := "polyctl auth logout gcp"
	if profile != "" {
		logout += " --profile " + profile
	}
	return "this account was logged in with an OAuth client of your own and keeps to it; to use polyctl's built-in client instead, run `" + logout + "` and log in again"
}

// runLoopbackFlow performs the authorization-code dance on a random
// 127.0.0.1 port and returns a token with a refresh token. The request
// carries a PKCE challenge (S256) and the exchange its verifier, as Google
// requires of desktop applications: the client secret protects nothing
// there.
func runLoopbackFlow(ctx context.Context, in platform.LoginInput, pio *prompt.IO, client oauthClient) (*oauth2.Token, *oauth2.Config, error) {
	lb, err := loopback.Listen("/callback")
	if err != nil {
		return nil, nil, err
	}
	defer lb.Close()
	cfg := oauthConfig(client, lb.RedirectURL())
	verifier := oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL(lb.State,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
		oauth2.S256ChallengeOption(verifier))

	fmt.Fprintln(pio.Err, "Open this URL in your browser to authorize polyctl:")
	fmt.Fprintln(pio.Err)
	fmt.Fprintln(pio.Err, "    "+authURL)
	fmt.Fprintln(pio.Err)
	if in.MayOpenBrowser() {
		if err := in.OpenBrowser(authURL); err != nil {
			fmt.Fprintf(pio.Err, "could not open the browser automatically: %v\n", err)
		}
	}
	// On a terminal the user ends the wait with Ctrl-C. Without one nobody
	// may be there: the wait is bounded.
	var wait time.Duration
	if in.Interactive {
		fmt.Fprintln(pio.Err, "Waiting for the browser to return (Ctrl-C to cancel)...")
	} else {
		fmt.Fprintf(pio.Err, "Waiting up to %s for the browser to return...\n", oauthWait)
		wait = oauthWait
	}
	code, err := lb.Wait(ctx, wait)
	switch {
	case errors.Is(err, loopback.ErrTimeout):
		return nil, nil, fmt.Errorf("%w: no authorization received within %s", platform.ErrLoginCancelled, oauthWait)
	case err != nil:
		return nil, nil, fmt.Errorf("%w: %v", platform.ErrLoginCancelled, err)
	}
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: exchange authorization code: %v", platform.ErrUnauthorized, err)
	}
	if tok.RefreshToken == "" {
		return nil, nil, errors.New("Google did not return a refresh token; revoke polyctl's access at https://myaccount.google.com/permissions and retry")
	}
	return tok, cfg, nil
}

// lookupEmail asks the userinfo endpoint for the account email; failures
// (missing scope, service accounts) are tolerated.
func lookupEmail(ctx context.Context, ts oauth2.TokenSource) string {
	svc, err := oauth2api.NewService(ctx, clientOptions(ts)...)
	if err != nil {
		return ""
	}
	ui, err := svc.Userinfo.Get().Context(ctx).Do()
	if err != nil || ui == nil {
		return ""
	}
	return ui.Email
}

// chooseProject resolves the project id: --set project, then, in the
// interactive flow, a pick list from Resource Manager or a prompt, with the
// previous profile's project or the ADC project as the default. The
// non-interactive flow takes that default without asking, then the only
// listed project; several candidates are a usage error.
func chooseProject(ctx context.Context, in platform.LoginInput, pio *prompt.IO, ts oauth2.TokenSource, adcProject string) (string, error) {
	if p := in.Opt("project", ""); p != "" {
		return p, nil
	}
	def := adcProject
	if in.Existing != nil && in.Existing["project"] != "" {
		def = in.Existing["project"]
	}
	if !in.Interactive {
		if def != "" {
			fmt.Fprintf(pio.Err, "using project %s (pass --set project=<id> to choose another)\n", def)
			return def, nil
		}
		var ids []string
		if crm, err := cloudresourcemanager.NewService(ctx, clientOptions(ts)...); err == nil {
			if projects, err := listProjects(ctx, crm); err == nil {
				for _, p := range projects {
					ids = append(ids, p.ProjectId)
				}
			}
		}
		switch len(ids) {
		case 0:
			return "", app.UsageErrf("gcp login needs a project: pass --set project=<id>")
		case 1:
			fmt.Fprintf(pio.Err, "using the only visible project: %s\n", ids[0])
			return ids[0], nil
		}
		return "", app.UsageErrf("several projects are visible: pass --set project=<id> to choose one of: %s", strings.Join(ids, ", "))
	}
	var ids []string
	if crm, err := cloudresourcemanager.NewService(ctx, clientOptions(ts)...); err == nil {
		if projects, err := listProjects(ctx, crm); err == nil {
			for _, p := range projects {
				ids = append(ids, p.ProjectId)
			}
		} else {
			fmt.Fprintf(pio.Err, "note: could not list projects (%v); enter the project id manually\n", err)
		}
	}
	if len(ids) == 1 && def == "" {
		def = ids[0]
	}
	if len(ids) > 0 {
		if def == "" || !containsValue(ids, def) {
			if def == "" {
				def = ids[0]
			} else {
				ids = append(ids, def)
			}
		}
		opts := make([]prompt.Option, len(ids))
		for i, id := range ids {
			opts[i] = prompt.Option{Label: id, Value: id}
		}
		return in.Select(pio, "Google Cloud project", opts, def)
	}
	if def != "" {
		return pio.Line("Google Cloud project id", def)
	}
	return pio.Required("Google Cloud project id")
}

// verifyAccess checks the credentials against the project: Cloud DNS first,
// then Compute Engine, then Resource Manager, so a principal with any one of
// those roles passes.
func verifyAccess(ctx context.Context, ts oauth2.TokenSource, project, email, method string) (*client, error) {
	c, err := newClient(ctx, project, email, method, clientOptions(ts)...)
	if err != nil {
		return nil, err
	}
	var errs []error
	if _, err := c.dns.ManagedZones.List(project).Context(ctx).Do(); err == nil {
		return c, nil
	} else if !isPermissionErr(err) {
		return nil, fmt.Errorf("verify Cloud DNS access to project %s: %w", project, mapErr(err))
	} else {
		errs = append(errs, err)
	}
	if _, err := c.compute.Zones.List(project).Context(ctx).Do(); err == nil {
		return c, nil
	} else {
		errs = append(errs, err)
	}
	if _, err := c.crm.Projects.Get(project).Context(ctx).Do(); err == nil {
		return c, nil
	} else {
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("%w: credentials cannot access project %s (Cloud DNS, Compute Engine and Resource Manager all denied): %v", platform.ErrUnauthorized, project, errors.Join(errs...))
}

func label(email, project string) string {
	if email == "" {
		return "project " + project
	}
	return email + " (project " + project + ")"
}
