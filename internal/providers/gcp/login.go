package gcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudresourcemanager/v1"
	oauth2api "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/httpx"
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
	method := strings.ToLower(in.Opt("method", ""))
	if method == "" && in.Existing != nil {
		method = in.Existing["method"]
	}
	switch method {
	case "", methodADC:
		return loginADC(ctx, in, pio)
	case methodServiceAccount, "service-account", "sa":
		return loginServiceAccount(ctx, in, pio)
	case methodOAuth:
		return loginOAuth(ctx, in, pio)
	}
	return nil, fmt.Errorf("unknown login method %q (expected adc, service-account or oauth)", method)
}

// loginADC uses Application Default Credentials; nothing sensitive is stored.
func loginADC(ctx context.Context, in platform.LoginInput, pio *prompt.IO) (*platform.LoginResult, error) {
	creds, err := google.FindDefaultCredentials(ctx, scopeCloudPlatform)
	if err != nil {
		fmt.Fprintln(pio.Err, "No Application Default Credentials were found on this machine.")
		fmt.Fprintln(pio.Err, "Run the following command, complete the browser login, then re-run `polyctl auth login gcp`:")
		fmt.Fprintln(pio.Err)
		fmt.Fprintln(pio.Err, "    gcloud auth application-default login")
		fmt.Fprintln(pio.Err)
		fmt.Fprintf(pio.Err, "Documentation: %s\n", adcDocsURL)
		if in.MayOpenBrowser() {
			_ = in.OpenBrowser(adcDocsURL)
		}
		return nil, fmt.Errorf("%w: application default credentials not found: %v", platform.ErrUnauthorized, err)
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
	path = expandHome(path)
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

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return home + p[1:]
		}
	}
	return p
}

// loginOAuth runs an installed-app OAuth flow with a user-supplied client.
func loginOAuth(ctx context.Context, in platform.LoginInput, pio *prompt.IO) (*platform.LoginResult, error) {
	clientID := in.Opt("client_id", "")
	clientSecret := in.Opt("client_secret", "")
	if !in.Interactive {
		// Everything that would be asked is checked before the listener
		// starts, so that nobody goes through the browser for nothing.
		var missing []string
		if clientID == "" {
			missing = append(missing, "--set client_id=<id>")
		}
		if clientSecret == "" {
			missing = append(missing, "--set client_secret=- (the secret on stdin)")
		}
		if in.Opt("project", "") == "" && in.Existing["project"] == "" {
			missing = append(missing, "--set project=<id>")
		}
		if len(missing) > 0 {
			return nil, app.UsageErrf("gcp login with method=oauth needs %s", strings.Join(missing, ", "))
		}
	}
	if clientID == "" || clientSecret == "" {
		fmt.Fprintln(pio.Err, "polyctl needs an OAuth client of your own: in the Google Cloud console open APIs & Services > Credentials,")
		fmt.Fprintln(pio.Err, "create an OAuth client ID of type \"Desktop app\", and enter its id and secret below.")
	}
	var err error
	if clientID == "" {
		if clientID, err = pio.Required("OAuth client id"); err != nil {
			return nil, err
		}
	}
	if clientSecret == "" {
		if clientSecret, err = pio.RequiredSecret("OAuth client secret"); err != nil {
			return nil, err
		}
	}
	tok, cfg, err := runLoopbackFlow(ctx, in, pio, clientID, clientSecret)
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
	return &platform.LoginResult{
		Secret:   map[string]string{"client_id": clientID, "client_secret": clientSecret, "refresh_token": tok.RefreshToken},
		Metadata: meta,
		Label:    label(c.email, project),
	}, nil
}

// runLoopbackFlow performs the authorization-code + PKCE dance on a random
// 127.0.0.1 port and returns a token with a refresh token.
func runLoopbackFlow(ctx context.Context, in platform.LoginInput, pio *prompt.IO, clientID, clientSecret string) (*oauth2.Token, *oauth2.Config, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("start loopback listener: %w", err)
	}
	defer ln.Close()
	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  fmt.Sprintf("http://%s/callback", ln.Addr().String()),
		Scopes:       []string{scopeCloudPlatform, scopeUserinfoEmail},
	}
	state, err := randomToken()
	if err != nil {
		return nil, nil, err
	}
	verifier := oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
		oauth2.S256ChallengeOption(verifier))

	type result struct {
		code string
		err  error
	}
	results := make(chan result, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		var res result
		switch {
		case q.Get("state") != state:
			res.err = errors.New("oauth callback state mismatch")
		case q.Get("error") != "":
			res.err = fmt.Errorf("authorization denied: %s", q.Get("error"))
		case q.Get("code") == "":
			res.err = errors.New("oauth callback without code")
		default:
			res.code = q.Get("code")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.err != nil {
			fmt.Fprintf(w, "<html><body><h2>Login failed</h2><p>%s</p></body></html>", html.EscapeString(res.err.Error()))
		} else {
			fmt.Fprint(w, "<html><body><h2>polyctl login complete</h2><p>You can close this window.</p></body></html>")
		}
		select {
		case results <- res:
		default:
		}
	})}
	go srv.Serve(ln) //nolint:errcheck
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

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
	var timeout <-chan time.Time
	if in.Interactive {
		fmt.Fprintln(pio.Err, "Waiting for the browser to return (Ctrl-C to cancel)...")
	} else {
		fmt.Fprintf(pio.Err, "Waiting up to %s for the browser to return...\n", oauthWait)
		timer := time.NewTimer(oauthWait)
		defer timer.Stop()
		timeout = timer.C
	}

	var res result
	select {
	case res = <-results:
	case <-timeout:
		return nil, nil, fmt.Errorf("%w: no authorization received within %s", platform.ErrLoginCancelled, oauthWait)
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("%w: %v", platform.ErrLoginCancelled, ctx.Err())
	}
	if res.err != nil {
		return nil, nil, fmt.Errorf("%w: %v", platform.ErrLoginCancelled, res.err)
	}
	tok, err := cfg.Exchange(ctx, res.code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: exchange authorization code: %v", platform.ErrUnauthorized, err)
	}
	if tok.RefreshToken == "" {
		return nil, nil, errors.New("Google did not return a refresh token; revoke polyctl's access at https://myaccount.google.com/permissions and retry")
	}
	return tok, cfg, nil
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
		return pio.Choose("Google Cloud project", ids, def)
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
