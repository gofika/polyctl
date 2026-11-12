package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// refusingReader fails the test when the login reads stdin.
type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}

// stubVerify replaces the STS check and records the credentials it was
// given.
func stubVerify(t *testing.T) *awssdk.Credentials {
	t.Helper()
	var seen awssdk.Credentials
	old := verifyLogin
	verifyLogin = func(ctx context.Context, cfg awssdk.Config) (*platform.Identity, error) {
		c, err := cfg.Credentials.Retrieve(ctx)
		if err != nil {
			return nil, err
		}
		seen = c
		return &platform.Identity{Account: "111122223333", User: "arn:aws:iam::111122223333:user/dev"}, nil
	}
	t.Cleanup(func() { verifyLogin = old })
	return &seen
}

func clearKeyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{envAccessKeyID, envSecretAccessKey, envSessionToken} {
		t.Setenv(k, "")
	}
}

// login runs the provider's Login with a counting browser.
func login(t *testing.T, interactive bool, stdin io.Reader, opts, existing map[string]string) (*platform.LoginResult, string, int, error) {
	t.Helper()
	var stderr bytes.Buffer
	opened := 0
	res, err := (&provider{}).Login(context.Background(), platform.LoginInput{
		Interactive: interactive, Options: opts, Existing: existing,
		Stdin: stdin, Stdout: &bytes.Buffer{}, Stderr: &stderr,
		OpenBrowser: func(string) error { opened++; return nil },
	})
	return res, stderr.String(), opened, err
}

// The non-interactive flow asks nothing and reads nothing: an open choice or
// a missing value is a usage error naming the --set key, before any request.
func TestLoginNonInteractiveNeverAsks(t *testing.T) {
	clearKeyEnv(t)
	seen := stubVerify(t)
	for _, tc := range []struct {
		name    string
		opts    map[string]string
		want    []string
		wantNot string
	}{
		{"no method", nil, []string{"--set method=sso", "--set method=keys", "--set method=profile"}, ""},
		{"keys without values", map[string]string{"method": "keys"}, []string{"--set access_key_id=<id>", "--set secret_access_key=-", envAccessKeyID, envSecretAccessKey, envSessionToken}, ""},
		{"keys without the secret", map[string]string{"method": "keys", "access_key_id": "AKIAONE"}, []string{"--set secret_access_key=-"}, "--set access_key_id"},
		{"keys without the id", map[string]string{"method": "keys", "secret_access_key": "s"}, []string{"--set access_key_id=<id>"}, "--set secret_access_key"},
		{"sso without the start URL", map[string]string{"method": "sso"}, []string{"--set start_url=<url>", "--set sso_region="}, ""},
	} {
		_, stderr, opened, err := login(t, false, refusingReader{t}, tc.opts, nil)
		if !errors.Is(err, app.ErrUsage) {
			t.Errorf("%s: %v, want a usage error", tc.name, err)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: the error does not name %q: %v", tc.name, w, err)
			}
		}
		if tc.wantNot != "" && strings.Contains(err.Error(), tc.wantNot) {
			t.Errorf("%s: the error names %q, which was given: %v", tc.name, tc.wantNot, err)
		}
		if opened != 0 || stderr != "" || seen.AccessKeyID != "" {
			t.Errorf("%s: browser opened %d time(s), stderr %q, verified %q; want none of it", tc.name, opened, stderr, seen.AccessKeyID)
		}
	}
}

// The keys method takes its values from --set, then from the environment as
// a whole, and prompts only in the interactive flow.
func TestLoginKeysSources(t *testing.T) {
	clearKeyEnv(t)
	seen := stubVerify(t)

	res, stderr, _, err := login(t, false, refusingReader{t}, map[string]string{"method": "keys", "access_key_id": "AKIASET", "secret_access_key": "setsecret"}, nil)
	if err != nil || seen.AccessKeyID != "AKIASET" || seen.SecretAccessKey != "setsecret" || seen.SessionToken != "" {
		t.Fatalf("--set keys: %v %+v", err, seen)
	}
	if res.Secret[secretAccessKeyID] != "AKIASET" || res.Secret[secretSecretAccessKey] != "setsecret" || res.Metadata[metaMethod] != methodKeys {
		t.Errorf("--set keys result: %+v", res)
	}
	if _, has := res.Secret[secretSessionToken]; has || stderr != "" {
		t.Errorf("--set keys: session token stored or something printed: %+v / %q", res.Secret, stderr)
	}
	if res, _, _, err = login(t, false, refusingReader{t}, map[string]string{"method": "keys", "access_key_id": "AKIASET", "secret_access_key": "s", "session_token": "tok"}, nil); err != nil || res.Secret[secretSessionToken] != "tok" {
		t.Errorf("--set session_token: %v %+v", err, res)
	}

	t.Setenv(envAccessKeyID, "AKIAENV")
	t.Setenv(envSecretAccessKey, "envsecret")
	t.Setenv(envSessionToken, "envtoken")
	res, stderr, _, err = login(t, false, refusingReader{t}, map[string]string{"method": "keys"}, nil)
	if err != nil || seen.AccessKeyID != "AKIAENV" || seen.SecretAccessKey != "envsecret" || seen.SessionToken != "envtoken" {
		t.Fatalf("environment keys: %v %+v", err, seen)
	}
	if !strings.Contains(stderr, envAccessKeyID) || strings.Contains(stderr, "envsecret") || res.Secret[secretSessionToken] != "envtoken" {
		t.Errorf("environment keys: stderr %q, secret %+v", stderr, res.Secret)
	}
	// --set wins as a pair, and takes nothing of the environment's pair.
	if _, _, _, err = login(t, false, refusingReader{t}, map[string]string{"method": "keys", "access_key_id": "AKIASET", "secret_access_key": "s"}, nil); err != nil || seen.AccessKeyID != "AKIASET" || seen.SessionToken != "" {
		t.Errorf("--set over the environment: %v %+v", err, seen)
	}
	if _, _, _, err = login(t, false, refusingReader{t}, map[string]string{"method": "keys", "access_key_id": "AKIASET"}, nil); !errors.Is(err, app.ErrUsage) {
		t.Errorf("half a key next to the environment = %v, want a usage error", err)
	}

	// Interactive: the three questions, in order.
	clearKeyEnv(t)
	res, stderr, _, err = login(t, true, strings.NewReader("AKIAASK\nasksecret\n\n"), map[string]string{"method": "keys"}, nil)
	if err != nil || seen.AccessKeyID != "AKIAASK" || seen.SecretAccessKey != "asksecret" {
		t.Fatalf("interactive keys: %v %+v", err, seen)
	}
	for _, label := range []string{"Access key id: ", "Secret access key: ", "Session token"} {
		if !strings.Contains(stderr, label) {
			t.Errorf("interactive keys: the question %q was not asked: %q", label, stderr)
		}
	}
	// Interactive, with the method chosen from the list.
	if _, stderr, _, err = login(t, true, strings.NewReader("keys\nAKIAASK\nasksecret\n\n"), nil, nil); err != nil || !strings.Contains(stderr, "Method [sso]: ") {
		t.Errorf("interactive method choice: %v (stderr %q)", err, stderr)
	}
}

// The profile method never asks for the profile name without a terminal: it
// takes the default of the question.
func TestLoginProfileNonInteractive(t *testing.T) {
	stubVerify(t)
	dir := t.TempDir()
	cfgFile, credFile := filepath.Join(dir, "config"), filepath.Join(dir, "credentials")
	if err := os.WriteFile(cfgFile, []byte("[default]\nregion = eu-west-1\n\n[profile work]\nregion = eu-central-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credFile, []byte("[default]\naws_access_key_id = AKIADEF\naws_secret_access_key = s\n\n[work]\naws_access_key_id = AKIAWORK\naws_secret_access_key = s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgFile)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credFile)
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", envAccessKeyID, envSecretAccessKey, envSessionToken} {
		t.Setenv(k, "")
	}
	res, stderr, _, err := login(t, false, refusingReader{t}, map[string]string{"method": "profile"}, nil)
	if err != nil || res.Metadata[metaAWSProfile] != "default" {
		t.Fatalf("default profile: %v %+v", err, res)
	}
	if !strings.Contains(stderr, `using AWS profile "default"`) || strings.Contains(stderr, "AWS profile name") {
		t.Errorf("default profile: stderr %q", stderr)
	}
	// A re-authentication keeps its profile; --set wins and says nothing.
	if res, _, _, err = login(t, false, refusingReader{t}, map[string]string{"method": "profile"}, map[string]string{metaAWSProfile: "work"}); err != nil || res.Metadata[metaAWSProfile] != "work" {
		t.Errorf("existing profile: %v %+v", err, res)
	}
	if res, stderr, _, err = login(t, false, refusingReader{t}, map[string]string{"method": "profile", "aws_profile": "work"}, nil); err != nil || res.Metadata[metaAWSProfile] != "work" || stderr != "" {
		t.Errorf("--set aws_profile: %v %+v (stderr %q)", err, res, stderr)
	}
	// Interactive: asked, with the default.
	if res, stderr, _, err = login(t, true, strings.NewReader("work\n"), map[string]string{"method": "profile"}, nil); err != nil || res.Metadata[metaAWSProfile] != "work" || !strings.Contains(stderr, "AWS profile name (from ~/.aws/config) [default]: ") {
		t.Errorf("interactive profile: %v %+v (stderr %q)", err, res, stderr)
	}
}

// fakeSSO serves the two listings the account and role choice read.
func fakeSSO(t *testing.T, accounts []ssoAccount, roles map[string][]string) *sso.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/assignment/accounts":
			var list []map[string]string
			for _, a := range accounts {
				list = append(list, map[string]string{"accountId": a.ID, "accountName": a.Name, "emailAddress": a.Email})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accountList": list})
		case "/assignment/roles":
			id := r.URL.Query().Get("account_id")
			var list []map[string]string
			for _, name := range roles[id] {
				list = append(list, map[string]string{"roleName": name, "accountId": id})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"roleList": list})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return sso.New(sso.Options{Region: "us-east-1", BaseEndpoint: awssdk.String(srv.URL), Credentials: awssdk.AnonymousCredentials{}})
}

// After the device approval the account and the role are a choice only in
// the interactive flow. Without a terminal one candidate, --set or the
// previous login decides; several are a usage error that lists them.
func TestSSOAccountAndRoleChoice(t *testing.T) {
	ctx := context.Background()
	two := []ssoAccount{{ID: "111111111111", Name: "Dev"}, {ID: "222222222222", Name: "Prod"}}
	roles := map[string][]string{"111111111111": {"Admin", "ReadOnly"}, "222222222222": {"Admin"}}
	c := fakeSSO(t, two, roles)
	input := func(interactive bool, stdin io.Reader, opts, existing map[string]string) (platform.LoginInput, *bytes.Buffer) {
		var stderr bytes.Buffer
		return platform.LoginInput{Interactive: interactive, Options: opts, Existing: existing, Stdin: stdin, Stdout: &bytes.Buffer{}, Stderr: &stderr}, &stderr
	}

	// Non-interactive, several accounts.
	in, stderr := input(false, refusingReader{t}, nil, nil)
	_, _, err := chooseAccount(ctx, c, "tok", in, in.IO(ctx))
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set account_id=<id>") || !strings.Contains(err.Error(), "111111111111 (Dev)") || !strings.Contains(err.Error(), "222222222222 (Prod)") {
		t.Errorf("several accounts = %v, want a usage error listing them", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("several accounts printed %q", stderr.String())
	}
	in, _ = input(false, refusingReader{t}, map[string]string{"account_id": "222222222222"}, nil)
	if id, _, err := chooseAccount(ctx, c, "tok", in, in.IO(ctx)); err != nil || id != "222222222222" {
		t.Errorf("--set account_id = %q, %v", id, err)
	}
	in, _ = input(false, refusingReader{t}, nil, map[string]string{metaAccountID: "222222222222"})
	if id, _, err := chooseAccount(ctx, c, "tok", in, in.IO(ctx)); err != nil || id != "222222222222" {
		t.Errorf("account of the previous login = %q, %v", id, err)
	}
	in, _ = input(false, refusingReader{t}, nil, map[string]string{metaAccountID: "999999999999"})
	if _, _, err := chooseAccount(ctx, c, "tok", in, in.IO(ctx)); !errors.Is(err, app.ErrUsage) {
		t.Errorf("previous account no longer accessible = %v, want a usage error", err)
	}
	in, _ = input(false, refusingReader{t}, map[string]string{"account_id": "333333333333"}, nil)
	if _, _, err := chooseAccount(ctx, c, "tok", in, in.IO(ctx)); err == nil || !strings.Contains(err.Error(), "111111111111 (Dev)") {
		t.Errorf("--set account_id that is not accessible = %v, want an error listing the accessible ones", err)
	}
	one := fakeSSO(t, two[:1], roles)
	in, _ = input(false, refusingReader{t}, nil, nil)
	if id, _, err := chooseAccount(ctx, one, "tok", in, in.IO(ctx)); err != nil || id != "111111111111" {
		t.Errorf("the only account = %q, %v", id, err)
	}

	// Non-interactive, roles.
	in, stderr = input(false, refusingReader{t}, nil, nil)
	_, err = chooseRole(ctx, c, "tok", "111111111111", in, in.IO(ctx))
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set role_name=<name>") || !strings.Contains(err.Error(), "Admin, ReadOnly") {
		t.Errorf("several roles = %v, want a usage error listing them", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("several roles printed %q", stderr.String())
	}
	in, _ = input(false, refusingReader{t}, map[string]string{"role_name": "ReadOnly"}, nil)
	if r, err := chooseRole(ctx, c, "tok", "111111111111", in, in.IO(ctx)); err != nil || r != "ReadOnly" {
		t.Errorf("--set role_name = %q, %v", r, err)
	}
	in, _ = input(false, refusingReader{t}, nil, map[string]string{metaRoleName: "ReadOnly"})
	if r, err := chooseRole(ctx, c, "tok", "111111111111", in, in.IO(ctx)); err != nil || r != "ReadOnly" {
		t.Errorf("role of the previous login = %q, %v", r, err)
	}
	in, _ = input(false, refusingReader{t}, nil, nil)
	if r, err := chooseRole(ctx, c, "tok", "222222222222", in, in.IO(ctx)); err != nil || r != "Admin" {
		t.Errorf("the only role = %q, %v", r, err)
	}

	// Interactive: both are asked.
	in, stderr = input(true, strings.NewReader("2\n"), nil, nil)
	if id, _, err := chooseAccount(ctx, c, "tok", in, in.IO(ctx)); err != nil || id != "222222222222" || !strings.Contains(stderr.String(), "Account") {
		t.Errorf("interactive account = %q, %v (stderr %q)", id, err, stderr.String())
	}
	in, stderr = input(true, strings.NewReader("ReadOnly\n"), nil, nil)
	if r, err := chooseRole(ctx, c, "tok", "111111111111", in, in.IO(ctx)); err != nil || r != "ReadOnly" || !strings.Contains(stderr.String(), "Role") {
		t.Errorf("interactive role = %q, %v (stderr %q)", r, err, stderr.String())
	}
}
