package aliyun

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

func siteLogin(t *testing.T, in platform.LoginInput) (*platform.LoginResult, string, error) {
	t.Helper()
	var stderr bytes.Buffer
	in.Stdout, in.Stderr = &bytes.Buffer{}, &stderr
	if in.Stdin == nil {
		in.Stdin = refusingReader{t}
	}
	res, err := (&provider{}).Login(context.Background(), in)
	return res, stderr.String(), err
}

// The site is required: asked first in the interactive flow, a usage error
// without --set site in the non-interactive one, and never changed by a
// later login.
func TestLoginRequiresTheSite(t *testing.T) {
	f := newFakeAPI(t)
	withFakeEndpoint(t, f)
	f.on("GetCallerIdentity", func(q url.Values) (int, any) {
		return 200, map[string]any{"AccountId": "42", "Arn": "acs:ram::42:user/dev", "IdentityType": "RAMUser"}
	})
	t.Setenv(envKeyID, "")
	t.Setenv(envKeySecret, "")
	key := map[string]string{"access_key_id": "LTAIset", "access_key_secret": "s"}

	// Non-interactive, key given, no site: nothing is called or printed.
	_, stderr, err := siteLogin(t, platform.LoginInput{Options: key})
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set site=cn") || !strings.Contains(err.Error(), "--set site=intl") || strings.Contains(err.Error(), "AccessKey") {
		t.Errorf("no site = %v", err)
	}
	if stderr != "" || len(f.calls) != 0 {
		t.Errorf("no site: stderr %q, %d call(s)", stderr, len(f.calls))
	}
	// Neither site nor key: both are named.
	_, _, err = siteLogin(t, platform.LoginInput{})
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set site=cn") || !strings.Contains(err.Error(), "--set access_key_id=<id>") {
		t.Errorf("nothing = %v", err)
	}
	// An unknown site is a usage error.
	if _, _, err := siteLogin(t, platform.LoginInput{Options: map[string]string{"site": "eu", "access_key_id": "a", "access_key_secret": "b"}}); !errors.Is(err, app.ErrUsage) {
		t.Errorf("site=eu = %v", err)
	}
	// A re-authentication keeps the recorded site, and refuses another one.
	res, _, err := siteLogin(t, platform.LoginInput{Options: key, Existing: map[string]string{metaSite: "intl"}})
	if err != nil || res.Metadata[metaSite] != siteIntl {
		t.Errorf("re-authentication = %+v, %v", res, err)
	}
	_, _, err = siteLogin(t, platform.LoginInput{ProfileName: "acme", Options: map[string]string{"site": "cn", "access_key_id": "a", "access_key_secret": "b"}, Existing: map[string]string{metaSite: "intl"}})
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "auth logout aliyun --profile acme") {
		t.Errorf("site change = %v", err)
	}
	// The same site again is fine.
	if _, _, err := siteLogin(t, platform.LoginInput{Options: map[string]string{"site": "intl", "access_key_id": "a", "access_key_secret": "b"}, Existing: map[string]string{metaSite: "intl"}}); err != nil {
		t.Errorf("same site = %v", err)
	}
}

// sitePicker answers the site question.
type sitePicker struct {
	answer string
	titles []string
}

func (p *sitePicker) Select(title string, opts []prompt.Option, def string) (string, error) {
	p.titles = append(p.titles, title)
	if def != "" {
		return "", errors.New("the site question must not preselect an answer")
	}
	if p.answer == "" {
		return "", prompt.ErrAborted
	}
	return p.answer, nil
}
func (p *sitePicker) MultiSelect(string, []prompt.Option) ([]string, error) {
	return nil, prompt.ErrAborted
}
func (p *sitePicker) Confirm(string, bool) (bool, error) { return false, prompt.ErrAborted }
func (p *sitePicker) Input(string, string, func(string) error) (string, error) {
	return "", prompt.ErrAborted
}

func TestLoginAsksTheSiteFromAList(t *testing.T) {
	f := newFakeAPI(t)
	withFakeEndpoint(t, f)
	f.on("GetCallerIdentity", func(q url.Values) (int, any) {
		return 200, map[string]any{"AccountId": "42", "Arn": "acs:ram::42:user/dev", "IdentityType": "RAMUser"}
	})
	t.Setenv(envKeyID, "")
	t.Setenv(envKeySecret, "")
	p := &sitePicker{answer: "cn"}
	res, stderr, err := siteLogin(t, platform.LoginInput{Interactive: true, Picker: p, Options: map[string]string{"access_key_id": "a", "access_key_secret": "b"}, Stdin: strings.NewReader("\n"), NoBrowser: true})
	if err != nil || res.Metadata[metaSite] != siteCN || len(p.titles) != 1 || !strings.Contains(stderr, "usually belongs to one of them") {
		t.Errorf("picked site = %+v, %v, %v (stderr %q)", res, err, p.titles, stderr)
	}
	// Leaving the question ends the login.
	_, _, err = siteLogin(t, platform.LoginInput{Interactive: true, Picker: &sitePicker{}, Stdin: strings.NewReader("")})
	if !errors.Is(err, prompt.ErrAborted) || len(f.callsFor("GetCallerIdentity")) != 1 {
		t.Errorf("left question = %v", err)
	}
}

// The site is cross-checked with the billing API for main accounts only,
// and the check never stops the login.
func TestLoginChecksTheSite(t *testing.T) {
	f := newFakeAPI(t)
	withFakeEndpoint(t, f)
	identity := "Account"
	f.on("GetCallerIdentity", func(q url.Values) (int, any) {
		return 200, map[string]any{"AccountId": "42", "Arn": "acs:ram::42:root", "IdentityType": identity}
	})
	t.Setenv(envKeyID, "")
	t.Setenv(envKeySecret, "")
	opts := map[string]string{"site": "intl", "access_key_id": "a", "access_key_secret": "b"}
	for _, tc := range []struct {
		name, identity string
		status         int
		body           any
		want           string
		calls          int
	}{
		{"confirmed", "Account", 200, map[string]any{"Success": true, "Code": "Success", "Data": map[string]any{"Currency": "USD"}}, "", 1},
		{"other site", "Account", 400, apiErr("AuthSiteFail", "site"), "warning: the billing API of the International site (alibabacloud.com) refused this account (AuthSiteFail)", 1},
		{"no permission", "Account", 400, apiErr("NotAuthorized", "no"), "note: the key has no billing permission", 1},
		{"unknown failure", "Account", 400, apiErr("InvalidParameter", "oops"), "note: could not confirm the site", 1},
		{"RAM user", "RAMUser", 200, nil, "note: the key belongs to a RAM identity", 0},
	} {
		identity = tc.identity
		before := len(f.callsFor("QueryAccountBalance"))
		f.on("QueryAccountBalance", func(q url.Values) (int, any) { return tc.status, tc.body })
		res, stderr, err := siteLogin(t, platform.LoginInput{Options: opts})
		if err != nil || res.Metadata[metaSite] != siteIntl {
			t.Errorf("%s: login = %+v, %v", tc.name, res, err)
			continue
		}
		if tc.want == "" && strings.Contains(stderr, "site") || tc.want != "" && !strings.Contains(stderr, tc.want) {
			t.Errorf("%s: stderr = %q, want %q", tc.name, stderr, tc.want)
		}
		if n := len(f.callsFor("QueryAccountBalance")) - before; n != tc.calls {
			t.Errorf("%s: %d billing call(s), want %d", tc.name, n, tc.calls)
		}
	}
}

func TestVerifyReportsTheSite(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client()
	c.site = siteIntl
	f.on("GetCallerIdentity", func(q url.Values) (int, any) {
		return 200, map[string]any{"AccountId": "42", "Arn": "acs:ram::42:root", "IdentityType": "Account"}
	})
	id, err := c.Verify(context.Background())
	if err != nil || id.Extra["site"] != siteIntl {
		t.Errorf("Verify = %+v, %v", id, err)
	}
}
