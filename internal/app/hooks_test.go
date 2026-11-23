package app

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
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

// hookRuntime returns a Runtime whose config sets hooks.on_failure.
func hookRuntime(t *testing.T, hook string) (*Runtime, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.Load(filepath.Join(dir, config.FileName))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Hooks.OnFailure = hook
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	var errb bytes.Buffer
	rt := New(Flags{ConfigDir: dir}, strings.NewReader(""), &bytes.Buffer{}, &errb)
	return rt, &errb
}

func TestNotifyFailureWebhook(t *testing.T) {
	var mu sync.Mutex
	var got []Failure
	status := http.StatusNoContent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var f Failure
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || json.Unmarshal(b, &f) != nil {
			t.Errorf("bad request %s %q", r.Method, b)
		}
		mu.Lock()
		got = append(got, f)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	defer srv.Close()
	rt, errb := hookRuntime(t, srv.URL+"/hook")
	rt.NotifyFailure(t.Context(), Failure{Event: "cert.deploy.failed", Platform: "aliyun", Profile: "acme", Domain: "example.com", Error: "boom"})
	if len(got) != 1 || got[0].Event != "cert.deploy.failed" || got[0].Error != "boom" || got[0].Time == "" || errb.Len() != 0 {
		t.Fatalf("webhook got %+v, stderr %q", got, errb.String())
	}
	// A failing webhook is a warning, nothing more.
	status = http.StatusInternalServerError
	rt.NotifyFailure(t.Context(), Failure{Event: "x.failed", Error: "e"})
	if !strings.Contains(errb.String(), "warning: hooks.on_failure: webhook answered HTTP 500") {
		t.Errorf("stderr = %q", errb.String())
	}
	// A dry run notifies nobody.
	rt.Flags.DryRun = true
	rt.NotifyFailure(t.Context(), Failure{Event: "x.failed", Error: "e"})
	if len(got) != 2 {
		t.Errorf("dry run notified: %d calls", len(got))
	}
}

// A webhook that cannot be reached is reported without its URL, which is
// often the secret of the webhook.
func TestNotifyFailureWebhookErrorHidesTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL + "/services/T000/B000/secret-token"
	srv.Close()
	rt, errb := hookRuntime(t, url)
	rt.NotifyFailure(t.Context(), Failure{Event: "x.failed", Error: "e"})
	if !strings.Contains(errb.String(), "warning: hooks.on_failure: webhook request failed") || strings.Contains(errb.String(), "secret-token") {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestNotifyFailureCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	out := filepath.Join(t.TempDir(), "hook.out")
	rt, errb := hookRuntime(t, `{ printf '%s|%s|%s\n' "$POLYCTL_EVENT" "$POLYCTL_PROFILE" "$POLYCTL_ERROR"; cat; } > '`+out+`'`)
	rt.NotifyFailure(t.Context(), Failure{Event: "aws.rds.instance.ensure.failed", Profile: "acme", Error: "boom"})
	b, err := os.ReadFile(out)
	if err != nil || !strings.HasPrefix(string(b), "aws.rds.instance.ensure.failed|acme|boom\n{") || !strings.Contains(string(b), `"event":"aws.rds.instance.ensure.failed"`) {
		t.Fatalf("hook output %q, %v (stderr %q)", b, err, errb.String())
	}
	rt, errb = hookRuntime(t, "exit 3")
	rt.NotifyFailure(t.Context(), Failure{Event: "x.failed", Error: "e"})
	if !strings.Contains(errb.String(), "warning: hooks.on_failure: command failed") {
		t.Errorf("stderr = %q", errb.String())
	}
	old := HookTimeout
	HookTimeout = 200 * time.Millisecond
	defer func() { HookTimeout = old }()
	rt, errb = hookRuntime(t, "sleep 5")
	start := time.Now()
	rt.NotifyFailure(t.Context(), Failure{Event: "x.failed", Error: "e"})
	if time.Since(start) > 3*time.Second || !strings.Contains(errb.String(), "timed out") {
		t.Errorf("timeout: %s, stderr %q", time.Since(start), errb.String())
	}
}

func TestEnsureNotifiesOnFailure(t *testing.T) {
	var events []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var f Failure
		_ = json.NewDecoder(r.Body).Decode(&f)
		events = append(events, f.Event+":"+f.Profile)
	}))
	defer srv.Close()
	rt, _ := hookRuntime(t, srv.URL)
	boom := errors.New("boom")
	failing := func() *platform.Plan {
		return &platform.Plan{Steps: []platform.Step{{Resource: "x", Action: platform.Created, Apply: func(context.Context) (platform.Change, error) { return platform.Change{}, boom }}}}
	}
	target := platform.Target{Platform: platform.AWS, Profile: "acme"}
	_ = rt.Ensure(t.Context(), "aws.ec2.key-pair.ensure", target, failing())
	rt.Flags.DryRun = true
	_ = rt.Ensure(t.Context(), "aws.ec2.key-pair.ensure", target, failing()) // a dry run does not fail and does not notify
	if len(events) != 1 || events[0] != "aws.ec2.key-pair.ensure.failed:acme" {
		t.Errorf("events = %v", events)
	}
}

func TestSettings(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := config.Load(filepath.Join(dir, config.FileName))
	cfg.Defaults = config.Defaults{"aliyun": {"region": "cn-hongkong"}}
	cfg.Profiles["p"] = &config.Profile{Platforms: map[platform.ID]*config.Account{}, Defaults: config.Defaults{"aliyun": {"resource_group": "rg-1"}}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	rt := New(Flags{ConfigDir: dir}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if v, err := rt.Setting("p", platform.Aliyun, "region", ""); err != nil || v != "cn-hongkong" {
		t.Errorf("config value = %q, %v", v, err)
	}
	if v, _ := rt.Setting("p", platform.Aliyun, "region", "us-west-1"); v != "us-west-1" {
		t.Errorf("flag value = %q", v)
	}
	if v, _ := rt.RequireSetting("p", platform.Aliyun, "resource_group", "resource-group", ""); v != "rg-1" {
		t.Errorf("profile value = %q", v)
	}
	_, err := rt.RequireSetting("p", platform.Aliyun, "vpc_id", "vpc", "")
	if !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "--vpc") || !strings.Contains(err.Error(), "defaults.aliyun.vpc_id") {
		t.Errorf("missing = %v", err)
	}
	if n, err := rt.ResourceName("aliyun_vpc", "", map[string]string{"region": "cn-hongkong"}); err != nil || n != "cn-hongkong-vpc" {
		t.Errorf("name = %q, %v", n, err)
	}
	if n, _ := rt.ResourceName("aliyun_vpc", "mine", nil); n != "mine" {
		t.Errorf("explicit name = %q", n)
	}
}
