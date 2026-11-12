package aliyun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// aliAccount is the account the harness configures.
var aliAccount = config.AccountRef{Profile: "ali", Platform: platform.Aliyun}

// harness is a Runtime with one aliyun account (profile "ali", region cn-shanghai)
// whose requests go to a fake API.
type harness struct {
	t      *testing.T
	rt     *app.Runtime
	api    *fakeAPI
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func newHarness(t *testing.T, flags app.Flags) *harness {
	t.Helper()
	f := newFakeAPI(t)
	withFakeEndpoint(t, f)
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")

	cfgPath := filepath.Join(dir, "config.yaml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CredentialStore = "file"
	cfg.Profiles = map[string]*config.Profile{
		"ali": {Platforms: map[platform.ID]*config.Account{
			platform.Aliyun: {Metadata: map[string]string{metaRegion: "cn-shanghai"}},
		}},
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := creds.NewFile(dir).Set(creds.Key("ali", string(platform.Aliyun)), map[string]string{secretKeyID: "LTAItestkeyid000", secretKeySecret: "testsecret"}); err != nil {
		t.Fatal(err)
	}
	flags.ConfigDir = filepath.Dir(cfgPath)
	if flags.Output == "" {
		flags.Output = "json"
	}
	h := &harness{t: t, api: f, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	h.rt = app.New(flags, strings.NewReader(""), h.stdout, h.stderr)
	if err := h.rt.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = h.rt.Close() })
	return h
}

func (h *harness) db() *inventory.DB {
	h.t.Helper()
	db, err := h.rt.DB()
	if err != nil {
		h.t.Fatal(err)
	}
	return db
}

// run executes `polyctl aliyun <args>` and returns the error.
func (h *harness) run(args ...string) error {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	cmd := Command(h.rt)
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return cmd.ExecuteContext(context.Background())
}

func (h *harness) jsonOut(v any) {
	h.t.Helper()
	if err := json.Unmarshal(h.stdout.Bytes(), v); err != nil {
		h.t.Fatalf("stdout is not JSON: %v\n%s", err, h.stdout.String())
	}
}

func domainListBody(names ...string) map[string]any {
	var items []map[string]any
	for _, n := range names {
		items = append(items, map[string]any{"DomainName": n, "DomainStatus": "3", "DnsList": map[string]any{"Dns": []string{"ns1.x", "ns2.x"}}})
	}
	return map[string]any{"TotalPageNum": 1, "CurrentPageNum": 1, "NextPage": false, "Data": map[string]any{"Domain": items}}
}

func instancesBody(region string, ids ...string) map[string]any {
	var items []map[string]any
	for _, id := range ids {
		items = append(items, map[string]any{"InstanceId": id, "InstanceName": "n-" + id, "Status": "Running", "RegionId": region, "ZoneId": region + "-a"})
	}
	return map[string]any{"TotalCount": len(items), "Instances": map[string]any{"Instance": items}}
}

func TestSyncAccountKeepsDomainsWhenRegistrarForbidden(t *testing.T) {
	h := newHarness(t, app.Flags{})
	ctx := context.Background()
	set := inventory.Set{Platform: platform.Aliyun, Profile: "ali", Type: platform.ResDomain}
	// A previous sync recorded one registered domain.
	if err := h.db().Replace(ctx, set, app.DomainResources([]platform.Domain{{Name: "kept.example", Nameservers: []string{"ns1.x"}}}), time.Hour); err != nil {
		t.Fatal(err)
	}
	before, err := h.db().GetState(ctx, set)
	if err != nil || before == nil {
		t.Fatalf("state before = %v, %v", before, err)
	}

	h.api.on("DescribeDomains", func(q url.Values) (int, any) {
		return 200, map[string]any{"TotalCount": 1, "Domains": map[string]any{"Domain": []map[string]any{{"DomainName": "zone.example"}}}}
	})
	h.api.on("DescribeDomainRecords", func(q url.Values) (int, any) {
		return 200, map[string]any{"TotalCount": 0, "DomainRecords": map[string]any{"Record": []map[string]any{}}}
	})
	h.api.on("QueryDomainList", func(q url.Values) (int, any) {
		return 403, apiErr("Forbidden.RAM", "User not authorized to operate on the specified resource")
	})
	h.api.on("DescribeInstances", func(q url.Values) (int, any) { return 200, instancesBody(q.Get("RegionId"), "i-1") })

	reports, err := h.rt.SyncAccount(ctx, aliAccount, nil)
	if err != nil {
		t.Fatalf("SyncAccount must not abort on a RAM denial: %v", err)
	}
	byType := map[platform.ResourceType]app.SyncReport{}
	for _, r := range reports {
		byType[r.Type] = r
	}
	if r := byType[platform.ResDomain]; !strings.Contains(r.Error, "Forbidden.RAM") {
		t.Errorf("domain report should carry the denial, got %+v", r)
	}
	if r, ok := byType[platform.ResInstance]; !ok || r.Error != "" || r.Count != 1 {
		t.Errorf("instances must still be synced after the denial, got %+v (present %v)", r, ok)
	}
	if r := byType[platform.ResZone]; r.Error != "" || r.Count != 1 {
		t.Errorf("zone report = %+v", r)
	}

	// The registered domains and their index are untouched.
	rows, err := h.db().List(ctx, inventory.Query{Platform: platform.Aliyun, Profile: "ali", Type: platform.ResDomain})
	if err != nil || len(rows) != 1 || rows[0].ID != "kept.example" {
		t.Errorf("domain rows after denied sync = %+v, %v; want kept.example only", rows, err)
	}
	entries, err := h.db().LookupDomain(ctx, []string{"kept.example"}, platform.ResDomain)
	if err != nil || len(entries) != 1 {
		t.Errorf("domain index after denied sync = %+v, %v", entries, err)
	}
	after, err := h.db().GetState(ctx, set)
	if err != nil || after == nil || !after.SyncedAt.Equal(before.SyncedAt) {
		t.Errorf("domain set state must not be marked fresh by a failed sync: before %+v after %+v (%v)", before, after, err)
	}

	// An authentication failure still aborts.
	h.api.on("DescribeDomains", func(q url.Values) (int, any) { return 404, apiErr("InvalidAccessKeyId.NotFound", "bad key") })
	if _, err := h.rt.SyncAccount(ctx, aliAccount, nil); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("bad key sync = %v, want ErrUnauthorized", err)
	}
}

func TestECSListScopesToProfileRegion(t *testing.T) {
	h := newHarness(t, app.Flags{})
	h.api.on("DescribeInstances", func(q url.Values) (int, any) {
		switch q.Get("RegionId") {
		case "cn-shanghai":
			return 200, instancesBody("cn-shanghai", "i-sh")
		case "cn-beijing":
			return 200, instancesBody("cn-beijing", "i-bj")
		}
		t.Errorf("unexpected RegionId %q", q.Get("RegionId"))
		return 400, apiErr("InvalidRegionId.NotFound", "")
	})
	var out instanceList

	if err := h.run("ecs", "instance", "list", "--region", "cn-beijing"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&out)
	if out.Region != "cn-beijing" || len(out.Instances) != 1 || out.Instances[0].ID != "i-bj" || out.Cached {
		t.Errorf("explicit region list = %+v", out)
	}

	// Without --region: the profile region only, labelled as such, even
	// though cn-beijing instances are cached for the profile.
	if err := h.run("ecs", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&out)
	if out.Region != "cn-shanghai" || len(out.Instances) != 1 || out.Instances[0].ID != "i-sh" || out.Cached {
		t.Errorf("unscoped list = %+v, want only the cn-shanghai instance", out)
	}
	if !strings.Contains(h.stderr.String(), "in cn-shanghai via aliyun/ali") {
		t.Errorf("status line should name the resolved region: %s", h.stderr.String())
	}

	// Second run is served from the region-scoped cache.
	n := len(h.api.callsFor("DescribeInstances"))
	if err := h.run("ecs", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&out)
	if !out.Cached || out.Region != "cn-shanghai" || len(out.Instances) != 1 || out.Instances[0].ID != "i-sh" {
		t.Errorf("cached list = %+v", out)
	}
	if len(h.api.callsFor("DescribeInstances")) != n {
		t.Error("cached read must not call the API")
	}

	// A full sync (unscoped Replace) still serves the scoped read from cache.
	h.api.on("DescribeDomains", func(q url.Values) (int, any) {
		return 200, map[string]any{"TotalCount": 0, "Domains": map[string]any{"Domain": []map[string]any{}}}
	})
	h.api.on("QueryDomainList", func(q url.Values) (int, any) { return 200, domainListBody() })
	if _, err := h.rt.SyncAccount(context.Background(), aliAccount, nil); err != nil {
		t.Fatal(err)
	}
	n = len(h.api.callsFor("DescribeInstances"))
	if err := h.run("ecs", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&out)
	if !out.Cached || len(out.Instances) != 1 || out.Instances[0].ID != "i-sh" || len(h.api.callsFor("DescribeInstances")) != n {
		t.Errorf("after sync: list = %+v (api calls %d -> %d)", out, n, len(h.api.callsFor("DescribeInstances")))
	}
}

func TestDomainGetUsesInventory(t *testing.T) {
	h := newHarness(t, app.Flags{})
	calls := 0
	h.api.on("QueryDomainByDomainName", func(q url.Values) (int, any) {
		calls++
		return 200, map[string]any{"DomainName": "d1.example", "DomainStatus": "3", "ExpirationDate": "2030-01-01 00:00:00", "DnsList": map[string]any{"Dns": []string{"ns1.x", "ns2.x"}}}
	})
	var out struct {
		Name        string   `json:"name"`
		Nameservers []string `json:"nameservers"`
		Profile     string   `json:"profile"`
		Cached      bool     `json:"cached"`
	}

	// Nothing cached: remote fetch, mirrored into the inventory.
	if err := h.run("domain", "get", "D1.Example"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&out)
	if out.Name != "d1.example" || out.Cached || out.Profile != "ali" || len(out.Nameservers) != 2 || calls != 1 {
		t.Errorf("first get = %+v (calls %d)", out, calls)
	}

	// The set is not marked fresh by an Upsert alone; a sync makes it fresh.
	h.api.on("QueryDomainList", func(q url.Values) (int, any) { return 200, domainListBody("d1.example") })
	if _, err := h.rt.SyncAccount(context.Background(), aliAccount, []platform.ResourceType{platform.ResDomain}); err != nil {
		t.Fatal(err)
	}
	if err := h.run("domain", "get", "d1.example"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&out)
	if !out.Cached || out.Name != "d1.example" || calls != 1 {
		t.Errorf("fresh set should be served from the inventory: %+v (calls %d)", out, calls)
	}
	if !strings.Contains(h.stderr.String(), "(local inventory)") {
		t.Errorf("status line should say the record is cached: %s", h.stderr.String())
	}

	// --refresh forces the registrar.
	h.rt.Flags.Refresh = true
	if err := h.run("domain", "get", "d1.example"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&out)
	if out.Cached || calls != 2 {
		t.Errorf("--refresh get = %+v (calls %d)", out, calls)
	}
	h.rt.Flags.Refresh = false

	// --offline serves the inventory and never opens the client.
	h.rt.Flags.Offline = true
	if err := h.run("domain", "get", "d1.example"); err != nil {
		t.Fatalf("offline get with cached domain: %v", err)
	}
	h.jsonOut(&out)
	if !out.Cached || out.Name != "d1.example" || calls != 2 {
		t.Errorf("offline get = %+v (calls %d)", out, calls)
	}
	if err := h.run("domain", "get", "unknown.example"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("offline get of an unknown domain = %v, want ErrNotFound", err)
	}
}

func TestDomainNSSetDoesNotCacheOnPendingTask(t *testing.T) {
	h := newHarness(t, app.Flags{})
	shortTaskWait(t)
	h.api.on("SaveBatchTaskForModifyingDomainDns", func(q url.Values) (int, any) { return 200, map[string]any{"TaskNo": "t9"} })
	h.api.on("QueryTaskDetailList", func(q url.Values) (int, any) {
		return 200, map[string]any{"Data": map[string]any{"TaskDetail": []map[string]any{{"TaskNo": "t9", "DomainName": "d1.example", "TaskStatus": "EXECUTING", "TaskStatusCode": 1}}}}
	})
	gets := 0
	h.api.on("QueryDomainByDomainName", func(q url.Values) (int, any) {
		gets++
		return 200, map[string]any{"DomainName": "d1.example", "DomainStatus": "3", "DnsList": map[string]any{"Dns": []string{"old1.x", "old2.x"}}}
	})
	err := h.run("domain", "ns", "set", "d1.example", "ns1.example.net", "ns2.example.net")
	if !errors.Is(err, ErrTaskPending) {
		t.Fatalf("pending task = %v, want ErrTaskPending", err)
	}
	if gets != 0 {
		t.Error("the old record must not be re-read while the task is pending")
	}
	rows, _ := h.db().List(context.Background(), inventory.Query{Platform: platform.Aliyun, Profile: "ali", Type: platform.ResDomain})
	if len(rows) != 0 {
		t.Errorf("nothing must be cached for a pending task, got %+v", rows)
	}

	// Once the task succeeds the fresh record is cached and printed.
	h.api.on("QueryTaskDetailList", func(q url.Values) (int, any) {
		return 200, map[string]any{"Data": map[string]any{"TaskDetail": []map[string]any{{"TaskNo": "t9", "DomainName": "d1.example", "TaskStatus": "EXECUTE_SUCCESS", "TaskStatusCode": 2}}}}
	})
	h.api.on("QueryDomainByDomainName", func(q url.Values) (int, any) {
		gets++
		return 200, map[string]any{"DomainName": "d1.example", "DomainStatus": "3", "DnsList": map[string]any{"Dns": []string{"ns1.example.net", "ns2.example.net"}}}
	})
	if err := h.run("domain", "ns", "set", "d1.example", "ns1.example.net", "ns2.example.net"); err != nil {
		t.Fatal(err)
	}
	var out platform.Domain
	h.jsonOut(&out)
	if gets != 1 || strings.Join(out.Nameservers, ",") != "ns1.example.net,ns2.example.net" {
		t.Errorf("after success: %+v (gets %d)", out, gets)
	}
	rows, _ = h.db().List(context.Background(), inventory.Query{Platform: platform.Aliyun, Profile: "ali", Type: platform.ResDomain})
	if len(rows) != 1 || rows[0].ID != "d1.example" {
		t.Errorf("new record should be cached, got %+v", rows)
	}
}

// A declined confirmation of `ecs stop` stops nothing and is not an error: a
// note on stderr and a nil error, which is exit code 0. The question belongs
// to the interactive flow.
func TestECSStopDeclinedIsNotAnError(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "") // not the developer's setting
	for _, answer := range []string{"n\n", "\n"} {
		h := newHarness(t, app.Flags{})
		h.rt.Picker = terminalStub{t}
		h.rt.Stdin = strings.NewReader(answer)
		if err := h.run("ecs", "instance", "stop", "i-1"); err != nil {
			t.Errorf("answer %q: ecs stop = %v, want no error", answer, err)
		}
		stderr := h.stderr.String()
		if !strings.Contains(stderr, "stop instance i-1 (y/N)") {
			t.Errorf("answer %q: the question was not asked: %q", answer, stderr)
		}
		if !strings.HasSuffix(stderr, "nothing to do: instance i-1 was not stopped\n") || strings.Contains(stderr, "error:") || strings.Contains(stderr, "stop requested") {
			t.Errorf("answer %q: stderr = %q, want the note", answer, stderr)
		}
		if h.stdout.Len() != 0 {
			t.Errorf("answer %q: stdout = %q, want nothing", answer, h.stdout.String())
		}
		if n := len(h.api.callsFor("StopInstance")); n != 0 {
			t.Errorf("answer %q: StopInstance was called %d time(s)", answer, n)
		}
	}
}

// The two flows of `ecs stop`: the interactive one asks, the non-interactive
// one never asks or reads stdin and needs --yes.
func TestECSStopFlows(t *testing.T) {
	stoppable := func(h *harness) {
		h.api.on("StopInstance", func(q url.Values) (int, any) { return 200, map[string]any{"RequestId": "r"} })
	}
	for _, tc := range []struct {
		name     string
		flags    app.Flags
		env      string // POLYCTL_NON_INTERACTIVE
		terminal bool   // a terminal is attached (the injected picker)
		stdin    string // only read by the interactive flow
		stopped  bool
		refused  bool
		asked    bool
	}{
		{name: "interactive, yes", terminal: true, stdin: "y\n", stopped: true, asked: true},
		{name: "interactive, --yes", flags: app.Flags{Yes: true}, terminal: true, stopped: true},
		{name: "no terminal", refused: true},
		{name: "no terminal, --yes", flags: app.Flags{Yes: true}, stopped: true},
		{name: "--non-interactive on a terminal", flags: app.Flags{NonInteractive: true}, terminal: true, refused: true},
		{name: "--non-interactive --yes on a terminal", flags: app.Flags{NonInteractive: true, Yes: true}, terminal: true, stopped: true},
		{name: "POLYCTL_NON_INTERACTIVE on a terminal", env: "1", terminal: true, refused: true},
		{name: "POLYCTL_NON_INTERACTIVE with --yes", env: "true", flags: app.Flags{Yes: true}, terminal: true, stopped: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(app.EnvNonInteractive, tc.env)
			h := newHarness(t, tc.flags)
			stoppable(h)
			if tc.terminal {
				h.rt.Picker = terminalStub{t}
			}
			h.rt.Stdin = unreadStdin{t}
			if tc.asked {
				h.rt.Stdin = strings.NewReader(tc.stdin)
			}
			err := h.run("ecs", "instance", "stop", "i-1")
			stderr := h.stderr.String()
			if asked := strings.Contains(stderr, "(y/N)"); asked != tc.asked {
				t.Errorf("question asked = %v, want %v (stderr %q)", asked, tc.asked, stderr)
			}
			if tc.refused {
				if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "confirmation required: pass --yes to proceed (would stop instance i-1)") {
					t.Errorf("ecs stop = %v, want the usage error that names --yes", err)
				}
				// Refused before the account is opened: nothing was sent.
				if n := len(h.api.calls); n != 0 || stderr != "" || h.stdout.Len() != 0 {
					t.Errorf("refused: %d API call(s), stderr %q, stdout %q; want nothing", n, stderr, h.stdout.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("ecs stop = %v", err)
			}
			if n := len(h.api.callsFor("StopInstance")); (n == 1) != tc.stopped {
				t.Errorf("StopInstance was called %d time(s), stopped want %v", n, tc.stopped)
			}
		})
	}
}

// terminalStub stands in for a terminal: a Runtime with it is in the
// interactive flow. It fails the test when an arrow-key prompt is shown.
type terminalStub struct{ t *testing.T }

func (p terminalStub) Select(title string, _ []prompt.Option, _ string) (string, error) {
	p.t.Errorf("unexpected select prompt %q", title)
	return "", prompt.ErrAborted
}

func (p terminalStub) MultiSelect(title string, _ []prompt.Option) ([]string, error) {
	p.t.Errorf("unexpected multi-select prompt %q", title)
	return nil, prompt.ErrAborted
}

func (p terminalStub) Confirm(title string, _ bool) (bool, error) {
	p.t.Errorf("unexpected confirm prompt %q", title)
	return false, prompt.ErrAborted
}

func (p terminalStub) Input(title, _ string, _ func(string) error) (string, error) {
	p.t.Errorf("unexpected input prompt %q", title)
	return "", prompt.ErrAborted
}

// unreadStdin fails the test when it is read.
type unreadStdin struct{ t *testing.T }

func (r unreadStdin) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}
