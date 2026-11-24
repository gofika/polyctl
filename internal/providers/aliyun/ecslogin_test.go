package aliyun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

var winCreate = []string{"ecs", "instance", "create", "win-a", "--os", "windows", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--no-wait"}

func winHarness(t *testing.T, flags app.Flags) (*harness, *fakeECS) {
	t.Helper()
	h, f, _ := computeHarness(t, flags)
	siteNet(f)
	f.typeArch = map[string]string{"ecs.u1-c1m2.large": "X86"}
	return h, f
}

// storedLogin returns the credentials stored for name ("" fields when
// none).
func storedLogin(t *testing.T, h *harness, name string) []secrets.Credentials {
	t.Helper()
	st, err := h.rt.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Find(context.Background(), platform.Aliyun, "ali", "", name)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// assertNoPlaintext checks that no file of the configuration directory
// (the inventory database, the credential file) holds secret.
func assertNoPlaintext(t *testing.T, h *harness, secret string) {
	t.Helper()
	dir, err := h.rt.ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), secret) {
			t.Errorf("%s holds the password in plain text", filepath.Base(p))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A non-interactive Windows create sends a generated password in the form
// body (never in the URL), stores it encrypted and prints it nowhere: a
// note names the password command.
func TestWindowsCreateNonInteractive(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	run := h.api.callsFor("RunInstances")[0]
	pw := run.Get("Password")
	if !secrets.ValidPassword(pw) || run.Has("KeyPairName") || run.Has("PasswordInherit") {
		t.Fatalf("RunInstances = %v", run)
	}
	for _, q := range h.api.queries {
		if strings.Contains(q, "Password") {
			t.Errorf("the password is in the URL query: %s", q)
		}
	}
	id := f.instances[0]["InstanceId"].(string)
	if strings.Contains(h.stdout.String(), pw) || strings.Contains(h.stderr.String(), pw) {
		t.Errorf("the password was printed:\n%s\n%s", h.stdout.String(), h.stderr.String())
	}
	note := "user Administrator; `polyctl aliyun ecs instance password " + id + "` shows the password"
	if !strings.Contains(h.stderr.String(), note) {
		t.Errorf("stderr lacks %q:\n%s", note, h.stderr.String())
	}
	var rep struct {
		Changes []platform.Change `json:"changes"`
	}
	h.jsonOut(&rep)
	if len(rep.Changes) != 1 || !strings.Contains(rep.Changes[0].Detail, id) {
		t.Errorf("report = %+v", rep)
	}
	got := storedLogin(t, h, "win-a")
	if len(got) != 1 || got[0].Password != pw || got[0].User != windowsUser || got[0].InstanceID != id || got[0].Location != "cn-shanghai" {
		t.Fatalf("stored = %+v", got)
	}
	assertNoPlaintext(t, h, pw)

	// The password command shows it (-o json), by name or id, with --region.
	for _, args := range [][]string{{"win-a"}, {id, "--region", "cn-shanghai"}} {
		if err := h.run(append([]string{"ecs", "instance", "password"}, args...)...); err != nil {
			t.Fatalf("password %v: %v", args, err)
		}
		var login map[string]any
		h.jsonOut(&login)
		if login["instance"] != "win-a" || login["id"] != id || login["user"] != windowsUser || login["password"] != pw || login["platform"] != "aliyun" || login["location"] != "cn-shanghai" {
			t.Errorf("password %v = %v", args, login)
		}
	}
	// Another region holds nothing.
	err := h.run("ecs", "instance", "password", "win-a", "--region", "cn-hongkong")
	if !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("other region = %v", err)
	}
}

// An interactive create prints the login at the end: on stdout after the
// table report, on stderr with -o json so that stdout stays one document.
func TestWindowsCreateInteractive(t *testing.T) {
	h, f := winHarness(t, app.Flags{Output: "table"})
	h.rt.Picker = terminalStub{t}
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	pw := h.api.callsFor("RunInstances")[0].Get("Password")
	id := f.instances[0]["InstanceId"].(string)
	out := h.stdout.String()
	login := strings.Index(out, "Windows login of instance win-a ("+id+"):")
	if login < 0 || login < strings.Index(out, "instance/win-a") || !strings.Contains(out[login:], "password: "+pw) || !strings.Contains(out[login:], "user:     Administrator") {
		t.Errorf("stdout:\n%s", out)
	}
	if strings.Contains(h.stderr.String(), pw) {
		t.Error("the password went to stderr too")
	}
	// The table of the password command.
	if err := h.run("ecs", "instance", "password", id); err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); !strings.Contains(out, "INSTANCE") || !strings.Contains(out, "PASSWORD") || !strings.Contains(out, pw) {
		t.Errorf("password table:\n%s", out)
	}

	h, _ = winHarness(t, app.Flags{})
	h.rt.Picker = terminalStub{t}
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	pw = h.api.callsFor("RunInstances")[0].Get("Password")
	var rep map[string]any
	h.jsonOut(&rep)
	if strings.Contains(h.stdout.String(), pw) || !strings.Contains(h.stderr.String(), "password: "+pw) {
		t.Errorf("-o json: stdout %s\nstderr %s", h.stdout.String(), h.stderr.String())
	}
}

// A dry run generates no password, stores nothing and creates no data key.
func TestWindowsCreateDryRun(t *testing.T) {
	h, f := winHarness(t, app.Flags{DryRun: true})
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(f.writes) != 0 {
		t.Fatalf("dry run wrote %v", f.writes)
	}
	var rep struct {
		Changes []platform.Change `json:"changes"`
	}
	h.jsonOut(&rep)
	if len(rep.Changes) != 1 || !strings.Contains(rep.Changes[0].Detail, "login Administrator with a generated password") {
		t.Errorf("report = %+v", rep)
	}
	if strings.Contains(h.stderr.String(), "password:") || strings.Contains(h.stderr.String(), "stored encrypted") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	if n, err := h.db().CountSecrets(context.Background()); err != nil || n != 0 {
		t.Errorf("secrets = %d, %v", n, err)
	}
	dir, _ := h.rt.ConfigDir()
	if m, err := creds.NewFile(dir).Get(secrets.DataKeyName); err == nil && len(m) > 0 {
		t.Error("a dry run created the data key")
	}
}

// ensure creates a Windows instance with a stored password; run again on
// the existing instance it changes nothing and leaves the password alone.
func TestWindowsEnsure(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	args := []string{"ecs", "instance", "ensure", "win-a", "--os", "windows", "--type", "ecs.u1-c1m2.large", "--eip=false"}
	if err := h.run(args...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	pw := h.api.callsFor("RunInstances")[0].Get("Password")
	got := storedLogin(t, h, "win-a")
	if !secrets.ValidPassword(pw) || len(got) != 1 || got[0].Password != pw {
		t.Fatalf("stored %+v, sent %q", got, pw)
	}
	if !strings.Contains(h.stderr.String(), "`polyctl aliyun ecs instance password "+got[0].InstanceID+"`") || strings.Contains(h.stderr.String(), pw) {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	var out instanceEnsureReport
	h.jsonOut(&out)
	if out.Result.InstanceID != got[0].InstanceID {
		t.Errorf("result = %+v", out.Result)
	}

	writes := len(f.writes)
	h.rt.Picker = terminalStub{t}
	if err := h.run(args...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(f.writes) != writes || len(h.api.callsFor("RunInstances")) != 1 {
		t.Errorf("second ensure wrote %v", f.writes[writes:])
	}
	if again := storedLogin(t, h, "win-a"); len(again) != 1 || again[0].Password != pw {
		t.Errorf("stored after ensure = %+v", again)
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), "Windows login") {
		t.Errorf("an existing instance's login was shown:\n%s", h.stderr.String())
	}
}

// delete removes the stored credentials once the instance is deleted; a
// declined delete keeps them.
func TestWindowsDeleteForgetsTheLogin(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	id := f.instances[0]["InstanceId"].(string)
	f.instances[0]["Status"] = instStopped

	h.rt.Picker = terminalStub{t}
	h.rt.Stdin = strings.NewReader("n\n")
	if err := h.run("ecs", "instance", "delete", id); !errors.Is(err, platform.ErrNothingToDo) {
		t.Fatalf("declined delete = %v", err)
	}
	if len(storedLogin(t, h, id)) != 1 {
		t.Fatal("a declined delete removed the login")
	}
	h.rt.Picker = nil
	h.rt.Flags.Yes = true
	if err := h.run("ecs", "instance", "delete", id); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got := storedLogin(t, h, id); len(got) != 0 {
		t.Errorf("stored after delete = %+v", got)
	}
	err := h.run("ecs", "instance", "password", id)
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "reset the password in the platform's console") {
		t.Errorf("password after delete = %v", err)
	}
}

// The password command of an instance polyctl did not create is exit code
// 4 with a hint, and reads nothing from Alibaba Cloud.
func TestWindowsPasswordNotStored(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	f.addVM("i-other", "win-x", instRunning, "ecs.u1-c1m2.large", "vpc-1", "vsw-b")
	calls := len(h.api.calls)
	err := h.run("ecs", "instance", "password", "win-x")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "--os windows") {
		t.Errorf("not stored = %v", err)
	}
	if len(h.api.calls) != calls {
		t.Errorf("the password command called Alibaba Cloud %d times", len(h.api.calls)-calls)
	}
	if err := h.run("ecs", "instance", "password"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("no argument = %v", err)
	}
}

// Key pair flags are refused with --os windows, with what to do instead.
func TestWindowsCreateRefusesKeys(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	err := h.run(append(append([]string{}, winCreate...), "--key-pair", "ops")...)
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "Linux instances only") || !strings.Contains(err.Error(), "aliyun ecs instance password") {
		t.Errorf("--key-pair = %v", err)
	}
	if len(f.writes) != 0 {
		t.Errorf("wrote %v", f.writes)
	}
}

// winImageID is a Windows image only --image reaches (the English
// edition: --os windows picks the Chinese one).
const winImageID = "win2022_datacenter_en_40G.vhd"

// winImageHarness is winHarness with that image and a custom Ubuntu one.
func winImageHarness(t *testing.T, flags app.Flags) (*harness, *fakeECS) {
	t.Helper()
	h, f := winHarness(t, flags)
	en := winImg(winImageID, "acs:win_2022_datacenter_x64_en", "2026-10-01T00:00:00Z")
	en["Size"] = 40
	ubuntu := img("m-ubuntu", "", "Ubuntu 24.04 64 bit", "x86_64", "2026-11-01T00:00:00Z")
	ubuntu["ImageOwnerAlias"] = "self"
	f.images = append(f.images, en, ubuntu)
	return h, f
}

// A create of a Windows --image takes the Windows path: a generated
// password in the form body, no key pair, a 40 GiB disk, a Windows host
// name, the login stored and forgotten on delete.
func TestWindowsImageCreate(t *testing.T) {
	h, f := winImageHarness(t, app.Flags{})
	if err := h.run("ecs", "instance", "create", "web.site-number-one", "--image", winImageID, "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--no-wait"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if !slices.Equal(f.writes, []string{"RunInstances"}) || len(h.api.callsFor("DescribeKeyPairs")) != 0 {
		t.Fatalf("writes = %v, key pair reads %d", f.writes, len(h.api.callsFor("DescribeKeyPairs")))
	}
	if q := h.api.callsFor("DescribeImages"); len(q) != 1 || q[0].Get("ImageId") != winImageID || q[0].Has("ImageOwnerAlias") {
		t.Errorf("DescribeImages = %v", q)
	}
	run := h.api.callsFor("RunInstances")[0]
	pw := run.Get("Password")
	if !secrets.ValidPassword(pw) || run.Has("KeyPairName") || run.Has("PasswordInherit") || run.Get("ImageId") != winImageID ||
		run.Get("SystemDisk.Size") != "40" || run.Get("HostName") != "web-site-number" {
		t.Fatalf("RunInstances = %v", run)
	}
	for _, q := range h.api.queries {
		if strings.Contains(q, "Password") {
			t.Errorf("the password is in the URL query: %s", q)
		}
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), pw) || !strings.Contains(h.stderr.String(), "is a Windows image") {
		t.Errorf("stdout %s\nstderr %s", h.stdout.String(), h.stderr.String())
	}
	id := f.instances[0]["InstanceId"].(string)
	got := storedLogin(t, h, id)
	if len(got) != 1 || got[0].Password != pw || got[0].User != windowsUser {
		t.Fatalf("stored = %+v", got)
	}
	if !strings.Contains(h.stderr.String(), "`polyctl aliyun ecs instance password "+id+"` shows the password") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	f.instances[0]["Status"] = instStopped
	h.rt.Flags.Yes = true
	if err := h.run("ecs", "instance", "delete", id); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got := storedLogin(t, h, id); len(got) != 0 {
		t.Errorf("stored after delete = %+v", got)
	}
}

// A dry run of a Windows --image reads the image, generates and stores
// nothing.
func TestWindowsImageCreateDryRun(t *testing.T) {
	h, f := winImageHarness(t, app.Flags{DryRun: true})
	if err := h.run("ecs", "instance", "create", "win-a", "--image", winImageID, "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(f.writes) != 0 {
		t.Fatalf("dry run wrote %v", f.writes)
	}
	var rep struct {
		Changes []platform.Change `json:"changes"`
	}
	h.jsonOut(&rep)
	if len(rep.Changes) == 0 || !strings.Contains(rep.Changes[0].Detail, "login Administrator with a generated password") {
		t.Errorf("report = %+v", rep)
	}
	if n, err := h.db().CountSecrets(context.Background()); err != nil || n != 0 {
		t.Errorf("secrets = %d, %v", n, err)
	}
}

// Refused with exit code 2 and nothing created: the key pair flags with a
// Windows --image, a Linux --image without any key in the non-interactive
// flow, and a --disk smaller than the Windows image. An image that does
// not exist is exit code 4.
func TestImageDecidesTheLogin(t *testing.T) {
	h, f := winImageHarness(t, app.Flags{})
	base := []string{"ecs", "instance", "create", "site-a", "--type", "ecs.u1-c1m2.large", "--security-group", "sg-common", "--no-wait"}
	for _, extra := range [][]string{
		{"--image", winImageID, "--key-pair", "ops"},
		{"--image", winImageID, "--ssh-key", testKey(t, "ed25519"), "--key-pair", "ops"},
		{"--image", winImageID, "--disk", "30"},
		{"--image", "m-ubuntu"},
	} {
		err := h.run(append(append([]string{}, base...), extra...)...)
		if !errors.Is(err, app.ErrUsage) {
			t.Errorf("%v = %v, want a usage error", extra, err)
		}
	}
	if len(f.writes) != 0 || len(h.api.callsFor("RunInstances")) != 0 {
		t.Errorf("wrote %v", f.writes)
	}
	err := h.run(append(append([]string{}, base...), "--image", "m-nosuch")...)
	if !errors.Is(err, platform.ErrNotFound) || len(f.writes) != 0 {
		t.Errorf("missing image = %v, writes %v", err, f.writes)
	}
	// A deprecated image is never used: not found too, with a hint, and
	// the lookup asks for available images only.
	old := img("m-old", "", "Ubuntu 18.04 64 bit", "x86_64", "2020-01-01T00:00:00Z")
	old["Status"], old["ImageOwnerAlias"] = "Deprecated", "self"
	f.images = append(f.images, old)
	err = h.run(append(append([]string{}, base...), "--image", "m-old", "--key-pair", "ops")...)
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "deprecated") ||
		!strings.Contains(err.Error(), "polyctl aliyun ecs image latest") || !strings.Contains(err.Error(), "--os") || len(f.writes) != 0 {
		t.Errorf("deprecated image = %v, writes %v", err, f.writes)
	}
	if q := h.api.callsFor("DescribeImages"); q[len(q)-1].Get("Status") != "Available" {
		t.Errorf("DescribeImages Status = %q", q[len(q)-1].Get("Status"))
	}

	// A Linux --image with a key pair sends the key pair and no password.
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	if err := h.run(append(append([]string{}, base...), "--image", "m-ubuntu", "--key-pair", "ops")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	run := h.api.callsFor("RunInstances")[0]
	if run.Get("KeyPairName") != "ops" || run.Has("Password") || run.Has("PasswordInherit") || run.Has("UserData") {
		t.Errorf("RunInstances = %v", run)
	}
}

// ensure of a new instance of a Windows --image: no key pair step, a
// generated password stored.
func TestWindowsImageEnsure(t *testing.T) {
	h, f := winImageHarness(t, app.Flags{})
	if err := h.run("ecs", "instance", "ensure", "win-a", "--image", winImageID, "--type", "ecs.u1-c1m2.large", "--eip=false"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	run := h.api.callsFor("RunInstances")[0]
	pw := run.Get("Password")
	got := storedLogin(t, h, "win-a")
	if !secrets.ValidPassword(pw) || run.Has("KeyPairName") || run.Get("SystemDisk.Size") != "40" || len(got) != 1 || got[0].Password != pw {
		t.Fatalf("RunInstances %v, stored %+v", run, got)
	}
	if slices.Contains(f.writes, "ImportKeyPair") {
		t.Errorf("writes = %v", f.writes)
	}
	err := h.run("ecs", "instance", "ensure", "win-b", "--image", winImageID, "--type", "ecs.u1-c1m2.large", "--key-pair", "ops")
	if !errors.Is(err, app.ErrUsage) {
		t.Errorf("ensure --key-pair = %v", err)
	}
}

// A RunInstances whose answer is lost is asked again with the same client
// token: ECS answers the instance it created, and the login is stored.
func TestWindowsRunAnswersLost(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	f.runLost = 3 // more than the SDK retries itself
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	runs := h.api.callsFor("RunInstances")
	if len(f.instances) != 1 || len(runs) < 2 || runs[1].Get("ClientToken") != runs[0].Get("ClientToken") {
		t.Fatalf("instances %d, runs %d", len(f.instances), len(runs))
	}
	got := storedLogin(t, h, "win-a")
	if len(got) != 1 || got[0].InstanceID != f.instances[0]["InstanceId"] || got[0].Password != runs[0].Get("Password") {
		t.Errorf("stored = %+v", got)
	}
}

// When the result stays unknown, the generated password is stored under
// the instance name and the password command shows it.
func TestWindowsRunResultUnknown(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	f.runLost = 100
	err := h.run(winCreate...)
	if err == nil || !strings.Contains(err.Error(), "result is unknown, the instance may already exist") {
		t.Fatalf("unknown = %v", err)
	}
	pw := h.api.callsFor("RunInstances")[0].Get("Password")
	got := storedLogin(t, h, "win-a")
	if len(got) != 1 || got[0].Password != pw || !strings.HasPrefix(got[0].InstanceID, pendingInstancePrefix) {
		t.Fatalf("stored = %+v", got)
	}
	if strings.Contains(h.stderr.String(), pw) {
		t.Errorf("the password was printed: %s", h.stderr.String())
	}
	if err := h.run("ecs", "instance", "password", "win-a"); err != nil {
		t.Fatal(err)
	}
	var login map[string]any
	h.jsonOut(&login)
	if login["password"] != pw {
		t.Errorf("login = %v", login)
	}
}

// A run cancelled while RunInstances was in flight (an unknown result)
// still stores the generated password.
func TestWindowsPendingCancelled(t *testing.T) {
	h, _ := winHarness(t, app.Flags{})
	w := newWindowsLogin(h.rt, &ecsScope{c: h.api.client(), profile: "ali", region: "cn-shanghai"}, "win-a")
	if _, err := w.generate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.pending(ctx, "token-1")
	if got := storedLogin(t, h, "win-a"); len(got) != 1 || got[0].Password == "" || got[0].InstanceID != pendingInstancePrefix+"token-1" {
		t.Errorf("stored = %+v\n%s", got, h.stderr.String())
	}
}

// A create of the name that succeeds after an uncertain one drops the
// password stored for the uncertain one: it created nothing that lasted.
func TestWindowsPendingDroppedByCreate(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	f.runLost = 100
	if err := h.run(winCreate...); err == nil {
		t.Fatal("unknown result succeeded")
	}
	f.runLost = 0
	f.instances = nil // nothing lasted
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got := storedLogin(t, h, "win-a"); len(got) != 1 || strings.HasPrefix(got[0].InstanceID, pendingInstancePrefix) {
		t.Errorf("stored = %+v", got)
	}
}

// The request asked again under a new token (the first answered a deleted
// instance) keeps the password too when its result stays unknown.
func TestWindowsRunNewTokenResultUnknown(t *testing.T) {
	h, f := winHarness(t, app.Flags{})
	f.runGhost, f.runLost = 1, 100
	err := h.run(winCreate...)
	if err == nil || !strings.Contains(err.Error(), "result is unknown, the instance may already exist") {
		t.Fatalf("unknown = %v", err)
	}
	if got := storedLogin(t, h, "win-a"); len(got) != 1 || !strings.HasPrefix(got[0].InstanceID, pendingInstancePrefix) || got[0].Password == "" {
		t.Errorf("stored = %+v", got)
	}
}
