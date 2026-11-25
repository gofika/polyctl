package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

const winPassword = "Kp7-tes7Password:abc"

func winCreds() secrets.Credentials {
	return secrets.Credentials{Ref: secrets.Ref{Platform: platform.NameCom, Profile: "a", Location: "r1", InstanceID: "i-1"},
		Name: "win-1", User: "Administrator", Password: winPassword}
}

const tree = "fake compute instance"

func TestSaveCredentialsInteractiveTable(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a"}, nil)
	h.rt.Picker = &terminalStub{}
	if err := h.rt.SaveCredentials(ctx, winCreds(), tree, nil); err != nil {
		t.Fatal(err)
	}
	out := h.stdout.String()
	for _, want := range []string{"Windows login of instance win-1 (i-1):", "user:     Administrator", "password: " + winPassword,
		"`polyctl fake compute instance password i-1` shows it again"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(h.stderr.String(), winPassword) {
		t.Error("the password went to stderr too")
	}
	st, _ := h.rt.Secrets()
	got, err := st.Get(ctx, winCreds().Ref)
	if err != nil || got.Password != winPassword {
		t.Fatalf("stored = %+v, %v", got, err)
	}
	// The data key is in the credential store (the file backend here),
	// and the password is nowhere in plain text on disk.
	if m, err := creds.NewFile(h.dir).Get(secrets.DataKeyName); err != nil || m["key"] == "" {
		t.Errorf("data key = %v, %v", m, err)
	}
	assertNoPlaintext(t, h.dir, winPassword)
}

// An instance name holding terminal escapes (a Name tag anyone allowed to
// tag the instance may set) is printed escaped above the password.
func TestSaveCredentialsEscapesName(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a"}, nil)
	h.rt.Picker = &terminalStub{}
	c := winCreds()
	c.Name = "win-1\r\x1b[2Kprod-db"
	if err := h.rt.SaveCredentials(ctx, c, tree, nil); err != nil {
		t.Fatal(err)
	}
	out := h.stdout.String()
	if strings.ContainsAny(out, "\r\x1b") || !strings.Contains(out, `Windows login of instance win-1\x0d\x1b[2Kprod-db (i-1):`) {
		t.Errorf("stdout %q", out)
	}
}

func TestSaveCredentialsInteractiveJSONUsesStderr(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a", Output: "json"}, nil)
	h.rt.Picker = &terminalStub{}
	if err := h.rt.SaveCredentials(ctx, winCreds(), tree, nil); err != nil {
		t.Fatal(err)
	}
	if h.stdout.Len() != 0 {
		t.Errorf("stdout must stay one JSON document: %q", h.stdout.String())
	}
	if !strings.Contains(h.stderr.String(), "password: "+winPassword) {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

func TestSaveCredentialsNonInteractive(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a"}, nil)
	if err := h.rt.SaveCredentials(ctx, winCreds(), tree, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), winPassword) {
		t.Fatalf("the non-interactive flow printed the password:\n%s%s", h.stdout.String(), h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "`polyctl fake compute instance password i-1` shows the password") ||
		!strings.Contains(h.stderr.String(), "user Administrator") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	if h.stdout.Len() != 0 {
		t.Errorf("stdout = %q", h.stdout.String())
	}
	// A password not known yet (AWS) is a note in both flows.
	h.stderr.Reset()
	c := winCreds()
	c.Password = ""
	h.rt.ShowCredentials(c, tree)
	if !strings.Contains(h.stderr.String(), "not available yet") {
		t.Errorf("pending = %q", h.stderr.String())
	}
}

func TestDryRunStoresAndShowsNothing(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a", DryRun: true}, nil)
	h.rt.Picker = &terminalStub{}
	if err := h.rt.PrepareSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := h.rt.SaveCredentials(ctx, winCreds(), tree, nil); err != nil {
		t.Fatal(err)
	}
	h.rt.ShowCredentials(winCreds(), tree)
	h.rt.ForgetCredentials(ctx, winCreds().Ref)
	if h.stdout.Len()+h.stderr.Len() != 0 {
		t.Errorf("output: %q %q", h.stdout.String(), h.stderr.String())
	}
	if _, err := creds.NewFile(h.dir).Get(secrets.DataKeyName); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("a dry run created the data key: %v", err)
	}
	db := h.db()
	if n, _ := db.CountSecrets(ctx); n != 0 {
		t.Errorf("a dry run stored %d secrets", n)
	}
}

func TestPrepareSecretsCreatesTheKeyOnce(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a"}, nil)
	if err := h.rt.PrepareSecrets(); err != nil {
		t.Fatal(err)
	}
	first, err := creds.NewFile(h.dir).Get(secrets.DataKeyName)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.rt.PrepareSecrets(); err != nil {
		t.Fatal(err)
	}
	second, _ := creds.NewFile(h.dir).Get(secrets.DataKeyName)
	if first["key"] != second["key"] {
		t.Error("the data key changed")
	}
}

func TestSaveCredentialsFailure(t *testing.T) {
	// A data key entry that is not a key: nothing can be sealed.
	h := newHarness(t, app.Flags{Profile: "a"}, nil)
	if err := creds.NewFile(h.dir).Set(secrets.DataKeyName, map[string]string{"key": "broken"}); err != nil {
		t.Fatal(err)
	}
	err := h.rt.SaveCredentials(ctx, winCreds(), tree, nil)
	if err == nil || strings.Contains(err.Error(), winPassword) || !strings.Contains(err.Error(), "could not be stored") ||
		!strings.Contains(err.Error(), "reset the password in the platform's console") {
		t.Fatalf("non-interactive = %v", err)
	}
	// A platform's hint replaces the console advice, given the instance id.
	hint := func(ref string) string { return "`polyctl " + tree + " password " + ref + " --reset` sets a new one" }
	err = h.rt.SaveCredentials(ctx, winCreds(), tree, hint)
	if err == nil || !strings.Contains(err.Error(), "could not be stored") || !strings.Contains(err.Error(), "password i-1 --reset` sets a new one") ||
		strings.Contains(err.Error(), "console") {
		t.Fatalf("with a hint = %v", err)
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), winPassword) {
		t.Error("the password was printed")
	}
	// The interactive flow shows it once rather than lose it.
	h2 := newHarness(t, app.Flags{Profile: "a"}, nil)
	if err := creds.NewFile(h2.dir).Set(secrets.DataKeyName, map[string]string{"key": "broken"}); err != nil {
		t.Fatal(err)
	}
	h2.rt.Picker = &terminalStub{}
	if err := h2.rt.SaveCredentials(ctx, winCreds(), tree, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h2.stdout.String(), "password: "+winPassword) || !strings.Contains(h2.stderr.String(), "could not be stored") ||
		strings.Contains(h2.stdout.String(), "shows it again") {
		t.Errorf("stdout %q stderr %q", h2.stdout.String(), h2.stderr.String())
	}
}

// passwordCmd runs the password command of pc under a root command, the
// way a platform tree mounts it.
func passwordCmd(t *testing.T, h *harness, pc app.PasswordCommand, args ...string) error {
	t.Helper()
	root := &cobra.Command{Use: "polyctl", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(app.InstancePasswordCommand(h.rt, pc))
	root.SetArgs(append([]string{"password"}, args...))
	root.SetOut(h.stdout)
	root.SetErr(h.stderr)
	return root.ExecuteContext(context.Background())
}

func TestPasswordCommand(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a"}, nil)
	if err := h.rt.SaveCredentials(ctx, winCreds(), tree, nil); err != nil {
		t.Fatal(err)
	}
	pc := app.PasswordCommand{Platform: platform.NameCom, Tree: tree, LocationFlag: "region"}
	for _, arg := range []string{"win-1", "i-1"} {
		h.stdout.Reset()
		if err := passwordCmd(t, h, pc, arg); err != nil {
			t.Fatalf("%s: %v", arg, err)
		}
		lines := strings.Split(strings.TrimSpace(h.stdout.String()), "\n")
		if len(lines) != 2 || strings.Join(strings.Fields(lines[0]), " ") != "INSTANCE USER PASSWORD" ||
			strings.Join(strings.Fields(lines[1]), " ") != "win-1 (i-1) Administrator "+winPassword {
			t.Errorf("%s: table = %q", arg, h.stdout.String())
		}
	}
	// -o json.
	hj := newHarnessIn(t, h.dir, app.Flags{Profile: "a", Output: "json"})
	if err := passwordCmd(t, hj, pc, "win-1"); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(hj.stdout.Bytes(), &v); err != nil {
		t.Fatalf("%v: %s", err, hj.stdout.String())
	}
	if v["instance"] != "win-1" || v["user"] != "Administrator" || v["password"] != winPassword || v["id"] != "i-1" || v["location"] != "r1" {
		t.Errorf("json = %v", v)
	}
	if _, ok := v["private_key"]; ok {
		t.Error("the private key is part of the output")
	}
	// Another location narrows it away: not found.
	if err := passwordCmd(t, h, pc, "win-1", "--region", "r2"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("other region = %v", err)
	}
	// Nothing stored: not found, with a hint.
	err := passwordCmd(t, h, pc, "nosuch")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "--os windows") {
		t.Errorf("missing = %v", err)
	}
	// No argument: usage error.
	if err := passwordCmd(t, h, pc); !errors.Is(err, app.ErrUsage) {
		t.Errorf("no argument = %v", err)
	}
	// A name stored twice is ambiguous; the id is not.
	c2 := winCreds()
	c2.Location, c2.InstanceID = "r2", "i-2"
	if err := h.rt.SaveCredentials(ctx, c2, tree, nil); err != nil {
		t.Fatal(err)
	}
	var amb *app.AmbiguousError
	if err := passwordCmd(t, h, pc, "win-1"); !errors.As(err, &amb) || len(amb.Candidates) != 2 || !strings.Contains(amb.Hint, "--region") {
		t.Errorf("duplicate name = %v", err)
	}
	if err := passwordCmd(t, h, pc, "i-2"); err != nil {
		t.Errorf("by id = %v", err)
	}
	if err := passwordCmd(t, h, pc, "win-1", "--region", "r2"); err != nil {
		t.Errorf("by name and region = %v", err)
	}
	// After the delete the credentials are gone.
	h.rt.ForgetCredentials(ctx, c2.Ref)
	if err := passwordCmd(t, h, pc, "i-2"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("after delete = %v", err)
	}
}

func TestPasswordCommandLostKey(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a"}, nil)
	if err := h.rt.SaveCredentials(ctx, winCreds(), tree, nil); err != nil {
		t.Fatal(err)
	}
	if err := creds.NewFile(h.dir).Delete(secrets.DataKeyName); err != nil {
		t.Fatal(err)
	}
	h2 := newHarnessIn(t, h.dir, app.Flags{Profile: "a"})
	err := passwordCmd(t, h2, app.PasswordCommand{Platform: platform.NameCom, Tree: tree}, "win-1")
	if !errors.Is(err, secrets.ErrKeyLost) || errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("lost key = %v", err)
	}
	if _, err := creds.NewFile(h.dir).Get(secrets.DataKeyName); !errors.Is(err, creds.ErrNotFound) {
		t.Error("a read created a new data key")
	}
}

func TestPasswordCommandRetrieve(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a"}, nil)
	pending := winCreds()
	pending.Password = ""
	pending.PrivateKey = "PEM"
	if err := h.rt.SaveCredentials(ctx, pending, tree, nil); err != nil {
		t.Fatal(err)
	}
	calls := 0
	pc := app.PasswordCommand{Platform: platform.NameCom, Tree: tree,
		Retrieve: func(_ context.Context, profile, location, instance string, stored *secrets.Credentials) (*secrets.Credentials, error) {
			calls++
			if stored == nil {
				return nil, platform.ErrNotFound
			}
			if stored.PrivateKey != "PEM" || profile != "a" {
				t.Errorf("stored = %+v, profile %s", stored, profile)
			}
			c := *stored
			c.Password = winPassword
			return &c, nil
		}}
	// --offline never asks the platform.
	h.rt.Flags.Offline = true
	if err := passwordCmd(t, h, pc, "win-1"); !errors.Is(err, platform.ErrNotFound) || calls != 0 {
		t.Fatalf("offline = %v (%d calls)", err, calls)
	}
	h.rt.Flags.Offline = false
	if err := passwordCmd(t, h, pc, "win-1"); err != nil || calls != 1 || !strings.Contains(h.stdout.String(), winPassword) {
		t.Fatalf("retrieve = %v (%d calls) %q", err, calls, h.stdout.String())
	}
	// It was stored: the next run does not ask again.
	if err := passwordCmd(t, h, pc, "win-1"); err != nil || calls != 1 {
		t.Fatalf("second run = %v (%d calls)", err, calls)
	}
	if err := passwordCmd(t, h, pc, "nosuch"); !errors.Is(err, platform.ErrNotFound) || calls != 2 {
		t.Errorf("unknown instance = %v (%d calls)", err, calls)
	}
	// An explanation of Retrieve is the error of the command.
	pc.Retrieve = func(context.Context, string, string, string, *secrets.Credentials) (*secrets.Credentials, error) {
		return nil, fmt.Errorf("%w: pass --key-file", platform.ErrNotFound)
	}
	if err := passwordCmd(t, h, pc, "other"); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "pass --key-file") {
		t.Errorf("explained = %v", err)
	}
}

// newHarnessIn opens a second runtime on the config directory of another
// harness (another polyctl process).
func newHarnessIn(t *testing.T, dir string, flags app.Flags) *harness {
	t.Helper()
	flags.ConfigDir = dir
	h := &harness{t: t, dir: dir, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	h.rt = app.New(flags, strings.NewReader(""), h.stdout, h.stderr)
	if err := h.rt.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.rt.Close() })
	return h
}

// assertNoPlaintext fails when any file of dir holds secret.
func assertNoPlaintext(t *testing.T, dir, secret string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
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
