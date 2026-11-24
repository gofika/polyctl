package aws

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

const winPassword = "Wq7.x@Kd2#pLm9-zRt4"

var winCreate = []string{"ec2", "instance", "create", "win-a", "--os", "windows", "--type", "t3.large"}

// winHarness is an instance harness whose regions publish Windows Server
// images and whose Windows instances generate winPassword, ready on the
// third GetPasswordData.
func winHarness(t *testing.T, flags app.Flags) *awsHarness {
	t.Helper()
	h := newInstanceHarness(t, flags)
	addWindowsFixtures(h)
	return h
}

// addWindowsFixtures publishes the Windows Server images and parameters
// and makes Windows instances generate winPassword.
func addWindowsFixtures(h *awsHarness) {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	fi := &h.ec2.inst
	fi.init()
	win := func(id, name, created string) ec2types.Image {
		return ec2types.Image{ImageId: awssdk.String(id), Name: awssdk.String(name), Architecture: "x86_64", Platform: ec2types.PlatformValuesWindows,
			RootDeviceName: awssdk.String("/dev/sda1"), CreationDate: awssdk.String(created)}
	}
	for _, r := range []string{"ap-east-1", "us-west-2"} {
		fi.images[r] = append(fi.images[r],
			win("ami-0win2019", "Windows_Server-2019-English-Full-Base-2026.11.12", "2026-11-12T00:00:00.000Z"),
			win("ami-0win2022", "Windows_Server-2022-English-Full-Base-2026.11.12", "2026-11-12T00:00:00.000Z"),
			win("ami-0win2025old", "Windows_Server-2025-English-Full-Base-2026.10.08", "2026-10-08T00:00:00.000Z"),
			win("ami-0win2025", "Windows_Server-2025-English-Full-Base-2026.11.12", "2026-11-12T00:00:00.000Z"),
			win("ami-0win2025jp", "Windows_Server-2025-Japanese-Full-Base-2026.11.12", "2026-11-12T00:00:00.000Z"),
		)
	}
	for k, v := range map[string]string{
		"Windows_Server-2016-English-Full-Base":              "ami-0win2016",
		"Windows_Server-2022-English-Full-Base":              "ami-0win2022",
		"Windows_Server-2025-English-Full-Base":              "ami-0win2025",
		"Windows_Server-2025-Japanese-Full-Base":             "ami-0win2025jp",
		"Windows_Server-2030-English-Core-Base":              "ami-0core",
		"Windows_Server-2019-English-Full-SQL_2022_Standard": "ami-0sql",
		"EC2LaunchV2-Windows_Server-2019-English-Full-Base":  "ami-0launch",
	} {
		fi.ssmValue[windowsParamPath+k] = v
	}
	fi.ssmValue[windowsParamPath+"nested/Windows_Server-2040-English-Full-Base"] = "ami-0nested"
	fi.winPassword, fi.pwDelay = winPassword, 2
}

// exit2 reports an error of exit code 2.
func exit2(err error) bool {
	return errors.Is(err, app.ErrUsage) || errors.Is(err, platform.ErrInvalidInput)
}

// storedWin returns the credentials stored for ref.
func storedWin(t *testing.T, h *awsHarness, ref string) []secrets.Credentials {
	t.Helper()
	st, err := h.rt.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Find(context.Background(), platform.AWS, "lab", "", ref)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// assertNotInFiles checks that no file of the configuration directory
// holds secret.
func assertNotInFiles(t *testing.T, h *awsHarness, secret string) {
	t.Helper()
	err := filepath.WalkDir(h.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(b), secret) {
			t.Errorf("%s holds a secret in plain text", filepath.Base(p))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// keyBody is a line from the middle of a PEM key: a piece of secret
// material that must appear nowhere.
func keyBody(pemText string) string {
	lines := strings.Split(strings.TrimSpace(pemText), "\n")
	return lines[len(lines)/2]
}

func (h *awsHarness) runs() []string {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	var out []string
	for _, r := range h.ec2.inst.runs {
		out = append(out, awssdk.ToString(r.ImageId)+" key="+awssdk.ToString(r.KeyName))
	}
	return out
}

// A non-interactive Windows create makes an RSA key pair, launches with it,
// waits for the password, decrypts it and stores it encrypted with the
// private key; it prints neither, only a note naming the password command.
func TestWindowsCreateNonInteractive(t *testing.T) {
	h := winHarness(t, app.Flags{})
	clk := instanceClock.(*fakeClock)
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got := h.runs(); len(got) != 1 || got[0] != "ami-0win2025 key=win-a-win" {
		t.Fatalf("runs = %v", got)
	}
	if len(h.ec2.creates) != 1 || awssdk.ToString(h.ec2.creates[0].KeyName) != "win-a-win" {
		t.Fatalf("CreateKeyPair = %+v", h.ec2.creates)
	}
	if w := h.writes(); strings.Join(w, ",") != "CreateKeyPair,RunInstances" {
		t.Errorf("writes = %v", w)
	}
	got := storedWin(t, h, "win-a")
	if len(got) != 1 {
		t.Fatalf("stored = %+v", got)
	}
	c := got[0]
	id := c.InstanceID
	if c.User != "Administrator" || c.Password != winPassword || c.KeyPair != "win-a-win" || c.Location != "ap-east-1" || !strings.Contains(c.PrivateKey, "PRIVATE KEY") {
		t.Fatalf("stored = %+v", c)
	}
	out := h.stdout.String() + h.stderr.String()
	if strings.Contains(out, winPassword) || strings.Contains(out, keyBody(c.PrivateKey)) || strings.Contains(out, "PRIVATE KEY") {
		t.Errorf("a secret was printed:\n%s", out)
	}
	note := "user Administrator; `polyctl aws ec2 instance password " + id + "` shows the password"
	if !strings.Contains(h.stderr.String(), note) {
		t.Errorf("stderr lacks %q:\n%s", note, h.stderr.String())
	}
	rep := h.report()
	if len(rep.Changes) != 2 || rep.Changes[0].Resource != "key-pair/win-a-win" || rep.Changes[0].Action != platform.Created ||
		rep.Changes[1].ID != id || !strings.Contains(rep.Changes[1].Detail, "Windows password retrieved") || !strings.Contains(rep.Changes[1].Detail, "login=Administrator") {
		t.Errorf("report = %+v", rep.Changes)
	}
	// The password was polled every 15 seconds until it was generated.
	if n := h.ec2.inst.pwCalls[id]; n != 3 {
		t.Errorf("GetPasswordData calls = %d", n)
	}
	polls := 0
	for _, d := range clk.slept {
		if d == passwordPollInterval {
			polls++
		}
	}
	if polls != 2 {
		t.Errorf("slept %v", clk.slept)
	}
	assertNotInFiles(t, h, winPassword)
	assertNotInFiles(t, h, keyBody(c.PrivateKey))

	// The password command shows it, by name or by id with --region,
	// without asking AWS.
	calls := h.ec2.count("GetPasswordData")
	for _, args := range [][]string{{"win-a"}, {id, "--region", "ap-east-1"}} {
		if err := h.run(append([]string{"ec2", "instance", "password"}, args...)...); err != nil {
			t.Fatalf("password %v: %v", args, err)
		}
		var login map[string]any
		h.jsonOut(&login)
		if login["instance"] != "win-a" || login["id"] != id || login["user"] != "Administrator" || login["password"] != winPassword || login["platform"] != "aws" || login["location"] != "ap-east-1" {
			t.Errorf("password %v = %v", args, login)
		}
		if _, ok := login["private_key"]; ok {
			t.Error("the private key is in the output")
		}
	}
	if h.ec2.count("GetPasswordData") != calls {
		t.Error("the password command asked AWS for a stored password")
	}
}

// An interactive create prints the login at the end: on stdout after the
// table report, on stderr with -o json.
func TestWindowsCreateInteractive(t *testing.T) {
	h := winHarness(t, app.Flags{Output: "table", NonInteractiveSet: true})
	h.rt.Picker = &scriptedPicker{t: t}
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	id := storedWin(t, h, "win-a")[0].InstanceID
	out := h.stdout.String()
	login := strings.Index(out, "Windows login of instance win-a ("+id+"):")
	if login < 0 || login < strings.Index(out, "instance/win-a") || !strings.Contains(out[login:], "password: "+winPassword) || !strings.Contains(out[login:], "user:     Administrator") {
		t.Errorf("stdout:\n%s", out)
	}
	if strings.Contains(h.stderr.String(), winPassword) || strings.Contains(out, "PRIVATE KEY") {
		t.Errorf("stderr:\n%s", h.stderr.String())
	}
	// The table of the password command.
	if err := h.run("ec2", "instance", "password", id); err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); !strings.Contains(out, "INSTANCE") || !strings.Contains(out, "USER") || !strings.Contains(out, winPassword) {
		t.Errorf("password table:\n%s", out)
	}

	h = winHarness(t, app.Flags{NonInteractiveSet: true})
	h.rt.Picker = &scriptedPicker{t: t}
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	h.report()
	if strings.Contains(h.stdout.String(), winPassword) || !strings.Contains(h.stderr.String(), "password: "+winPassword) {
		t.Errorf("-o json: stdout %s\nstderr %s", h.stdout.String(), h.stderr.String())
	}
}

// A dry run resolves the image and the key pair name, creates and stores
// nothing and creates no data key.
func TestWindowsCreateDryRun(t *testing.T) {
	h := winHarness(t, app.Flags{DryRun: true})
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if w := h.writes(); len(w) != 0 || h.ec2.count("GetPasswordData") != 0 {
		t.Fatalf("dry run wrote %v", w)
	}
	rep := h.report()
	if len(rep.Changes) != 2 || rep.Changes[0].Resource != "key-pair/win-a-win" || rep.Changes[0].Action != platform.WouldCreate ||
		!strings.Contains(rep.Changes[1].Detail, "ami=ami-0win2025") || !strings.Contains(rep.Changes[1].Detail, "key-pair=win-a-win") {
		t.Errorf("report = %+v", rep.Changes)
	}
	if s := h.stderr.String(); strings.Contains(s, "password:") || strings.Contains(s, "stored encrypted") {
		t.Errorf("stderr = %s", s)
	}
	db, err := h.rt.DB()
	if err != nil {
		t.Fatal(err)
	}
	if n, err := db.CountSecrets(context.Background()); err != nil || n != 0 {
		t.Errorf("secrets = %d, %v", n, err)
	}
	if m, err := creds.NewFile(h.dir).Get(secrets.DataKeyName); err == nil && len(m) > 0 {
		t.Error("a dry run created the data key")
	}
}

// A password that is not generated within --password-timeout leaves the
// create successful with a note; the password command fetches it later
// with the stored private key, and stores it.
func TestWindowsPasswordLater(t *testing.T) {
	h := winHarness(t, app.Flags{})
	h.ec2.inst.pwDelay = 1000
	if err := h.run(append(winCreate, "--password-timeout", "1m")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	c := storedWin(t, h, "win-a")[0]
	if c.Password != "" || c.PrivateKey == "" || c.KeyPair != "win-a-win" {
		t.Fatalf("stored = %+v", c)
	}
	if s := h.stderr.String(); !strings.Contains(s, "was not generated within 1m0s") || !strings.Contains(s, "not available yet; `polyctl aws ec2 instance password "+c.InstanceID+"`") {
		t.Errorf("stderr = %s", s)
	}
	if rep := h.report(); !strings.Contains(rep.Changes[1].Detail, "Windows password not available yet") {
		t.Errorf("report = %+v", rep.Changes)
	}

	// Still not generated: exit code 4, nothing stored.
	err := h.run("ec2", "instance", "password", "win-a")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "try again in a few minutes") {
		t.Fatalf("not generated = %v", err)
	}
	// --offline never asks AWS.
	h.rt.Flags.Offline = true
	calls := h.ec2.count("GetPasswordData")
	if err := h.run("ec2", "instance", "password", "win-a"); !errors.Is(err, platform.ErrNotFound) || h.ec2.count("GetPasswordData") != calls {
		t.Fatalf("offline = %v", err)
	}
	h.rt.Flags.Offline = false

	h.ec2.inst.pwDelay = 0
	if err := h.run("ec2", "instance", "password", "win-a"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	var login map[string]any
	h.jsonOut(&login)
	if login["password"] != winPassword || login["user"] != "Administrator" {
		t.Errorf("login = %v", login)
	}
	if again := storedWin(t, h, "win-a")[0]; again.Password != winPassword || again.PrivateKey != c.PrivateKey || again.KeyPair != "win-a-win" {
		t.Errorf("stored after retrieve = %+v", again)
	}
	calls = h.ec2.count("GetPasswordData")
	if err := h.run("ec2", "instance", "password", "win-a"); err != nil || h.ec2.count("GetPasswordData") != calls {
		t.Errorf("second read = %v", err)
	}
}

// --no-wait waits for neither the instance nor the password.
func TestWindowsCreateNoWait(t *testing.T) {
	h := winHarness(t, app.Flags{})
	if err := h.run(append(winCreate, "--no-wait")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if h.ec2.count("GetPasswordData") != 0 {
		t.Error("--no-wait asked for the password")
	}
	c := storedWin(t, h, "win-a")[0]
	if c.Password != "" || c.PrivateKey == "" {
		t.Errorf("stored = %+v", c)
	}
	if !strings.Contains(h.stderr.String(), "not available yet") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
}

// writeRSAKey writes an RSA private key file in PKCS #1 PEM and returns
// its path and key.
func writeRSAKey(t *testing.T, dir string) (string, *rsa.PrivateKey) {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ops-rsa.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, rk
}

// --key-file uses the key pair that holds its public key and never stores
// the private key; delete leaves that key pair alone.
func TestWindowsCreateWithKeyFile(t *testing.T) {
	h := winHarness(t, app.Flags{})
	path, rk := writeRSAKey(t, t.TempDir())
	pub, err := ssh.NewPublicKey(&rk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	h.add("ap-east-1", newFakeKeyPair("ops-rsa", pub))
	if err := h.run(append(winCreate, "--key-file", path)...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got := h.runs(); len(got) != 1 || got[0] != "ami-0win2025 key=ops-rsa" {
		t.Fatalf("runs = %v", got)
	}
	if w := h.writes(); strings.Join(w, ",") != "RunInstances" {
		t.Errorf("writes = %v", w)
	}
	c := storedWin(t, h, "win-a")[0]
	if c.Password != winPassword || c.PrivateKey != "" || c.KeyPair != "" {
		t.Fatalf("stored = %+v", c)
	}
	raw, _ := os.ReadFile(path)
	assertNotInFiles(t, h, keyBody(string(raw)))

	h.rt.Flags.Yes = true
	if err := h.run("ec2", "instance", "delete", "win-a"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if h.ec2.count("DeleteKeyPair") != 0 || len(h.pairs("ap-east-1")) != 2 {
		t.Errorf("a key pair of the user's was deleted: %v", h.ec2.deletedKeyPairs)
	}
	if len(storedWin(t, h, c.InstanceID)) != 0 {
		t.Error("the login survived the delete")
	}

	// A key no key pair holds is imported under --key-pair; the password
	// is fetched later with --key-file only.
	h = winHarness(t, app.Flags{})
	h.ec2.inst.pwDelay = 1000
	path, _ = writeRSAKey(t, t.TempDir())
	if err := h.run(append(winCreate, "--key-file", path, "--key-pair", "laptop", "--no-wait")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if w := h.writes(); strings.Join(w, ",") != "ImportKeyPair,RunInstances" {
		t.Errorf("writes = %v", w)
	}
	if !strings.Contains(h.stderr.String(), "pass it to `polyctl aws ec2 instance password ") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	h.ec2.inst.pwDelay = 0
	err = h.run("ec2", "instance", "password", "win-a")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "--key-file") {
		t.Fatalf("without --key-file = %v", err)
	}
	if err := h.run("ec2", "instance", "password", "win-a", "--key-file", path); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	var login map[string]any
	h.jsonOut(&login)
	if login["password"] != winPassword {
		t.Errorf("login = %v", login)
	}
	// Another key does not decrypt it: a general failure.
	other, _ := writeRSAKey(t, t.TempDir())
	h2 := winHarness(t, app.Flags{})
	h2.ec2.inst.pwDelay = 1000
	if err := h2.run(append(winCreate, "--key-file", path, "--key-pair", "laptop", "--no-wait")...); err != nil {
		t.Fatal(err)
	}
	h2.ec2.inst.pwDelay = 0
	err = h2.run("ec2", "instance", "password", "win-a", "--key-file", other)
	if err == nil || errors.Is(err, platform.ErrNotFound) || exit2(err) || !strings.Contains(err.Error(), "does not decrypt") {
		t.Errorf("wrong key = %v", err)
	}
}

// The password command of an instance polyctl did not create.
func TestWindowsPasswordForeignInstance(t *testing.T) {
	h := winHarness(t, app.Flags{})
	path, rk := writeRSAKey(t, t.TempDir())
	pub, _ := ssh.NewPublicKey(&rk.PublicKey)
	h.add("ap-east-1", newFakeKeyPair("ops-rsa", pub))
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa1", name: "old-win", typ: "t3.large", state: stateRunning, platform: "windows", keyName: "ops-rsa"})
	h.addInstance("ap-east-1", &fakeInstance{id: "i-0aaaaaaaaaaaaaaa2", name: "web", typ: "t3.large", state: stateRunning, keyName: "ops-rsa"})

	err := h.run("ec2", "instance", "password", "old-win")
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "--key-file") || h.ec2.count("DescribeInstances") != 0 {
		t.Fatalf("nothing stored = %v", err)
	}
	h.ec2.inst.pwDelay = 0
	if err := h.run("ec2", "instance", "password", "old-win", "--key-file", path); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	var login map[string]any
	h.jsonOut(&login)
	if login["password"] != winPassword || login["id"] != "i-0aaaaaaaaaaaaaaa1" || login["instance"] != "old-win" {
		t.Errorf("login = %v", login)
	}
	if c := storedWin(t, h, "old-win"); len(c) != 1 || c[0].Password != winPassword || c[0].PrivateKey != "" {
		t.Errorf("stored = %+v", c)
	}
	err = h.run("ec2", "instance", "password", "web", "--key-file", path)
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "not a Windows instance") {
		t.Errorf("linux = %v", err)
	}
	if err := h.run("ec2", "instance", "password", "old-win", "--key-file", filepath.Join(h.dir, "nosuch.pem")); err != nil {
		// Stored by now: --key-file is not read.
		t.Errorf("stored login with a bad --key-file = %v", err)
	}
}

// delete removes the stored login and the key pair polyctl created; a
// dry run shows both and changes nothing.
func TestWindowsDeleteRemovesLoginAndKeyPair(t *testing.T) {
	h := winHarness(t, app.Flags{})
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	id := storedWin(t, h, "win-a")[0].InstanceID

	h.rt.Flags.DryRun = true
	if err := h.run("ec2", "instance", "delete", "win-a"); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if len(rep.Changes) != 2 || rep.Changes[1].Resource != "key-pair/win-a-win" || rep.Changes[1].Action != platform.WouldDelete {
		t.Errorf("dry run = %+v", rep.Changes)
	}
	if len(storedWin(t, h, id)) != 1 || h.ec2.count("DeleteKeyPair") != 0 || h.ec2.count("TerminateInstances") != 0 {
		t.Fatal("the dry run changed something")
	}
	h.rt.Flags.DryRun = false

	// A declined confirmation keeps everything.
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = &scriptedPicker{t: t, answers: []string{"no"}}
	if err := h.run("ec2", "instance", "delete", "win-a"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Fatalf("declined = %v", err)
	}
	if len(storedWin(t, h, id)) != 1 || h.ec2.count("DeleteKeyPair") != 0 {
		t.Fatal("a declined delete removed the login")
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true

	h.rt.Flags.Yes = true
	if err := h.run("ec2", "instance", "delete", "win-a"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(storedWin(t, h, id)) != 0 {
		t.Error("the login survived the delete")
	}
	if strings.Join(h.ec2.deletedKeyPairs, ",") != "win-a-win" {
		t.Errorf("deleted key pairs = %v", h.ec2.deletedKeyPairs)
	}
	for _, kp := range h.pairs("ap-east-1") {
		if kp.name == "win-a-win" {
			t.Error("the key pair is still there")
		}
	}
	rep = h.report()
	if len(rep.Changes) != 2 || rep.Changes[1].Resource != "key-pair/win-a-win" || rep.Changes[1].Action != platform.Deleted {
		t.Errorf("report = %+v", rep.Changes)
	}
	err := h.run("ec2", "instance", "password", id)
	if !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("password after delete = %v", err)
	}
}

// A key pair recorded for an instance that no longer uses it is not
// deleted.
func TestWindowsDeleteKeepsAKeyPairTheInstanceDoesNotUse(t *testing.T) {
	h := winHarness(t, app.Flags{Yes: true})
	if err := h.run(winCreate...); err != nil {
		t.Fatal(err)
	}
	id := storedWin(t, h, "win-a")[0].InstanceID
	h.ec2.mu.Lock()
	h.ec2.inst.find("ap-east-1", id).keyName = "someone-else"
	h.ec2.mu.Unlock()
	if err := h.run("ec2", "instance", "delete", id); err != nil {
		t.Fatal(err)
	}
	if h.ec2.count("DeleteKeyPair") != 0 || len(storedWin(t, h, id)) != 0 {
		t.Errorf("deleted %v", h.ec2.deletedKeyPairs)
	}
}

// The key flags that cannot serve Windows, unusable types and keys, and a
// key pair name that is taken are usage errors before anything is
// written.
func TestWindowsCreateRefusals(t *testing.T) {
	h := winHarness(t, app.Flags{})
	dir := t.TempDir()
	rsaPath, _ := writeRSAKey(t, dir)
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edBlock, err := ssh.MarshalPrivateKey(edPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	edPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(edPath, pem.EncodeToMemory(edBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	encBlock, err := ssh.MarshalPrivateKeyWithPassphrase(edPriv, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	encPath := filepath.Join(dir, "enc")
	if err := os.WriteFile(encPath, pem.EncodeToMemory(encBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	pubPath := writeKeyFile(t, dir, "id.pub", genED25519(t))
	h.ec2.mu.Lock()
	h.ec2.inst.archs["mac1.metal"] = []string{"x86_64_mac"}
	h.ec2.inst.offerings["mac1.metal"] = []string{"ap-east-1a"}
	h.ec2.mu.Unlock()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--ssh-key-file", pubPath}, "--ssh-key and --ssh-key-file do not apply"},
		{[]string{"--key-pair", "ops"}, "needs --key-file"},
		{[]string{"--key-file", edPath}, "RSA key pairs only"},
		{[]string{"--key-file", encPath}, "passphrase"},
		{[]string{"--key-file", filepath.Join(dir, "nosuch")}, "--key-file"},
		{[]string{"--arch", "arm64"}, "x86_64 only"},
		{[]string{"--password-timeout", "0s"}, "--password-timeout"},
		{[]string{"--type", "t4g.small"}, "x86_64 only"},
	} {
		args := append(append([]string{}, winCreate...), tc.args...)
		err := h.run(args...)
		if !exit2(err) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v = %v", tc.args, err)
		}
	}
	if err := h.run(append(winCreate, "--type", "mac1.metal")...); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("mac = %v", err)
	}
	// --key-file is for Windows only.
	if err := h.run("ec2", "instance", "create", "lin", "--type", "t3.large", "--key-file", rsaPath); !exit2(err) || !strings.Contains(err.Error(), "Windows instances only") {
		t.Errorf("linux --key-file = %v", err)
	}
	// The key pair name polyctl would create is taken.
	h.add("ap-east-1", newFakeKeyPair("win-a-win", genED25519(t)))
	if err := h.run(winCreate...); !exit2(err) || !strings.Contains(err.Error(), "naming.aws_windows_key_pair") {
		t.Errorf("taken name = %v", err)
	}
	if w := h.writes(); len(w) != 0 {
		t.Errorf("writes = %v", w)
	}
	if n, _ := func() (int, error) { db, _ := h.rt.DB(); return db.CountSecrets(context.Background()) }(); n != 0 {
		t.Errorf("secrets = %d", n)
	}
}

// An --ami whose platform is windows makes a Windows instance; an --ami of
// a Linux image without any key is refused once the image is read.
func TestWindowsCreateFromAMI(t *testing.T) {
	h := newInstanceHarnessNoKey(t)
	addWindowsFixtures(h)
	if err := h.run("ec2", "instance", "create", "win-b", "--ami", "ami-0win2022", "--type", "t3.large"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got := h.runs(); len(got) != 1 || got[0] != "ami-0win2022 key=win-b-win" {
		t.Fatalf("runs = %v", got)
	}
	if c := storedWin(t, h, "win-b"); len(c) != 1 || c[0].Password != winPassword {
		t.Fatalf("stored = %+v", c)
	}
	err := h.run("ec2", "instance", "create", "lin-b", "--ami", "ami-0x86", "--type", "t3.large")
	if !exit2(err) || !strings.Contains(err.Error(), "a key pair is required") {
		t.Errorf("linux --ami without a key = %v", err)
	}
	if got := h.runs(); len(got) != 1 {
		t.Errorf("runs = %v", got)
	}
	// Without --ami a Linux create without a key reads nothing.
	h.ec2.reset()
	err = h.run("ec2", "instance", "create", "lin-c", "--type", "t3.large")
	if !exit2(err) || len(h.ec2.calls()) != 0 {
		t.Errorf("linux without a key = %v, calls %v", err, h.ec2.calls())
	}
}

// newInstanceHarnessNoKey is an instance harness without defaults.aws.key_name.
func newInstanceHarnessNoKey(t *testing.T) *awsHarness {
	t.Helper()
	useFakeClock(t)
	return newAWSHarness(t, app.Flags{}, map[string]any{"subnet_id": "subnet-0def", "security_group_ids": []any{"sg-0aaa"}})
}

// The image is the newest year among the English Full Base parameters;
// without SSM it is the newest such image by name and date.
func TestLatestWindowsAMI(t *testing.T) {
	h := winHarness(t, app.Flags{})
	c := &client{region: "ap-east-1", ec2For: func(r string) ec2API { return newEC2(awssdk.Config{Region: r}) },
		ssmFor: func(r string) ssmAPI { return newSSM(awssdk.Config{Region: r}) }}
	img, err := c.latestWindowsAMI(context.Background(), "", nil)
	if err != nil || img.ID != "ami-0win2025" || !img.Windows || img.RootDevice != "/dev/sda1" {
		t.Fatalf("ssm = %+v, %v", img, err)
	}
	if h.ec2.inst.ssmPathCalls != 1 {
		t.Errorf("GetParametersByPath calls = %d", h.ec2.inst.ssmPathCalls)
	}
	h.ec2.inst.ssmPathErr = &fakeAPIError{"AccessDeniedException", "not authorized to perform ssm:GetParametersByPath"}
	var notes []string
	img, err = c.latestWindowsAMI(context.Background(), "", func(s string) { notes = append(notes, s) })
	if err != nil || img.ID != "ami-0win2025" || !img.Windows {
		t.Fatalf("fallback = %+v, %v", img, err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], windowsParamPath) {
		t.Errorf("notes = %v", notes)
	}
	h.ec2.mu.Lock()
	h.ec2.inst.images["ap-east-1"] = nil
	h.ec2.mu.Unlock()
	if _, err := c.latestWindowsAMI(context.Background(), "", nil); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("none = %v", err)
	}
}

// A failed RunInstances deletes the key pair polyctl created for it.
func TestWindowsRunFailureDeletesTheKeyPair(t *testing.T) {
	h := winHarness(t, app.Flags{})
	h.ec2.inst.errs["RunInstances"] = &fakeAPIError{"InsufficientInstanceCapacity", "no capacity"}
	if err := h.run(winCreate...); err == nil {
		t.Fatal("create succeeded")
	}
	if strings.Join(h.ec2.deletedKeyPairs, ",") != "win-a-win" || len(storedWin(t, h, "win-a")) != 0 {
		t.Errorf("deleted %v", h.ec2.deletedKeyPairs)
	}
	db, err := h.rt.DB()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.List(context.Background(), inventory.Query{Platform: platform.AWS, Type: platform.ResKeyPair})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Name == "win-a-win" {
			t.Errorf("the deleted key pair is still in the inventory: %+v", r)
		}
	}
}

func TestParseWindowsKeyAndDecrypt(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(rk)
	openssh, err := ssh.MarshalPrivateKey(rk, "")
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := rsa.EncryptPKCS1v15(rand.Reader, &rk.PublicKey, []byte(winPassword))
	data := base64.StdEncoding.EncodeToString(ct)
	for name, text := range map[string][]byte{
		"pkcs1":   pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}),
		"pkcs8":   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		"openssh": pem.EncodeToMemory(openssh),
	} {
		k, err := parseWindowsKey(string(text))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pw, err := decryptWindowsPassword(k.key, "\r\n"+data[:10]+"\n"+data[10:])
		if err != nil || pw != winPassword {
			t.Errorf("%s: %q, %v", name, pw, err)
		}
	}
	if _, err := parseWindowsKey("not a key"); err == nil || strings.Contains(err.Error(), "not a key") {
		t.Errorf("garbage = %v", err)
	}
	k, _ := parseWindowsKey(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})))
	if _, err := decryptWindowsPassword(k.key, "%%%"); err == nil {
		t.Error("bad base64 decrypted")
	}
}
