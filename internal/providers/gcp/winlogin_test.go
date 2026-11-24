package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the guest agent's encryption
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

// agentPassword is the password the fake guest agent sets.
const agentPassword = "Ag3nt-Pw_q7Zr2Lx9"

// fakeAgent emulates the Windows guest agent of the fake instances: a
// password request written into windows-keys is answered on serial port 4
// with the password encrypted for the request's key.
type fakeAgent struct {
	// silent: no answer at all; errorMessage: an answer with an error.
	silent       bool
	errorMessage string
	// delay is the number of serial port reads before the answer shows;
	// split delivers it in two reads.
	delay int
	split bool
	// staleMetadata makes the next n SetMetadata calls see a stale
	// fingerprint.
	staleMetadata int
	serial        map[string]string // instance self link -> port 4 output
	pending       map[string]*pendingAnswer
	requests      []windowsKeyEntry
	metadata      []*compute.Metadata
	reads         int
}

type pendingAnswer struct {
	line string
	wait int
	half bool
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{serial: map[string]string{}, pending: map[string]*pendingAnswer{}}
}

// agentNoise is what serial port 4 holds before any request: other lines,
// and the answer to someone else's request.
const agentNoise = "GCEWindowsAgent: started\n{\"ready\":true,\"version\":\"20261101\"}\n" +
	`{"userName":"other","passwordFound":true,"encryptedPassword":"AAAA","modulus":"b3RoZXI=","exponent":"AQAB"}` + "\n"

func encryptFor(t *testing.T, e windowsKeyEntry, plain string) string {
	t.Helper()
	n, err := base64.StdEncoding.DecodeString(e.Modulus)
	if err != nil {
		t.Fatalf("modulus: %v", err)
	}
	x, err := base64.StdEncoding.DecodeString(e.Exponent)
	if err != nil {
		t.Fatalf("exponent: %v", err)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(x).Int64())}
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, []byte(plain), nil) //nolint:gosec // see the import
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(ct)
}

// handleAgent answers setMetadata and serialPort; f.mu is held.
func (f *fakeCompute) handleAgent(w http.ResponseWriter, r *http.Request, in *compute.Instance, action string) {
	a := f.agent
	if _, ok := a.serial[in.SelfLink]; !ok {
		a.serial[in.SelfLink] = agentNoise
	}
	switch action {
	case "setMetadata":
		var body compute.Metadata
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			apiError(w, fakeErr{400, "invalid", err.Error()})
			return
		}
		if a.staleMetadata > 0 {
			a.staleMetadata--
			if in.Metadata == nil {
				in.Metadata = &compute.Metadata{}
			}
			in.Metadata.Fingerprint = "md-" + strconv.Itoa(f.next())
		}
		fp := ""
		if in.Metadata != nil {
			fp = in.Metadata.Fingerprint
		}
		if body.Fingerprint != fp {
			apiError(w, fakeErr{412, "conditionNotMet", "Supplied fingerprint does not match current metadata fingerprint."})
			return
		}
		body.Fingerprint = "md-" + strconv.Itoa(f.next())
		in.Metadata = &body
		a.metadata = append(a.metadata, &body)
		for _, it := range body.Items {
			if it.Key != windowsKeysKey || it.Value == nil {
				continue
			}
			lines := strings.Split(*it.Value, "\n")
			var e windowsKeyEntry
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &e); err != nil {
				f.t.Errorf("windows-keys entry: %v", err)
				continue
			}
			a.requests = append(a.requests, e)
			if a.silent {
				continue
			}
			ans := map[string]any{"userName": e.UserName, "modulus": e.Modulus, "exponent": e.Exponent}
			if a.errorMessage != "" {
				ans["errorMessage"] = a.errorMessage
			} else {
				ans["passwordFound"] = true
				ans["encryptedPassword"] = encryptFor(f.t, e, agentPassword)
			}
			b, _ := json.Marshal(ans)
			a.pending[in.SelfLink] = &pendingAnswer{line: string(b) + "\n", wait: a.delay}
		}
		writeJSONStatus(w, 200, f.op("setMetadata", in.SelfLink))
	case "serialPort":
		if r.URL.Query().Get("port") != "4" {
			apiError(w, fakeErr{400, "invalid", "unexpected port " + r.URL.Query().Get("port")})
			return
		}
		a.reads++
		if p := a.pending[in.SelfLink]; p != nil {
			switch {
			case p.wait > 0:
				p.wait--
			case a.split && !p.half:
				half := len(p.line) / 2
				a.serial[in.SelfLink] += p.line[:half]
				p.line, p.half = p.line[half:], true
			default:
				a.serial[in.SelfLink] += p.line
				delete(a.pending, in.SelfLink)
			}
		}
		out := a.serial[in.SelfLink]
		start, _ := strconv.ParseInt(r.URL.Query().Get("start"), 10, 64)
		contents := ""
		if int(start) < len(out) {
			contents = out[start:]
		}
		writeJSONStatus(w, 200, &compute.SerialPortOutput{Contents: contents, Start: start, Next: int64(len(out))})
	}
}

var winCreate = []string{"compute", "instance", "create", "win-1", "--machine-type", "e2-standard-4", "--os", "windows", "--static-ip=false"}

func winHarness(t *testing.T, flags app.Flags) *gcpHarness {
	t.Helper()
	h := newGCPHarness(t, flags, map[string]any{"zone": "us-central1-a"})
	// A Windows instance needs no SSH key anywhere.
	h.gce.projectMeta["proj"] = nil
	return h
}

func storedWin(t *testing.T, h *gcpHarness, ref string) []secrets.Credentials {
	t.Helper()
	st, err := h.rt.Secrets()
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Find(context.Background(), platform.GCP, "lab", "", ref)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// assertNoPlaintext checks that no file of the configuration directory
// holds secret.
func assertNoPlaintext(t *testing.T, h *gcpHarness, secret string) {
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
			t.Errorf("%s holds the password in plain text", filepath.Base(p))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func hasDataKey(t *testing.T, h *gcpHarness) bool {
	t.Helper()
	_, err := creds.NewFile(h.dir).Get(secrets.DataKeyName)
	if err != nil && !errors.Is(err, creds.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func (h *gcpHarness) countCalls(sub string) int {
	h.gce.mu.Lock()
	defer h.gce.mu.Unlock()
	n := 0
	for _, c := range h.gce.calls {
		if strings.Contains(c, sub) {
			n++
		}
	}
	return n
}

func TestCheckWindowsUser(t *testing.T) {
	for _, u := range []string{"polyctl-admin", "Administrator", "ops", "a.b", "x_1", "abcdefghijklmnopqrst"} {
		if err := checkWindowsUser(u, "--windows-user"); err != nil {
			t.Errorf("%q: %v", u, err)
		}
	}
	for _, u := range []string{"", "abcdefghijklmnopqrstu", "...", "ops.", "a b", "a/b", `a\b`, "a@b", "a:b", "a*b", "ä", "a\tb"} {
		if err := checkWindowsUser(u, "--windows-user"); exitClass(err) != "usage" {
			t.Errorf("%q = %v", u, err)
		}
	}
}

// The key of a request round-trips: the entry carries its public half the
// way the guest agent reads it, and what the agent encrypts for it
// decrypts. Errors never quote the ciphertext.
func TestWindowsKeyRoundTrip(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	k, e, err := newWindowsKey("ops", "", now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if k.N.BitLen() != 2048 || e.Exponent != "AQAB" || e.UserName != "ops" || e.Email != "polyctl" || e.ExpireOn != "2026-01-01T00:05:00Z" {
		t.Fatalf("entry = %+v (bits %d)", e, k.N.BitLen())
	}
	if _, e2, _ := newWindowsKey("ops", "sa@proj.iam.gserviceaccount.com", now, 10*time.Minute); e2.ExpireOn != "2026-01-01T00:10:00Z" || e2.Email != "sa@proj.iam.gserviceaccount.com" {
		t.Errorf("entry = %+v", e2)
	}
	b, _ := json.Marshal(e)
	for _, field := range []string{`"userName"`, `"modulus"`, `"exponent"`, `"email"`, `"expireOn"`} {
		if !strings.Contains(string(b), field) {
			t.Errorf("entry JSON lacks %s: %s", field, b)
		}
	}
	enc := encryptFor(t, e, "s3cret-Pw")
	if got, err := decryptAgentPassword(k, enc); err != nil || got != "s3cret-Pw" {
		t.Fatalf("decrypt = %q, %v", got, err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := decryptAgentPassword(other, enc); err == nil || strings.Contains(err.Error(), enc[:16]) {
		t.Errorf("wrong key = %v", err)
	}
	if _, err := decryptAgentPassword(k, "not base64!"); err == nil {
		t.Error("bad base64 decrypted")
	}
}

func TestWindowsKeysValue(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expired := `{"userName":"old","modulus":"m1","exponent":"AQAB","email":"x","expireOn":"2025-12-31T00:00:00Z"}`
	valid := `{"userName":"live","modulus":"m2","exponent":"AQAB","email":"x","expireOn":"2026-06-01T00:00:00Z"}`
	v, err := windowsKeysValue(expired+"\n"+valid+"\n\nnot json\n", windowsKeyEntry{UserName: "new", Modulus: "m3", Exponent: "AQAB", Email: "e", ExpireOn: "2026-01-01T00:10:00Z"}, now)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(v, "\n")
	if len(lines) != 3 || lines[0] != valid || lines[1] != "not json" || !strings.Contains(lines[2], `"userName":"new"`) {
		t.Errorf("value = %q", v)
	}
	if v, _ := windowsKeysValue("", windowsKeyEntry{UserName: "a"}, now); strings.Contains(v, "\n") {
		t.Errorf("empty = %q", v)
	}
}

func TestMatchAnswer(t *testing.T) {
	text := agentNoise + `{"userName":"ops","passwordFound":true,"encryptedPassword":"ZZZ","modulus":"bWluZQ==","exponent":"AQAB"}` + "\n"
	if a := matchAnswer(text, "bWluZQ=="); a == nil || a.EncryptedPassword != "ZZZ" || a.UserName != "ops" {
		t.Errorf("match = %+v", a)
	}
	if a := matchAnswer(agentNoise, "bWluZQ=="); a != nil {
		t.Errorf("noise matched: %+v", a)
	}
}

// A non-interactive Windows create waits until the instance runs, asks
// the guest agent for the password, stores user and password encrypted and
// prints the password nowhere: a note names the password command.
func TestWindowsCreateNonInteractive(t *testing.T) {
	h := winHarness(t, app.Flags{})
	h.gce.agent.delay, h.gce.agent.split = 2, true
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	in := h.gce.instance("us-central1-a", "win-1")
	id := strconv.FormatUint(in.Id, 10)
	reqs := h.gce.agent.requests
	if len(reqs) != 1 || reqs[0].UserName != defaultWindowsUser || reqs[0].Exponent != "AQAB" || reqs[0].Email != "sa@proj.iam.gserviceaccount.com" {
		t.Fatalf("requests = %+v", reqs)
	}
	if exp, err := time.Parse(time.RFC3339, reqs[0].ExpireOn); err != nil || !exp.After(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("expireOn = %q", reqs[0].ExpireOn)
	}
	if out := h.stdout.String() + h.stderr.String(); strings.Contains(out, agentPassword) {
		t.Errorf("the password was printed:\n%s", out)
	}
	note := "user " + defaultWindowsUser + "; `polyctl gcp compute instance password " + id + "` shows the password"
	if !strings.Contains(h.stderr.String(), note) {
		t.Errorf("stderr lacks %q:\n%s", note, h.stderr.String())
	}
	r := rows(h.report())
	if len(r) != 4 || r[3] != "instance/win-1/windows-login created user polyctl-admin: password set, stored encrypted" || !strings.Contains(r[1], "Windows login polyctl-admin") {
		t.Errorf("rows = %v", r)
	}
	got := storedWin(t, h, "win-1")
	if len(got) != 1 || got[0].Password != agentPassword || got[0].User != defaultWindowsUser || got[0].InstanceID != id || got[0].Location != "us-central1-a" {
		t.Fatalf("stored = %+v", got)
	}
	assertNoPlaintext(t, h, agentPassword)

	// The password command shows it by name or id, reading nothing live.
	for _, args := range [][]string{{"win-1"}, {id, "--zone", "us-central1-a"}} {
		if err := h.run(append([]string{"compute", "instance", "password"}, args...)...); err != nil {
			t.Fatalf("password %v: %v", args, err)
		}
		var login map[string]any
		h.jsonOut(&login)
		if login["instance"] != "win-1" || login["id"] != id || login["user"] != defaultWindowsUser || login["password"] != agentPassword || login["platform"] != "gcp" || login["location"] != "us-central1-a" {
			t.Errorf("password %v = %v", args, login)
		}
		if n := len(h.gce.calls); n != 0 {
			t.Errorf("the password command made %d API calls", n)
		}
	}
	// Another zone holds nothing: exit code 4 with the hint to --reset.
	err := h.run("compute", "instance", "password", "win-1", "--zone", "us-central1-b")
	if exitClass(err) != "notfound" || !strings.Contains(err.Error(), "password win-1 --reset") {
		t.Errorf("other zone = %v", err)
	}
	// --user without --reset is a usage error.
	if err := h.run("compute", "instance", "password", "win-1", "--user", "ops"); exitClass(err) != "usage" {
		t.Errorf("--user alone = %v", err)
	}

	// Deleting the instance removes its credentials; a dry run keeps them.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "delete", "win-1"); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.DryRun = false
	if len(storedWin(t, h, id)) != 1 {
		t.Fatal("a dry run removed the credentials")
	}
	if err := h.run("compute", "instance", "delete", "win-1", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(storedWin(t, h, id)) != 0 {
		t.Error("the credentials survived the delete")
	}
}

// An interactive create prints the login at the end: on stdout after the
// table report, on stderr with -o json.
func TestWindowsCreateInteractive(t *testing.T) {
	h := winHarness(t, app.Flags{Output: "table", NonInteractiveSet: true})
	h.rt.Picker = &scriptedPicker{t: t}
	if err := h.run(append(winCreate, "--windows-user", "ops")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	id := storedWin(t, h, "win-1")[0].InstanceID
	out := h.stdout.String()
	login := strings.Index(out, "Windows login of instance win-1 ("+id+"):")
	if login < 0 || login < strings.Index(out, "instance/win-1/windows-login") || !strings.Contains(out[login:], "password: "+agentPassword) || !strings.Contains(out[login:], "user:     ops") {
		t.Errorf("stdout:\n%s", out)
	}
	if strings.Contains(h.stderr.String(), agentPassword) {
		t.Errorf("stderr:\n%s", h.stderr.String())
	}
	if err := h.run("compute", "instance", "password", "win-1"); err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); !strings.Contains(out, "INSTANCE") || !strings.Contains(out, "USER") || !strings.Contains(out, agentPassword) {
		t.Errorf("password table:\n%s", out)
	}

	h = winHarness(t, app.Flags{NonInteractiveSet: true})
	h.rt.Picker = &scriptedPicker{t: t}
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	h.report()
	if strings.Contains(h.stdout.String(), agentPassword) || !strings.Contains(h.stderr.String(), "password: "+agentPassword) {
		t.Errorf("-o json: stdout %s\nstderr %s", h.stdout.String(), h.stderr.String())
	}
}

// A dry run reads, reports the login row, and writes, generates and stores
// nothing (no data key either).
func TestWindowsCreateDryRun(t *testing.T) {
	h := winHarness(t, app.Flags{DryRun: true})
	if err := h.run(winCreate...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if w := h.gce.writes(); len(w) != 0 || h.countCalls("serialPort") != 0 || len(h.gce.agent.requests) != 0 {
		t.Fatalf("dry run wrote %v", w)
	}
	r := rows(h.report())
	if len(r) != 3 || !strings.HasPrefix(r[2], "instance/win-1/windows-login would_create user polyctl-admin") {
		t.Errorf("rows = %v", r)
	}
	if hasDataKey(t, h) {
		t.Error("a dry run created the data key")
	}
	if n, _ := h.rt.DB(); n != nil {
		if c, _ := n.CountSecrets(context.Background()); c != 0 {
			t.Errorf("a dry run stored %d secrets", c)
		}
	}
}

// When the agent does not answer in time, create still succeeds; nothing
// is stored, and a note names the command that sets a password.
func TestWindowsCreateNoAnswer(t *testing.T) {
	h := winHarness(t, app.Flags{})
	h.gce.agent.silent = true
	if err := h.run(append(winCreate, "--password-timeout", "1m")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	id := strconv.FormatUint(h.gce.instance("us-central1-a", "win-1").Id, 10)
	if r := rows(h.report()); len(r) != 4 || r[3] != "instance/win-1/windows-login created user polyctl-admin: password not set yet" {
		t.Errorf("rows = %v", r)
	}
	// One read for the position, then one every 10 seconds for a minute.
	if n := h.countCalls("serialPort"); n < 6 || n > 8 {
		t.Errorf("serial port reads = %d", n)
	}
	if !strings.Contains(h.stderr.String(), "did not answer within 1m0s") || !strings.Contains(h.stderr.String(), "`polyctl gcp compute instance password "+id+" --reset`") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	if len(storedWin(t, h, "win-1")) != 0 {
		t.Error("credentials without a password were stored")
	}
	err := h.run("compute", "instance", "password", "win-1")
	if exitClass(err) != "notfound" || !strings.Contains(err.Error(), "--reset") {
		t.Errorf("password = %v", err)
	}

	// An agent that reports an error, and a serial port that cannot be
	// read, are warnings too.
	h = winHarness(t, app.Flags{})
	h.gce.agent.errorMessage = "user creation failed"
	if err := h.run(winCreate...); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.stderr.String(), "user creation failed") || len(storedWin(t, h, "win-1")) != 0 {
		t.Errorf("agent error: stderr %s", h.stderr.String())
	}
	h = winHarness(t, app.Flags{})
	h.gce.fail["/serialPort"] = fakeErr{403, "forbidden", "Required 'compute.instances.getSerialPortOutput' permission"}
	if err := h.run(winCreate...); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.stderr.String(), "cannot read serial port 4") || len(h.gce.agent.requests) != 0 {
		t.Errorf("serial forbidden: stderr %s", h.stderr.String())
	}
}

// --no-wait sets no password: a note names the command that sets one,
// with the user when it is not the default.
func TestWindowsCreateNoWait(t *testing.T) {
	h := winHarness(t, app.Flags{})
	if err := h.run(append(winCreate, "--no-wait", "--windows-user", "ops")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(h.gce.agent.requests) != 0 || h.countCalls("serialPort") != 0 {
		t.Error("--no-wait asked the agent")
	}
	if !strings.Contains(h.stderr.String(), "was not set (--no-wait)") || !strings.Contains(h.stderr.String(), "password win-1 --reset --user ops`") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	if hasDataKey(t, h) {
		t.Error("--no-wait created the data key")
	}
}

// The Windows login flags are refused on Linux, and a bad user name is a
// usage error, before anything is written.
func TestWindowsCreateFlags(t *testing.T) {
	h := winHarness(t, app.Flags{})
	key := testPublicKey(t, "")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--os", "debian", "--windows-user", "ops", "--ssh-key", "a:" + key}, "--windows-user applies to Windows instances only"},
		{[]string{"--os", "debian", "--password-timeout", "5m", "--ssh-key", "a:" + key}, "--password-timeout applies to Windows instances only"},
		{[]string{"--image", "projects/debian-cloud/global/images/debian-12-bookworm-v20261117", "--windows-user", "ops", "--ssh-key", "a:" + key}, "is not a Windows image"},
		{[]string{"--os", "windows", "--windows-user", "a/b"}, "not a valid Windows user name"},
		{[]string{"--os", "windows", "--password-timeout", "0s"}, "--password-timeout must be a positive duration"},
	} {
		args := append([]string{"compute", "instance", "create", "x-1", "--machine-type", "e2-small", "--static-ip=false"}, tc.args...)
		err := h.run(args...)
		if exitClass(err) != "usage" || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v = %v", tc.args, err)
		}
		if w := h.gce.writes(); len(w) != 0 {
			t.Errorf("%v wrote %v", tc.args, w)
		}
	}
	// A Linux create never writes windows-keys or any password metadata.
	if err := h.run("compute", "instance", "create", "web-1", "--machine-type", "e2-small", "--static-ip=false", "--ssh-key", "a:"+key); err != nil {
		t.Fatal(err)
	}
	in := h.gce.instance("us-central1-a", "web-1")
	if in.Metadata == nil || len(in.Metadata.Items) != 1 || in.Metadata.Items[0].Key != "ssh-keys" || len(h.gce.agent.requests) != 0 || h.countCalls("setMetadata") != 0 {
		t.Errorf("Linux metadata = %+v", in.Metadata)
	}
}

// addWindows puts a running Windows instance with metadata into the fake.
func addWindows(h *gcpHarness, name string) *compute.Instance {
	in := h.gce.addInstance("proj", "us-central1-a", name, "10.128.0.9", "203.0.113.9")
	h.gce.mu.Lock()
	defer h.gce.mu.Unlock()
	in.Disks[0].Licenses = []string{apiBase + "projects/windows-cloud/global/licenses/windows-server-2022-dc"}
	in.Metadata = &compute.Metadata{Fingerprint: "md-0", Items: []*compute.MetadataItems{
		{Key: "ssh-keys", Value: strPtr("ops:ssh-ed25519 AAAA")},
		{Key: windowsKeysKey, Value: strPtr(`{"userName":"old","modulus":"m1","exponent":"AQAB","email":"x","expireOn":"2025-12-31T00:00:00Z"}` + "\n" +
			`{"userName":"live","modulus":"m2","exponent":"AQAB","email":"x","expireOn":"2026-06-01T00:00:00Z"}`)},
	}}
	return in
}

// password --reset sets a new password through the agent of a running
// Windows instance (also one polyctl did not create), after a
// confirmation, and stores and shows it.
func TestPasswordReset(t *testing.T) {
	h := winHarness(t, app.Flags{})
	in := addWindows(h, "win-9")
	id := strconv.FormatUint(in.Id, 10)
	reset := []string{"compute", "instance", "password", "win-9", "--reset"}

	// The non-interactive flow needs --yes: refused before any lookup.
	if err := h.run(reset...); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--yes") || len(h.gce.calls) != 0 {
		t.Fatalf("without --yes = %v (%d calls)", err, len(h.gce.calls))
	}
	// A dry run reports and writes, generates and stores nothing.
	h.rt.Flags.DryRun = true
	if err := h.run(reset...); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.DryRun = false
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/win-9/windows-login would_update user polyctl-admin: new password set by the guest agent (windows-keys metadata)"}) {
		t.Errorf("dry run rows = %v", r)
	}
	if len(h.gce.writes()) != 0 || h.countCalls("serialPort") != 0 || hasDataKey(t, h) || strings.Contains(h.stdout.String(), "password\"") {
		t.Fatal("the dry run changed something")
	}
	// A declined confirmation changes nothing.
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = &scriptedPicker{t: t, answers: []string{"no"}}
	if err := h.run(reset...); exitClass(err) != "nothing" || len(h.gce.writes()) != 0 {
		t.Fatalf("declined = %v, writes %v", err, h.gce.writes())
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true

	// With --yes (and a stale fingerprint once) the request goes in,
	// keeping the other metadata and the live entries.
	h.gce.agent.staleMetadata = 1
	if err := h.run(append(reset, "--yes")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	var login map[string]any
	h.jsonOut(&login)
	if login["instance"] != "win-9" || login["id"] != id || login["user"] != defaultWindowsUser || login["password"] != agentPassword {
		t.Errorf("login = %v", login)
	}
	md := h.gce.agent.metadata
	if len(md) != 1 || len(md[0].Items) != 2 || md[0].Items[0].Key != "ssh-keys" {
		t.Fatalf("metadata = %+v", md)
	}
	lines := strings.Split(*md[0].Items[1].Value, "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"live"`) || !strings.Contains(lines[1], `"userName":"polyctl-admin"`) {
		t.Errorf("windows-keys = %q", lines)
	}
	if got := storedWin(t, h, id); len(got) != 1 || got[0].Password != agentPassword {
		t.Fatalf("stored = %+v", got)
	}
	assertNoPlaintext(t, h, agentPassword)

	// The stored user is the default of the next reset; --user overrides it.
	if err := h.run(append(reset, "--yes", "--user", "ops")...); err != nil {
		t.Fatal(err)
	}
	if reqs := h.gce.agent.requests; reqs[len(reqs)-1].UserName != "ops" || storedWin(t, h, id)[0].User != "ops" {
		t.Errorf("requests = %+v", reqs)
	}
	if err := h.run(append(reset, "--yes")...); err != nil {
		t.Fatal(err)
	}
	if reqs := h.gce.agent.requests; reqs[len(reqs)-1].UserName != "ops" {
		t.Errorf("default user = %+v", reqs[len(reqs)-1])
	}
	// A stored row that no longer decrypts (a lost or changed data key)
	// still names the user: the reset updates it instead of creating
	// another administrator.
	db, err := h.rt.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutSecret(t.Context(), inventory.SecretRow{SecretKey: inventory.SecretKey{Platform: platform.GCP, Profile: "lab", Location: "us-central1-a", InstanceID: id},
		Name: "win-9", User: "ops", Nonce: make([]byte, 12), Sealed: []byte("not sealed with the data key")}); err != nil {
		t.Fatal(err)
	}
	if err := h.run(append(reset, "--yes")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if reqs := h.gce.agent.requests; reqs[len(reqs)-1].UserName != "ops" || storedWin(t, h, id)[0].Password != agentPassword {
		t.Errorf("user with an undecryptable row = %+v", reqs[len(reqs)-1])
	}
	if err := h.run(append(reset, "--yes", "--user", "a b")...); exitClass(err) != "usage" {
		t.Errorf("bad user = %v", err)
	}
	if err := h.run(append(reset, "--yes", "--password-timeout", "-1s")...); exitClass(err) != "usage" {
		t.Errorf("bad timeout = %v", err)
	}
}

func TestPasswordResetRefusals(t *testing.T) {
	h := winHarness(t, app.Flags{})
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "203.0.113.10")
	// A Linux instance: never a password.
	err := h.run("compute", "instance", "password", "web-1", "--reset", "--yes")
	if exitClass(err) != "usage" || !strings.Contains(err.Error(), "SSH key only") || len(h.gce.writes()) != 0 {
		t.Errorf("Linux = %v", err)
	}
	// A stopped Windows instance: exit code 1.
	in := addWindows(h, "win-s")
	h.gce.mu.Lock()
	in.Status = statusTerminated
	h.gce.mu.Unlock()
	if err := h.run("compute", "instance", "password", "win-s", "--reset", "--yes"); exitClass(err) != "general" || !strings.Contains(err.Error(), "start it first") {
		t.Errorf("stopped = %v", err)
	}
	h.gce.mu.Lock()
	in.Status = statusRunning
	h.gce.mu.Unlock()
	// No answer in time: exit code 1, nothing stored.
	h.gce.agent.silent = true
	if err := h.run("compute", "instance", "password", "win-s", "--reset", "--yes", "--password-timeout", "30s"); exitClass(err) != "general" || !errors.Is(err, errNoAnswer) {
		t.Errorf("no answer = %v", err)
	}
	// The agent's error: exit code 1.
	h.gce.agent.silent, h.gce.agent.errorMessage = false, "user is a reserved name"
	if err := h.run("compute", "instance", "password", "win-s", "--reset", "--yes"); exitClass(err) != "general" || !strings.Contains(err.Error(), "reserved name") {
		t.Errorf("agent error = %v", err)
	}
	if len(storedWin(t, h, "win-s")) != 0 {
		t.Error("a failed reset stored credentials")
	}
	// --offline needs the network.
	h.rt.Flags.Offline = true
	if err := h.run("compute", "instance", "password", "win-s", "--reset", "--yes"); exitClass(err) != "offline" {
		t.Errorf("offline = %v", err)
	}
	h.rt.Flags.Offline = false
	// Unknown instance: exit code 4.
	if err := h.run("compute", "instance", "password", "nope", "--reset", "--yes"); exitClass(err) != "notfound" {
		t.Errorf("missing = %v", err)
	}
}

func TestInstanceWindows(t *testing.T) {
	boot := func(d *compute.AttachedDisk) *compute.Instance {
		d.Boot = true
		return &compute.Instance{Disks: []*compute.AttachedDisk{d}}
	}
	if !instanceWindows(boot(&compute.AttachedDisk{Licenses: []string{apiBase + "projects/windows-cloud/global/licenses/windows-server-2025-dc"}})) {
		t.Error("license")
	}
	if !instanceWindows(boot(&compute.AttachedDisk{GuestOsFeatures: []*compute.GuestOsFeature{{Type: "WINDOWS"}}})) {
		t.Error("guest OS feature")
	}
	if instanceWindows(boot(&compute.AttachedDisk{Licenses: []string{apiBase + "projects/debian-cloud/global/licenses/debian-12-bookworm"}})) {
		t.Error("debian")
	}
}

// Credentials a non-interactive create could not store fail the command
// with the --reset hint of the password command, not the console advice.
func TestWindowsLoginStoreFailureHintsReset(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	if err := creds.NewFile(h.dir).Set(secrets.DataKeyName, map[string]string{"key": "broken"}); err != nil {
		t.Fatal(err)
	}
	w := &windowsLogin{rt: h.rt, profile: "default", zone: "us-central1-a", name: "win-1", user: defaultWindowsUser,
		created: true, id: "1234", password: agentPassword}
	err := w.finish(context.Background())
	if err == nil || !strings.Contains(err.Error(), "could not be stored") ||
		!strings.Contains(err.Error(), "`polyctl gcp compute instance password 1234 --reset`") || strings.Contains(err.Error(), "console") ||
		strings.Contains(err.Error(), agentPassword) {
		t.Fatalf("finish = %v", err)
	}
}
