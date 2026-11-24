package aliyun

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// testKey returns a new public key line ("ssh-ed25519 AAAA... comment").
func testKey(t *testing.T, kind string) string {
	t.Helper()
	var pub any
	switch kind {
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	case "ecdsa":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	default:
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = p
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " ops@example"
}

func writeKeyFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(p, []byte(body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The fingerprint ECS reports is the MD5 of the key's wire bytes, lower
// case, without colons: the local computation matches it for every type.
func TestKeyFingerprintIsMD5Hex(t *testing.T) {
	for _, kind := range []string{"ed25519", "rsa", "ecdsa"} {
		line := testKey(t, kind)
		k, err := platform.ParsePublicKey(line)
		if err != nil {
			t.Fatal(err)
		}
		fp := k.FingerprintMD5Hex()
		if fp != md5Hex(t, line) || len(fp) != 32 || strings.Contains(fp, ":") || strings.ToLower(fp) != fp {
			t.Errorf("%s fingerprint %q", kind, fp)
		}
		if !platform.MatchByFingerprintMD5.Match(k, platform.KeyPair{Fingerprint: strings.ToUpper(fp)}) {
			t.Errorf("%s: an upper-case fingerprint does not match", kind)
		}
	}
}

func TestParseKeyPairTime(t *testing.T) {
	for in, want := range map[string]string{
		"2026-11-17T13:54Z":    "2026-11-17T13:54:00Z",
		"2026-11-17T13:54:12Z": "2026-11-17T13:54:12Z",
	} {
		got, ok := parseKeyPairTime(in)
		if !ok || got.Format("2006-01-02T15:04:05Z07:00") != want {
			t.Errorf("parse %q = %v %v", in, got, ok)
		}
	}
	if _, ok := parseKeyPairTime("yesterday"); ok {
		t.Error("garbage parsed")
	}
	if k := keyPairFrom("r", ecsKeyPair("a", "AB", "yesterday")); k.Created != "yesterday" || k.Fingerprint != "ab" {
		t.Errorf("unparsed time / fingerprint case: %+v", k)
	}
}

func TestKeyPairListPagesBy50(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	for i := 0; i < 57; i++ {
		f.addKeyPair(fmt.Sprintf("kp-%02d", i), fmt.Sprintf("%032x", i), "2026-11-17T13:54Z")
	}
	if err := h.run("ecs", "key-pair", "list"); err != nil {
		t.Fatal(err)
	}
	var kps []keyPairInfo
	h.jsonOut(&kps)
	calls := h.api.callsFor("DescribeKeyPairs")
	if len(kps) != 57 || len(calls) != 2 || calls[0].Get("PageSize") != "50" {
		t.Fatalf("got %d key pairs in %d call(s)", len(kps), len(calls))
	}
	if kps[0].Created != "2026-11-17T13:54:00Z" || kps[0].Region != "cn-shanghai" {
		t.Errorf("key pair = %+v", kps[0])
	}
	f.keyPairs = nil
	if err := h.run("ecs", "key-pair", "list", "--region", "cn-hongkong"); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no key pairs in cn-hongkong") {
		t.Errorf("empty list: %q / %q", h.stdout.String(), h.stderr.String())
	}
}

func TestKeyPairImport(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	line := testKey(t, "ed25519")
	path := writeKeyFile(t, line)
	if err := h.run("ecs", "key-pair", "import", "ops", "--ssh-key-file", path); err != nil {
		t.Fatal(err)
	}
	c := h.api.callsFor("ImportKeyPair")
	if len(c) != 1 || c[0].Get("KeyPairName") != "ops" || !strings.HasPrefix(c[0].Get("PublicKeyBody"), "ssh-ed25519 AAAA") || strings.Contains(c[0].Get("PublicKeyBody"), "ops@example") {
		t.Fatalf("import calls = %v", c)
	}
	rep := reportOf(t, h)
	if rep.Changes[0].Action != platform.Created || rep.Changes[0].Attrs["fingerprint"] != md5Hex(t, line) || strings.Contains(h.stdout.String(), "AAAA") {
		t.Errorf("report = %+v", rep.Changes)
	}
	// A taken name is invalid input (exit code 2) whatever key it holds.
	if err := h.run("ecs", "key-pair", "import", "ops", "--ssh-key", line); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("import of a taken name = %v", err)
	}
	if n := len(f.writes); n != 1 {
		t.Errorf("writes = %v", f.writes)
	}
	// Local checks, before anything is sent.
	priv := filepath.Join(t.TempDir(), "id")
	der, _ := x509.MarshalPKCS8PrivateKey(mustED25519(t))
	_ = os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	calls := len(h.api.calls)
	for _, args := range [][]string{
		{"ecs", "key-pair", "import", "x2", "--ssh-key", "ssh-ed25519 AAAAnotakey"},
		{"ecs", "key-pair", "import", "x2", "--ssh-key", path},
		{"ecs", "key-pair", "import", "x2", "--ssh-key-file", priv},
		{"ecs", "key-pair", "import", "x2", "--ssh-key", line, "--ssh-key-file", path},
		{"ecs", "key-pair", "import", "x2"},
		{"ecs", "key-pair", "import", "x", "--ssh-key", line},
		{"ecs", "key-pair", "import", "a*", "--ssh-key", line},
	} {
		if err := h.run(args...); !errors.Is(err, app.ErrUsage) && !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%v = %v, want a usage error", args[3:], err)
		}
	}
	if len(h.api.calls) != calls {
		t.Errorf("local checks sent %d request(s)", len(h.api.calls)-calls)
	}
}

func mustED25519(t *testing.T) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyPairEnsure(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	line := testKey(t, "ed25519")
	fp := md5Hex(t, line)
	other := testKey(t, "rsa")

	// Not there: imported under <name>.
	if err := h.run("ecs", "key-pair", "ensure", "ops", "--ssh-key", line); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); rep.Changes[0].Action != platform.Created || len(h.api.callsFor("ImportKeyPair")) != 1 {
		t.Fatalf("first ensure = %+v", rep.Changes)
	}
	// Matched by fingerprint (one server-side query), under its own name.
	f.writes = nil
	if err := h.run("ecs", "key-pair", "ensure", "--ssh-key", line); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if rep.Changes[0].Action != platform.Unchanged || rep.Changes[0].Resource != "key-pair/ops" || rep.Changes[0].Detail != "matched by fingerprint" || len(f.writes) != 0 {
		t.Errorf("ensure by fingerprint = %+v, writes %v", rep.Changes, f.writes)
	}
	last := h.api.callsFor("DescribeKeyPairs")
	if q := last[len(last)-1]; q.Get("KeyPairFingerPrint") != fp {
		t.Errorf("fingerprint query = %v", q)
	}
	// <name> taken by another key: never replaced, exit code 2.
	if err := h.run("ecs", "key-pair", "ensure", "ops", "--ssh-key", other); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("ensure of a taken name = %v", err)
	}
	// <name> alone, existing: unchanged.
	if err := h.run("ecs", "key-pair", "ensure", "ops"); err != nil {
		t.Fatal(err)
	}
	// Creating without a name, or without a key, in the non-interactive flow.
	if err := h.run("ecs", "key-pair", "ensure", "--ssh-key", other); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "needs a name") {
		t.Errorf("ensure without a name = %v", err)
	}
	if err := h.run("ecs", "key-pair", "ensure", "newname"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("ensure of a missing name without a key = %v", err)
	}
	// The same key under two names: <name> picks, else ambiguous.
	f.addKeyPair("ops-copy", strings.ToUpper(fp), "2026-01-01T00:00Z")
	if err := h.run("ecs", "key-pair", "ensure", "ops-copy", "--ssh-key", line); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); rep.Changes[0].Resource != "key-pair/ops-copy" {
		t.Errorf("pick = %+v", rep.Changes)
	}
	if err := h.run("ecs", "key-pair", "ensure", "--ssh-key", line); !errors.Is(err, platform.ErrAmbiguous) {
		t.Errorf("several names = %v, want ambiguous", err)
	}
	if len(h.api.callsFor("ImportKeyPair")) != 1 {
		t.Errorf("imports = %d", len(h.api.callsFor("ImportKeyPair")))
	}
}

func TestKeyPairEnsureDryRun(t *testing.T) {
	h, f := sgHarness(t, app.Flags{DryRun: true})
	path := writeKeyFile(t, testKey(t, "ecdsa"))
	if err := h.run("ecs", "key-pair", "ensure", "ops", "--ssh-key-file", path); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if !rep.DryRun || rep.Changes[0].Action != platform.WouldCreate || !strings.Contains(rep.Changes[0].Detail, "import from --ssh-key-file "+path) || len(f.writes) != 0 {
		t.Errorf("dry run = %+v, writes %v", rep, f.writes)
	}
	if strings.Contains(h.stdout.String(), "AAAA") {
		t.Error("the public key was printed")
	}
	if err := h.run("ecs", "key-pair", "import", "ops", "--ssh-key-file", path); err != nil || len(f.writes) != 0 {
		t.Errorf("import dry run = %v, writes %v", err, f.writes)
	}
}

// keyPicker answers the questions of the interactive key pair flow.
type keyPicker struct {
	t      *testing.T
	path   string
	name   string
	titles []string
}

func (p *keyPicker) Select(title string, opts []prompt.Option, _ string) (string, error) {
	p.titles = append(p.titles, title)
	return opts[len(opts)-1].Value, nil // "Another file..."
}
func (p *keyPicker) MultiSelect(title string, _ []prompt.Option) ([]string, error) {
	p.t.Errorf("unexpected multi-select %q", title)
	return nil, prompt.ErrAborted
}
func (p *keyPicker) Confirm(title string, _ bool) (bool, error) {
	p.t.Errorf("unexpected confirm %q", title)
	return false, prompt.ErrAborted
}
func (p *keyPicker) Input(title, _ string, _ func(string) error) (string, error) {
	p.titles = append(p.titles, title)
	if strings.Contains(title, "public key file") {
		return p.path, nil
	}
	return p.name, nil
}

// On a terminal, ensure without a key asks for the key file and the name.
func TestKeyPairEnsureInteractive(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	h, _ := sgHarness(t, app.Flags{})
	line := testKey(t, "ed25519")
	p := &keyPicker{t: t, path: writeKeyFile(t, line), name: "laptop"}
	h.rt.Picker = p
	if err := h.run("ecs", "key-pair", "ensure"); err != nil {
		t.Fatal(err)
	}
	c := h.api.callsFor("ImportKeyPair")
	if len(c) != 1 || c[0].Get("KeyPairName") != "laptop" || md5Hex(t, c[0].Get("PublicKeyBody")) != md5Hex(t, line) {
		t.Errorf("import = %v", c)
	}
	if len(p.titles) != 2 || !strings.Contains(p.titles[0], "public key file") || !strings.Contains(p.titles[1], "Name of the new key pair") {
		t.Errorf("questions = %q", p.titles)
	}
}

func ecsKeyPair(name, fp, created string) ecs.KeyPair {
	return ecs.KeyPair{KeyPairName: name, KeyPairFingerPrint: fp, CreationTime: created}
}

// On a terminal, ensure without a key or a name lists the existing key
// pairs, the one holding ~/.ssh/id_ed25519.pub marked and preselected, with
// "Import a new key pair..." last; leaving the list changes nothing.
func TestKeyPairEnsureOffersExistingKeyPairs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	line := testKey(t, "ed25519")
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	h, f := sgHarness(t, app.Flags{})
	f.addKeyPair("laptop", md5Hex(t, line), "2026-11-17T13:54Z")
	f.addKeyPair("other", fmt.Sprintf("%032x", 7), "2026-11-17T13:54Z")

	p := prompttest.New(t, "other")
	h.rt.Picker = p
	if err := h.run("ecs", "key-pair", "ensure"); err != nil {
		t.Fatal(err)
	}
	p.Done()
	a := p.Find("Key pair")
	labels := prompttest.Labels(a.Options)
	if a.Default != "laptop" || !strings.Contains(labels, "[matches ~/.ssh/id_ed25519.pub]") || !strings.HasSuffix(labels, "Import a new key pair from a public key file...") {
		t.Errorf("options (default %q):\n%s", a.Default, labels)
	}
	if c := h.api.callsFor("ImportKeyPair"); len(c) != 0 {
		t.Errorf("an existing key pair was chosen, but ImportKeyPair ran: %v", c)
	}

	// Leaving the list: prompt.ErrAborted, which the command tree turns
	// into "cancelled" with exit code 0 (app.QuietAbort); nothing imported.
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("ecs", "key-pair", "ensure"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
	if c := h.api.callsFor("ImportKeyPair"); len(c) != 0 {
		t.Errorf("ImportKeyPair ran after a cancel: %v", c)
	}
}
