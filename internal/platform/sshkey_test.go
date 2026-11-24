package platform

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func ed25519Line(t *testing.T, comment string) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " " + comment, k
}

func TestParsePublicKey(t *testing.T) {
	line, k := ed25519Line(t, "ops@example.com laptop of somebody")
	pk, err := ParsePublicKey(line)
	if err != nil || !pk.Equal(k) || pk.Comment != "ops@example.com laptop of somebody" || pk.Algorithm() != "ed25519" {
		t.Fatalf("ParsePublicKey = %+v, %v", pk, err)
	}
	sum := md5.Sum(k.Marshal())
	if pk.FingerprintMD5Hex() != hex.EncodeToString(sum[:]) || strings.Contains(pk.FingerprintMD5Hex(), ":") {
		t.Errorf("md5 fingerprint = %s", pk.FingerprintMD5Hex())
	}
	if fp := pk.FingerprintAWSED25519(); !strings.HasSuffix(fp, "=") || strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("AWS ed25519 fingerprint = %s", fp)
	}
	sum2 := strings.Fields(line)[1]
	if s := pk.Summary(); strings.Contains(s, sum2) || !strings.HasPrefix(s, "ed25519 SHA256:") || !strings.Contains(s, "ops@example.com lapt…") {
		t.Errorf("Summary = %q", s)
	}
	// A path is refused with a hint.
	f := filepath.Join(t.TempDir(), "id.pub")
	_ = os.WriteFile(f, []byte(line+"\n"), 0o600)
	if _, err := ParsePublicKey(f); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "--ssh-key-file") {
		t.Errorf("path = %v", err)
	}
	for in, want := range map[string]string{
		"":                                       "empty",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nx": "private key",
		"not a key":                              "not an SSH public key",
		line + "\n" + line:                       "more than one",
	} {
		if _, err := ParsePublicKey(in); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), want) {
			t.Errorf("ParsePublicKey(%.20q) = %v, want %q", in, err, want)
		}
	}
}

func TestLoadPublicKeyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	line, k := ed25519Line(t, "c")
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), []byte("# comment\n\n"+line+"\n"), 0o600)
	pk, err := LoadPublicKeyFile("~/.ssh/id_ed25519.pub")
	if err != nil || !pk.Equal(k) || pk.Source != "--ssh-key-file ~/.ssh/id_ed25519.pub" {
		t.Fatalf("LoadPublicKeyFile = %+v, %v", pk, err)
	}
	if got := PublicKeyFiles(); len(got) != 1 || filepath.Base(got[0]) != "id_ed25519.pub" {
		t.Errorf("PublicKeyFiles = %v", got)
	}
	priv := filepath.Join(home, ".ssh", "id_ed25519")
	_ = os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("x")}), 0o600)
	if _, err := LoadPublicKeyFile(priv); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key file = %v", err)
	}
	empty := filepath.Join(home, "empty.pub")
	_ = os.WriteFile(empty, []byte("# nothing\n"), 0o600)
	if _, err := LoadPublicKeyFile(empty); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("empty file = %v", err)
	}
	if _, err := LoadPublicKeyFile(filepath.Join(home, "missing.pub")); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("missing file = %v", err)
	}
}

func TestKeyTypes(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eck, _ := ssh.NewPublicKey(&ec.PublicKey)
	ecpk := &PublicKey{Key: eck}
	if err := ecpk.CheckType(AWSKeyTypes); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "ecdsa-p256 keys are not supported here (supported: rsa, ed25519)") {
		t.Errorf("ecdsa on AWS = %v", err)
	}
	if err := ecpk.CheckType(AliyunKeyTypes); err != nil {
		t.Errorf("ecdsa on Alibaba Cloud = %v", err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rpk, _ := ssh.NewPublicKey(&rk.PublicKey)
	if err := (&PublicKey{Key: rpk}).CheckType(AWSKeyTypes); err != nil {
		t.Errorf("rsa on AWS = %v", err)
	}
}

type fakeLister struct {
	pairs []KeyPair
	err   error
}

func (f fakeLister) ListKeyPairs(context.Context) ([]KeyPair, error) { return f.pairs, f.err }

type fakeKeyPrompter struct {
	file, name, choice, pair string
	names                    []string // name answers tried in turn
	asked                    []string
	pairs                    []KeyPair
	local                    map[string]string
	files                    []KeyFileCandidate
}

func (p *fakeKeyPrompter) ChooseKeyPairOrCreate(pairs []KeyPair, local map[string]string) (string, error) {
	p.asked = append(p.asked, "pair")
	p.pairs, p.local = pairs, local
	return p.pair, nil
}
func (p *fakeKeyPrompter) KeyFile(c []KeyFileCandidate) (string, error) {
	p.asked = append(p.asked, "file")
	p.files = c
	return p.file, nil
}

// KeyPairName answers with names until one passes validate, like the
// terminal, which keeps the question open; then with name.
func (p *fakeKeyPrompter) KeyPairName(validate func(string) error) (string, error) {
	p.asked = append(p.asked, "name")
	for _, n := range p.names {
		if validate(n) == nil {
			return n, nil
		}
		p.asked = append(p.asked, "rejected:"+n)
	}
	if err := validate(p.name); err != nil {
		return "", ErrNothingToDo // the user would have left the question
	}
	return p.name, nil
}
func (p *fakeKeyPrompter) ChooseKeyPair(names []string) (string, error) {
	p.asked = append(p.asked, "choose:"+strings.Join(names, ","))
	return p.choice, nil
}

func TestResolveKeyPairAliyunFingerprint(t *testing.T) {
	line, _ := ed25519Line(t, "c")
	pk, _ := ParsePublicKey(line)
	lister := fakeLister{pairs: []KeyPair{{Name: "ops", Fingerprint: pk.FingerprintMD5Hex()}, {Name: "other", Fingerprint: "00"}}}
	in := KeyInput{Key: pk, Name: "polyctl", Match: MatchByFingerprintMD5, AllowedTypes: AliyunKeyTypes, MinNameLength: 2}
	plan, err := ResolveKeyPair(t.Context(), lister, in)
	if err != nil || plan.Create || plan.Name != "ops" || plan.Change.Action != Unchanged || plan.Change.Detail != "matched by fingerprint" ||
		len(plan.Notes) != 1 || !strings.Contains(plan.Notes[0], `ignoring --key-pair "polyctl"`) {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	// Not registered yet: created under --key-pair.
	in.Key, _ = ParsePublicKey(func() string { l, _ := ed25519Line(t, "new"); return l }())
	plan, err = ResolveKeyPair(t.Context(), lister, in)
	if err != nil || !plan.Create || plan.Name != "polyctl" || plan.Change.Action != Created || !strings.Contains(plan.Change.Detail, "import from --ssh-key (ed25519 SHA256:") {
		t.Fatalf("create plan = %+v, %v", plan, err)
	}
	// The name is taken by another key: never replaced.
	in.Name = "other"
	if _, err := ResolveKeyPair(t.Context(), lister, in); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "already exists with a different public key") {
		t.Errorf("name clash = %v", err)
	}
	in.Name = "x"
	if _, err := ResolveKeyPair(t.Context(), lister, in); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "too short") {
		t.Errorf("short name = %v", err)
	}
}

func TestResolveKeyPairNeedsANameToCreate(t *testing.T) {
	line, _ := ed25519Line(t, "c")
	pk, _ := ParsePublicKey(line)
	lister := fakeLister{}
	// Non-interactive: never a default name.
	_, err := ResolveKeyPair(t.Context(), lister, KeyInput{Key: pk, Match: MatchByPublicKey})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "pass --key-pair <name>") {
		t.Errorf("non-interactive without a name = %v", err)
	}
	// Interactive: asked, with the empty, the too short and the taken name
	// rejected inline until a valid one is given.
	lister = fakeLister{pairs: []KeyPair{{Name: "taken", Fingerprint: "00"}}}
	p := &fakeKeyPrompter{names: []string{"  ", "x", "taken", "BAD"}, name: "laptop"}
	plan, err := ResolveKeyPair(t.Context(), lister, KeyInput{Key: pk, Match: MatchByPublicKey, Interactive: true, Prompter: p, MinNameLength: 2,
		CheckName: func(s string) error {
			if s == "BAD" {
				return errors.New("bad")
			}
			return nil
		}})
	if err != nil || plan.Name != "laptop" || strings.Join(p.asked, ",") != "name,rejected:  ,rejected:x,rejected:taken,rejected:BAD" {
		t.Errorf("validated name = %+v, %v (asked %v)", plan, err, p.asked)
	}
	p = &fakeKeyPrompter{name: "laptop"}
	plan, err = ResolveKeyPair(t.Context(), lister, KeyInput{Key: pk, Match: MatchByPublicKey, Interactive: true, Prompter: p})
	if err != nil || plan.Name != "laptop" || !plan.Create {
		t.Errorf("asked name = %+v, %v", plan, err)
	}
}

func TestResolveKeyPairAWSPublicKeyMatches(t *testing.T) {
	line, k := ed25519Line(t, "c")
	pk, _ := ParsePublicKey(line)
	lister := fakeLister{pairs: []KeyPair{{Name: "b", PublicKey: k}, {Name: "a", PublicKey: k}, {Name: "c"}}}
	in := KeyInput{Key: pk, Match: MatchByPublicKey, AllowedTypes: AWSKeyTypes}
	if _, err := ResolveKeyPair(t.Context(), lister, in); !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), "a, b") {
		t.Errorf("several matches, non-interactive = %v", err)
	}
	in.Name = "b"
	if plan, err := ResolveKeyPair(t.Context(), lister, in); err != nil || plan.Name != "b" || plan.Create || len(plan.Notes) != 0 {
		t.Errorf("--key-pair among the matches = %+v, %v", plan, err)
	}
	in.Name, in.Interactive, in.Prompter = "", true, &fakeKeyPrompter{choice: "a"}
	if plan, err := ResolveKeyPair(t.Context(), lister, in); err != nil || plan.Name != "a" || plan.Change.Detail != "matched by public key" {
		t.Errorf("interactive choice = %+v, %v", plan, err)
	}
}

func TestResolveKeyPairWithoutKey(t *testing.T) {
	home := t.TempDir()
	line, _ := ed25519Line(t, "c")
	file := filepath.Join(home, "k.pub")
	_ = os.WriteFile(file, []byte(line), 0o600)
	lister := fakeLister{pairs: []KeyPair{{Name: "ops", ID: "kp-1"}}}
	if plan, err := ResolveKeyPair(t.Context(), lister, KeyInput{Name: "ops"}); err != nil || plan.Name != "ops" || plan.Create || plan.Change.ID != "kp-1" {
		t.Errorf("existing by name = %+v, %v", plan, err)
	}
	if _, err := ResolveKeyPair(t.Context(), lister, KeyInput{Name: "new"}); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "--ssh-key-file") {
		t.Errorf("missing by name, non-interactive = %v", err)
	}
	p := &fakeKeyPrompter{file: file}
	if plan, err := ResolveKeyPair(t.Context(), lister, KeyInput{Name: "new", Interactive: true, Prompter: p, Match: MatchByPublicKey}); err != nil || !plan.Create || plan.Name != "new" || p.asked[0] != "file" {
		t.Errorf("missing by name, interactive = %+v, %v (%v)", plan, err, p.asked)
	}
	if plan, err := ResolveKeyPair(t.Context(), lister, KeyInput{DefaultName: "ops"}); err != nil || plan.Name != "ops" || plan.Change.Detail != "default key pair" {
		t.Errorf("default = %+v, %v", plan, err)
	}
	if _, err := ResolveKeyPair(t.Context(), lister, KeyInput{DefaultName: "gone"}); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "--key-pair") {
		t.Errorf("neither, non-interactive = %v", err)
	}
	boom := errors.New("boom")
	if _, err := ResolveKeyPair(t.Context(), fakeLister{err: boom}, KeyInput{Name: "x1"}); !errors.Is(err, boom) {
		t.Errorf("list error = %v", err)
	}
}

func TestKeyPairPlanStep(t *testing.T) {
	line, _ := ed25519Line(t, "c")
	pk, _ := ParsePublicKey(line)
	plan, _ := ResolveKeyPair(t.Context(), fakeLister{}, KeyInput{Key: pk, Name: "new", Match: MatchByPublicKey})
	imports := 0
	step := plan.Step(func(_ context.Context, name string, key *PublicKey) (string, error) {
		imports++
		if name != "new" || key != pk {
			t.Errorf("import(%q, %v)", name, key)
		}
		return "kp-9", nil
	})
	p := &Plan{Steps: []Step{step}}
	if chs, err := p.Run(t.Context(), true); err != nil || imports != 0 || chs[0].Action != WouldCreate {
		t.Errorf("dry run = %+v, %v (%d imports)", chs, err, imports)
	}
	p = &Plan{Steps: []Step{step}}
	if chs, err := p.Run(t.Context(), false); err != nil || imports != 1 || chs[0].ID != "kp-9" || chs[0].Action != Created {
		t.Errorf("run = %+v, %v", chs, err)
	}
	existing := KeyPairPlan{Name: "ops", Change: Change{Resource: "key-pair/ops", Action: Unchanged, ID: "kp-1", Detail: "matched by fingerprint"}}
	p = &Plan{Steps: []Step{existing.Step(nil)}}
	if chs, _ := p.Run(t.Context(), false); chs[0].Action != Unchanged || chs[0].ID != "kp-1" || chs[0].Detail != "matched by fingerprint" {
		t.Errorf("existing step = %+v", chs)
	}
}

// A caller that names no matcher still finds an existing key pair, by key
// when the listing carries it, else by the MD5 fingerprint.
func TestResolveKeyPairDefaultMatcher(t *testing.T) {
	line, _ := ed25519Line(t, "d")
	pk, _ := ParsePublicKey(line)
	for name, kp := range map[string]KeyPair{
		"by key":         {Name: "mine", PublicKey: pk.Key},
		"by fingerprint": {Name: "mine", Fingerprint: pk.FingerprintMD5Hex()},
	} {
		plan, err := ResolveKeyPair(t.Context(), fakeLister{pairs: []KeyPair{kp}}, KeyInput{Key: pk, Name: "mine"})
		if err != nil || plan.Create || plan.Name != "mine" {
			t.Errorf("%s: plan = %+v, %v", name, plan, err)
		}
	}
}

func TestFingerprintAWSRSA(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rpk, _ := ssh.NewPublicKey(&rk.PublicKey)
	der, err := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(der)
	var want []string
	for _, b := range sum {
		want = append(want, fmt.Sprintf("%02x", b))
	}
	pk := &PublicKey{Key: rpk}
	if got := pk.FingerprintAWSRSA(); got != strings.Join(want, ":") {
		t.Errorf("FingerprintAWSRSA = %q, want %q", got, strings.Join(want, ":"))
	}
	// Not the MD5 of the wire bytes, which AWS does not report.
	if strings.ReplaceAll(pk.FingerprintAWSRSA(), ":", "") == pk.FingerprintMD5Hex() {
		t.Error("RSA fingerprint must be computed over the PKIX DER, not the wire bytes")
	}
	_, ek := ed25519Line(t, "c")
	if got := (&PublicKey{Key: ek}).FingerprintAWSRSA(); got != "" {
		t.Errorf("ed25519 FingerprintAWSRSA = %q, want empty", got)
	}
}

func TestMatchAWS(t *testing.T) {
	_, ek := ed25519Line(t, "c")
	_, other := ed25519Line(t, "d")
	ed := &PublicKey{Key: ek}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rpk, _ := ssh.NewPublicKey(&rk.PublicKey)
	rs := &PublicKey{Key: rpk}

	cases := []struct {
		name  string
		local *PublicKey
		kp    KeyPair
		want  bool
	}{
		{"same public key", ed, KeyPair{PublicKey: ek, Fingerprint: "unrelated"}, true},
		{"other public key wins over a matching fingerprint", ed, KeyPair{PublicKey: other, Fingerprint: ed.FingerprintAWSED25519()}, false},
		{"ed25519 padded fingerprint", ed, KeyPair{Fingerprint: ed.FingerprintAWSED25519()}, true},
		{"ed25519 unpadded with prefix", ed, KeyPair{Fingerprint: ed.FingerprintSHA256()}, true},
		{"rsa md5 of the DER", rs, KeyPair{Fingerprint: strings.ToUpper(rs.FingerprintAWSRSA())}, true},
		{"rsa md5 of the wire bytes", rs, KeyPair{Fingerprint: rs.FingerprintMD5Hex()}, false},
		{"rsa generated by AWS (SHA-1 of the private key)", rs, KeyPair{Fingerprint: "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"}, false},
		{"nothing to compare", ed, KeyPair{}, false},
	}
	for _, c := range cases {
		if got := MatchAWS.Match(c.local, c.kp); got != c.want {
			t.Errorf("%s: MatchAWS = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestResolveKeyPairNameFlag(t *testing.T) {
	line, _ := ed25519Line(t, "c")
	pk, err := ParsePublicKey(line)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ResolveKeyPair(t.Context(), fakeLister{}, KeyInput{Key: pk, Match: MatchAWS, NameFlag: "<name>"})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "pass <name>") || strings.Contains(err.Error(), "--key-pair") {
		t.Errorf("missing name with NameFlag = %v", err)
	}
	_, err = ResolveKeyPair(t.Context(), fakeLister{}, KeyInput{Key: pk, Match: MatchAWS})
	if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "pass --key-pair <name>") {
		t.Errorf("missing name by default = %v", err)
	}
	_, err = ResolveKeyPair(t.Context(), fakeLister{}, KeyInput{NameFlag: "<name>"})
	if !errors.Is(err, ErrInvalidInput) || strings.Contains(err.Error(), "--key-pair") {
		t.Errorf("nothing given with NameFlag = %v", err)
	}
}

// With neither a key nor a name, the interactive flow offers the existing
// key pairs first, marking those that hold a ~/.ssh/*.pub key, and creates
// one only when asked to.
func TestResolveKeyPairOffersExistingKeyPairs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	line, k := ed25519Line(t, "laptop")
	_ = os.WriteFile(filepath.Join(sshDir, "id_ed25519.pub"), []byte(line), 0o600)
	newLine, _ := ed25519Line(t, "new")
	_ = os.WriteFile(filepath.Join(sshDir, "new.pub"), []byte(newLine), 0o600)
	_ = os.WriteFile(filepath.Join(sshDir, "junk.pub"), []byte("not a key"), 0o600)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eck, _ := ssh.NewPublicKey(&ec.PublicKey)
	_ = os.WriteFile(filepath.Join(sshDir, "ec.pub"), ssh.MarshalAuthorizedKey(eck), 0o600)

	lister := fakeLister{pairs: []KeyPair{{Name: "zeta", Fingerprint: "00"}, {Name: "mine", PublicKey: k}}}
	in := KeyInput{Match: MatchByPublicKey, AllowedTypes: AWSKeyTypes, Interactive: true}

	p := &fakeKeyPrompter{pair: "zeta"}
	in.Prompter = p
	plan, err := ResolveKeyPair(t.Context(), lister, in)
	if err != nil || plan.Name != "zeta" || plan.Create || plan.Change.Detail != "chosen key pair" {
		t.Fatalf("chosen = %+v, %v", plan, err)
	}
	if len(p.pairs) != 2 || p.pairs[0].Name != "mine" || p.local["mine"] != filepath.Join(sshDir, "id_ed25519.pub") || len(p.local) != 1 {
		t.Errorf("offered %+v, local %v", p.pairs, p.local)
	}

	// "Import a new key pair": the usable files only (no junk, no ECDSA
	// on AWS), the registered one marked; then the name.
	p = &fakeKeyPrompter{file: filepath.Join(sshDir, "new.pub"), name: "work"}
	in.Prompter = p
	plan, err = ResolveKeyPair(t.Context(), lister, in)
	if err != nil || !plan.Create || plan.Name != "work" || strings.Join(p.asked, ",") != "pair,file,name" {
		t.Fatalf("create = %+v, %v (asked %v)", plan, err, p.asked)
	}
	var files []string
	for _, c := range p.files {
		files = append(files, filepath.Base(c.Path)+"="+strings.Join(c.Registered, "+"))
	}
	if strings.Join(files, " ") != "id_ed25519.pub=mine new.pub=" {
		t.Errorf("file candidates = %v", files)
	}

	// Picking a file that is already registered uses that key pair.
	p = &fakeKeyPrompter{file: filepath.Join(sshDir, "id_ed25519.pub")}
	in.Prompter = p
	if plan, err = ResolveKeyPair(t.Context(), lister, in); err != nil || plan.Create || plan.Name != "mine" {
		t.Errorf("registered file = %+v, %v", plan, err)
	}

	// No key pair yet: straight to the import.
	p = &fakeKeyPrompter{file: filepath.Join(sshDir, "new.pub"), name: "work"}
	in.Prompter = p
	if plan, err = ResolveKeyPair(t.Context(), fakeLister{}, in); err != nil || !plan.Create || strings.Join(p.asked, ",") != "file,name" {
		t.Errorf("no key pairs = %+v, %v (asked %v)", plan, err, p.asked)
	}
}
