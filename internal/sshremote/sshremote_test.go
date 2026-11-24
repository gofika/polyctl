package sshremote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/sshremote/sshtest"
)

type testKey struct {
	signer ssh.Signer
	priv   ed25519.PrivateKey
	pub    ssh.PublicKey
}

func newKey(t *testing.T) testKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{signer: s, priv: priv, pub: s.PublicKey()}
}

// writePrivate writes k as an OpenSSH private key file, encrypted when
// passphrase is set.
func writePrivate(t *testing.T, path string, k testKey, passphrase string) {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(k.priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(k.priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}

// home moves the home directory to a new temporary one (HOME and
// USERPROFILE) and clears the agent.
func home(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv(EnvAgent, "")
	old := GlobalKnownHosts
	GlobalKnownHosts = filepath.Join(h, "no-global-known-hosts")
	t.Cleanup(func() { GlobalKnownHosts = old })
	return h
}

func opts(srv *sshtest.Server, ks *KeySet, hk *HostKeys, users ...string) Options {
	return Options{Address: srv.Host, Port: srv.Port, Users: users, Keys: ks, HostKeys: hk}
}

func keys(signers ...ssh.Signer) *KeySet {
	ks := &KeySet{}
	for _, s := range signers {
		ks.add(Signer{Signer: s, Source: "test"})
	}
	return ks
}

func TestHostKeyRules(t *testing.T) {
	h := home(t)
	srv := sshtest.New(t)
	k := newKey(t)
	srv.Authorize("alice", k.pub)
	known := filepath.Join(h, ".ssh", "known_hosts")

	// Unknown host, non-interactive: a usage error naming the flag, and
	// known_hosts is not created.
	_, err := Dial(t.Context(), opts(srv, keys(k.signer), &HostKeys{}, "alice"))
	if !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "--accept-new-host-key") || !strings.Contains(err.Error(), ssh.FingerprintSHA256(srv.HostKey.PublicKey())) {
		t.Fatalf("unknown host non-interactive: %v", err)
	}
	if _, err := os.Stat(known); !os.IsNotExist(err) {
		t.Fatalf("known_hosts written: %v", err)
	}

	// Unknown host, the user declines: nothing to do, nothing written.
	asked := ""
	_, err = Dial(t.Context(), opts(srv, keys(k.signer), &HostKeys{Trust: func(host string, key ssh.PublicKey) (bool, error) {
		asked = host + " " + ssh.FingerprintSHA256(key)
		return false, nil
	}}, "alice"))
	if !errors.Is(err, ErrHostKeyDeclined) || !errors.Is(err, platform.ErrNothingToDo) {
		t.Fatalf("declined: %v", err)
	}
	if want := "[127.0.0.1]:"; !strings.HasPrefix(asked, want) || !strings.Contains(asked, ssh.FingerprintSHA256(srv.HostKey.PublicKey())) {
		t.Errorf("trust asked about %q", asked)
	}
	if _, err := os.Stat(known); !os.IsNotExist(err) {
		t.Fatalf("known_hosts written after a decline: %v", err)
	}

	// --accept-new-host-key: trusted, appended after an existing line
	// without a final newline, and asked once for several users.
	if err := os.MkdirAll(filepath.Dir(known), 0o700); err != nil {
		t.Fatal(err)
	}
	other := newKey(t)
	if err := os.WriteFile(known, []byte(strings.TrimSpace("example.org "+string(ssh.MarshalAuthorizedKey(other.pub)))), 0o600); err != nil {
		t.Fatal(err)
	}
	var notes []string
	hk := &HostKeys{AcceptNew: true, Notef: func(f string, a ...any) { notes = append(notes, f) }}
	c, err := Dial(t.Context(), opts(srv, keys(k.signer), hk, "nobody", "alice"))
	if err != nil {
		t.Fatalf("accept new: %v", err)
	}
	_ = c.Close()
	data, _ := os.ReadFile(known)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "example.org ") || !strings.HasPrefix(lines[1], "[127.0.0.1]:") || len(notes) != 1 {
		t.Fatalf("known_hosts after accept-new:\n%s\nnotes %v", data, notes)
	}

	// Known now: no question, no flag needed.
	c, err = Dial(t.Context(), opts(srv, keys(k.signer), &HostKeys{}, "alice"))
	if err != nil {
		t.Fatalf("known host: %v", err)
	}
	_ = c.Close()

	// Another server on the same address and port would present another
	// key: simulate by replacing the entry with a different key.
	wrong := strings.Replace(string(data), strings.Fields(lines[1])[2], strings.Fields(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.pub))))[1], 1)
	if err := os.WriteFile(known, []byte(wrong), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Dial(t.Context(), opts(srv, keys(k.signer), &HostKeys{AcceptNew: true, Trust: func(string, ssh.PublicKey) (bool, error) {
		t.Error("asked to trust a mismatched key")
		return true, nil
	}}, "alice"))
	if !errors.Is(err, ErrHostKeyMismatch) || !strings.Contains(err.Error(), "man-in-the-middle") || !strings.Contains(err.Error(), "ssh-keygen -R") {
		t.Fatalf("mismatch: %v", err)
	}
	if after, _ := os.ReadFile(known); string(after) != wrong {
		t.Errorf("known_hosts changed on a mismatch:\n%s", after)
	}

	// A host key marked @revoked is refused, not taken for an unknown
	// host that --accept-new-host-key trusts.
	revoked := "@revoked * " + string(ssh.MarshalAuthorizedKey(srv.HostKey.PublicKey()))
	if err := os.WriteFile(known, []byte(revoked), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Dial(t.Context(), opts(srv, keys(k.signer), &HostKeys{AcceptNew: true}, "alice"))
	if !errors.Is(err, ErrHostKeyMismatch) || !strings.Contains(err.Error(), "@revoked") {
		t.Fatalf("revoked: %v", err)
	}
	if after, _ := os.ReadFile(known); string(after) != revoked {
		t.Errorf("known_hosts changed on a revoked key:\n%s", after)
	}
}

// A host whose known_hosts entry is of another key type than the server's
// first choice is not a mismatch: the known types are negotiated.
func TestHostKeyAlgorithmsFollowKnownHosts(t *testing.T) {
	h := home(t)
	srv := sshtest.New(t)
	k := newKey(t)
	srv.Authorize("alice", k.pub)
	known := filepath.Join(h, ".ssh", "known_hosts")
	_ = os.MkdirAll(filepath.Dir(known), 0o700)
	line := "[127.0.0.1]:" + strconv.Itoa(srv.Port) + " " + string(ssh.MarshalAuthorizedKey(srv.HostKey.PublicKey()))
	if err := os.WriteFile(known, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	hk := &HostKeys{}
	if got := hk.Algorithms(srv.Addr()); len(got) != 1 || got[0] != ssh.KeyAlgoED25519 {
		t.Errorf("algorithms = %v", got)
	}
	if got := hk.Algorithms("192.0.2.1:22"); got != nil {
		t.Errorf("algorithms of an unknown host = %v", got)
	}
}

func acceptAll() *HostKeys { return &HostKeys{AcceptNew: true} }

// The login users are tried in order: a user whose key is not accepted and
// a user whose session is refused by a forced command are skipped, and the
// first that works is the login; the key that authenticated is known.
func TestLoginUserTrial(t *testing.T) {
	home(t)
	srv := sshtest.New(t)
	a, b := newKey(t), newKey(t)
	srv.Authorize("root", b.pub)
	srv.Force("root", `Please login as the user "ec2-user" rather than the user "root".`)
	srv.Authorize("ec2-user", b.pub)
	c, err := Dial(t.Context(), opts(srv, keys(a.signer, b.signer), acceptAll(), "centos", "root", "ec2-user"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.User != "ec2-user" || !SameKey(c.Key, b.pub) || c.KeySource != "test" {
		t.Errorf("login %s with %v (%s)", c.User, c.Key, c.KeySource)
	}
	if len(c.Tried) != 2 || c.Tried[0].User != "centos" || c.Tried[0].Reason != "no key accepted" ||
		c.Tried[1].User != "root" || !strings.Contains(c.Tried[1].Reason, "Please login as the user") {
		t.Errorf("tried %+v", c.Tried)
	}

	_, err = Dial(t.Context(), opts(srv, keys(a.signer), acceptAll(), "centos", "ec2-user"))
	var ae *AuthError
	if !errors.As(err, &ae) || len(ae.Tried) != 2 || !strings.Contains(err.Error(), "centos (no key accepted), ec2-user (no key accepted)") {
		t.Fatalf("no login: %v", err)
	}
}

// Without --identity-file the unencrypted default keys of ~/.ssh are used;
// an encrypted one is left for later and unlocked only when nothing else
// works (and a passphrase function is given).
func TestDefaultKeysAndUnlock(t *testing.T) {
	h := home(t)
	srv := sshtest.New(t)
	plain, locked := newKey(t), newKey(t)
	writePrivate(t, filepath.Join(h, ".ssh", "id_ed25519"), locked, "secret")
	writePrivate(t, filepath.Join(h, ".ssh", "id_rsa"), plain, "") // the name does not matter to the parser
	srv.Authorize("alice", plain.pub)
	ks, err := LoadKeys(KeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ks.Signers) != 1 || ks.Signers[0].Source != "~/.ssh/id_rsa" || len(ks.Locked) != 1 {
		t.Fatalf("signers %+v locked %v", ks.Signers, ks.Locked)
	}
	c, err := Dial(t.Context(), Options{Address: srv.Host, Port: srv.Port, Users: []string{"alice"}, Keys: ks, HostKeys: acceptAll(),
		Passphrase: func(string) (string, error) { t.Error("asked for a passphrase although a key worked"); return "", nil }})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()

	// Only the encrypted key is accepted: it is unlocked after the first
	// round, and the passphrase is asked once.
	srv2 := sshtest.New(t)
	srv2.Authorize("alice", locked.pub)
	ks, _ = LoadKeys(KeyOptions{})
	asked := 0
	c, err = Dial(t.Context(), Options{Address: srv2.Host, Port: srv2.Port, Users: []string{"alice"}, Keys: ks, HostKeys: acceptAll(),
		Passphrase: func(p string) (string, error) {
			asked++
			if asked == 1 {
				return "wrong", nil
			}
			return "secret", nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if asked != 2 || c.KeySource != "~/.ssh/id_ed25519" {
		t.Errorf("asked %d, source %s", asked, c.KeySource)
	}
}

func TestIdentityFile(t *testing.T) {
	h := home(t)
	srv := sshtest.New(t)
	k := newKey(t)
	srv.Authorize("alice", k.pub)
	path := filepath.Join(h, "keys", "deploy.pem")
	writePrivate(t, path, k, "pw")

	// Encrypted, non-interactive: a usage error naming SSH_AUTH_SOCK.
	if _, err := LoadKeys(KeyOptions{IdentityFile: path}); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), EnvAgent) {
		t.Fatalf("encrypted non-interactive: %v", err)
	}
	// A public key is refused.
	pubPath := path + ".pub"
	_ = os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(k.pub), 0o600)
	if _, err := LoadKeys(KeyOptions{IdentityFile: pubPath}); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("public key as identity: %v", err)
	}
	// Interactive: the passphrase is asked; the identity file is the only
	// key, even with an agent and default keys around.
	writePrivate(t, filepath.Join(h, ".ssh", "id_ed25519"), newKey(t), "")
	ks, err := LoadKeys(KeyOptions{IdentityFile: path, Passphrase: func(string) (string, error) { return "pw", nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(ks.Signers) != 1 || !strings.HasPrefix(ks.Signers[0].Source, "--identity-file ") {
		t.Fatalf("signers %+v", ks.Signers)
	}
	c, err := Dial(t.Context(), opts(srv, ks, acceptAll(), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	// Three wrong passphrases fail.
	if _, err := LoadKeys(KeyOptions{IdentityFile: path, Passphrase: func(string) (string, error) { return "no", nil }}); err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
}

// serveAgent serves keys from an SSH agent on a unix socket for the test
// (SSH_AUTH_SOCK).
func serveAgent(t *testing.T, keys ...testKey) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k.priv}); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, c); _ = c.Close() }()
		}
	}()
	t.Setenv(EnvAgent, sock)
}

// The agent's keys are offered; the one that authenticated is recorded.
func TestAgentKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test agent listens on a unix socket")
	}
	home(t)
	a, b := newKey(t), newKey(t)
	serveAgent(t, a, b)
	srv := sshtest.New(t)
	srv.Authorize("alice", b.pub)
	ks, err := LoadKeys(KeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()
	if len(ks.Signers) != 2 {
		t.Fatalf("agent signers %+v", ks.Signers)
	}
	c, err := Dial(t.Context(), opts(srv, ks, acceptAll(), "alice"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !SameKey(c.Key, b.pub) || c.KeySource != "SSH agent" {
		t.Errorf("key in use %v from %s", c.Key, c.KeySource)
	}
}

func TestCheckUser(t *testing.T) {
	for _, u := range []string{"ec2-user", "root", "ecs-user", "_svc", "Admin.1"} {
		if err := CheckUser(u, "--user"); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"", "-x", "a b", "a;b", "a'b", "1abc", strings.Repeat("a", 40)} {
		if err := CheckUser(u, "--user"); !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%q accepted", u)
		}
	}
}

func TestCustomAuthorizedKeysFile(t *testing.T) {
	for v, custom := range map[string]bool{
		"":                     false,
		".ssh/authorized_keys": false,
		".ssh/authorized_keys .ssh/authorized_keys2": false,
		"%h/.ssh/authorized_keys":                    false,
		"/etc/ssh/keys/%u":                           true,
		"none":                                       true,
	} {
		if got := (&AuthorizedKeys{AuthorizedKeysFile: v}).CustomFile(); got != custom {
			t.Errorf("%q: custom %v", v, got)
		}
	}
}

// With Match, only the key pair's key is loaded: from a default key, from
// an extra file (~/.ssh/<key pair>.pem), and from an encrypted file whose
// .pub sibling matches, whose passphrase alone is asked for; an encrypted
// key without .pub gets a note when no key matched, and without a way to
// ask, a matching encrypted key gets a note too.
func TestLoadKeysMatch(t *testing.T) {
	h := home(t)
	sshDir := filepath.Join(h, ".ssh")
	def, extra, enc, other, nopub := newKey(t), newKey(t), newKey(t), newKey(t), newKey(t)
	writePrivate(t, filepath.Join(sshDir, "id_ed25519"), def, "")
	writePrivate(t, filepath.Join(sshDir, "ops.pem"), extra, "")
	writePrivate(t, filepath.Join(sshDir, "id_ecdsa"), enc, "pw")
	_ = os.WriteFile(filepath.Join(sshDir, "id_ecdsa.pub"), ssh.MarshalAuthorizedKey(enc.pub), 0o644)
	writePrivate(t, filepath.Join(sshDir, "id_rsa"), other, "pw2")
	_ = os.WriteFile(filepath.Join(sshDir, "id_rsa.pub"), ssh.MarshalAuthorizedKey(other.pub), 0o644)
	writePrivate(t, filepath.Join(sshDir, "ops"), nopub, "pw3")
	files := []string{filepath.Join(sshDir, "ops.pem"), filepath.Join(sshDir, "ops")}

	load := func(want ssh.PublicKey, pass func(string) (string, error)) (*KeySet, []string) {
		t.Helper()
		var asked []string
		var p func(string) (string, error)
		if pass != nil {
			p = func(path string) (string, error) { asked = append(asked, filepath.Base(path)); return pass(path) }
		}
		ks, err := LoadKeys(KeyOptions{Match: func(k ssh.PublicKey) bool { return SameKey(k, want) }, Files: files, Passphrase: p})
		if err != nil {
			t.Fatal(err)
		}
		return ks, asked
	}
	pw := func(string) (string, error) { return "pw", nil }
	for _, c := range []struct {
		name string
		want testKey
		src  string
	}{{"default", def, "~/.ssh/id_ed25519"}, {"extra", extra, "~/.ssh/ops.pem"}, {"encrypted", enc, "~/.ssh/id_ecdsa"}} {
		ks, asked := load(c.want.pub, pw)
		if len(ks.Signers) != 1 || !SameKey(ks.Signers[0].PublicKey(), c.want.pub) || ks.Signers[0].Source != c.src || len(ks.Locked) != 0 {
			t.Errorf("%s: signers %+v locked %v", c.name, ks.Signers, ks.Locked)
		}
		if c.name == "encrypted" && strings.Join(asked, ",") != "id_ecdsa" || c.name != "encrypted" && len(asked) != 0 {
			t.Errorf("%s: passphrase asked for %v", c.name, asked)
		}
		if strings.Contains(strings.Join(ks.Notes, "\n"), "~/.ssh/ops is encrypted and has no readable") {
			t.Errorf("%s: a note about an undecidable file although a key matched: %v", c.name, ks.Notes)
		}
	}
	ks, _ := load(newKey(t).pub, pw)
	if len(ks.Signers) != 0 || !strings.Contains(strings.Join(ks.Notes, "\n"), "~/.ssh/ops is encrypted and has no readable") {
		t.Errorf("no match: %+v %v", ks.Signers, ks.Notes)
	}
	ks, _ = load(enc.pub, nil)
	if len(ks.Signers) != 0 || !strings.Contains(strings.Join(ks.Notes, "\n"), "~/.ssh/id_ecdsa holds the instance's key pair but is encrypted") {
		t.Errorf("non-interactive: %+v %v", ks.Signers, ks.Notes)
	}
}

// A matching key the SSH agent already holds asks for no passphrase of the
// encrypted file that holds it too, in either flow.
func TestLoadKeysMatchAgentFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test agent listens on a unix socket")
	}
	h := home(t)
	sshDir := filepath.Join(h, ".ssh")
	k := newKey(t)
	writePrivate(t, filepath.Join(sshDir, "id_ed25519"), k, "pw")
	_ = os.WriteFile(filepath.Join(sshDir, "id_ed25519.pub"), ssh.MarshalAuthorizedKey(k.pub), 0o644)
	serveAgent(t, k)
	for _, pass := range []func(string) (string, error){nil, func(p string) (string, error) {
		t.Errorf("passphrase asked for %s although the agent holds the key", p)
		return "", nil
	}} {
		ks, err := LoadKeys(KeyOptions{Match: func(p ssh.PublicKey) bool { return SameKey(p, k.pub) }, Passphrase: pass})
		if err != nil {
			t.Fatal(err)
		}
		if len(ks.Signers) != 1 || ks.Signers[0].Source != "SSH agent" || len(ks.Notes) != 0 {
			t.Errorf("signers %+v notes %v", ks.Signers, ks.Notes)
		}
		ks.Close()
	}
}
