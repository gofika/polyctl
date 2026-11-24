package sshremote

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/gofika/polyctl/internal/platform"
)

// ErrHostKeyMismatch is a host whose key differs from the one known_hosts
// holds for it. polyctl refuses to connect and never overwrites the entry.
var ErrHostKeyMismatch = errors.New("host key mismatch")

// ErrHostKeyDeclined is an unknown host key the user chose not to trust:
// nothing was changed, which is not a failure.
var ErrHostKeyDeclined = fmt.Errorf("%w: the host key was not trusted, nothing was changed", platform.ErrNothingToDo)

// GlobalKnownHosts is the system-wide known hosts file, read (never
// written) when it exists.
var GlobalKnownHosts = "/etc/ssh/ssh_known_hosts"

// HostKeys verifies host keys against known_hosts, as OpenSSH with
// StrictHostKeyChecking=ask (interactive) or accept-new (--accept-new-host-key):
//
//   - a key known_hosts holds for the host is accepted;
//   - a host known_hosts lists with other keys only is refused
//     (ErrHostKeyMismatch: possibly a man-in-the-middle), and the file is
//     never changed;
//   - an unknown host is trusted with AcceptNew, or when Trust says so (the
//     interactive flow shows the fingerprint and asks, default No); its key
//     is then appended to KnownHosts. Without either it is a usage error
//     naming --accept-new-host-key.
type HostKeys struct {
	// KnownHosts is the file keys are read from and a newly trusted key
	// is appended to; "" means ~/.ssh/known_hosts.
	KnownHosts string
	// AcceptNew trusts the key of an unknown host without asking.
	AcceptNew bool
	// Trust asks whether to trust the key of an unknown host; nil in the
	// non-interactive flow.
	Trust func(host string, key ssh.PublicKey) (bool, error)
	// Notef prints a note on stderr (a key added to known_hosts).
	Notef func(format string, args ...any)
	// NoSave trusts a new key for this run only, without writing
	// known_hosts (a dry run writes nothing).
	NoSave bool

	mu sync.Mutex
	// accepted holds the keys trusted in this run, by address, so that
	// trying several login users asks once.
	accepted map[string][]byte
	// err is the last refusal of the callback: the ssh package wraps it
	// in its own handshake error.
	err error
}

func (h *HostKeys) path() string {
	if h.KnownHosts != "" {
		return h.KnownHosts
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

func (h *HostKeys) files() []string {
	var out []string
	for _, f := range []string{h.path(), GlobalKnownHosts} {
		if f == "" {
			continue
		}
		if fi, err := os.Stat(f); err == nil && fi.Mode().IsRegular() {
			out = append(out, f)
		}
	}
	return out
}

// known returns the keys the known_hosts files hold for addr (host:port).
func (h *HostKeys) known(addr string) ([]ssh.PublicKey, error) {
	files := h.files()
	if len(files) == 0 {
		return nil, nil
	}
	cb, err := knownhosts.New(files...)
	if err != nil {
		return nil, fmt.Errorf("reading known_hosts: %w", err)
	}
	// A throwaway key matches nothing, so the error lists every key
	// known for the host.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	probe, _ := ssh.NewPublicKey(pub)
	err = cb(addr, tcpAddr(addr), probe)
	var ke *knownhosts.KeyError
	if errors.As(err, &ke) {
		out := make([]ssh.PublicKey, 0, len(ke.Want))
		for _, w := range ke.Want {
			out = append(out, w.Key)
		}
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// Algorithms are the host key algorithms to negotiate with addr: those of
// the keys known_hosts holds for it, so that a server that also has a key
// of another type does not look like a mismatch; nil (the defaults) for an
// unknown host.
func (h *HostKeys) Algorithms(addr string) []string {
	keys, err := h.known(addr)
	if err != nil || len(keys) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, k := range keys {
		algos := []string{k.Type()}
		if k.Type() == ssh.KeyAlgoRSA {
			algos = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
		}
		for _, a := range algos {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// Callback is the ssh.HostKeyCallback of the rules above.
func (h *HostKeys) Callback() ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := h.check(hostname, key)
		h.mu.Lock()
		h.err = err
		h.mu.Unlock()
		return err
	}
}

// LastError is the refusal of the last callback, if any.
func (h *HostKeys) LastError() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

func (h *HostKeys) check(addr string, key ssh.PublicKey) error {
	h.mu.Lock()
	if b, ok := h.accepted[addr]; ok && bytes.Equal(b, key.Marshal()) {
		h.mu.Unlock()
		return nil
	}
	h.mu.Unlock()
	known, err := h.known(addr)
	if err != nil {
		return err
	}
	for _, k := range known {
		if bytes.Equal(k.Marshal(), key.Marshal()) {
			return nil
		}
	}
	host := knownhosts.Normalize(addr)
	fp := ssh.FingerprintSHA256(key)
	if len(known) > 0 {
		return fmt.Errorf("%w: WARNING: the %s host key of %s is %s, which is not the key %s holds for it. Someone could be eavesdropping on the connection (a man-in-the-middle attack), or the host key changed (the instance was rebuilt, or the address now belongs to another instance). polyctl does not connect and does not change known_hosts; if the change is expected, remove the old entry with `ssh-keygen -R %s` and run the command again",
			ErrHostKeyMismatch, algorithmName(key.Type()), host, fp, homeRel(h.path()), host)
	}
	switch {
	case h.AcceptNew:
	case h.Trust == nil:
		return fmt.Errorf("%w: the host key of %s is not in %s (%s key %s); polyctl cannot ask whether to trust it in the non-interactive flow: verify the fingerprint and pass --accept-new-host-key, or add the key to known_hosts first",
			platform.ErrInvalidInput, host, homeRel(h.path()), algorithmName(key.Type()), fp)
	default:
		ok, err := h.Trust(host, key)
		if err != nil {
			return err
		}
		if !ok {
			return ErrHostKeyDeclined
		}
	}
	if !h.NoSave {
		if err := h.appendKey(host, key); err != nil {
			return err
		}
	}
	h.mu.Lock()
	if h.accepted == nil {
		h.accepted = map[string][]byte{}
	}
	h.accepted[addr] = key.Marshal()
	h.mu.Unlock()
	switch {
	case h.Notef == nil:
	case h.NoSave:
		h.Notef("note: trusted the %s host key of %s (%s) for this run only; %s is not changed", algorithmName(key.Type()), host, fp, homeRel(h.path()))
	default:
		h.Notef("note: added the %s host key of %s (%s) to %s", algorithmName(key.Type()), host, fp, homeRel(h.path()))
	}
	return nil
}

// appendKey adds a line for host to KnownHosts, creating the file (0600)
// and its directory (0700) when missing. Existing lines are never touched.
func (h *HostKeys) appendKey(host string, key ssh.PublicKey) error {
	path := h.path()
	if path == "" {
		return errors.New("cannot locate known_hosts: no home directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("known_hosts: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("known_hosts: %w", err)
	}
	defer f.Close()
	line := knownhosts.Line([]string{host}, key) + "\n"
	// A file that does not end with a newline gets one first, so the new
	// line does not join the last one.
	if fi, err := f.Stat(); err == nil && fi.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, fi.Size()-1); err == nil && last[0] != '\n' {
			line = "\n" + line
		}
	}
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("known_hosts: %w", err)
	}
	return f.Close()
}

func tcpAddr(addr string) net.Addr {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return &net.TCPAddr{}
	}
	ip := net.ParseIP(host)
	p, _ := net.LookupPort("tcp", port)
	return &net.TCPAddr{IP: ip, Port: p}
}

// algorithmName is the short name of a key type ("ed25519").
func algorithmName(t string) string {
	switch t {
	case ssh.KeyAlgoRSA:
		return "RSA"
	case ssh.KeyAlgoED25519:
		return "ED25519"
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return "ECDSA"
	}
	return t
}
