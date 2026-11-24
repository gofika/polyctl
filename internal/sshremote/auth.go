package sshremote

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/gofika/polyctl/internal/platform"
)

// Signer is a private key usable for authentication and where it came from
// ("~/.ssh/id_ed25519", "SSH agent", "--identity-file key.pem").
type Signer struct {
	ssh.Signer
	Source string
}

// DefaultKeyNames are the private keys of ~/.ssh tried when no
// --identity-file is given, in this order (as OpenSSH tries them).
var DefaultKeyNames = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// EnvAgent is the environment variable that names the SSH agent socket.
const EnvAgent = "SSH_AUTH_SOCK"

// maxKeyFile bounds what is read from a private key file.
const maxKeyFile = 1 << 20

// KeyOptions say where the private keys come from.
type KeyOptions struct {
	// IdentityFile is --identity-file. When set it is the only key used
	// (as OpenSSH's IdentitiesOnly): neither the agent nor the default
	// keys are offered, so a server's limit of authentication attempts is
	// not used up by keys that were not asked for.
	IdentityFile string
	// Passphrase asks for the passphrase of an encrypted key (the prompt
	// names path); nil in the non-interactive flow, where an encrypted
	// --identity-file is a usage error and encrypted default keys are
	// left out.
	Passphrase func(path string) (string, error)
	// NoAgent leaves the SSH agent out.
	NoAgent bool
}

// KeySet holds the signers of a connection attempt. Close releases the
// agent connection, which agent signers need until authentication is over.
type KeySet struct {
	Signers []Signer
	// Locked are the encrypted default keys that were not unlocked (see
	// Unlock): asked for only when nothing else authenticates.
	Locked []string
	// Notes are remarks for stderr (an unreadable key, an agent that did
	// not answer).
	Notes   []string
	closers []io.Closer
}

// Close releases the agent connection, if any.
func (k *KeySet) Close() {
	for _, c := range k.closers {
		_ = c.Close()
	}
	k.closers = nil
}

// LoadKeys gathers the signers of opts: the --identity-file alone, else the
// keys of the SSH agent (SSH_AUTH_SOCK) followed by the unencrypted default
// keys of ~/.ssh. Encrypted default keys go to Locked. A private key is
// read into memory only; nothing is ever written.
func LoadKeys(opts KeyOptions) (*KeySet, error) {
	ks := &KeySet{}
	if opts.IdentityFile != "" {
		s, err := loadIdentity(opts.IdentityFile, opts.Passphrase)
		if err != nil {
			return nil, err
		}
		ks.Signers = append(ks.Signers, s)
		return ks, nil
	}
	if !opts.NoAgent {
		if sock := os.Getenv(EnvAgent); sock != "" {
			conn, err := net.Dial("unix", sock)
			if err != nil {
				ks.Notes = append(ks.Notes, fmt.Sprintf("note: the SSH agent at %s=%s did not answer: %v", EnvAgent, sock, err))
			} else {
				signers, err := agent.NewClient(conn).Signers()
				if err != nil {
					_ = conn.Close()
					ks.Notes = append(ks.Notes, fmt.Sprintf("note: the SSH agent did not list its keys: %v", err))
				} else {
					ks.closers = append(ks.closers, conn)
					for _, s := range signers {
						ks.add(Signer{Signer: s, Source: "SSH agent"})
					}
				}
			}
		}
	}
	for _, path := range defaultKeyFiles() {
		data, err := readKeyFile(path)
		if err != nil {
			continue
		}
		s, err := ssh.ParsePrivateKey(data)
		var missing *ssh.PassphraseMissingError
		switch {
		case errors.As(err, &missing):
			ks.Locked = append(ks.Locked, path)
		case err != nil:
			ks.Notes = append(ks.Notes, fmt.Sprintf("note: %s is not a usable private key: %v", homeRel(path), err))
		default:
			ks.add(Signer{Signer: s, Source: homeRel(path)})
		}
	}
	return ks, nil
}

// Unlock asks for the passphrases of the locked default keys and adds the
// ones unlocked; an empty answer skips a key. It returns how many were
// added.
func (k *KeySet) Unlock(passphrase func(path string) (string, error)) (int, error) {
	if passphrase == nil {
		return 0, nil
	}
	added := 0
	locked := k.Locked
	k.Locked = nil
	for _, path := range locked {
		data, err := readKeyFile(path)
		if err != nil {
			continue
		}
		s, err := unlock(path, data, passphrase, true)
		if err != nil {
			return added, err
		}
		if s != nil && k.add(Signer{Signer: s, Source: homeRel(path)}) {
			added++
		}
	}
	return added, nil
}

// add appends s unless the same public key is there already.
func (k *KeySet) add(s Signer) bool {
	pub := s.PublicKey().Marshal()
	for _, o := range k.Signers {
		if bytes.Equal(o.PublicKey().Marshal(), pub) {
			return false
		}
	}
	k.Signers = append(k.Signers, s)
	return true
}

func loadIdentity(path string, passphrase func(string) (string, error)) (Signer, error) {
	full := platform.ExpandHome(strings.TrimSpace(path))
	data, err := readKeyFile(full)
	if err != nil {
		return Signer{}, fmt.Errorf("%w: --identity-file: %v", platform.ErrInvalidInput, err)
	}
	if _, _, _, _, perr := ssh.ParseAuthorizedKey(data); perr == nil {
		return Signer{}, fmt.Errorf("%w: --identity-file %s is a public key; pass the private key (the file without .pub)", platform.ErrInvalidInput, path)
	}
	src := "--identity-file " + path
	s, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		if passphrase == nil {
			return Signer{}, fmt.Errorf("%w: --identity-file %s is encrypted, and polyctl cannot ask for its passphrase in the non-interactive flow: add the key to an SSH agent (ssh-add) and run polyctl with %s set, without --identity-file", platform.ErrInvalidInput, path, EnvAgent)
		}
		s, err = unlock(full, data, passphrase, false)
		if err != nil {
			return Signer{}, err
		}
	case err != nil:
		return Signer{}, fmt.Errorf("%w: --identity-file %s is not a usable private key: %v", platform.ErrInvalidInput, path, err)
	}
	return Signer{Signer: s, Source: src}, nil
}

// unlock asks for the passphrase of an encrypted key, three times at most.
// With skippable, an empty answer skips the key (nil, nil).
func unlock(path string, data []byte, passphrase func(string) (string, error), skippable bool) (ssh.Signer, error) {
	for range 3 {
		pass, err := passphrase(path)
		if err != nil {
			return nil, err
		}
		if pass == "" && skippable {
			return nil, nil
		}
		s, err := ssh.ParsePrivateKeyWithPassphrase(data, []byte(pass))
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, x509.IncorrectPasswordError) {
			return nil, fmt.Errorf("%s: %w", homeRel(path), err)
		}
	}
	return nil, fmt.Errorf("%s: wrong passphrase", homeRel(path))
}

func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyFile {
		return nil, fmt.Errorf("%s is too large to be a private key", path)
	}
	return data, nil
}

func defaultKeyFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(DefaultKeyNames))
	for _, n := range DefaultKeyNames {
		out = append(out, filepath.Join(home, ".ssh", n))
	}
	return out
}

// homeRel shows a path under the home directory as ~/...
func homeRel(path string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(filepath.Join("~", rel))
		}
	}
	return path
}
