package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// KeyFlags are the SSH key flags of commands that bind a key pair:
// --ssh-key (the public key itself), --ssh-key-file (a file holding it) and
// --key-pair (the name of the key pair on the platform).
type KeyFlags struct {
	SSHKey     string
	SSHKeyFile string
	KeyPair    string
}

// AddKeyFlags registers the SSH key flags on cmd.
func AddKeyFlags(cmd *cobra.Command, f *KeyFlags) {
	AddPublicKeyFlags(cmd, f)
	cmd.Flags().StringVar(&f.KeyPair, "key-pair", "", "name of the key pair on the platform: an existing one is used, a missing one is imported from --ssh-key / --ssh-key-file")
}

// AddPublicKeyFlags registers --ssh-key and --ssh-key-file only, for
// commands that take the key pair name as an argument (key-pair import,
// key-pair ensure).
func AddPublicKeyFlags(cmd *cobra.Command, f *KeyFlags) {
	cmd.Flags().StringVar(&f.SSHKey, "ssh-key", "", "SSH public key itself, one line (\"ssh-ed25519 AAAA... comment\"); for a file use --ssh-key-file")
	cmd.Flags().StringVar(&f.SSHKeyFile, "ssh-key-file", "", "file holding the SSH public key (~ is expanded; a private key is refused)")
	// --ssh-key and --ssh-key-file are mutually exclusive, but that is
	// checked by PublicKey and not with a cobra flag group: cobra reports
	// a group violation as a plain error (exit code 1), not a usage error.
	_ = cmd.MarkFlagFilename("ssh-key-file", "pub")
}

// PublicKey returns the key of --ssh-key or --ssh-key-file, or nil when
// neither was given. Both together are a usage error.
func (f *KeyFlags) PublicKey() (*platform.PublicKey, error) {
	switch {
	case f.SSHKey != "" && f.SSHKeyFile != "":
		return nil, UsageErrf("--ssh-key and --ssh-key-file are mutually exclusive")
	case f.SSHKey != "":
		return platform.ParsePublicKey(f.SSHKey)
	case f.SSHKeyFile != "":
		return platform.LoadPublicKeyFile(f.SSHKeyFile)
	}
	return nil, nil
}

// Given reports whether any of the key flags was given.
func (f *KeyFlags) Given() bool { return f.SSHKey != "" || f.SSHKeyFile != "" || f.KeyPair != "" }

// KeyInput completes base (the platform's matcher, key types, name rules)
// with the flags and the flow of the command.
func (rt *Runtime) KeyInput(f *KeyFlags, base platform.KeyInput) (platform.KeyInput, error) {
	key, err := f.PublicKey()
	if err != nil {
		return base, err
	}
	base.Key, base.Name = key, f.KeyPair
	base.Interactive = rt.Interactive()
	if base.Interactive {
		base.Prompter = keyPrompter{rt}
	}
	return base, nil
}

// keyPrompter asks the key pair questions with the runtime's picker.
type keyPrompter struct{ rt *Runtime }

const (
	otherKeyFile = "\x00other"
	newKeyPair   = "\x00new"
)

// ChooseKeyPairOrCreate lists the existing key pairs, those holding a local
// ~/.ssh/*.pub key marked (and the first of them preselected), with
// "Import a new key pair..." last.
func (p keyPrompter) ChooseKeyPairOrCreate(pairs []platform.KeyPair, local map[string]string) (string, error) {
	opts := make([]prompt.Option, 0, len(pairs)+1)
	def := ""
	for _, kp := range pairs {
		label := kp.Name
		if fp := kp.DisplayFingerprint(); fp != "" {
			label += "  " + fp
		}
		if f, ok := local[kp.Name]; ok {
			label += "  [matches " + homeRelative(f) + "]"
			if def == "" {
				def = kp.Name
			}
		}
		opts = append(opts, prompt.Option{Label: label, Value: kp.Name})
	}
	opts = append(opts, prompt.Option{Label: "Import a new key pair from a public key file...", Value: newKeyPair})
	v, err := p.rt.Pick().Select("Key pair", opts, def)
	if err != nil || v == newKeyPair {
		return "", err
	}
	return v, nil
}

// KeyFile offers the usable ~/.ssh/*.pub files, each with its type,
// fingerprint and comment and the key pairs already holding it, and
// "Another file..." for a path checked as it is typed.
func (p keyPrompter) KeyFile(candidates []platform.KeyFileCandidate) (string, error) {
	pick := p.rt.Pick()
	if len(candidates) > 0 {
		opts := make([]prompt.Option, 0, len(candidates)+1)
		def := ""
		for _, c := range candidates {
			label := homeRelative(c.Path) + "  " + c.Key.Summary()
			if len(c.Registered) > 0 {
				label += "  [already key pair " + strings.Join(c.Registered, ", ") + "]"
			} else if def == "" || filepath.Base(c.Path) == "id_ed25519.pub" {
				def = c.Path
			}
			opts = append(opts, prompt.Option{Label: label, Value: c.Path})
		}
		opts = append(opts, prompt.Option{Label: "Another file...", Value: otherKeyFile})
		v, err := pick.Select("Public key file to import", opts, def)
		if err != nil {
			return "", err
		}
		if v != otherKeyFile {
			return v, nil
		}
	}
	return pick.Input("Path of the public key file (.pub)", "", func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("a path is required")
		}
		_, err := platform.LoadPublicKeyFile(s)
		return err
	})
}

func (p keyPrompter) KeyPairName(validate func(string) error) (string, error) {
	return p.rt.Pick().Input("Name of the new key pair", "", validate)
}

func (p keyPrompter) ChooseKeyPair(names []string) (string, error) {
	opts := make([]prompt.Option, 0, len(names))
	for _, n := range names {
		opts = append(opts, prompt.Option{Label: n, Value: n})
	}
	return p.rt.Pick().Select("The key is registered under several key pairs; use which one?", opts, "")
}

// homeRelative shows a path under the home directory as ~/...
func homeRelative(path string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(filepath.Join("~", rel))
		}
	}
	return path
}
