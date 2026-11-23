package app

import (
	"errors"
	"fmt"

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
	cmd.Flags().StringVar(&f.SSHKey, "ssh-key", "", "SSH public key itself, one line (\"ssh-ed25519 AAAA... comment\"); for a file use --ssh-key-file")
	cmd.Flags().StringVar(&f.SSHKeyFile, "ssh-key-file", "", "file holding the SSH public key (~ is expanded; a private key is refused)")
	cmd.Flags().StringVar(&f.KeyPair, "key-pair", "", "name of the key pair on the platform: an existing one is used, a missing one is imported from --ssh-key / --ssh-key-file")
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

const otherKeyFile = "\x00other"

func (p keyPrompter) KeyFile(candidates []string) (string, error) {
	pick := p.rt.Pick()
	if len(candidates) > 0 {
		opts := make([]prompt.Option, 0, len(candidates)+1)
		for _, c := range candidates {
			opts = append(opts, prompt.Option{Label: c, Value: c})
		}
		opts = append(opts, prompt.Option{Label: "Another file...", Value: otherKeyFile})
		v, err := pick.Select("Public key file to import", opts, "")
		if err != nil {
			return "", cancelled(err)
		}
		if v != otherKeyFile {
			return v, nil
		}
	}
	v, err := pick.Input("Path of the public key file (.pub)", "", func(s string) error {
		if s == "" {
			return errors.New("a path is required")
		}
		return nil
	})
	return v, cancelled(err)
}

func (p keyPrompter) KeyPairName() (string, error) {
	v, err := p.rt.Pick().Input("Name of the key pair to create (empty cancels)", "", nil)
	return v, cancelled(err)
}

func (p keyPrompter) ChooseKeyPair(names []string) (string, error) {
	opts := make([]prompt.Option, 0, len(names))
	for _, n := range names {
		opts = append(opts, prompt.Option{Label: n, Value: n})
	}
	v, err := p.rt.Pick().Select("The key is registered under several key pairs; use which one?", opts, "")
	return v, cancelled(err)
}

// cancelled turns a question that was left into "nothing to do".
func cancelled(err error) error {
	if errors.Is(err, prompt.ErrAborted) {
		return fmt.Errorf("%w: cancelled", platform.ErrNothingToDo)
	}
	return err
}
