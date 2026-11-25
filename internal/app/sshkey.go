package app

import (
	"errors"
	"fmt"
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
	typedKey     = "\x00typed"
	newKeyPair   = "\x00new"
	typedKeyPair = "\x00new-typed"
	importAgain  = "\x00again"
)

// Labels of the entries that import a new key pair or ask for its key.
const (
	labelImportFromFile = "Import a new key pair from a public key file..."
	labelImportTyped    = "Import a new key pair by entering its public key..."
	labelTypedKey       = "Enter a public key..."
)

// ChooseKeyPairOrCreate lists the existing key pairs as "name  fingerprint
// [matches ~/.ssh/id.pub]" ("-" for a fingerprint that is not known), those
// holding a local ~/.ssh/*.pub key marked (and the first of them
// preselected), with
// "Import a new key pair from a public key file..." and "... by entering
// its public key..." last.
func (p keyPrompter) ChooseKeyPairOrCreate(pairs []platform.KeyPair, local map[string]string) (string, platform.KeySource, error) {
	opts := make([]prompt.Option, 0, len(pairs)+2)
	def := ""
	for _, kp := range pairs {
		match := ""
		if f, ok := local[kp.Name]; ok {
			match = "[matches " + HomeRelative(f) + "]"
			if def == "" {
				def = kp.Name
			}
		}
		opts = append(opts, prompt.Option{Label: prompt.Cells(kp.Name, kp.DisplayFingerprint(), match), Value: kp.Name})
	}
	opts = append(opts, prompt.Option{Label: labelImportFromFile, Value: newKeyPair},
		prompt.Option{Label: labelImportTyped, Value: typedKeyPair})
	v, err := p.rt.Pick().Select("Key pair", opts, def)
	switch {
	case err != nil:
		return "", platform.KeyFromFile, err
	case v == newKeyPair:
		return "", platform.KeyFromFile, nil
	case v == typedKeyPair:
		return "", platform.KeyTyped, nil
	}
	return v, platform.KeyFromFile, nil
}

// NewKey offers the usable ~/.ssh/*.pub files, each with its type,
// fingerprint and comment and the key pairs already holding it, "Another
// file..." for a path and "Enter a public key..." for the key itself, both
// checked as they are typed. src KeyTyped asks for the key itself only.
func (p keyPrompter) NewKey(src platform.KeySource, candidates []platform.KeyFileCandidate, check func(*platform.PublicKey) error) (*platform.PublicKey, error) {
	choice := typedKey
	if src != platform.KeyTyped {
		var err error
		if choice, err = PickKeyFile(p.rt.Pick(), "Public key to import", candidates); err != nil {
			return nil, err
		}
	}
	switch choice {
	case typedKey:
		return AskTypedKey(p.rt.Pick(), "Public key (one line: \"ssh-ed25519 AAAA... comment\")", check)
	case otherKeyFile:
		return AskKeyFile(p.rt.Pick(), check)
	}
	key, err := platform.LoadPublicKeyFile(choice)
	if err != nil {
		return nil, err
	}
	return key, check(key)
}

// PickKeyFile is the shared choice of a public key: the usable
// ~/.ssh/*.pub candidates as "path  type  fingerprint  comment  [note]"
// (the note names the key pairs holding it; "-" for a key without a
// comment that has a note), "Another file..." and "Enter a public key...". It returns the path
// of a candidate, or IsOtherKeyFile / IsTypedKey of the answer tells which
// of the last two entries was chosen.
func PickKeyFile(pick prompt.Picker, title string, candidates []platform.KeyFileCandidate) (string, error) {
	opts := make([]prompt.Option, 0, len(candidates)+2)
	def := ""
	for _, c := range candidates {
		algo, fp, comment := c.Key.SummaryCells()
		note := ""
		if c.Note != "" {
			note = "[" + c.Note + "]"
		} else if len(c.Registered) > 0 {
			note = "[already key pair " + strings.Join(c.Registered, ", ") + "]"
		} else if def == "" || filepath.Base(c.Path) == "id_ed25519.pub" {
			def = c.Path
		}
		opts = append(opts, prompt.Option{Label: prompt.Cells(HomeRelative(c.Path), algo, fp, comment, note), Value: c.Path})
	}
	other := "Another file..."
	if len(candidates) == 0 {
		other = "A public key file..."
	}
	opts = append(opts, prompt.Option{Label: other, Value: otherKeyFile}, prompt.Option{Label: labelTypedKey, Value: typedKey})
	return pick.Select(title, opts, def)
}

// IsOtherKeyFile reports the "Another file..." answer of PickKeyFile.
func IsOtherKeyFile(v string) bool { return v == otherKeyFile }

// IsTypedKey reports the "Enter a public key..." answer of PickKeyFile.
func IsTypedKey(v string) bool { return v == typedKey }

// AskKeyFile asks for the path of a public key file, checked as it is
// typed (a public key, of a type check accepts).
func AskKeyFile(pick prompt.Picker, check func(*platform.PublicKey) error) (*platform.PublicKey, error) {
	path, err := pick.Input("Path of the public key file (.pub)", "", func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("a path is required")
		}
		k, err := platform.LoadPublicKeyFile(s)
		if err == nil && check != nil {
			err = check(k)
		}
		return inlineErr(err)
	})
	if err != nil {
		return nil, err
	}
	key, err := platform.LoadPublicKeyFile(path)
	if err == nil && check != nil {
		err = check(key)
	}
	return key, err
}

// AskTypedKey asks for a public key itself (one OpenSSH authorized_keys
// line, typed or pasted), checked as it is typed: a private key, a file
// path and a key of a type check refuses are explained inline.
func AskTypedKey(pick prompt.Picker, title string, check func(*platform.PublicKey) error) (*platform.PublicKey, error) {
	text, err := pick.Input(title, "", func(s string) error {
		k, err := platform.ParseTypedPublicKey(s)
		if err == nil && check != nil {
			err = check(k)
		}
		return inlineErr(err)
	})
	if err != nil {
		return nil, err
	}
	key, err := platform.ParseTypedPublicKey(text)
	if err == nil && check != nil {
		err = check(key)
	}
	return key, err
}

// inlineErr drops the "invalid input: " prefix of an error shown under a
// question.
func inlineErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": "))
}

// UseRegistered says that the key is already registered and offers each
// key pair holding it (the first preselected) and importing it again.
func (p keyPrompter) UseRegistered(names []string, importAs string) (string, error) {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = fmt.Sprintf("%q", n)
	}
	title := "This public key is already registered as key pair " + quoted[0]
	if len(names) > 1 {
		title = "This public key is already registered as key pairs " + strings.Join(quoted, ", ")
	}
	opts := make([]prompt.Option, 0, len(names)+1)
	for _, n := range names {
		opts = append(opts, prompt.Option{Label: "Use the existing key pair " + n, Value: n})
	}
	again := "Import it again under a new name"
	if importAs != "" {
		again = fmt.Sprintf("Import it again as %q", importAs)
	}
	opts = append(opts, prompt.Option{Label: again, Value: importAgain})
	v, err := p.rt.Pick().Select(title, opts, names[0])
	if err != nil || v == importAgain {
		return "", err
	}
	return v, nil
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

// HomeRelative shows a path under the home directory as ~/... (a label of
// the interactive flow).
func HomeRelative(path string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rel, err := filepath.Rel(home, path); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(filepath.Join("~", rel))
		}
	}
	return path
}
