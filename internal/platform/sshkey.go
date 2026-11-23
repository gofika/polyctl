package platform

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PublicKey is an SSH public key given with --ssh-key or --ssh-key-file.
// Its text is never printed: output shows Summary (algorithm, fingerprint
// and the start of the comment) only.
type PublicKey struct {
	Key     ssh.PublicKey
	Comment string
	// Source says where the key came from ("--ssh-key", "--ssh-key-file
	// ~/.ssh/id_ed25519.pub"), for change reports.
	Source string
}

// SSH key types (ssh.PublicKey.Type()).
const (
	KeyTypeRSA       = ssh.KeyAlgoRSA
	KeyTypeED25519   = ssh.KeyAlgoED25519
	KeyTypeECDSA256  = ssh.KeyAlgoECDSA256
	KeyTypeECDSA384  = ssh.KeyAlgoECDSA384
	KeyTypeECDSA521  = ssh.KeyAlgoECDSA521
	keyTypeDSA       = ssh.KeyAlgoDSA // named only to be refused
	maxPublicKeyFile = 1 << 20
)

// Key types each platform accepts. AWS imports RSA and ED25519 only (an
// ECDSA key fails there with InvalidKey.Format although it parses), so the
// list is checked before anything is sent. DSA is accepted nowhere.
var (
	AWSKeyTypes    = []string{KeyTypeRSA, KeyTypeED25519}
	AliyunKeyTypes = []string{KeyTypeRSA, KeyTypeED25519, KeyTypeECDSA256, KeyTypeECDSA384, KeyTypeECDSA521}
	AnyKeyTypes    = AliyunKeyTypes
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, args...))
}

// ParsePublicKey parses the text of --ssh-key: one public key line such as
// "ssh-ed25519 AAAA... comment". The value must be the key itself: a path
// to an existing file is refused with a hint to use --ssh-key-file, and a
// private key is refused outright.
func ParsePublicKey(text string) (*PublicKey, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, invalid("--ssh-key is empty")
	}
	if strings.Contains(text, "PRIVATE KEY") {
		return nil, invalid("--ssh-key holds a private key; pass the public key (the .pub file) instead")
	}
	key, comment, _, rest, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		if fi, serr := os.Stat(ExpandHome(text)); serr == nil && fi.Mode().IsRegular() {
			return nil, invalid("--ssh-key takes the public key itself, and %q is a file path: pass it with --ssh-key-file", text)
		}
		return nil, invalid("--ssh-key is not an SSH public key (expected one line such as \"ssh-ed25519 AAAA... comment\")")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, invalid("--ssh-key holds more than one key; pass exactly one")
	}
	return &PublicKey{Key: key, Comment: comment, Source: "--ssh-key"}, nil
}

// ExpandHome replaces a leading ~ with the home directory.
func ExpandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// LoadPublicKeyFile reads --ssh-key-file: the first valid public key line
// of the file (~ is expanded). A file that holds a private key is refused
// without being parsed.
func LoadPublicKeyFile(path string) (*PublicKey, error) {
	full := ExpandHome(strings.TrimSpace(path))
	f, err := os.Open(full)
	if err != nil {
		return nil, invalid("--ssh-key-file: %v", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPublicKeyFile+1))
	if err != nil {
		return nil, invalid("--ssh-key-file: %v", err)
	}
	if len(data) > maxPublicKeyFile {
		return nil, invalid("--ssh-key-file %s is too large to be a public key file", path)
	}
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		return nil, invalid("--ssh-key-file %s holds a private key; pass the public key (the .pub file) instead", path)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), maxPublicKeyFile)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err == nil {
			return &PublicKey{Key: key, Comment: comment, Source: "--ssh-key-file " + path}, nil
		}
	}
	return nil, invalid("--ssh-key-file %s holds no SSH public key", path)
}

// PublicKeyFiles lists ~/.ssh/*.pub, for the interactive choice of a key.
func PublicKeyFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".ssh", "*.pub"))
	sort.Strings(matches)
	return matches
}

// Type is the key's algorithm as ssh names it ("ssh-ed25519").
func (k *PublicKey) Type() string { return k.Key.Type() }

// Algorithm is the short algorithm name ("ed25519", "rsa", "ecdsa-p256").
func (k *PublicKey) Algorithm() string { return algorithmName(k.Key.Type()) }

func algorithmName(t string) string {
	switch t {
	case KeyTypeRSA:
		return "rsa"
	case KeyTypeED25519:
		return "ed25519"
	case KeyTypeECDSA256:
		return "ecdsa-p256"
	case KeyTypeECDSA384:
		return "ecdsa-p384"
	case KeyTypeECDSA521:
		return "ecdsa-p521"
	case keyTypeDSA:
		return "dsa"
	}
	return t
}

// CheckType refuses a key whose algorithm the platform does not accept.
func (k *PublicKey) CheckType(allowed []string) error {
	if !slices.Contains(allowed, k.Key.Type()) {
		names := make([]string, 0, len(allowed))
		for _, t := range allowed {
			names = append(names, algorithmName(t))
		}
		return invalid("%s keys are not supported here (supported: %s)", k.Algorithm(), strings.Join(names, ", "))
	}
	return nil
}

// FingerprintSHA256 is the OpenSSH fingerprint ("SHA256:..." of the wire
// bytes, unpadded base64).
func (k *PublicKey) FingerprintSHA256() string { return ssh.FingerprintSHA256(k.Key) }

// FingerprintMD5Hex is the fingerprint Alibaba Cloud reports as
// KeyPairFingerPrint for every key type: MD5 of the wire bytes, lower-case
// hexadecimal without colons.
func (k *PublicKey) FingerprintMD5Hex() string {
	sum := md5.Sum(k.Key.Marshal())
	return hex.EncodeToString(sum[:])
}

// FingerprintAWSED25519 is the fingerprint AWS reports for an ED25519 key
// pair: SHA-256 of the wire bytes, padded standard base64, no prefix. For
// display only: AWS key pairs are matched by their public key (see
// MatchByPublicKey), because AWS computes fingerprints differently for
// imported RSA keys and for keys it generated.
func (k *PublicKey) FingerprintAWSED25519() string {
	sum := sha256.Sum256(k.Key.Marshal())
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Summary describes the key without printing it: algorithm, a shortened
// SHA256 fingerprint and the first 20 characters of the comment.
func (k *PublicKey) Summary() string {
	fp := k.FingerprintSHA256()
	if len(fp) > len("SHA256:")+8 {
		fp = fp[:len("SHA256:")+8] + "…"
	}
	s := k.Algorithm() + " " + fp
	if c := strings.TrimSpace(k.Comment); c != "" {
		if r := []rune(c); len(r) > 20 {
			c = string(r[:20]) + "…"
		}
		s += " " + c
	}
	return s
}

// Equal reports whether other is the same public key (byte for byte).
func (k *PublicKey) Equal(other ssh.PublicKey) bool {
	return other != nil && bytes.Equal(k.Key.Marshal(), other.Marshal())
}

// KeyPair is an SSH key pair as a platform lists it.
type KeyPair struct {
	Name        string
	ID          string
	Fingerprint string
	// PublicKey is the key itself when the platform returns it (AWS with
	// IncludePublicKey=true), else nil.
	PublicKey ssh.PublicKey
}

// KeyPairLister lists the key pairs of the target region.
type KeyPairLister interface {
	ListKeyPairs(ctx context.Context) ([]KeyPair, error)
}

// KeyMatcher tells whether a listed key pair holds the local key.
type KeyMatcher struct {
	// Label is how a match is reported ("matched by public key").
	Label string
	Match func(local *PublicKey, kp KeyPair) bool
}

// MatchByFingerprintMD5 matches Alibaba Cloud key pairs: their
// KeyPairFingerPrint is the MD5 of the wire bytes in lower-case hex.
var MatchByFingerprintMD5 = KeyMatcher{Label: "matched by fingerprint", Match: func(local *PublicKey, kp KeyPair) bool {
	return kp.Fingerprint != "" && strings.EqualFold(strings.ReplaceAll(kp.Fingerprint, ":", ""), local.FingerprintMD5Hex())
}}

// MatchByPublicKey matches key pairs whose listing carries the public key
// (AWS DescribeKeyPairs with IncludePublicKey=true), byte for byte.
var MatchByPublicKey = KeyMatcher{Label: "matched by public key", Match: func(local *PublicKey, kp KeyPair) bool {
	return local.Equal(kp.PublicKey)
}}

// KeyPrompter asks the questions of the interactive flow of key pair
// resolution. It is never used in the non-interactive flow.
type KeyPrompter interface {
	// KeyFile asks for the path of a public key file; candidates are the
	// ~/.ssh/*.pub files found.
	KeyFile(candidates []string) (string, error)
	// KeyPairName asks for the name of the key pair to create; an empty
	// answer cancels.
	KeyPairName() (string, error)
	// ChooseKeyPair asks which of several key pairs holding the key to use.
	ChooseKeyPair(names []string) (string, error)
}

// KeyInput is what a command knows about the key pair it needs.
type KeyInput struct {
	// Key is the public key of --ssh-key / --ssh-key-file, or nil.
	Key *PublicKey
	// Name is --key-pair, or "".
	Name string
	// DefaultName is a configured default key pair name; it is used only
	// when that key pair exists. A key pair is never created under it.
	DefaultName string
	// Match finds the key pairs that hold Key.
	Match KeyMatcher
	// AllowedTypes are the key algorithms the platform accepts.
	AllowedTypes []string
	// MinNameLength is the shortest acceptable key pair name (Alibaba Cloud
	// wants 2).
	MinNameLength int
	// Interactive is the flow; Prompter asks its questions.
	Interactive bool
	Prompter    KeyPrompter
}

// KeyPairPlan is the outcome of ResolveKeyPair: use an existing key pair,
// or create one. Nothing has been written.
type KeyPairPlan struct {
	// Name is the key pair to bind.
	Name string
	// Create says the key pair must be imported (from Key) first.
	Create bool
	Key    *PublicKey
	// Change is the change report row for the key pair.
	Change Change
	// Notes are remarks for stderr (an ignored --key-pair, ...).
	Notes []string
}

// ResolveKeyPair decides which key pair a command binds, existing first:
//
//   - With a public key: the key pairs that hold it are looked up (by
//     KeyInput.Match). One match is used as it is, whatever --key-pair says
//     (a note says it was ignored); with several, --key-pair picks among
//     them, else the interactive flow asks and the non-interactive flow is
//     ambiguous (exit code 5). No match: the key pair is created, under
//     --key-pair, else a name asked for in the interactive flow (an empty
//     answer cancels, which is not an error). The non-interactive flow never
//     invents a name: it is a usage error. An existing key pair of that name
//     with another key is never overwritten: a usage error.
//   - Without a key but with --key-pair: an existing key pair is used; a
//     missing one needs a key, asked for in the interactive flow, a usage
//     error otherwise.
//   - With neither: the configured default key pair when it exists; else the
//     interactive flow asks for a key file (and then a name), and the
//     non-interactive flow is a usage error naming the flags.
//
// It writes nothing: creating the key pair is the caller's Step.
func ResolveKeyPair(ctx context.Context, lister KeyPairLister, in KeyInput) (KeyPairPlan, error) {
	if in.Key != nil {
		if err := in.Key.CheckType(allowedTypes(in)); err != nil {
			return KeyPairPlan{}, err
		}
	}
	if in.Name != "" {
		if err := checkKeyPairName(in.Name, in.MinNameLength); err != nil {
			return KeyPairPlan{}, err
		}
	}
	pairs, err := lister.ListKeyPairs(ctx)
	if err != nil {
		return KeyPairPlan{}, err
	}
	byName := map[string]KeyPair{}
	for _, kp := range pairs {
		byName[kp.Name] = kp
	}
	existing := func(name, detail string) KeyPairPlan {
		kp := byName[name]
		return KeyPairPlan{Name: name, Change: Change{Resource: "key-pair/" + name, Action: Unchanged, ID: kp.ID, Detail: detail}}
	}
	if in.Key == nil {
		switch {
		case in.Name != "":
			if _, ok := byName[in.Name]; ok {
				return existing(in.Name, "existing key pair"), nil
			}
			if !in.Interactive {
				return KeyPairPlan{}, invalid("key pair %q does not exist; to import it, pass its public key with --ssh-key-file <path> or --ssh-key <public key>", in.Name)
			}
		case in.DefaultName != "":
			if _, ok := byName[in.DefaultName]; ok {
				return existing(in.DefaultName, "default key pair"), nil
			}
			fallthrough
		default:
			if !in.Interactive {
				return KeyPairPlan{}, invalid("a key pair is required: pass --key-pair <name> (an existing key pair), or --ssh-key-file <path> / --ssh-key <public key> with --key-pair <name> to import one")
			}
		}
		key, err := askKey(in)
		if err != nil {
			return KeyPairPlan{}, err
		}
		in.Key = key
	}
	match := in.Match.Match
	if match == nil {
		// Without a matcher of its own, a listing that carries the public
		// key is compared by key, any other by the MD5 fingerprint: never
		// "no match", which would make an existing key pair look foreign.
		match = func(local *PublicKey, kp KeyPair) bool {
			if kp.PublicKey != nil {
				return MatchByPublicKey.Match(local, kp)
			}
			return MatchByFingerprintMD5.Match(local, kp)
		}
	}
	var matched []string
	for _, kp := range pairs {
		if match(in.Key, kp) {
			matched = append(matched, kp.Name)
		}
	}
	sort.Strings(matched)
	label := in.Match.Label
	if label == "" {
		label = "matched by public key"
	}
	switch {
	case len(matched) == 1:
		plan := existing(matched[0], label)
		if in.Name != "" && in.Name != matched[0] {
			plan.Notes = append(plan.Notes, fmt.Sprintf("note: key already exists as %q, ignoring --key-pair %q", matched[0], in.Name))
		}
		return plan, nil
	case len(matched) > 1:
		if slices.Contains(matched, in.Name) {
			return existing(in.Name, label), nil
		}
		if !in.Interactive || in.Prompter == nil {
			return KeyPairPlan{}, fmt.Errorf("%w: the key is registered under several key pairs (%s); pass --key-pair <name> to choose one", ErrAmbiguous, strings.Join(matched, ", "))
		}
		name, err := in.Prompter.ChooseKeyPair(matched)
		if err != nil {
			return KeyPairPlan{}, err
		}
		return existing(name, label), nil
	}
	name := in.Name
	if name == "" {
		if !in.Interactive || in.Prompter == nil {
			return KeyPairPlan{}, invalid("creating a key pair needs a name: pass --key-pair <name> (no name is ever chosen for you, since the key may be somebody else's)")
		}
		name, err = in.Prompter.KeyPairName()
		if err != nil {
			return KeyPairPlan{}, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return KeyPairPlan{}, fmt.Errorf("%w: no key pair name given, no key pair was created", ErrNothingToDo)
		}
		if err := checkKeyPairName(name, in.MinNameLength); err != nil {
			return KeyPairPlan{}, err
		}
	}
	if _, ok := byName[name]; ok {
		return KeyPairPlan{}, invalid("key pair %q already exists with a different public key; choose another name with --key-pair (an existing key pair is never replaced)", name)
	}
	return KeyPairPlan{Name: name, Create: true, Key: in.Key,
		Change: Change{Resource: "key-pair/" + name, Action: Created, Detail: "import from " + in.Key.Source + " (" + in.Key.Summary() + ")"}}, nil
}

func allowedTypes(in KeyInput) []string {
	if len(in.AllowedTypes) > 0 {
		return in.AllowedTypes
	}
	return AnyKeyTypes
}

func checkKeyPairName(name string, min int) error {
	if min > 0 && len([]rune(name)) < min {
		return invalid("key pair name %q is too short (at least %d characters)", name, min)
	}
	return nil
}

// askKey asks for a public key file in the interactive flow.
func askKey(in KeyInput) (*PublicKey, error) {
	if in.Prompter == nil {
		return nil, invalid("a public key is required: pass --ssh-key-file <path> or --ssh-key <public key>")
	}
	path, err := in.Prompter.KeyFile(PublicKeyFiles())
	if err != nil {
		return nil, err
	}
	key, err := LoadPublicKeyFile(path)
	if err != nil {
		return nil, err
	}
	if err := key.CheckType(allowedTypes(in)); err != nil {
		return nil, err
	}
	return key, nil
}

// Step turns the plan into a Plan step: an Unchanged report when the key
// pair exists, or a Created step whose Apply imports the key (the dry run
// reports "would create" without calling it).
func (p KeyPairPlan) Step(importKey func(ctx context.Context, name string, key *PublicKey) (id string, err error)) Step {
	if !p.Create {
		return Step{Resource: p.Change.Resource, Action: Unchanged, ID: p.Change.ID, Desc: p.Change.Detail}
	}
	return Step{Resource: p.Change.Resource, Action: Created, Desc: p.Change.Detail, Apply: func(ctx context.Context) (Change, error) {
		id, err := importKey(ctx, p.Name, p.Key)
		return Change{ID: id}, err
	}}
}
