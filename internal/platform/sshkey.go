package platform

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
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
	return parsePublicKeyText(text, "--ssh-key", "pass it with --ssh-key-file", "--ssh-key")
}

// TypedKeySource is the Source of a public key typed in the interactive
// flow.
const TypedKeySource = "typed public key"

// ParseTypedPublicKey parses a public key typed (or pasted) in the
// interactive flow, with the checks of ParsePublicKey: one OpenSSH
// authorized_keys line, no private key, no file path.
func ParseTypedPublicKey(text string) (*PublicKey, error) {
	return parsePublicKeyText(text, "the public key", "choose the file instead of typing the key", TypedKeySource)
}

func parsePublicKeyText(text, what, fileHint, source string) (*PublicKey, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, invalid("%s is empty", what)
	}
	if strings.Contains(text, "PRIVATE KEY") {
		return nil, invalid("%s holds a private key; pass the public key (the .pub file) instead", what)
	}
	key, comment, _, rest, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		if fi, serr := os.Stat(ExpandHome(text)); serr == nil && fi.Mode().IsRegular() {
			return nil, invalid("%s takes the public key itself, and %q is a file path: %s", what, text, fileHint)
		}
		return nil, invalid("%s is not an SSH public key (expected one line such as \"ssh-ed25519 AAAA... comment\")", what)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, invalid("%s holds more than one key; pass exactly one", what)
	}
	return &PublicKey{Key: key, Comment: comment, Source: source}, nil
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

// FingerprintAWSRSA is the fingerprint AWS reports for an imported RSA key
// pair: MD5 of the PKIX (SubjectPublicKeyInfo) DER encoding of the key, in
// colon-separated lower-case hexadecimal. It is "" for a key that is not
// RSA. (Key pairs AWS generated report the SHA-1 of the private key
// instead, which cannot be computed from the public key.)
func (k *PublicKey) FingerprintAWSRSA() string {
	if k.Key.Type() != KeyTypeRSA {
		return ""
	}
	ck, ok := k.Key.(ssh.CryptoPublicKey)
	if !ok {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(ck.CryptoPublicKey())
	if err != nil {
		return ""
	}
	sum := md5.Sum(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return strings.Join(parts, ":")
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

// MatchAWS matches AWS key pairs: by the public key when the listing
// carries it (DescribeKeyPairs with IncludePublicKey=true, which works for
// every kind of key pair), else by the fingerprint AWS computes for
// imported keys (padded base64 SHA-256 of the wire bytes for ED25519, MD5
// of the PKIX DER for RSA; the base64 padding and a "SHA256:" prefix are
// ignored, hexadecimal is compared without regard to case).
var MatchAWS = KeyMatcher{Label: "matched by public key", Match: func(local *PublicKey, kp KeyPair) bool {
	if kp.PublicKey != nil {
		return local.Equal(kp.PublicKey)
	}
	fp := strings.TrimSpace(kp.Fingerprint)
	if fp == "" {
		return false
	}
	switch local.Type() {
	case KeyTypeED25519:
		norm := func(s string) string { return strings.TrimRight(strings.TrimPrefix(s, "SHA256:"), "=") }
		return norm(fp) == norm(local.FingerprintAWSED25519())
	case KeyTypeRSA:
		return strings.EqualFold(fp, local.FingerprintAWSRSA())
	}
	return false
}}

// KeySource is how the interactive flow asks for a public key to import.
type KeySource int

const (
	// KeyFromFile offers the usable ~/.ssh/*.pub files, another file (a
	// path) and typing the key itself.
	KeyFromFile KeySource = iota
	// KeyTyped asks for the key itself, typed or pasted.
	KeyTyped
)

// KeyPrompter asks the questions of the interactive flow of key pair
// resolution. It is never used in the non-interactive flow.
type KeyPrompter interface {
	// ChooseKeyPairOrCreate asks which existing key pair to use, or to
	// import a new one (the answer "", with how its key is asked for).
	// pairs are the key pairs of the target region, sorted by name; local
	// maps the name of each key pair that holds one of the ~/.ssh/*.pub
	// keys to that file.
	ChooseKeyPairOrCreate(pairs []KeyPair, local map[string]string) (string, KeySource, error)
	// NewKey asks for the public key to import: from candidates (the
	// usable ~/.ssh/*.pub files: parsable, of an accepted type), another
	// file or typed (KeyFromFile), or typed only (KeyTyped). check refuses
	// a key the platform does not accept; the question stays open until
	// the answer passes.
	NewKey(src KeySource, candidates []KeyFileCandidate, check func(*PublicKey) error) (*PublicKey, error)
	// UseRegistered says that the key pairs names already hold the key
	// and asks whether to use one of them (its name), or to import the
	// key again (""), under importAs when the name is known.
	UseRegistered(names []string, importAs string) (string, error)
	// KeyPairName asks for the name of the key pair to create; validate
	// rejects an empty, malformed or taken name, and the question stays
	// open until the answer passes. There is no default name.
	KeyPairName(validate func(string) error) (string, error)
	// ChooseKeyPair asks which of several key pairs holding the key to use.
	ChooseKeyPair(names []string) (string, error)
}

// KeyFileCandidate is a ~/.ssh/*.pub file offered for import.
type KeyFileCandidate struct {
	Path string
	Key  *PublicKey
	// Registered names the key pairs that already hold the key.
	Registered []string
	// Note, when set, is shown instead of Registered: a remark of a
	// platform without key pairs ("in project metadata").
	Note string
}

// KeyInput is what a command knows about the key pair it needs.
type KeyInput struct {
	// Key is the public key of --ssh-key / --ssh-key-file, or nil.
	Key *PublicKey
	// Name is --key-pair, or "".
	Name string
	// NameFlag is how the command takes the key pair name, for messages:
	// "--key-pair" by default; a command that takes it as an argument says
	// so ("<name>").
	NameFlag string
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
	// CheckName applies the platform's own name rules to a name asked for
	// in the interactive flow (nil: none beyond MinNameLength).
	CheckName func(string) error
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
//     --key-pair, else a name asked for in the interactive flow (validated
//     inline: required, platform rules, not taken; leaving the question
//     cancels, which is not an error). The non-interactive flow never
//     invents a name: it is a usage error. An existing key pair of that name
//     with another key is never overwritten: a usage error.
//   - Without a key but with --key-pair: an existing key pair is used; a
//     missing one needs a key, asked for in the interactive flow, a usage
//     error otherwise.
//   - With neither: the configured default key pair when it exists; else the
//     interactive flow offers the existing key pairs (those holding a
//     ~/.ssh/*.pub key marked) and "import a new one", which asks for a key
//     (a file, or the key typed in) and then a name (no default name); the
//     non-interactive flow is a usage error naming the flags.
//
// A key asked for in the interactive flow that key pairs already hold is
// pointed out (AskNewKey): the user uses one of them, or imports the key
// again under a new name; a new key pair is never forced on it.
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
	// importAgain: the key was asked for, and the user chose to import it
	// even though key pairs may already hold it (AskNewKey asked).
	importAgain := false
	src := KeyFromFile
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
				return KeyPairPlan{}, invalid("a key pair is required: pass %[1]s (an existing key pair), or --ssh-key-file <path> / --ssh-key <public key> with %[1]s to import one", nameUsage(in))
			}
			// Neither a key nor a name: offer the existing key pairs
			// first, then importing a new one.
			if len(pairs) > 0 && in.Prompter != nil {
				name, how, err := in.Prompter.ChooseKeyPairOrCreate(sortedPairs(pairs), localMatches(in, pairs))
				if err != nil {
					return KeyPairPlan{}, err
				}
				if name != "" {
					if _, ok := byName[name]; !ok {
						return KeyPairPlan{}, invalid("key pair %q does not exist", name)
					}
					return existing(name, "chosen key pair"), nil
				}
				src = how
			}
		}
		key, reuse, err := AskNewKey(in, pairs, src, in.Name)
		if err != nil {
			return KeyPairPlan{}, err
		}
		if reuse != "" {
			return existing(reuse, "chosen key pair (holds the key)"), nil
		}
		in.Key, importAgain = key, true
	}
	// Without a matcher of its own, a listing that carries the public key
	// is compared by key, any other by the MD5 fingerprint: never "no
	// match", which would make an existing key pair look foreign.
	match := matcher(in)
	var matched []string
	for _, kp := range pairs {
		if match(in.Key, kp) {
			matched = append(matched, kp.Name)
		}
	}
	sort.Strings(matched)
	holders := matched
	if importAgain {
		matched = nil
	}
	label := in.Match.Label
	if label == "" {
		label = "matched by public key"
	}
	switch {
	case len(matched) == 1:
		plan := existing(matched[0], label)
		if in.Name != "" && in.Name != matched[0] {
			plan.Notes = append(plan.Notes, fmt.Sprintf("note: key already exists as %q, ignoring %s %q", matched[0], nameFlag(in), in.Name))
		}
		return plan, nil
	case len(matched) > 1:
		if slices.Contains(matched, in.Name) {
			return existing(in.Name, label), nil
		}
		if !in.Interactive || in.Prompter == nil {
			return KeyPairPlan{}, fmt.Errorf("%w: the key is registered under several key pairs (%s); pass %s to choose one", ErrAmbiguous, strings.Join(matched, ", "), nameUsage(in))
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
			return KeyPairPlan{}, invalid("creating a key pair needs a name: pass %s (no name is ever chosen for you, since the key may be somebody else's)", nameUsage(in))
		}
		name, err = in.Prompter.KeyPairName(func(s string) error {
			s = strings.TrimSpace(s)
			if s == "" {
				return fmt.Errorf("a name is required (no name is chosen for you)")
			}
			if err := checkKeyPairName(s, in.MinNameLength); err != nil {
				return err
			}
			if in.CheckName != nil {
				if err := in.CheckName(s); err != nil {
					return err
				}
			}
			if slices.Contains(holders, s) {
				return fmt.Errorf("key pair %q already holds this key; choose a new name", s)
			}
			if _, ok := byName[s]; ok {
				return fmt.Errorf("key pair %q already exists with another key", s)
			}
			return nil
		})
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
		return KeyPairPlan{}, invalid("key pair %q already exists with a different public key; choose another name with %s (an existing key pair is never replaced)", name, nameUsage(in))
	}
	return KeyPairPlan{Name: name, Create: true, Key: in.Key,
		Change: Change{Resource: "key-pair/" + name, Action: Created, Detail: "import from " + in.Key.Source + " (" + in.Key.Summary() + ")"}}, nil
}

// nameFlag is how the command takes the key pair name ("--key-pair").
func nameFlag(in KeyInput) string {
	if in.NameFlag != "" {
		return in.NameFlag
	}
	return "--key-pair"
}

// nameUsage is the name option with its value ("--key-pair <name>"), or
// the argument alone ("<name>").
func nameUsage(in KeyInput) string {
	f := nameFlag(in)
	if strings.HasPrefix(f, "-") {
		return f + " <name>"
	}
	return f
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

// AskNewKey asks, in the interactive flow, for a public key to import
// (src: see KeySource), of a type the platform accepts. When key pairs of
// pairs already hold it (compared as ResolveKeyPair compares), it says so
// and asks whether to use one of them, whose name is then reuse, or to
// import the key again (under importAs when that name is already known): a
// new key pair is never forced on a key that is already registered.
func AskNewKey(in KeyInput, pairs []KeyPair, src KeySource, importAs string) (key *PublicKey, reuse string, err error) {
	if in.Prompter == nil {
		return nil, "", invalid("a public key is required: pass --ssh-key-file <path> or --ssh-key <public key>")
	}
	allowed := allowedTypes(in)
	key, err = in.Prompter.NewKey(src, KeyFileCandidates(in, pairs), func(k *PublicKey) error { return k.CheckType(allowed) })
	if err != nil {
		return nil, "", err
	}
	if key == nil {
		return nil, "", fmt.Errorf("%w: no public key given, no key pair was created", ErrNothingToDo)
	}
	if err := key.CheckType(allowed); err != nil {
		return nil, "", err
	}
	match := matcher(in)
	var holders []string
	for _, kp := range sortedPairs(pairs) {
		if match(key, kp) {
			holders = append(holders, kp.Name)
		}
	}
	if len(holders) == 0 {
		return key, "", nil
	}
	reuse, err = in.Prompter.UseRegistered(holders, importAs)
	if err != nil {
		return nil, "", err
	}
	if reuse != "" && !slices.Contains(holders, reuse) {
		return nil, "", invalid("key pair %q does not hold the key", reuse)
	}
	return key, reuse, nil
}

// matcher is in.Match.Match, or the default comparison of ResolveKeyPair.
func matcher(in KeyInput) func(*PublicKey, KeyPair) bool {
	if in.Match.Match != nil {
		return in.Match.Match
	}
	return func(local *PublicKey, kp KeyPair) bool {
		if kp.PublicKey != nil {
			return MatchByPublicKey.Match(local, kp)
		}
		return MatchByFingerprintMD5.Match(local, kp)
	}
}

// KeyFileCandidates loads the ~/.ssh/*.pub files and keeps the usable ones:
// parsable public keys of a type the platform accepts. Each names the key
// pairs that already hold it.
func KeyFileCandidates(in KeyInput, pairs []KeyPair) []KeyFileCandidate {
	match := matcher(in)
	var out []KeyFileCandidate
	for _, path := range PublicKeyFiles() {
		key, err := LoadPublicKeyFile(path)
		if err != nil || key.CheckType(allowedTypes(in)) != nil {
			continue
		}
		c := KeyFileCandidate{Path: path, Key: key}
		for _, kp := range sortedPairs(pairs) {
			if match(key, kp) {
				c.Registered = append(c.Registered, kp.Name)
			}
		}
		out = append(out, c)
	}
	return out
}

// localMatches maps the name of each key pair that holds one of the usable
// ~/.ssh/*.pub keys to that file.
func localMatches(in KeyInput, pairs []KeyPair) map[string]string {
	out := map[string]string{}
	for _, c := range KeyFileCandidates(in, pairs) {
		for _, n := range c.Registered {
			if _, ok := out[n]; !ok {
				out[n] = c.Path
			}
		}
	}
	return out
}

func sortedPairs(pairs []KeyPair) []KeyPair {
	out := append([]KeyPair(nil), pairs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DisplayFingerprint is the fingerprint to show for a key pair: the SHA256
// fingerprint of its public key when the listing carries it, else the
// fingerprint the platform reports.
func (kp KeyPair) DisplayFingerprint() string {
	if kp.PublicKey != nil {
		return ssh.FingerprintSHA256(kp.PublicKey)
	}
	return kp.Fingerprint
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
