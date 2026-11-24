package gcp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// Compute Engine has no key pairs: SSH keys are lines "USERNAME:KEY" of
// the ssh-keys metadata item, of the project (every instance) or of one
// instance. The server does not check the keys, so they are parsed here.

const (
	sshKeysItem      = "ssh-keys"
	legacySSHKeys    = "sshKeys"
	osLoginItem      = "enable-oslogin"
	blockProjectKeys = "block-project-ssh-keys"
	maxSSHKeyFile    = 1 << 20
	sshUserMaxLength = 32
)

// sshKey is one key to install: the user it logs in as and the key.
type sshKey struct {
	User   string
	Key    *platform.PublicKey
	Source string
}

// Line is the metadata line of the key: "user:type base64 comment".
func (k sshKey) Line() string {
	line := k.User + ":" + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.Key.Key)))
	if c := strings.TrimSpace(k.Key.Comment); c != "" {
		line += " " + c
	}
	return line
}

// same reports whether two keys log in the same user with the same key.
func (k sshKey) same(user string, key ssh.PublicKey) bool {
	return k.User == user && k.Key.Equal(key)
}

var (
	// commentUserRe takes the user from the e-mail address at the end of a
	// key's comment: the whole local part ("... john.smith@my-mac.local"
	// -> "john.smith").
	commentUserRe = regexp.MustCompile(`([A-Za-z0-9._-]+)@[A-Za-z0-9.-]+\s*$`)
	sshUserRe     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	userPrefixRe  = regexp.MustCompile(`^([^\s:]+):(\S.*)$`)
)

func checkSSHUser(user, flag string) error {
	if len(user) > sshUserMaxLength || !sshUserRe.MatchString(user) {
		return fmt.Errorf("%w: %s: %q is not a valid user name (letters, digits, '.', '_' and '-', at most %d characters)", platform.ErrInvalidInput, flag, user, sshUserMaxLength)
	}
	return nil
}

// splitUser separates a "user:" prefix from a key line. A line without
// one is returned as it is.
func splitUser(text string) (user, rest string) {
	if m := userPrefixRe.FindStringSubmatch(text); m != nil {
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m[2])); err == nil {
			return m[1], m[2]
		}
	}
	return "", text
}

// commentUser is the local part of the e-mail address that ends a key's
// comment, "" when there is none or it is not a valid user name.
func commentUser(comment string) string {
	m := commentUserRe.FindStringSubmatch(comment)
	if m == nil || checkSSHUser(m[1], "comment") != nil {
		return ""
	}
	return m[1]
}

// keyUser decides the user of a key: the "user:" prefix, else --ssh-user,
// else the whole local part of the e-mail address that ends the key's
// comment. None of them is a usage error.
func keyUser(prefix, sshUser string, key *platform.PublicKey, source string) (string, error) {
	user := prefix
	flag := source
	if user == "" {
		user, flag = sshUser, "--ssh-user"
	}
	if user == "" {
		user = commentUser(key.Comment)
		if user == "" {
			return "", fmt.Errorf("%w: %s: cannot tell the user of the key (its comment ends with no e-mail address whose local part is a valid user name); write it as user:ssh-ed25519 AAAA..., or pass --ssh-user <name>", platform.ErrInvalidInput, source)
		}
		flag = source
	}
	if err := checkSSHUser(user, flag); err != nil {
		return "", err
	}
	return user, nil
}

// parseSSHKey parses one --ssh-key value (or one entry of
// defaults.gcp.ssh_keys): a public key line, optionally prefixed with
// "user:". A file path is refused with a hint to use --ssh-key-file.
func parseSSHKey(text, sshUser, source string) (sshKey, error) {
	prefix, rest := splitUser(strings.TrimSpace(text))
	pk, err := platform.ParsePublicKey(rest)
	if err != nil {
		return sshKey{}, err
	}
	pk.Source = source
	if err := pk.CheckType(platform.AnyKeyTypes); err != nil {
		return sshKey{}, err
	}
	user, err := keyUser(prefix, sshUser, pk, source)
	if err != nil {
		return sshKey{}, err
	}
	return sshKey{User: user, Key: pk, Source: source}, nil
}

// loadSSHKeyFile reads every public key line of an --ssh-key-file (~ is
// expanded); a line may carry a "user:" prefix. A private key, or a file
// without any public key, is a usage error.
func loadSSHKeyFile(path, sshUser string) ([]sshKey, error) {
	source := "--ssh-key-file " + path
	f, err := os.Open(platform.ExpandHome(strings.TrimSpace(path)))
	if err != nil {
		return nil, fmt.Errorf("%w: --ssh-key-file: %v", platform.ErrInvalidInput, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSSHKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("%w: --ssh-key-file: %v", platform.ErrInvalidInput, err)
	}
	if len(data) > maxSSHKeyFile {
		return nil, fmt.Errorf("%w: --ssh-key-file %s is too large to be a public key file", platform.ErrInvalidInput, path)
	}
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		return nil, fmt.Errorf("%w: --ssh-key-file %s holds a private key; pass the public key (the .pub file) instead", platform.ErrInvalidInput, path)
	}
	var out []sshKey
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), maxSSHKeyFile)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, rest := splitUser(line)
		key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(rest))
		if err != nil {
			continue
		}
		pk := &platform.PublicKey{Key: key, Comment: comment, Source: source}
		if err := pk.CheckType(platform.AnyKeyTypes); err != nil {
			return nil, err
		}
		user, err := keyUser(prefix, sshUser, pk, source)
		if err != nil {
			return nil, err
		}
		out = append(out, sshKey{User: user, Key: pk, Source: source})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: --ssh-key-file %s holds no SSH public key", platform.ErrInvalidInput, path)
	}
	return out, nil
}

// collectSSHKeys parses --ssh-key values, --ssh-key-file files and the
// configured defaults.gcp.ssh_keys, dropping repeats (same user and key).
func collectSSHKeys(keys, files, defaults []string, sshUser string) ([]sshKey, error) {
	var out []sshKey
	add := func(k sshKey) {
		for _, o := range out {
			if o.same(k.User, k.Key.Key) {
				return
			}
		}
		out = append(out, k)
	}
	for _, text := range keys {
		k, err := parseSSHKey(text, sshUser, "--ssh-key")
		if err != nil {
			return nil, err
		}
		add(k)
	}
	for _, path := range files {
		ks, err := loadSSHKeyFile(path, sshUser)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			add(k)
		}
	}
	for _, text := range defaults {
		k, err := parseSSHKey(text, sshUser, "defaults.gcp.ssh_keys")
		if err != nil {
			return nil, err
		}
		add(k)
	}
	return out, nil
}

// metadataKey is one parsed line of an ssh-keys metadata item.
type metadataKey struct {
	User string
	Key  ssh.PublicKey
}

// metadataValue returns the value of a metadata item ("" when absent).
func metadataValue(md *compute.Metadata, key string) (string, bool) {
	if md == nil {
		return "", false
	}
	for _, it := range md.Items {
		if it != nil && it.Key == key && it.Value != nil {
			return *it.Value, true
		}
	}
	return "", false
}

// metadataKeys parses the ssh-keys (and legacy sshKeys) items of metadata.
// Lines that do not parse are skipped.
func metadataKeys(md *compute.Metadata) []metadataKey {
	var out []metadataKey
	for _, item := range []string{sshKeysItem, legacySSHKeys} {
		v, ok := metadataValue(md, item)
		if !ok {
			continue
		}
		for _, line := range strings.Split(v, "\n") {
			user, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok || user == "" {
				continue
			}
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(rest))
			if err != nil {
				continue
			}
			out = append(out, metadataKey{User: user, Key: key})
		}
	}
	return out
}

// presentIn reports whether k is one of the metadata keys.
func (k sshKey) presentIn(keys []metadataKey) bool {
	for _, m := range keys {
		if k.same(m.User, m.Key) {
			return true
		}
	}
	return false
}

// osLoginEnabled reports enable-oslogin=TRUE in metadata.
func osLoginEnabled(md *compute.Metadata) bool {
	v, ok := metadataValue(md, osLoginItem)
	return ok && strings.EqualFold(strings.TrimSpace(v), "true")
}

// projectKeysBlocked reports block-project-ssh-keys=TRUE in metadata: set
// project-wide, it is inherited by new instances, which then ignore the
// project's ssh-keys, so every key has to go into the instance metadata.
func projectKeysBlocked(md *compute.Metadata) bool {
	v, ok := metadataValue(md, blockProjectKeys)
	return ok && strings.EqualFold(strings.TrimSpace(v), "true")
}

// sshKeysMetadata is the ssh-keys metadata item holding keys, one per line.
func sshKeysMetadata(keys []sshKey) *compute.MetadataItems {
	lines := make([]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, k.Line())
	}
	v := strings.Join(lines, "\n")
	return &compute.MetadataItems{Key: sshKeysItem, Value: &v}
}
