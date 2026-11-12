// Package config loads and saves ~/.config/polyctl/config.yaml.
// The file holds only non-secret metadata; secrets live in internal/creds.
package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gofika/polyctl/internal/platform"
)

// EnvConfigDir overrides the configuration directory when set.
const EnvConfigDir = "POLYCTL_CONFIG_DIR"

// DefaultProfile is the profile `auth login` creates when none is named and
// none is current.
const DefaultProfile = "default"

// Account is one platform account inside a profile.
type Account struct {
	Metadata map[string]string `yaml:"metadata,omitempty"`
	// CredentialBackend records where the secret was stored ("keyring" or "file").
	CredentialBackend string    `yaml:"credential_backend,omitempty"`
	CreatedAt         time.Time `yaml:"created_at,omitempty"`
	UpdatedAt         time.Time `yaml:"updated_at,omitempty"`
	// LegacySecret marks an account converted from the one-platform-per-
	// profile layout whose secret is still stored under the bare profile
	// name. It is cleared once the secret has been moved.
	LegacySecret bool `yaml:"legacy_secret,omitempty"`
	// LegacyBackend names the backend that holds that bare-name entry when
	// it is not CredentialBackend: the secret was stored again elsewhere
	// while the old backend was out of reach. Empty means CredentialBackend.
	LegacyBackend string `yaml:"legacy_backend,omitempty"`
}

// LegacySecretBackend returns the backend that holds the bare-profile-name
// entry of an account marked LegacySecret.
func (a *Account) LegacySecretBackend() string {
	if a.LegacyBackend != "" {
		return a.LegacyBackend
	}
	return a.CredentialBackend
}

// SetCredentialBackend records the backend the account's secret is stored
// in now. While the legacy mark is set, the backend of the bare-name entry
// is remembered, so that it can still be found and removed later.
func (a *Account) SetCredentialBackend(backend string) {
	if a.LegacySecret && a.LegacyBackend == "" && a.CredentialBackend != backend {
		a.LegacyBackend = a.CredentialBackend
	}
	a.CredentialBackend = backend
}

// ClearLegacySecret removes the legacy mark once the bare-name entry is gone.
func (a *Account) ClearLegacySecret() {
	a.LegacySecret, a.LegacyBackend = false, ""
}

// Profile is a named set of accounts, at most one per platform. It usually
// stands for one project or one customer.
type Profile struct {
	Platforms map[platform.ID]*Account `yaml:"platforms"`
}

// legacyProfile is the pre-0.2 layout: one platform per profile.
type legacyProfile struct {
	Platform          string            `yaml:"platform"`
	Metadata          map[string]string `yaml:"metadata"`
	CredentialBackend string            `yaml:"credential_backend"`
	CreatedAt         time.Time         `yaml:"created_at"`
	UpdatedAt         time.Time         `yaml:"updated_at"`
}

// legacyKeys are the keys of the legacy layout, in file order.
var legacyKeys = []string{"platform", "metadata", "credential_backend", "created_at", "updated_at"}

// UnmarshalYAML accepts both the current layout and the legacy one, which is
// converted to a profile holding that single platform. A hand-edited mixture
// of the two is rejected rather than loaded with a part of it dropped: the
// next save would make the loss permanent.
func (p *Profile) UnmarshalYAML(n *yaml.Node) error {
	p.Platforms = map[platform.ID]*Account{}
	// Presence is what counts, not the value: "platform:" with nothing
	// after it is still a profile written in the legacy layout.
	has := map[string]bool{}
	mappingKeys(n, has, 0)
	if has["platform"] && has["platforms"] {
		return errors.New("both platform (legacy layout) and platforms are set; keep only platforms")
	}
	if has["platform"] {
		var old legacyProfile
		if err := n.Decode(&old); err != nil {
			return err
		}
		if old.Platform == "" {
			return errors.New("platform (legacy layout) is empty; name the platform, or move the account under platforms")
		}
		id, err := platform.Parse(old.Platform)
		if err != nil {
			return err
		}
		p.Platforms[id] = &Account{
			Metadata:          old.Metadata,
			CredentialBackend: old.CredentialBackend,
			CreatedAt:         old.CreatedAt,
			UpdatedAt:         old.UpdatedAt,
			LegacySecret:      true,
		}
		return nil
	}
	for _, k := range legacyKeys {
		if has[k] {
			return fmt.Errorf("%s is set on the profile itself (legacy layout) without platform; move it under platforms.<platform>", k)
		}
	}
	var cur struct {
		Platforms map[string]*Account `yaml:"platforms"`
	}
	if err := n.Decode(&cur); err != nil {
		return err
	}
	for name, a := range cur.Platforms {
		id, err := platform.Parse(name)
		if err != nil {
			return err
		}
		if _, dup := p.Platforms[id]; dup {
			return fmt.Errorf("platform %s is configured twice", id)
		}
		if a == nil {
			a = &Account{}
		}
		p.Platforms[id] = a
	}
	return nil
}

// mappingKeys records in has the keys of mapping n as decoding sees them:
// an alias stands for the node it names, and the keys a merge key ("<<")
// brings in count like the ones written out. depth stops a self-referencing
// alias.
func mappingKeys(n *yaml.Node, has map[string]bool, depth int) {
	const maxDepth = 32
	if n == nil || depth > maxDepth {
		return
	}
	switch n.Kind {
	case yaml.AliasNode:
		mappingKeys(n.Alias, has, depth+1)
	case yaml.SequenceNode:
		// Only reached below a merge key, which may list several mappings.
		for _, c := range n.Content {
			mappingKeys(c, has, depth+1)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i]; k.Kind == yaml.ScalarNode && k.ShortTag() == "!!merge" {
				mappingKeys(n.Content[i+1], has, depth+1)
			} else {
				has[k.Value] = true
			}
		}
	}
}

// PlatformIDs returns the profile's platforms, sorted.
func (p *Profile) PlatformIDs() []platform.ID {
	ids := make([]platform.ID, 0, len(p.Platforms))
	for id := range p.Platforms {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Config is the on-disk document.
type Config struct {
	CurrentProfile string              `yaml:"current_profile,omitempty"`
	Profiles       map[string]*Profile `yaml:"profiles"`
	// CredentialStore is "auto" (default), "keyring" or "file".
	CredentialStore string              `yaml:"credential_store,omitempty"`
	TTL             map[string]Duration `yaml:"ttl,omitempty"`
	Output          string              `yaml:"output,omitempty"`

	path string
	// read is the state of the file when it was loaded or last saved; Save
	// compares it with the file to notice a change made in between.
	read fileState
}

// fileState identifies the contents of the config file.
type fileState struct {
	exists bool
	sum    [sha256.Size]byte
}

func stateOf(b []byte) fileState { return fileState{exists: true, sum: sha256.Sum256(b)} }

// ErrChanged is returned by Save when the file was changed, by another
// polyctl process or by hand, after this copy of it was loaded. Saving would
// silently undo that change.
var ErrChanged = errors.New("the config file was changed since it was read")

// Duration marshals as a Go duration string.
type Duration time.Duration

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Dir returns the configuration directory, creating it with 0700.
func Dir() (string, error) {
	if d := os.Getenv(EnvConfigDir); d != "" {
		return d, os.MkdirAll(d, 0o700)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, ".config", "polyctl")
	return d, os.MkdirAll(d, 0o700)
}

// DefaultPath returns the config file path.
func DefaultPath() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.yaml"), nil
}

// Load reads the config at path, returning an empty config if it does not exist.
func Load(path string) (*Config, error) {
	c := &Config{Profiles: map[string]*Profile{}, path: path}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return nil, err
	}
	c.read = stateOf(b)
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]*Profile{}
	}
	for name, p := range c.Profiles {
		if p == nil {
			// An empty mapping ("name:" with nothing under it).
			p = &Profile{}
			c.Profiles[name] = p
		}
		if p.Platforms == nil {
			p.Platforms = map[platform.ID]*Account{}
		}
	}
	return c, nil
}

// Path returns where the config is saved.
func (c *Config) Path() string { return c.path }

// Save writes the config atomically with mode 0600. It refuses with
// ErrChanged when the file no longer is what this copy was loaded from: the
// copy lacks whatever was written in between, and saving it would drop that.
func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	var now fileState
	switch cur, err := os.ReadFile(c.path); {
	case err == nil:
		now = stateOf(cur)
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if now != c.read {
		return fmt.Errorf("%w (%s); nothing was saved, run the command again", ErrChanged, c.path)
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".config.yaml.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), c.path); err != nil {
		return err
	}
	c.read = stateOf(b)
	return nil
}

// Profile returns a profile by name.
func (c *Config) Profile(name string) (*Profile, error) {
	p, ok := c.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("profile %q not found (run `polyctl auth list`)", name)
	}
	return p, nil
}

// ProfileNames returns profile names sorted.
func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Account returns the account of a profile on a platform.
func (c *Config) Account(profile string, id platform.ID) (*Account, error) {
	p, err := c.Profile(profile)
	if err != nil {
		return nil, err
	}
	a, ok := p.Platforms[id]
	if !ok {
		return nil, fmt.Errorf("profile %q has no %s account (run `polyctl auth login %s --profile %s`)", profile, id, id, profile)
	}
	return a, nil
}

// ProfilesFor returns the names of the profiles that have an account on a
// platform, sorted.
func (c *Config) ProfilesFor(id platform.ID) []string {
	var out []string
	for _, n := range c.ProfileNames() {
		if _, ok := c.Profiles[n].Platforms[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

// AccountRef names one account: a profile and a platform.
type AccountRef struct {
	Profile  string
	Platform platform.ID
}

// String renders "profile/platform".
func (r AccountRef) String() string { return r.Profile + "/" + string(r.Platform) }

// Label renders "platform/profile", the form used in status lines.
func (r AccountRef) Label() string { return string(r.Platform) + "/" + r.Profile }

// Accounts returns every configured account, sorted by profile then platform.
// A non-empty profile restricts the result to that profile.
func (c *Config) Accounts(profile string) []AccountRef {
	var out []AccountRef
	for _, n := range c.ProfileNames() {
		if profile != "" && n != profile {
			continue
		}
		for _, id := range c.Profiles[n].PlatformIDs() {
			out = append(out, AccountRef{Profile: n, Platform: id})
		}
	}
	return out
}

// DefaultTTLs are used when ttl is not configured.
var DefaultTTLs = map[string]time.Duration{
	"default":                     24 * time.Hour,
	string(platform.ResDNSRecord): time.Hour,
	string(platform.ResZone):      24 * time.Hour,
	string(platform.ResDomain):    24 * time.Hour,
	string(platform.ResInstance):  15 * time.Minute,
}

// TTLFor returns the freshness window for a resource type.
func (c *Config) TTLFor(rt platform.ResourceType) time.Duration {
	if c.TTL != nil {
		if d, ok := c.TTL[string(rt)]; ok {
			return time.Duration(d)
		}
		if d, ok := c.TTL["default"]; ok {
			return time.Duration(d)
		}
	}
	if d, ok := DefaultTTLs[string(rt)]; ok {
		return d
	}
	return DefaultTTLs["default"]
}
