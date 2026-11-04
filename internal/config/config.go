// Package config loads and saves ~/.config/polyctl/config.yaml.
// The file holds only non-secret metadata; secrets live in internal/creds.
package config

import (
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

// Profile is a configured account on one platform.
type Profile struct {
	Platform platform.ID       `yaml:"platform"`
	Metadata map[string]string `yaml:"metadata,omitempty"`
	// CredentialBackend records where the secret was stored ("keyring" or "file").
	CredentialBackend string    `yaml:"credential_backend,omitempty"`
	CreatedAt         time.Time `yaml:"created_at,omitempty"`
	UpdatedAt         time.Time `yaml:"updated_at,omitempty"`
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
}

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
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]*Profile{}
	}
	for name, p := range c.Profiles {
		if p == nil {
			return nil, fmt.Errorf("parse %s: profile %q is empty", path, name)
		}
		id, err := platform.Parse(string(p.Platform))
		if err != nil {
			return nil, fmt.Errorf("parse %s: profile %q: %w", path, name, err)
		}
		p.Platform = id
	}
	return c, nil
}

// Path returns where the config is saved.
func (c *Config) Path() string { return c.path }

// Save writes the config atomically with mode 0600.
func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
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
	return os.Rename(tmp.Name(), c.path)
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

// ProfilesFor returns profile names on a platform, sorted.
func (c *Config) ProfilesFor(id platform.ID) []string {
	var out []string
	for _, n := range c.ProfileNames() {
		if c.Profiles[n].Platform == id {
			out = append(out, n)
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
