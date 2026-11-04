// Package app wires configuration, credentials, the inventory database and
// the provider registry into a Runtime shared by every command.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gofika/polyctl/internal/browser"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// Flags are the global CLI flags.
type Flags struct {
	ConfigPath string
	Profile    string
	Refresh    bool
	Offline    bool
	Output     string
	Verbose    bool
	NoBrowser  bool
	Yes        bool
}

// Runtime is the shared command context.
type Runtime struct {
	Flags  Flags
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	cfg       *config.Config
	store     *creds.Multi
	db        *inventory.DB
	format    output.Format
	warned    bool
	configDir string
}

// New creates a Runtime; nothing is loaded until first use.
func New(flags Flags, stdin io.Reader, stdout, stderr io.Writer) *Runtime {
	return &Runtime{Flags: flags, Stdin: stdin, Stdout: stdout, Stderr: stderr}
}

// Init validates flags and loads config. Call once before running a command.
func (rt *Runtime) Init() error {
	if rt.Flags.Refresh && rt.Flags.Offline {
		return errors.New("--refresh and --offline are mutually exclusive")
	}
	if _, err := rt.Config(); err != nil {
		return err
	}
	f := rt.Flags.Output
	if f == "" {
		f = rt.cfg.Output
	}
	if f == "" {
		f = os.Getenv("POLYCTL_OUTPUT")
	}
	format, err := output.ParseFormat(f)
	if err != nil {
		return err
	}
	rt.format = format
	return nil
}

// Close releases resources.
func (rt *Runtime) Close() error {
	if rt.db != nil {
		return rt.db.Close()
	}
	return nil
}

// Format is the resolved output format.
func (rt *Runtime) Format() output.Format { return rt.format }

// Render prints value in the resolved output format.
func (rt *Runtime) Render(value any, grid func() output.Grid) error {
	return output.Render(rt.Stdout, rt.format, value, grid)
}

// Verbosef prints to stderr when --verbose is set.
func (rt *Runtime) Verbosef(format string, args ...any) {
	if rt.Flags.Verbose {
		fmt.Fprintf(rt.Stderr, format+"\n", args...)
	}
}

// Infof prints a status line to stderr (never stdout, which holds results).
func (rt *Runtime) Infof(format string, args ...any) {
	fmt.Fprintf(rt.Stderr, format+"\n", args...)
}

// Prompt returns the interactive IO.
func (rt *Runtime) Prompt() *prompt.IO { return prompt.New(rt.Stdin, rt.Stdout, rt.Stderr) }

// ConfigDir returns the configuration directory.
func (rt *Runtime) ConfigDir() (string, error) {
	if rt.configDir != "" {
		return rt.configDir, nil
	}
	if rt.Flags.ConfigPath != "" {
		rt.configDir = filepath.Dir(rt.Flags.ConfigPath)
		return rt.configDir, os.MkdirAll(rt.configDir, 0o700)
	}
	d, err := config.Dir()
	if err != nil {
		return "", err
	}
	rt.configDir = d
	return d, nil
}

// Config loads (once) and returns the configuration.
func (rt *Runtime) Config() (*config.Config, error) {
	if rt.cfg != nil {
		return rt.cfg, nil
	}
	path := rt.Flags.ConfigPath
	if path == "" {
		var err error
		if path, err = config.DefaultPath(); err != nil {
			return nil, err
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	rt.cfg = cfg
	return cfg, nil
}

// Creds returns the credential store.
func (rt *Runtime) Creds() (*creds.Multi, error) {
	if rt.store != nil {
		return rt.store, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	dir, err := rt.ConfigDir()
	if err != nil {
		return nil, err
	}
	mode := cfg.CredentialStore
	if v := os.Getenv("POLYCTL_CREDENTIAL_STORE"); v != "" {
		mode = v
	}
	st, err := creds.Open(mode, dir)
	if err != nil {
		return nil, err
	}
	if st.Warning != "" && !rt.warned {
		rt.warned = true
		fmt.Fprintln(rt.Stderr, "warning: "+st.Warning)
	}
	rt.store = st
	return st, nil
}

// DB opens (once) the inventory database.
func (rt *Runtime) DB() (*inventory.DB, error) {
	if rt.db != nil {
		return rt.db, nil
	}
	dir, err := rt.ConfigDir()
	if err != nil {
		return nil, err
	}
	path := os.Getenv("POLYCTL_INVENTORY_DB")
	if path == "" {
		path = filepath.Join(dir, "inventory.db")
	}
	db, err := inventory.Open(path)
	if err != nil {
		return nil, err
	}
	rt.db = db
	return db, nil
}

// LoginInput builds the input for a provider login flow.
func (rt *Runtime) LoginInput(profileName string, opts map[string]string, existing map[string]string) platform.LoginInput {
	return platform.LoginInput{
		ProfileName: profileName,
		Options:     opts,
		Existing:    existing,
		Stdin:       rt.Stdin,
		Stdout:      rt.Stdout,
		Stderr:      rt.Stderr,
		OpenBrowser: browser.Open,
		NoBrowser:   rt.Flags.NoBrowser,
	}
}

// LoadProfile returns the profile with its secret attached.
func (rt *Runtime) LoadProfile(name string) (platform.Profile, error) {
	cfg, err := rt.Config()
	if err != nil {
		return platform.Profile{}, err
	}
	p, err := cfg.Profile(name)
	if err != nil {
		return platform.Profile{}, err
	}
	st, err := rt.Creds()
	if err != nil {
		return platform.Profile{}, err
	}
	secret, err := st.Get(name)
	if err != nil {
		if errors.Is(err, creds.ErrNotFound) {
			return platform.Profile{}, fmt.Errorf("%w: no stored credentials for profile %q (run `polyctl auth login %s --profile %s`)", platform.ErrUnauthorized, name, p.Platform, name)
		}
		return platform.Profile{}, err
	}
	return platform.Profile{Name: name, Platform: p.Platform, Metadata: p.Metadata, Secret: secret}, nil
}

// ProfileFor picks the profile to use for a platform:
// --profile (validated against the platform) > current_profile if it matches
// > the only profile on that platform > error listing candidates.
func (rt *Runtime) ProfileFor(id platform.ID) (string, error) {
	cfg, err := rt.Config()
	if err != nil {
		return "", err
	}
	if rt.Flags.Profile != "" {
		p, err := cfg.Profile(rt.Flags.Profile)
		if err != nil {
			return "", err
		}
		if p.Platform != id {
			return "", fmt.Errorf("profile %q is a %s profile, but this command needs %s", rt.Flags.Profile, p.Platform, id)
		}
		return rt.Flags.Profile, nil
	}
	if cfg.CurrentProfile != "" {
		if p, ok := cfg.Profiles[cfg.CurrentProfile]; ok && p.Platform == id {
			return cfg.CurrentProfile, nil
		}
	}
	names := cfg.ProfilesFor(id)
	switch len(names) {
	case 0:
		return "", fmt.Errorf("%w: no %s profile configured (run `polyctl auth login %s --profile <name>`)", platform.ErrUnauthorized, id, id)
	case 1:
		return names[0], nil
	}
	return "", &AmbiguousError{What: fmt.Sprintf("%s profile", id), Candidates: names}
}

// AmbiguousError is returned when more than one profile could serve a request.
type AmbiguousError struct {
	What       string
	Candidates []string
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("ambiguous %s: candidates are %v; pass --profile <name> to choose", e.What, e.Candidates)
}

// Open creates an authenticated client for a profile.
func (rt *Runtime) Open(ctx context.Context, name string) (platform.Client, platform.Profile, error) {
	if rt.Flags.Offline {
		return nil, platform.Profile{}, ErrOffline
	}
	p, err := rt.LoadProfile(name)
	if err != nil {
		return nil, p, err
	}
	prov, err := platform.Get(p.Platform)
	if err != nil {
		return nil, p, err
	}
	c, err := prov.Open(ctx, p)
	if err != nil {
		return nil, p, fmt.Errorf("open %s profile %q: %w", p.Platform, name, err)
	}
	return c, p, nil
}

// OpenFor resolves the profile for a platform and opens it.
func (rt *Runtime) OpenFor(ctx context.Context, id platform.ID) (platform.Client, platform.Profile, error) {
	name, err := rt.ProfileFor(id)
	if err != nil {
		return nil, platform.Profile{}, err
	}
	return rt.Open(ctx, name)
}

// ErrOffline is returned when a network operation is attempted with --offline.
var ErrOffline = errors.New("network access disabled by --offline")

// SyncReport summarises one Replace.
type SyncReport struct {
	Platform platform.ID           `json:"platform" yaml:"platform"`
	Profile  string                `json:"profile" yaml:"profile"`
	Type     platform.ResourceType `json:"resource_type" yaml:"resource_type"`
	Count    int                   `json:"count" yaml:"count"`
	Error    string                `json:"error,omitempty" yaml:"error,omitempty"`
	Duration time.Duration         `json:"-" yaml:"-"`
}

// SyncProfile fetches the given resource types (nil = all supported) from
// the platform and replaces them in the inventory.
func (rt *Runtime) SyncProfile(ctx context.Context, name string, types []platform.ResourceType) ([]SyncReport, error) {
	client, p, err := rt.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	prov, _ := platform.Get(p.Platform)
	if types == nil {
		types = prov.ResourceTypes()
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	cfg, _ := rt.Config()
	var reports []SyncReport
	for _, t := range types {
		if !platform.Supports(prov, t) {
			continue
		}
		start := time.Now()
		rep := SyncReport{Platform: p.Platform, Profile: name, Type: t}
		rt.Verbosef("sync %s/%s %s ...", p.Platform, name, t)
		res, err := client.Sync(ctx, t)
		if err != nil {
			rep.Error = err.Error()
			reports = append(reports, rep)
			if errors.Is(err, platform.ErrUnauthorized) {
				return reports, err
			}
			continue
		}
		if err := db.Replace(ctx, inventory.Set{Platform: p.Platform, Profile: name, Type: t}, res, cfg.TTLFor(t)); err != nil {
			return reports, err
		}
		rep.Count = len(res)
		rep.Duration = time.Since(start)
		reports = append(reports, rep)
	}
	return reports, nil
}

// NeedsRefresh decides whether a set must be re-fetched given the flags and TTL.
func (rt *Runtime) NeedsRefresh(ctx context.Context, s inventory.Set) (bool, error) {
	if rt.Flags.Offline {
		return false, nil
	}
	if rt.Flags.Refresh {
		return true, nil
	}
	db, err := rt.DB()
	if err != nil {
		return false, err
	}
	st, err := db.GetState(ctx, s)
	if err != nil {
		return false, err
	}
	return !st.Fresh(time.Now()), nil
}

// EnsureSet makes a set available locally: it refreshes when required and
// otherwise serves the cached contents. fetch is called only when a refresh
// is needed. It returns the (possibly stale) cached rows and whether the
// data came from the cache.
func (rt *Runtime) EnsureSet(ctx context.Context, s inventory.Set, fetch func(ctx context.Context) ([]platform.Resource, error)) ([]inventory.Resource, bool, error) {
	db, err := rt.DB()
	if err != nil {
		return nil, false, err
	}
	need, err := rt.NeedsRefresh(ctx, s)
	if err != nil {
		return nil, false, err
	}
	cfg, _ := rt.Config()
	if need {
		rt.Verbosef("refreshing %s/%s %s %s", s.Platform, s.Profile, s.Type, s.Scope)
		res, err := fetch(ctx)
		if err != nil {
			return nil, false, err
		}
		if err := db.Replace(ctx, s, res, cfg.TTLFor(s.Type)); err != nil {
			return nil, false, err
		}
	} else if rt.Flags.Offline {
		st, err := db.GetState(ctx, s)
		if err != nil {
			return nil, false, err
		}
		if st == nil {
			return nil, true, fmt.Errorf("%w: %s %s for %s/%s is not in the local inventory", inventory.ErrNeverSynced, s.Type, s.Scope, s.Platform, s.Profile)
		}
	}
	rows, err := db.List(ctx, inventory.Query{Platform: s.Platform, Profile: s.Profile, Type: s.Type, ParentID: s.Scope})
	if err != nil {
		return nil, false, err
	}
	return rows, !need, nil
}

// DomainProfiles returns the names of profiles whose provider can hold
// zones or registered domains, sorted.
func (rt *Runtime) DomainProfiles() ([]string, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range cfg.ProfileNames() {
		prov, err := platform.Get(cfg.Profiles[n].Platform)
		if err != nil {
			continue
		}
		if platform.Supports(prov, platform.ResZone) || platform.Supports(prov, platform.ResDomain) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}
