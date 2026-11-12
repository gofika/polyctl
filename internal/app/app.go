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
	// Platform restricts domain routing (dns / domain commands) to one
	// platform; it tells apart two accounts of one profile.
	Platform  string
	Refresh   bool
	Offline   bool
	Output    string
	Verbose   bool
	NoBrowser bool
	Yes       bool
}

// Runtime is the shared command context.
type Runtime struct {
	Flags  Flags
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Picker answers the arrow-key prompts. Nil means the terminal one;
	// tests inject a scripted implementation.
	Picker prompt.Picker

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

// Pick returns the Picker for arrow-key prompts: the injected one, or the
// terminal implementation, which reads Stdin and draws on Stderr.
func (rt *Runtime) Pick() prompt.Picker {
	if rt.Picker != nil {
		return rt.Picker
	}
	return prompt.NewPicker(rt.Stdin, rt.Stderr)
}

// Interactive reports whether the command may ask questions: both stdin and
// stderr are terminals, or a Picker was injected. Commands must not prompt
// for a missing argument when it is false, so scripts never block.
func (rt *Runtime) Interactive() bool {
	if rt.Picker != nil {
		return true
	}
	return prompt.IsTerminal(rt.Stdin) && prompt.IsTerminal(rt.Stderr)
}

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
	rt.migrateSecrets(cfg, st)
	return st, nil
}

// migrateSecrets moves the secrets of accounts converted from the legacy
// one-platform-per-profile layout from the bare profile name to their
// profile/platform key, then rewrites the config in the current layout.
// It is best effort: an account whose secret could not be moved keeps its
// legacy_secret mark and is still readable through LoadProfile.
func (rt *Runtime) migrateSecrets(cfg *config.Config, st *creds.Multi) {
	changed := false
	for _, ref := range cfg.Accounts("") {
		a := cfg.Profiles[ref.Profile].Platforms[ref.Platform]
		if !a.LegacySecret {
			continue
		}
		if !st.Has(a.CredentialBackend) {
			// The backend that holds the legacy secret is not reachable in
			// this run (keyring unavailable): nothing can be moved or
			// removed there, so keep the mark and retry on a later run.
			continue
		}
		key := creds.Key(ref.Profile, string(ref.Platform))
		_, err := st.Get(key)
		switch {
		case err == nil:
			// Already under the new key (an interrupted migration, or a
			// token refreshed since): never overwrite it with the old copy.
		case errors.Is(err, creds.ErrNotFound):
			secret, err := st.Get(ref.Profile)
			if err != nil {
				// Not found here does not prove there is nothing to move:
				// the secret may sit in a backend this run cannot reach
				// (keyring unavailable). Keep the mark and try again later.
				if !errors.Is(err, creds.ErrNotFound) {
					rt.Verbosef("migrate credentials of %s: %v", ref.Label(), err)
				}
				continue
			}
			if err := st.Set(key, secret); err != nil {
				rt.Verbosef("migrate credentials of %s: %v", ref.Label(), err)
				continue
			}
			a.CredentialBackend = st.Name()
		default:
			rt.Verbosef("migrate credentials of %s: %v", ref.Label(), err)
			continue
		}
		if err := st.Delete(ref.Profile); err != nil && !errors.Is(err, creds.ErrNotFound) {
			// Keep the mark so the removal is retried on a later run.
			rt.Verbosef("remove legacy credentials of %s: %v", ref.Label(), err)
			continue
		}
		a.LegacySecret = false
		changed = true
	}
	if changed {
		if err := cfg.Save(); err != nil {
			rt.Verbosef("save migrated config: %v", err)
		}
	}
}

// InventoryPath returns the inventory database path: POLYCTL_INVENTORY_DB
// when set, otherwise inventory.db in the config directory.
func (rt *Runtime) InventoryPath() (string, error) {
	if p := os.Getenv("POLYCTL_INVENTORY_DB"); p != "" {
		return p, nil
	}
	dir, err := rt.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "inventory.db"), nil
}

// DB opens (once) the inventory database.
func (rt *Runtime) DB() (*inventory.DB, error) {
	if rt.db != nil {
		return rt.db, nil
	}
	path, err := rt.InventoryPath()
	if err != nil {
		return nil, err
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

// LoadProfile returns a profile's account on a platform with its secret
// attached.
func (rt *Runtime) LoadProfile(name string, id platform.ID) (platform.Profile, error) {
	cfg, err := rt.Config()
	if err != nil {
		return platform.Profile{}, err
	}
	a, err := cfg.Account(name, id)
	if err != nil {
		return platform.Profile{}, err
	}
	st, err := rt.Creds()
	if err != nil {
		return platform.Profile{}, err
	}
	key := creds.Key(name, string(id))
	secret, err := st.Get(key)
	if errors.Is(err, creds.ErrNotFound) && a.LegacySecret {
		secret, err = st.Get(name)
	}
	if err != nil {
		if errors.Is(err, creds.ErrNotFound) {
			return platform.Profile{}, fmt.Errorf("%w: no stored %s credentials for profile %q (run `polyctl auth login %s --profile %s`)", platform.ErrUnauthorized, id, name, id, name)
		}
		return platform.Profile{}, err
	}
	return platform.Profile{Name: name, Platform: id, Metadata: a.Metadata, Secret: secret,
		UpdateSecret: func(s map[string]string) error { return st.Set(key, s) }}, nil
}

// ProfileFor picks the profile to use for a platform:
// --profile (which must have an account on the platform) > current_profile
// if it has one > the only profile that has one > error listing candidates.
func (rt *Runtime) ProfileFor(id platform.ID) (string, error) {
	cfg, err := rt.Config()
	if err != nil {
		return "", err
	}
	if rt.Flags.Profile != "" {
		if _, err := cfg.Profile(rt.Flags.Profile); err != nil {
			return "", fmt.Errorf("%w: %v", platform.ErrNotFound, err)
		}
		if _, err := cfg.Account(rt.Flags.Profile, id); err != nil {
			return "", fmt.Errorf("%w: %v", platform.ErrUnauthorized, err)
		}
		return rt.Flags.Profile, nil
	}
	if cfg.CurrentProfile != "" {
		if p, ok := cfg.Profiles[cfg.CurrentProfile]; ok {
			if _, ok := p.Platforms[id]; ok {
				return cfg.CurrentProfile, nil
			}
		}
	}
	names := cfg.ProfilesFor(id)
	switch len(names) {
	case 0:
		return "", fmt.Errorf("%w: no %s account configured (run `polyctl auth login %s`)", platform.ErrUnauthorized, id, id)
	case 1:
		return names[0], nil
	}
	return "", &AmbiguousError{What: fmt.Sprintf("profile for %s", id), Candidates: names}
}

// AmbiguousError is returned when more than one account or resource could
// serve a request. Hint says how to choose; it defaults to --profile.
type AmbiguousError struct {
	What       string
	Candidates []string
	Hint       string
}

func (e *AmbiguousError) Error() string {
	hint := e.Hint
	if hint == "" {
		hint = "pass --profile <name> to choose"
	}
	return fmt.Sprintf("ambiguous %s: candidates are %v; %s", e.What, e.Candidates, hint)
}

// Open creates an authenticated client for a profile's account on a platform.
func (rt *Runtime) Open(ctx context.Context, name string, id platform.ID) (platform.Client, platform.Profile, error) {
	if rt.Flags.Offline {
		return nil, platform.Profile{}, ErrOffline
	}
	p, err := rt.LoadProfile(name, id)
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
	return rt.Open(ctx, name, id)
}

// ErrOffline is returned when a network operation is attempted with --offline.
var ErrOffline = errors.New("network access disabled by --offline")

// ErrUsage marks command-line usage errors (exit code 2).
var ErrUsage = errors.New("usage error")

// UsageErrf returns an error wrapping ErrUsage.
func UsageErrf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUsage, fmt.Sprintf(format, args...))
}

// SyncReport summarises one Replace.
type SyncReport struct {
	Platform platform.ID           `json:"platform" yaml:"platform"`
	Profile  string                `json:"profile" yaml:"profile"`
	Type     platform.ResourceType `json:"resource_type" yaml:"resource_type"`
	Count    int                   `json:"count" yaml:"count"`
	Error    string                `json:"error,omitempty" yaml:"error,omitempty"`
	Duration time.Duration         `json:"-" yaml:"-"`
}

// SyncAccount fetches the given resource types (nil = all supported) of one
// account and replaces them in the inventory.
func (rt *Runtime) SyncAccount(ctx context.Context, ref config.AccountRef, types []platform.ResourceType) ([]SyncReport, error) {
	name := ref.Profile
	client, p, err := rt.Open(ctx, name, ref.Platform)
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
			what := string(s.Type)
			if s.Scope != "" {
				what += " " + s.Scope
			}
			return nil, true, fmt.Errorf("%w: %s for %s/%s is not in the local inventory", inventory.ErrNeverSynced, what, s.Platform, s.Profile)
		}
	}
	rows, err := db.List(ctx, inventory.Query{Platform: s.Platform, Profile: s.Profile, Type: s.Type, ParentID: s.Scope})
	if err != nil {
		return nil, false, err
	}
	return rows, !need, nil
}

// RoutePlatform returns the platform given with --platform on a dns or
// domain command, or "" when the flag is not set.
func (rt *Runtime) RoutePlatform() (platform.ID, error) {
	if rt.Flags.Platform == "" {
		return "", nil
	}
	id, err := platform.Parse(rt.Flags.Platform)
	if err != nil {
		return "", UsageErrf("%v", err)
	}
	return id, nil
}

// Accounts returns the configured accounts, restricted to --profile and to
// the routing --platform when they are set (an unknown profile is an error).
func (rt *Runtime) Accounts() ([]config.AccountRef, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	if rt.Flags.Profile != "" {
		if _, err := cfg.Profile(rt.Flags.Profile); err != nil {
			return nil, fmt.Errorf("%w: %v", platform.ErrNotFound, err)
		}
	}
	only, err := rt.RoutePlatform()
	if err != nil {
		return nil, err
	}
	var out []config.AccountRef
	for _, ref := range cfg.Accounts(rt.Flags.Profile) {
		if only == "" || ref.Platform == only {
			out = append(out, ref)
		}
	}
	return out, nil
}

// AccountsFor returns the accounts from Accounts whose provider supports at
// least one of the given resource types.
func (rt *Runtime) AccountsFor(kinds ...platform.ResourceType) ([]config.AccountRef, error) {
	all, err := rt.Accounts()
	if err != nil {
		return nil, err
	}
	var out []config.AccountRef
	for _, ref := range all {
		prov, err := platform.Get(ref.Platform)
		if err != nil {
			continue
		}
		for _, k := range kinds {
			if platform.Supports(prov, k) {
				out = append(out, ref)
				break
			}
		}
	}
	return out, nil
}

// DomainAccounts returns the accounts that can hold zones or registered
// domains.
func (rt *Runtime) DomainAccounts() ([]config.AccountRef, error) {
	return rt.AccountsFor(platform.ResZone, platform.ResDomain)
}
