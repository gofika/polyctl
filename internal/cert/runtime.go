package cert

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/httpx"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// LocalPlatform is the platform name of the certificates of the local
// store in the inventory (`inventory list --type certificate`).
const LocalPlatform = platform.ID("local")

// DefaultCertTimeout bounds the wait for a certificate after the order was
// finalized.
const DefaultCertTimeout = 3 * time.Minute

// NewIssuer creates the Issuer of an ACME directory; tests replace it.
var NewIssuer = func(directory string, verbosef func(string, ...any)) Issuer {
	return &LegoIssuer{Directory: directory, UserAgent: httpx.UserAgent, Verbosef: verbosef}
}

// Directory returns the ACME directory of the cert settings: --staging
// selects Let's Encrypt staging, which cannot be combined with a custom
// cert.acme_directory (usage error).
func Directory(cfg *config.Config, staging bool) (string, error) {
	configured := strings.TrimSpace(cfg.Cert.ACMEDirectory)
	if !staging {
		if configured == "" {
			return LetsEncryptProduction, nil
		}
		return configured, nil
	}
	if configured != "" && configured != LetsEncryptProduction && configured != LetsEncryptStaging {
		return "", usage("--staging cannot be combined with cert.acme_directory %s: unset one of them", configured)
	}
	return LetsEncryptStaging, nil
}

// OpenRuntimeStore opens the certificate store of the runtime's settings
// (cert.dir) for the ACME directory selected by staging.
func OpenRuntimeStore(rt *app.Runtime, staging bool) (*Store, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	dir, err := Directory(cfg, staging)
	if err != nil {
		return nil, err
	}
	st := OpenStore(cfg.CertDir(), dir)
	st.Warnf = rt.Infof
	return st, nil
}

// NewEnv builds the Env of `cert ensure` from the runtime: the store and
// the ACME directory of the cert settings, domain routing to the DNS
// account, the questions of the interactive flow, and the inventory.
func NewEnv(rt *app.Runtime, staging bool) (*Env, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	s := cfg.CertSettings()
	st, err := OpenRuntimeStore(rt, staging)
	if err != nil {
		return nil, err
	}
	resolvers := make([]string, 0, len(s.DNS.Resolvers))
	for _, r := range s.DNS.Resolvers {
		addr, err := platform.ParseResolver(r)
		if err != nil {
			return nil, usage("cert.dns.resolvers: %v", err)
		}
		resolvers = append(resolvers, addr)
	}
	env := &Env{
		Store:  st,
		Issuer: NewIssuer(st.Directory, rt.Verbosef),
		DNS: DNSSettings{
			Resolvers:          resolvers,
			MinResolvers:       s.DNS.MinResolvers,
			PropagationTimeout: time.Duration(s.DNS.PropagationTimeout),
			PollInterval:       time.Duration(s.DNS.PollInterval),
			SettleDelay:        time.Duration(s.DNS.SettleDelay),
			QueryTimeout:       cfg.NSTimeout(),
		},
		CertTimeout: DefaultCertTimeout,
		Infof:       rt.Infof,
		Verbosef:    rt.Verbosef,
	}
	pins, err := ParseDNSAccounts(s.DNSAccounts)
	if err != nil {
		return nil, usage("cert.dns_accounts: %v", err)
	}
	env.Route = func(ctx context.Context, root string) (*Route, error) {
		pin, ok := pins[root]
		// --profile / --platform of cert ensure win over the pin.
		if !ok || rt.Flags.Profile != "" || rt.Flags.Platform != "" {
			return route(ctx, rt, root)
		}
		if _, err := cfg.Profile(pin.Profile); err != nil {
			return nil, usage("cert.dns_accounts: %s: %v", root, err)
		}
		pinned, err := rt.Pinned(pin.Profile, pin.Platform)
		if err != nil {
			return nil, err
		}
		rt.Verbosef("DNS account of %s: %s (cert.dns_accounts)", root, pin)
		r, err := route(ctx, pinned, root)
		if err != nil && errors.Is(err, app.ErrDomainUnknown) {
			// The pin says the account hosts root: not finding it there is
			// a configuration error, not "managed elsewhere" (which cert
			// deploy skips).
			return nil, fmt.Errorf("%w: cert.dns_accounts names %s for %s, but it does not host the zone of %s (%v)",
				platform.ErrNotFound, pin, root, root, err)
		}
		return r, err
	}
	env.LiveNS = func(ctx context.Context, root string) []string {
		r := platform.LiveNS(ctx, root, resolvers, cfg.NSTimeout())
		if r.Kind != platform.NSOK {
			rt.Verbosef("live nameservers of %s: %s", root, r.Kind)
			return nil
		}
		return r.Nameservers
	}
	env.AskEmail = func(ctx context.Context) (string, error) {
		if !rt.Interactive() {
			return "", usage("an ACME account e-mail address is required to register an account: pass --email or set cert.email")
		}
		v, err := rt.Pick().Input("ACME account e-mail address (for expiry notices)", "", validEmail)
		if errors.Is(err, prompt.ErrAborted) {
			return "", fmt.Errorf("%w: no e-mail address given; no certificate was issued", platform.ErrNothingToDo)
		}
		return strings.TrimSpace(v), err
	}
	env.ConfirmTOS = func(ctx context.Context, directory string) (bool, error) {
		if !rt.Interactive() {
			return false, usage("registering an ACME account needs the agreement to the CA's terms of service: pass --agree-tos or set cert.agree_tos: true")
		}
		ok, err := rt.Pick().Confirm(fmt.Sprintf("Agree to the terms of service of the CA (%s)?", directory), false)
		if errors.Is(err, prompt.ErrAborted) {
			return false, nil
		}
		return ok, err
	}
	env.Remember = func(ctx context.Context, b *Bundle) { remember(ctx, rt, cfg, b) }
	return env, nil
}

// DNSPin is the DNS account cert.dns_accounts names for a root domain.
type DNSPin struct {
	Profile string
	// Platform is empty when the entry names the profile only.
	Platform platform.ID
}

func (p DNSPin) String() string {
	if p.Platform == "" {
		return p.Profile
	}
	return string(p.Platform) + "/" + p.Profile
}

// ParseDNSAccounts parses cert.dns_accounts: root domain -> "profile" or
// "platform/profile". A key must be a root domain.
func ParseDNSAccounts(m map[string]string) (map[string]DNSPin, error) {
	out := make(map[string]DNSPin, len(m))
	for k, v := range m {
		root, err := RootDomain(k)
		if err != nil {
			return nil, fmt.Errorf("%q: %v", k, err)
		}
		if key := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(k)), "."); key != root {
			return nil, fmt.Errorf("%q is not a root domain (use %s)", k, root)
		}
		v = strings.TrimSpace(v)
		var pin DNSPin
		if plat, prof, found := strings.Cut(v, "/"); found {
			id, err := platform.Parse(plat)
			if err != nil {
				return nil, fmt.Errorf("%s: %q: %v", root, v, err)
			}
			pin = DNSPin{Profile: strings.TrimSpace(prof), Platform: id}
		} else {
			pin = DNSPin{Profile: v}
		}
		if pin.Profile == "" || strings.Contains(pin.Profile, "/") {
			return nil, fmt.Errorf("%s: %q is not \"profile\" or \"platform/profile\"", root, v)
		}
		out[root] = pin
	}
	return out, nil
}

// validEmail is the check of the e-mail question.
func validEmail(s string) error {
	s = strings.TrimSpace(s)
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || !strings.Contains(s[strings.LastIndexByte(s, '@')+1:], ".") {
		return errors.New("enter an e-mail address such as you@your-domain.tld")
	}
	return nil
}

// route finds and opens the DNS account of root.
func route(ctx context.Context, rt *app.Runtime, root string) (*Route, error) {
	t, err := rt.ResolveDomain(ctx, root, platform.ResZone)
	if err != nil {
		if errors.Is(err, app.ErrDomainUnknown) {
			return nil, fmt.Errorf("%w; no DNS account hosts %s: log in to its DNS platform with `polyctl auth login` and run `polyctl sync`, or see where its nameservers point with `polyctl domain ns check %s`", err, root, root)
		}
		return nil, err
	}
	dns, err := rt.OpenDNS(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %w", t.Platform, t.Profile, err)
	}
	r := &Route{DNS: dns, Platform: t.Platform, Profile: t.Profile, ZoneID: t.ResourceID, Zone: t.Domain}
	if zg, ok := dns.(platform.ZoneGetter); ok {
		if z, err := zg.GetZone(ctx, t.ResourceID); err == nil {
			r.ZoneNS = z.Nameservers
		} else {
			rt.Verbosef("zone %s: %v", t.Domain, err)
		}
	} else if zones, err := dns.ListZones(ctx); err == nil {
		for _, z := range zones {
			if z.ID == t.ResourceID {
				r.ZoneNS = z.Nameservers
			}
		}
	} else {
		rt.Verbosef("zones of %s/%s: %v", t.Platform, t.Profile, err)
	}
	rt.Infof("zone %s via %s/%s", t.Domain, t.Platform, t.Profile)
	return r, nil
}

// remember upserts the certificate into the inventory as a resource of
// the local store, so that `inventory list --type certificate` shows it.
func remember(ctx context.Context, rt *app.Runtime, cfg *config.Config, b *Bundle) {
	db, err := rt.DB()
	if err != nil {
		rt.Verbosef("inventory: %v", err)
		return
	}
	set := inventory.Set{Platform: LocalPlatform, Profile: "", Type: platform.ResCertificate}
	data := map[string]any{
		"names": b.Names, "serial": b.Serial, "not_before": b.NotBefore.Format(time.RFC3339),
		"not_after": b.NotAfter.Format(time.RFC3339), "key_type": b.KeyType, "issuer": b.Issuer,
		"path": b.Path, "acme_directory": b.ACMEDirectory,
	}
	r := platform.Resource{Type: platform.ResCertificate, ID: b.Path, Name: b.Domain, Data: data}
	if err := db.Upsert(ctx, set, r, cfg.TTLFor(platform.ResCertificate)); err != nil {
		rt.Verbosef("inventory: %v", err)
	}
}
