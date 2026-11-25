package cert

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// EnsureOptions are the inputs of `cert ensure`.
type EnsureOptions struct {
	// Domain is any name under the root domain (www.example.com,
	// *.example.com, example.com).
	Domain string
	// Days: a certificate with at most this many whole days left is
	// renewed.
	Days  int
	Force bool
	// KeyType is the key type the certificate must have (KeyTypes).
	KeyType string
	// Email is the ACME account address (only used to find or register
	// the account); AgreeTOS agrees to the CA's terms of service.
	Email    string
	AgreeTOS bool
	// ReuseKey keeps the private key of the current certificate on
	// renewal instead of creating a new one.
	ReuseKey bool
	DryRun   bool
	// Offline refuses anything that needs the network.
	Offline bool
}

// Route is the DNS account that receives the challenge records of a root
// domain.
type Route struct {
	DNS      platform.DNSService
	Platform platform.ID
	Profile  string
	ZoneID   string
	Zone     string
	// ZoneNS are the nameservers the platform assigned to the zone, when
	// it says.
	ZoneNS []string
}

// Label is "platform/profile".
func (r *Route) Label() string { return string(r.Platform) + "/" + r.Profile }

// DNSSettings tune the challenge records and their propagation check.
type DNSSettings struct {
	Resolvers          []string // host:port
	MinResolvers       int
	PropagationTimeout time.Duration
	PollInterval       time.Duration
	SettleDelay        time.Duration
	QueryTimeout       time.Duration
}

// Env is everything Ensure works with; the command line builds it from the
// runtime (NewEnv), tests from fakes.
type Env struct {
	Store  *Store
	Issuer Issuer
	DNS    DNSSettings
	// CertTimeout bounds the wait for the certificate after finalization.
	CertTimeout time.Duration
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// Route finds the DNS account of a root domain, read-only. Its errors
	// carry the exit codes (not found, ambiguous, authentication).
	Route func(ctx context.Context, root string) (*Route, error)
	// LiveNS returns the nameservers public resolvers report for a root
	// domain (nil when unknown).
	LiveNS func(ctx context.Context, root string) []string
	// AskEmail asks for the account address in the interactive flow; in
	// the non-interactive one it returns the usage error. Nil: usage error.
	AskEmail func(ctx context.Context) (string, error)
	// ConfirmTOS asks for the agreement to the CA's terms of service in
	// the interactive flow (false: declined); in the non-interactive one
	// it returns the usage error. Nil: usage error.
	ConfirmTOS func(ctx context.Context, directory string) (bool, error)
	// Remember records an issued certificate in the inventory (nil: not).
	Remember func(ctx context.Context, b *Bundle)
	// Lookup and Sleep replace DNS queries and waits in tests.
	Lookup TXTLookup
	Sleep  func(ctx context.Context, d time.Duration) error
	// Infof and Verbosef report progress on stderr (nil: silent).
	Infof, Verbosef func(format string, args ...any)
}

// ReportTarget is the target of the change report of `cert ensure`.
type ReportTarget struct {
	// Store is the certificate store directory.
	Store string `json:"store" yaml:"store"`
	// ACME is the ACME directory URL.
	ACME string `json:"acme" yaml:"acme"`
	// DNS is the DNS account of the challenge records (platform/profile),
	// when the run needed one.
	DNS string `json:"dns,omitempty" yaml:"dns,omitempty"`
}

// Result is the change report of `cert ensure`.
type Result struct {
	Target  ReportTarget      `json:"target" yaml:"target"`
	DryRun  bool              `json:"dry_run" yaml:"dry_run"`
	Changes []platform.Change `json:"changes" yaml:"changes"`
	// Bundle is the certificate the store holds afterwards (nil in a dry
	// run that would issue one).
	Bundle *Bundle `json:"-" yaml:"-"`
}

// ErrDeclined marks a question the user answered with no (the terms of
// service): nothing was issued, and that is not a failure.
var ErrDeclined = platform.ErrNothingToDo

// usage wraps a message as invalid input (exit code 2).
func usage(format string, args ...any) error {
	return fmt.Errorf("%w: %s", platform.ErrInvalidInput, fmt.Sprintf(format, args...))
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) infof(format string, args ...any) {
	if e.Infof != nil {
		e.Infof(format, args...)
	}
}

func (e *Env) verbosef(format string, args ...any) {
	if e.Verbosef != nil {
		e.Verbosef(format, args...)
	}
}

// CAName names the ACME directory in the report: letsencrypt,
// letsencrypt-staging, or the host of any other directory.
func CAName(directory string) string {
	switch directory {
	case LetsEncryptProduction:
		return "letsencrypt"
	case LetsEncryptStaging:
		return "letsencrypt-staging"
	}
	if u, err := url.Parse(directory); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return directory
}

// Ensure makes sure the store holds a certificate of the root domain of
// o.Domain and its wildcard, with more than o.Days whole days left and the
// requested key type: it is issued when missing, renewed when it is not
// good enough (or with o.Force), and left alone otherwise. Issuance uses
// DNS-01 through the DNS account that hosts the root domain. The steps:
//
//  1. read the store (no lock): a good certificate ends here, unchanged;
//  2. route the domain to its DNS account and check the nameservers and
//     the challenge name (read-only, in a dry run too); a dry run ends here;
//  3. take the lock of the root domain and read the store again (another
//     process may have renewed it meanwhile);
//  4. find or register the ACME account; write the new private key to
//     pending/ first; order the certificate; check it and install it
//     atomically; append history.log; record it in the inventory.
//
// A failed issuance is not retried: the CA's rate limits make blind
// retries counterproductive.
func Ensure(ctx context.Context, env *Env, o EnsureOptions) (*Result, error) {
	root, err := RootDomain(o.Domain)
	if err != nil {
		return nil, err
	}
	if o.Days < 0 {
		return nil, usage("--days must not be negative, got %d", o.Days)
	}
	if o.KeyType == "" {
		o.KeyType = KeyEC256
	}
	if !slices.Contains(KeyTypes, o.KeyType) {
		return nil, usage("--key-type: %q is not one of %s", o.KeyType, strings.Join(KeyTypes, ", "))
	}
	if n := len(env.DNS.Resolvers); env.DNS.MinResolvers > n {
		return nil, usage("cert.dns.min_resolvers is %d but only %d resolver(s) are configured in cert.dns.resolvers", env.DNS.MinResolvers, n)
	}
	st := env.Store
	res := &Result{Target: ReportTarget{Store: st.Dir, ACME: st.Directory}, DryRun: o.DryRun, Changes: []platform.Change{}}
	certRes := "cert/" + root
	acctRes := "acme-account/" + CAName(st.Directory)

	cur, err := st.Load(root, false)
	if err != nil {
		return res, err
	}
	if cur != nil && cur.NeedsRepair && !o.DryRun {
		// Repairs (a restore from the archive, a key mode) are made under
		// the lock: another process may be replacing the bundle right now.
		unlock, err := st.Lock(ctx, root)
		if err != nil {
			return res, err
		}
		cur, err = st.Load(root, true)
		unlock()
		if err != nil {
			return res, err
		}
	}
	reason, action := renewReason(cur, o, env.now())
	if reason == "" {
		res.Bundle = cur
		res.Changes = append(res.Changes, certChange(certRes, platform.Unchanged, cur, env.now()))
		return res, nil
	}
	if o.Offline {
		return res, fmt.Errorf("%w: issuing the certificate of %s needs the network (%s)", app.ErrOffline, root, reason)
	}
	route, err := env.Route(ctx, root)
	if err != nil {
		return res, err
	}
	res.Target.DNS = route.Label()
	if env.LiveNS != nil {
		if w := nsWarning(root, route.ZoneNS, env.LiveNS(ctx, root)); w != "" {
			env.infof("%s", w)
		}
	}
	if err := checkChallengeName(ctx, route, root); err != nil {
		return res, err
	}
	acct, email, err := findAccount(st, o.Email)
	if err != nil {
		return res, err
	}
	detail := fmt.Sprintf("%s; issue [%s] via dns-01, DNS account %s", reason, strings.Join(Names(root), " "), route.Label())
	if o.DryRun {
		if acct == nil || acct.URI == "" {
			// No account, or a key whose registration did not succeed:
			// the real run registers one.
			d := "register a new account"
			if email != "" {
				d += " for " + email
			} else {
				d += " (needs --email or cert.email)"
			}
			res.Changes = append(res.Changes, platform.Change{Resource: acctRes, Action: platform.WouldCreate, Detail: d})
		}
		res.Changes = append(res.Changes, platform.Change{Resource: certRes, Action: action.DryRun(), Detail: detail})
		return res, nil
	}
	// The questions come before the lock: nobody waits for a user.
	agreed := o.AgreeTOS
	if acct == nil || acct.URI == "" {
		if email == "" {
			if email, err = askEmail(ctx, env); err != nil {
				return res, err
			}
			if acct != nil && acct.Email == "" {
				// A key left without account.json was never registered
				// (account.json is written before registering): start a
				// new account under the address just given.
				acct = nil
			}
		}
		if !agreed {
			if agreed, err = confirmTOS(ctx, env); err != nil || !agreed {
				return res, declined(err)
			}
		}
	}

	// The stored account is looked up before the lock as well: when the CA
	// no longer knows it, registering it again needs the agreement to the
	// terms, and that question must not be asked while holding the lock.
	var resolvedURI string
	var resolveErr error
	if acct != nil && acct.URI != "" {
		resolvedURI, resolveErr = env.Issuer.ResolveAccount(ctx, acct)
		if errors.Is(resolveErr, ErrAccountNotFound) {
			env.infof("the CA does not know the account of %s any more; registering it again", acct.Email)
			// newAccount must be signed with the key itself (RFC 8555
			// section 7.3), never with the account URI the CA forgot.
			acct.URI, resolveErr = "", nil
			if !agreed {
				if agreed, err = confirmTOS(ctx, env); err != nil || !agreed {
					return res, declined(err)
				}
			}
		}
	}

	unlock, err := st.Lock(ctx, root)
	if err != nil {
		return res, err
	}
	defer unlock()
	if cur, err = st.Load(root, true); err != nil {
		return res, err
	}
	if reason, action = renewReason(cur, o, env.now()); reason == "" {
		env.infof("the certificate of %s was renewed by another process meanwhile", root)
		res.Bundle = cur
		res.Changes = append(res.Changes, certChange(certRes, platform.Unchanged, cur, env.now()))
		return res, nil
	}

	var plan platform.Plan
	plan.Add(platform.Step{
		Resource: acctRes,
		Action:   platform.Created,
		Check: func(ctx context.Context) (platform.Change, bool, error) {
			if acct == nil || acct.URI == "" {
				return platform.Change{}, false, nil
			}
			if resolveErr != nil {
				return platform.Change{}, false, fmt.Errorf("look up the ACME account: %w", resolveErr)
			}
			if resolvedURI != "" && resolvedURI != acct.URI {
				acct.URI = resolvedURI
				if err := st.SaveAccount(acct); err != nil {
					return platform.Change{}, false, err
				}
			}
			return platform.Change{ID: acct.ID(), Detail: acct.ID()}, true, nil
		},
		Apply: func(ctx context.Context) (platform.Change, error) {
			if acct == nil {
				var err error
				if acct, err = st.NewAccount(email); err != nil {
					return platform.Change{}, err
				}
			}
			uri, err := env.Issuer.Register(ctx, acct)
			if err != nil {
				return platform.Change{}, err
			}
			acct.URI, acct.RegisteredAt = uri, env.now()
			if err := st.SaveAccount(acct); err != nil {
				return platform.Change{}, err
			}
			env.infof("registered the ACME account %s (%s)", acct.ID(), acct.Email)
			return platform.Change{ID: acct.ID(), Detail: "registered " + acct.Email}, nil
		},
	})
	plan.Add(platform.Step{
		Resource: certRes,
		Action:   action,
		Desc:     detail,
		Apply: func(ctx context.Context) (platform.Change, error) {
			b, err := obtain(ctx, env, o, route, acct, root, cur)
			if err != nil {
				return platform.Change{}, err
			}
			res.Bundle = b
			ch := certChange(certRes, action, b, env.now())
			return ch, nil
		},
	})
	changes, err := plan.Run(ctx, false)
	res.Changes = changes
	return res, err
}

// declined turns a "no" to the terms of service into ErrDeclined.
func declined(err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: the terms of service of the CA were not accepted; no certificate was issued", ErrDeclined)
}

func askEmail(ctx context.Context, env *Env) (string, error) {
	if env.AskEmail == nil {
		return "", usage("an ACME account e-mail address is required to register an account: pass --email or set cert.email")
	}
	return env.AskEmail(ctx)
}

func confirmTOS(ctx context.Context, env *Env) (bool, error) {
	if env.ConfirmTOS == nil {
		return false, usage("registering an ACME account needs the agreement to the CA's terms of service: pass --agree-tos or set cert.agree_tos: true")
	}
	return env.ConfirmTOS(ctx, env.Store.Directory)
}

// renewReason says why the certificate needs issuing ("" when it does not)
// and whether that creates or updates it.
func renewReason(cur *Bundle, o EnsureOptions, now time.Time) (string, platform.Action) {
	if cur == nil {
		return "no certificate in the store", platform.Created
	}
	left := cur.DaysLeft(now)
	switch {
	case o.Force:
		return "--force", platform.Updated
	case !cur.CoversRoot():
		return fmt.Sprintf("the certificate does not cover both %s and *.%s", cur.Domain, cur.Domain), platform.Updated
	case cur.KeyType != o.KeyType:
		return fmt.Sprintf("key type %s, %s requested", cur.KeyType, o.KeyType), platform.Updated
	case left <= o.Days:
		return fmt.Sprintf("%d days left <= %d", left, o.Days), platform.Updated
	}
	return "", platform.Unchanged
}

// certChange is the report row of a certificate.
func certChange(resource string, action platform.Action, b *Bundle, now time.Time) platform.Change {
	left := b.DaysLeft(now)
	names := strings.Join(b.Names, ",")
	return platform.Change{
		Resource: resource,
		Action:   action,
		ID:       b.Serial,
		Detail:   fmt.Sprintf("names=%s not_after=%s days_left=%d", names, b.NotAfter.Format("2006-01-02"), left),
		Attrs: map[string]string{
			"names":      names,
			"not_before": b.NotBefore.Format(time.RFC3339),
			"not_after":  b.NotAfter.Format(time.RFC3339),
			"days_left":  strconv.Itoa(left),
			"key_type":   b.KeyType,
			"path":       b.Path,
		},
	}
}

// checkChallengeName refuses a CNAME at _acme-challenge.<root>: the ACME
// library would follow it and expect the TXT records at its target, in a
// zone this account may not hold (delegated validation is not supported).
// Platforms accept a TXT next to a CNAME of the same name, so this has to
// be checked here.
func checkChallengeName(ctx context.Context, route *Route, root string) error {
	recs, err := route.DNS.ListRecords(ctx, route.ZoneID)
	if err != nil {
		return fmt.Errorf("read the records of zone %s on %s: %w", route.Zone, route.Label(), err)
	}
	name := challengeFQDN(root)
	for _, r := range recs {
		if strings.EqualFold(r.Type, "CNAME") && platform.FQDN(r.Name, route.Zone) == name {
			return fmt.Errorf("%s is a CNAME to %s: delegated DNS-01 validation is not supported; remove the CNAME to let polyctl write the challenge records in zone %s", name, platform.NormalizeDomain(r.Value), route.Zone)
		}
	}
	return nil
}

// findAccount returns the stored account of email; without an address,
// the only account of the store's directory (there may be none). The
// address is returned too: the account's when one was found.
func findAccount(st *Store, email string) (*Account, string, error) {
	email = strings.TrimSpace(email)
	if email != "" {
		a, err := st.LoadAccount(email)
		return a, email, err
	}
	all, err := st.Accounts()
	if err != nil {
		return nil, "", err
	}
	if len(all) == 1 {
		return all[0], all[0].Email, nil
	}
	// A key whose registration the CA refused (a rejected address) stays in
	// the store; it must not make the one registered account ambiguous.
	var registered []*Account
	for _, a := range all {
		if a.URI != "" {
			registered = append(registered, a)
		}
	}
	switch {
	case len(all) == 0:
		return nil, "", nil
	case len(registered) == 1:
		return registered[0], registered[0].Email, nil
	}
	return nil, "", usage("the store holds %d ACME accounts for %s: pass --email or set cert.email to choose", len(all), st.Directory)
}

// obtain issues the certificate and installs it in the store.
func obtain(ctx context.Context, env *Env, o EnsureOptions, route *Route, acct *Account, root string, cur *Bundle) (*Bundle, error) {
	st := env.Store
	if b := pendingBundle(st, o, root, cur, env); b != nil {
		env.infof("installing the certificate (serial %s) an earlier run obtained and could not install, kept in %s; no new order", b.Serial, st.PendingChainPath(root))
		return install(ctx, env, root, cur, b)
	}
	key, err := issuanceKey(st, o, root, cur, env)
	if err != nil {
		return nil, err
	}
	if err := st.SavePendingKey(root, key); err != nil {
		return nil, fmt.Errorf("save the pending private key: %w", err)
	}
	keyPEM, err := MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	provider := &DNSProvider{
		Ctx: ctx, DNS: route.DNS, ZoneID: route.ZoneID, Zone: route.Zone, TTL: ChallengeTTL(route.Platform),
		PropagationTimeout: env.DNS.PropagationTimeout, PollInterval: env.DNS.PollInterval, SettleDelay: env.DNS.SettleDelay,
		Sleep: env.Sleep, Warnf: env.Infof, Verbosef: env.Verbosef, Ledger: st.Challenges(root),
	}
	prop := &Propagation{
		Ctx: ctx, Resolvers: env.DNS.Resolvers, Min: env.DNS.MinResolvers, QueryTimeout: env.DNS.QueryTimeout,
		SettleDelay: env.DNS.SettleDelay, Sleep: env.Sleep, Lookup: env.Lookup, Verbosef: env.Verbosef,
	}
	env.infof("issuing a certificate for %s via dns-01 (zone %s on %s)...", strings.Join(Names(root), ", "), route.Zone, route.Label())
	chain, err := env.Issuer.Obtain(ctx, acct, ObtainRequest{
		Domains: Names(root), Key: key, KeyType: o.KeyType, Provider: provider, Propagation: prop,
		Resolvers: env.DNS.Resolvers, CertTimeout: env.CertTimeout,
	})
	if err != nil {
		err = describeObtainError(err, prop, st.PendingKeyPath(root))
		if errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrForbidden) || errors.Is(err, platform.ErrNotSupported) {
			// The DNS account refused the challenge records: name it.
			err = fmt.Errorf("DNS account %s: %w", route.Label(), err)
		}
		return nil, err
	}
	b, err := NewBundle(root, chain, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("the CA's certificate cannot be used (the store was not changed): %w", err)
	}
	if !b.CoversRoot() {
		return nil, fmt.Errorf("the CA's certificate holds %v, not both %s and *.%s (the store was not changed)", b.Names, root, root)
	}
	if !b.NotAfter.After(env.now()) {
		return nil, fmt.Errorf("the CA's certificate expired at %s (the store was not changed)", b.NotAfter.Format(time.RFC3339))
	}
	// Kept with the pending key until it is installed: when Save fails, the
	// next run installs this certificate instead of ordering another one.
	if err := st.SavePendingChain(root, chain); err != nil {
		env.infof("warning: cannot keep the issued certificate at %s: %v", st.PendingChainPath(root), err)
	}
	return install(ctx, env, root, cur, b)
}

// install makes b the live bundle of root, then records it in history.log
// and the inventory.
func install(ctx context.Context, env *Env, root string, cur, b *Bundle) (*Bundle, error) {
	st := env.Store
	if err := st.Save(b); err != nil {
		return nil, fmt.Errorf("install the certificate (it is kept with its private key in %s; the next run installs it without a new order): %w", filepath.Dir(st.PendingKeyPath(root)), err)
	}
	action := "updated"
	if cur == nil {
		action = "created"
	}
	if err := st.AppendHistory(HistoryEntry{Action: action, Domain: root, Serial: b.Serial, NotAfter: b.NotAfter.Format(time.RFC3339), ACMEDirectory: st.Directory}); err != nil {
		env.infof("warning: history.log: %v", err)
	}
	if env.Remember != nil {
		env.Remember(ctx, b)
	}
	return b, nil
}

// pendingBundle returns the certificate an earlier run obtained and could
// not install, when it is still good enough: it holds both names, has the
// requested key type and more than o.Days days left, and is not the live
// certificate. --force orders a new one instead.
func pendingBundle(st *Store, o EnsureOptions, root string, cur *Bundle, env *Env) *Bundle {
	if o.Force {
		return nil
	}
	b, err := st.LoadPendingBundle(root)
	if err != nil {
		env.infof("warning: the certificate kept at %s cannot be used (%v); ordering a new one", st.PendingChainPath(root), err)
		return nil
	}
	if b == nil || !b.CoversRoot() || b.KeyType != o.KeyType || b.DaysLeft(env.now()) <= o.Days ||
		(cur != nil && cur.Serial == b.Serial) {
		return nil
	}
	return b
}

// issuanceKey picks the private key of the new certificate: the pending
// key an interrupted run left (an order may have reached the CA; reusing
// the key keeps a certificate it issued usable), else with reuse_key the
// current one, else a new key.
func issuanceKey(st *Store, o EnsureOptions, root string, cur *Bundle, env *Env) (crypto.Signer, error) {
	pending, err := st.LoadPendingKey(root)
	if err != nil {
		env.infof("warning: the pending private key %s cannot be read (%v); creating a new one", st.PendingKeyPath(root), err)
	} else if pending != nil && KeyTypeOf(pending.Public()) == o.KeyType {
		env.infof("using the private key an interrupted run left at %s", st.PendingKeyPath(root))
		return pending, nil
	}
	if o.ReuseKey && cur != nil && cur.KeyType == o.KeyType {
		env.verbosef("cert.reuse_key: keeping the private key of the current certificate")
		return cur.Key, nil
	}
	return GenerateKey(o.KeyType)
}
