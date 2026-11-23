package cert

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

// DeployEnsureMargin is added to --days when cert deploy asks the store for
// a certificate: with the same threshold on both sides, a certificate with
// days+1 days left would not be renewed, be deployed, and be due on the
// cloud again the next day, uploaded again and again.
const DeployEnsureMargin = 5

// DeployOptions are the inputs of `cert deploy`.
type DeployOptions struct {
	// Domain is the root domain to deploy (empty with All).
	Domain string
	All    bool
	// Days: in --all mode targets whose certificate has at most this many
	// whole days left are updated; the store is asked for a certificate
	// with more than Days+DeployEnsureMargin days left, in both modes.
	Days  int
	Force bool
	// Deployers are the deployers to run, in order.
	Deployers []platform.CertDeployer
	// Regions is --region: it replaces cert.<platform>.regions.
	Regions []string
	Prune   bool
	DryRun  bool
	NoWait  bool
	Timeout time.Duration
	// NameTemplate is cert.name_template (see platform.DeployOptions).
	NameTemplate string
}

// DeployEnv is what Deploy works with; the command line builds it from the
// runtime, tests from fakes.
type DeployEnv struct {
	// Accounts are the accounts to deploy to (--profile and --platform
	// applied), in order.
	Accounts []config.AccountRef
	// SkipAccounts is cert.skip_accounts: a profile name skips every
	// deployer of the profile, "profile:deployer" one deployer.
	SkipAccounts []string
	// Open opens the client of an account.
	Open func(ctx context.Context, ref config.AccountRef) (platform.Client, error)
	// Regions returns cert.<platform>.regions of an account (nil: the
	// deployer's default).
	Regions func(ref config.AccountRef) []string
	// Ensure makes sure the store holds a certificate of root with more
	// than days whole days left (cert ensure; its dry-run form in a dry
	// run). An error that is app.ErrDomainUnknown means that no DNS
	// account hosts the domain.
	Ensure func(ctx context.Context, root string, days int) (*Result, error)
	// Stored returns the certificate the store holds for root (nil: none).
	Stored func(root string) *Bundle
	// History records a deployment in history.log (nil: not).
	History func(e HistoryEntry)
	// Notify tells hooks.on_failure about a failure (nil: nobody).
	Notify func(ctx context.Context, f app.Failure)
	// ConfirmPrune asks before the expired certificates are deleted; nil
	// deletes without asking (--yes).
	ConfirmPrune func(ctx context.Context, resources []string) (bool, error)
	// Written is called for every account a run wrote certificates in, so
	// that the inventory can be updated (nil: nothing).
	Written func(ctx context.Context, ref config.AccountRef, c platform.Client)
	Now     func() time.Time
	Infof   func(format string, args ...any)
}

func (e *DeployEnv) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *DeployEnv) infof(format string, args ...any) {
	if e.Infof != nil {
		e.Infof(format, args...)
	}
}

// DeployScope is the target of the change report of `cert deploy`.
type DeployScope struct {
	// Scope is "all" or "domain".
	Scope  string `json:"scope" yaml:"scope"`
	Domain string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Days   int    `json:"days" yaml:"days"`
}

// DeployReport is the change report of `cert deploy`.
type DeployReport struct {
	Target  DeployScope       `json:"target" yaml:"target"`
	DryRun  bool              `json:"dry_run" yaml:"dry_run"`
	Changes []platform.Change `json:"changes" yaml:"changes"`
}

// bundleResult is the certificate of one root domain, fetched once per
// run.
type bundleResult struct {
	cert *platform.DeployCert
	// skip is why the targets of the root are skipped (no DNS account);
	// err why they fail.
	skip string
	err  error
}

// deployRun is the state of one Deploy.
type deployRun struct {
	env     *DeployEnv
	o       DeployOptions
	po      platform.DeployOptions
	rep     *DeployReport
	bundles map[string]*bundleResult
	// failed counts the failed items, auth those failed for credentials
	// or permissions; total counts the items handled.
	failed, auth, total int
	first               error
	prunes              []pruneJob
}

// pruneJob is the cleanup of one deployer in one account, run once every
// account was deployed to and the deletions were confirmed.
type pruneJob struct {
	ref    config.AccountRef
	client platform.Client
	steps  []platform.Step
}

// Deploy puts the certificates of the local store on every place of the
// accounts that serves them (cert deploy). For each account and each of
// its deployers the targets are discovered live (read-only); a target is
// updated when its certificate has at most o.Days days left (--all), when
// it is not the store's certificate of its root domain (a domain), or
// always (--force). The store's certificate is ensured first (cert ensure
// with o.Days+DeployEnsureMargin), once per root domain and run; a domain
// no DNS account hosts skips its targets (its certificates are managed
// elsewhere). Every target, deployer and account is handled on its own: a
// failure is reported as a failed change, sent to hooks.on_failure, and the
// run goes on; the error is then a PartialError (exit code 1), or an
// authentication error when every failure was one (exit code 3).
func Deploy(ctx context.Context, env *DeployEnv, o DeployOptions) (*DeployReport, error) {
	r := &deployRun{env: env, o: o, bundles: map[string]*bundleResult{}}
	r.po = platform.DeployOptions{Days: o.Days, Force: o.Force, All: o.All, DryRun: o.DryRun, NoWait: o.NoWait, Timeout: o.Timeout,
		Prune: o.Prune, NameTemplate: o.NameTemplate, Now: env.now, Infof: env.Infof}
	scope := DeployScope{Scope: "all", Days: o.Days}
	if !o.All {
		scope = DeployScope{Scope: "domain", Domain: o.Domain, Days: o.Days}
	}
	r.rep = &DeployReport{Target: scope, DryRun: o.DryRun, Changes: []platform.Change{}}
	if !o.All {
		// A named domain: its certificate first, whatever the targets.
		b := r.bundle(ctx, o.Domain)
		if b.skip != "" && (env.Stored == nil || env.Stored(o.Domain) == nil) {
			return r.rep, fmt.Errorf("%w: no certificate of %s in the local store, and %s", platform.ErrNotFound, o.Domain, b.skip)
		}
	}
	for _, ref := range env.Accounts {
		if err := ctx.Err(); err != nil {
			return r.rep, err
		}
		r.account(ctx, ref)
	}
	r.prune(ctx)
	if len(r.rep.Changes) == 0 {
		env.infof("nothing to deploy: no certificate target found in the selected accounts")
	}
	return r.rep, r.result()
}

// result is the error of the run.
func (r *deployRun) result() error {
	if r.failed == 0 {
		return nil
	}
	if r.auth == r.failed {
		return fmt.Errorf("%d item(s) failed for lack of credentials or permissions; first: %w", r.failed, r.first)
	}
	return &platform.PartialError{Failed: r.failed, Total: r.total, First: r.first}
}

func (r *deployRun) add(chs ...platform.Change) { r.rep.Changes = append(r.rep.Changes, chs...) }

// fail records a failed item: its change, the counts and the notification.
func (r *deployRun) fail(ctx context.Context, ch platform.Change, err error, f app.Failure, notify bool) {
	if ch.Action != platform.Failed {
		ch.Action = platform.Failed
	}
	if ch.Detail == "" {
		ch.Detail = err.Error()
	}
	r.add(ch)
	r.count(ctx, err, f, notify)
}

// count records a failure whose change is in the report already.
func (r *deployRun) count(ctx context.Context, err error, f app.Failure, notify bool) {
	r.failed++
	if errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrForbidden) {
		r.auth++
	}
	if r.first == nil {
		r.first = err
	}
	if notify && !r.o.DryRun && r.env.Notify != nil {
		f.Event = "cert.deploy.failed"
		f.Error = err.Error()
		r.env.Notify(ctx, f)
	}
}

// skipped reports whether the account (or one of its deployers) is listed
// in cert.skip_accounts.
func (r *deployRun) skipped(profile, deployer string) bool {
	for _, s := range r.env.SkipAccounts {
		s = strings.TrimSpace(s)
		if s == profile || s == profile+":"+deployer {
			return true
		}
	}
	return false
}

// account runs the deployers of one account.
func (r *deployRun) account(ctx context.Context, ref config.AccountRef) {
	var deps []platform.CertDeployer
	for _, d := range r.o.Deployers {
		if d.Platform() != ref.Platform {
			continue
		}
		if r.skipped(ref.Profile, d.ID()) {
			r.env.infof("skipping %s of %s (cert.skip_accounts)", d.ID(), ref.Label())
			continue
		}
		deps = append(deps, d)
	}
	if len(deps) == 0 {
		return
	}
	client, err := r.env.Open(ctx, ref)
	if err != nil {
		for _, d := range deps {
			r.total++
			r.fail(ctx, platform.Change{Resource: platform.DeployResource(d.ID(), ref.Profile, "account")}, err,
				app.Failure{Platform: string(ref.Platform), Profile: ref.Profile, Deployer: d.ID()}, true)
		}
		return
	}
	regions := r.o.Regions
	if len(regions) == 0 && r.env.Regions != nil {
		regions = r.env.Regions(ref)
	}
	wrote := false
	for _, d := range deps {
		acct := &platform.DeployAccount{Platform: ref.Platform, Profile: ref.Profile, Client: client, Regions: slices.Clone(regions)}
		if r.deployer(ctx, d, acct) {
			wrote = true
		}
	}
	if wrote && !r.o.DryRun && r.env.Written != nil {
		r.env.Written(ctx, ref, client)
	}
}

// deployer runs one deployer in one account and reports whether it wrote
// anything. A panic of the deployer fails it for this account only.
func (r *deployRun) deployer(ctx context.Context, d platform.CertDeployer, acct *platform.DeployAccount) (wrote bool) {
	base := app.Failure{Platform: string(acct.Platform), Profile: acct.Profile, Deployer: d.ID()}
	defer func() {
		if p := recover(); p != nil {
			r.total++
			r.fail(ctx, platform.Change{Resource: platform.DeployResource(d.ID(), acct.Profile, "account")},
				fmt.Errorf("internal error in deployer %s: %v", d.ID(), p), base, true)
		}
	}()
	targets, skipped, err := d.Discover(ctx, acct, r.po)
	for _, ch := range skipped {
		// With a named domain, what a deployer leaves alone for another
		// root domain is not reported.
		if !r.o.All && ch.Attrs["domain"] != "" {
			if root, err := RootDomain(ch.Attrs["domain"]); err == nil && root != r.o.Domain {
				continue
			}
		}
		r.add(ch)
	}
	if err != nil {
		r.total++
		r.fail(ctx, platform.Change{Resource: platform.DeployResource(d.ID(), acct.Profile, "account")}, err, base, true)
		return false
	}
	type group struct {
		key   string
		items []platform.DeployItem
	}
	var groups []*group
	byKey := map[string]*group{}
	bd, batch := d.(platform.BatchDeployer)
	now := r.env.now()
	for _, t := range targets {
		res := t.Resource()
		attrs := targetAttrs(t, now)
		f := base
		f.Target = t.Name
		domain := t.Domain()
		root, err := RootDomain(domain)
		if err != nil {
			r.add(platform.Change{Resource: res, Action: platform.Skipped, ID: t.CurrentCertID, Attrs: attrs,
				Detail: fmt.Sprintf("cannot tell the root domain of certificate %s (%q)", t.CurrentCertID, domain)})
			continue
		}
		if !r.o.All && root != r.o.Domain {
			continue
		}
		attrs["domain"] = root
		f.Domain = root
		left := t.DaysLeft(now)
		if r.o.All && !r.o.Force && t.CurrentNotAfter.IsZero() {
			r.add(platform.Change{Resource: res, Action: platform.Skipped, ID: t.CurrentCertID, Attrs: attrs,
				Detail: fmt.Sprintf("the expiry of certificate %s is unknown", t.CurrentCertID)})
			continue
		}
		if r.o.All && !r.o.Force && left > r.o.Days {
			r.add(platform.Change{Resource: res, Action: platform.Unchanged, ID: t.CurrentCertID, Attrs: attrs,
				Detail: fmt.Sprintf("days_left=%d", left)})
			continue
		}
		b := r.bundle(ctx, root)
		switch {
		case b.skip != "":
			r.add(platform.Change{Resource: res, Action: platform.Skipped, ID: t.CurrentCertID, Attrs: attrs, Detail: b.skip})
			continue
		case b.err != nil:
			// Notified once, with the certificate of the root.
			r.total++
			r.fail(ctx, platform.Change{Resource: res, ID: t.CurrentCertID, Attrs: attrs,
				Detail: "the certificate of " + root + " is not available: " + b.err.Error()}, b.err, f, false)
			continue
		}
		c := b.cert
		if !c.Pending {
			attrs["new_not_after"] = c.NotAfter.UTC().Format("2006-01-02")
		}
		if !r.o.All && !r.o.Force && !c.Pending && platform.SerialKey(t.CurrentSerial) != "" &&
			platform.SerialKey(t.CurrentSerial) == platform.SerialKey(c.Serial) {
			r.add(platform.Change{Resource: res, Action: platform.Unchanged, ID: t.CurrentCertID, Attrs: attrs,
				Detail: fmt.Sprintf("holds the current certificate (days_left=%d)", left)})
			continue
		}
		if t.Hostname != "" && !c.Pending && !c.Covers(t.Hostname) {
			r.add(platform.Change{Resource: res, Action: platform.Skipped, ID: t.CurrentCertID, Attrs: attrs,
				Detail: fmt.Sprintf("the certificate of %s does not cover %s; it needs a certificate of its own", root, t.Hostname)})
			continue
		}
		if batch && t.Group != "" {
			g := byKey[t.Group]
			if g == nil {
				g = &group{key: t.Group}
				byKey[t.Group] = g
				groups = append(groups, g)
			}
			g.items = append(g.items, platform.DeployItem{Target: t, Cert: c})
			continue
		}
		r.total++
		steps, err := d.Plan(ctx, acct, t, c, r.po)
		if err != nil {
			r.fail(ctx, platform.Change{Resource: res, ID: t.CurrentCertID, Attrs: attrs}, err, f, true)
			continue
		}
		if r.run(ctx, steps, res, attrs, f, c) {
			wrote = true
		}
	}
	for _, g := range groups {
		r.total++
		first := g.items[0].Target
		f := base
		f.Target, f.Domain = first.Name, rootOf(first)
		res := first.Resource()
		attrs := targetAttrs(first, now)
		steps, err := bd.PlanBatch(ctx, acct, g.key, g.items, r.po)
		if err != nil {
			r.fail(ctx, platform.Change{Resource: res, Attrs: attrs}, err, f, true)
			continue
		}
		if r.run(ctx, steps, res, attrs, f, g.items[0].Cert) {
			wrote = true
		}
	}
	if r.o.Prune {
		steps, err := d.Prune(ctx, acct, r.po)
		if err != nil {
			r.env.infof("warning: %s of %s: expired certificates not cleaned up: %v", d.ID(), acct.Profile, err)
			r.add(platform.Change{Resource: platform.DeployResource(d.ID(), acct.Profile, "prune"), Action: platform.Skipped,
				Detail: "expired certificates not cleaned up: " + err.Error()})
		} else if len(steps) > 0 {
			r.prunes = append(r.prunes, pruneJob{ref: config.AccountRef{Profile: acct.Profile, Platform: acct.Platform}, client: acct.Client, steps: steps})
		}
	}
	return wrote
}

// rootOf is the root domain of the certificate a target holds, or "".
func rootOf(t platform.DeployTarget) string {
	root, err := RootDomain(t.Domain())
	if err != nil {
		return ""
	}
	return root
}

// targetAttrs are the attrs every change of a target carries.
func targetAttrs(t platform.DeployTarget, now time.Time) map[string]string {
	a := map[string]string{"deployer": t.Deployer, "platform": string(t.Platform), "profile": t.Profile}
	if t.Region != "" {
		a["region"] = t.Region
	}
	if t.CurrentCertID != "" {
		a["old_cert_id"] = t.CurrentCertID
	}
	if !t.CurrentNotAfter.IsZero() {
		a["old_days_left"] = strconv.Itoa(t.DaysLeft(now))
	}
	return a
}

// run runs the steps of one target (or group) and reports whether they
// wrote anything. A failed step stops the steps of the target only.
func (r *deployRun) run(ctx context.Context, steps []platform.Step, res string, attrs map[string]string, f app.Failure, c *platform.DeployCert) bool {
	plan := platform.Plan{Steps: steps}
	changes, err := plan.Run(ctx, r.o.DryRun)
	wrote := false
	for _, ch := range changes {
		if ch.Resource == res {
			merged := map[string]string{}
			for k, v := range attrs {
				merged[k] = v
			}
			for k, v := range ch.Attrs {
				merged[k] = v
			}
			ch.Attrs = merged
		}
		r.add(ch)
		if ch.Action == platform.Created || ch.Action == platform.Updated || ch.Action == platform.Deleted {
			wrote = true
			r.history(ch, f, c)
		}
	}
	if err != nil {
		r.count(ctx, err, f, true)
	}
	return wrote
}

// history appends a deployment to history.log.
func (r *deployRun) history(ch platform.Change, f app.Failure, c *platform.DeployCert) {
	if r.env.History == nil || ch.Action == platform.Deleted {
		return
	}
	e := HistoryEntry{Action: string(ch.Action), Domain: f.Domain, Target: ch.Resource, Deployer: f.Deployer, Profile: f.Profile,
		CertName: ch.Attrs["cert_name"]}
	if c != nil && !c.Pending {
		e.Serial = c.Serial
		e.NotAfter = c.NotAfter.UTC().Format(time.RFC3339)
		left := int(c.NotAfter.Sub(r.env.now()).Hours() / 24)
		e.DaysLeft = &left
	}
	r.env.History(e)
}

// bundle returns the certificate of root, ensured once per run.
func (r *deployRun) bundle(ctx context.Context, root string) *bundleResult {
	if b, ok := r.bundles[root]; ok {
		return b
	}
	b := &bundleResult{}
	r.bundles[root] = b
	res, err := r.env.Ensure(ctx, root, r.o.Days+DeployEnsureMargin)
	if res != nil {
		for _, ch := range res.Changes {
			if ch.Action != platform.Failed {
				r.add(ch)
			}
		}
	}
	certRes := "cert/" + root
	switch {
	case err != nil && errors.Is(err, app.ErrDomainUnknown):
		b.skip = "no DNS account hosts " + root + ", so its certificate cannot be issued here (it is managed elsewhere)"
		r.add(platform.Change{Resource: certRes, Action: platform.Skipped, Detail: b.skip})
	case err != nil:
		b.err = err
		r.total++
		r.fail(ctx, platform.Change{Resource: certRes}, err, app.Failure{Domain: root, Target: certRes}, true)
	case res == nil || res.Bundle == nil:
		// A dry run that would issue or renew the certificate.
		b.cert = &platform.DeployCert{Root: root, Pending: true}
	default:
		b.cert = DeployCertOf(res.Bundle)
	}
	return b
}

// DeployCertOf turns a bundle of the store into the certificate deployers
// take.
func DeployCertOf(b *Bundle) *platform.DeployCert {
	return &platform.DeployCert{Root: b.Domain, Fullchain: b.FullchainPEM, Cert: b.CertPEM, Chain: b.ChainPEM, Key: b.PrivKeyPEM,
		Leaf: b.Leaf, Serial: b.Serial, Fingerprint: b.Fingerprint, NotAfter: b.NotAfter, Names: b.Names}
}

// prune deletes the expired certificates the deployers found, after one
// confirmation for all of them. A deletion that fails is a warning, never a
// failure of the run.
func (r *deployRun) prune(ctx context.Context) {
	var deletes []string
	for _, j := range r.prunes {
		for _, s := range j.steps {
			if s.Apply != nil && s.Action == platform.Deleted {
				deletes = append(deletes, s.Resource)
			}
		}
	}
	confirmed := true
	if len(deletes) > 0 && !r.o.DryRun && r.env.ConfirmPrune != nil {
		ok, err := r.env.ConfirmPrune(ctx, deletes)
		if err != nil {
			r.env.infof("warning: expired certificates not deleted: %v", err)
		}
		confirmed = ok && err == nil
	}
	for _, j := range r.prunes {
		steps := j.steps
		if !confirmed {
			steps = nil
			for _, s := range j.steps {
				if s.Apply != nil {
					s = platform.Step{Resource: s.Resource, Action: platform.Skipped, ID: s.ID, Desc: "expired, not deleted (not confirmed)", Attrs: s.Attrs}
				}
				steps = append(steps, s)
			}
		}
		plan := platform.Plan{Steps: steps, ContinueOnError: true}
		changes, _ := plan.Run(ctx, r.o.DryRun)
		wrote := false
		for _, ch := range changes {
			if ch.Action == platform.Failed {
				r.env.infof("warning: %s: not deleted: %s", ch.Resource, ch.Detail)
				ch.Action, ch.Detail = platform.Skipped, "not deleted: "+ch.Detail
			}
			if ch.Action == platform.Deleted {
				wrote = true
			}
			r.add(ch)
		}
		if wrote && r.env.Written != nil {
			r.env.Written(ctx, j.ref, j.client)
		}
	}
}
