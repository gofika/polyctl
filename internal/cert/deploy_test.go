package cert

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

var deployNow = time.Date(2026, 11, 20, 3, 17, 0, 0, time.UTC)

// deployBundle is a certificate of root and its wildcard valid for days.
func deployBundle(t *testing.T, root string, days int) *Bundle {
	t.Helper()
	ca := certtest.New("Fake R1")
	key := certtest.Key()
	chain := ca.Issue(key.Public(), []string{root, "*." + root}, deployNow.Add(-time.Hour), deployNow.Add(time.Duration(days)*24*time.Hour))
	b, err := NewBundle(root, chain, certtest.KeyPEM(key))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeTarget is a place of the fake deployer that holds a certificate.
type fakeTarget struct {
	id, name, group, host string
	domains               []string
	notAfter              time.Time
	serial                string
	// fail fails the bind step.
	fail error
}

// fakeDeployer keeps targets per profile in memory and logs its writes.
type fakeDeployer struct {
	id       string
	platform platform.ID
	targets  map[string][]*fakeTarget
	// discoverErr fails Discover for a profile; panics panics in it.
	discoverErr map[string]error
	panics      bool
	// expired are the certificates Prune finds; pruneFail fails their
	// deletion.
	expired   []string
	pruneFail error
	batch     bool
	writes    []string
	batches   [][]string
}

func (f *fakeDeployer) ID() string            { return f.id }
func (f *fakeDeployer) Platform() platform.ID { return f.platform }

func (f *fakeDeployer) Discover(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.DeployTarget, []platform.Change, error) {
	if f.panics {
		panic("boom")
	}
	if err := f.discoverErr[acct.Profile]; err != nil {
		return nil, nil, err
	}
	var out []platform.DeployTarget
	for _, t := range f.targets[acct.Profile] {
		out = append(out, platform.DeployTarget{Deployer: f.id, Platform: f.platform, Profile: acct.Profile, Kind: "fake", ID: t.id, Name: t.name,
			Group: t.group, Hostname: t.host, CurrentCertID: "c-" + t.serial, CurrentDomains: t.domains, CurrentNotAfter: t.notAfter, CurrentSerial: t.serial})
	}
	return out, []platform.Change{{Resource: platform.DeployResource(f.id, acct.Profile, "stopped"), Action: platform.Skipped, Detail: "stopped"}}, nil
}

func (f *fakeDeployer) find(profile, id string) *fakeTarget {
	for _, t := range f.targets[profile] {
		if t.id == id {
			return t
		}
	}
	return nil
}

func (f *fakeDeployer) Plan(ctx context.Context, acct *platform.DeployAccount, t platform.DeployTarget, c *platform.DeployCert, o platform.DeployOptions) ([]platform.Step, error) {
	uploaded := platform.Cached(acct, "uploaded", func() map[string]bool { return map[string]bool{} })
	var steps []platform.Step
	certID := platform.Pending
	if !c.Pending {
		certID = "c-" + c.Serial
	}
	if !uploaded[c.Root] {
		uploaded[c.Root] = true
		steps = append(steps, platform.Step{Resource: platform.DeployResource(f.id, acct.Profile, "cert"), Action: platform.Created, Desc: "upload " + c.Root,
			Apply: func(ctx context.Context) (platform.Change, error) {
				f.writes = append(f.writes, "upload "+acct.Profile+" "+c.Root)
				return platform.Change{ID: certID}, nil
			}})
	}
	ft := f.find(acct.Profile, t.ID)
	steps = append(steps, platform.Step{Resource: t.Resource(), Action: platform.Updated, Desc: "cert_id=" + certID, Attrs: map[string]string{"cert_name": "n-" + c.Root},
		Apply: func(ctx context.Context) (platform.Change, error) {
			if ft.fail != nil {
				return platform.Change{}, ft.fail
			}
			f.writes = append(f.writes, "bind "+acct.Profile+" "+t.ID)
			ft.serial, ft.notAfter = c.Serial, c.NotAfter
			return platform.Change{ID: certID}, nil
		}})
	return steps, nil
}

func (f *fakeDeployer) PlanBatch(ctx context.Context, acct *platform.DeployAccount, group string, items []platform.DeployItem, o platform.DeployOptions) ([]platform.Step, error) {
	var ids []string
	for _, it := range items {
		ids = append(ids, it.Target.ID)
	}
	f.batches = append(f.batches, ids)
	return []platform.Step{{Resource: items[0].Target.Resource(), Action: platform.Updated, Desc: "batch " + strings.Join(ids, ","),
		Apply: func(ctx context.Context) (platform.Change, error) {
			f.writes = append(f.writes, "batch "+strings.Join(ids, ","))
			return platform.Change{}, nil
		}}}, nil
}

func (f *fakeDeployer) Prune(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.Step, error) {
	var steps []platform.Step
	for _, id := range f.expired {
		steps = append(steps, platform.Step{Resource: platform.DeployResource(f.id, acct.Profile, "cert/"+id), Action: platform.Deleted, Desc: "expired",
			Apply: func(ctx context.Context) (platform.Change, error) {
				if f.pruneFail != nil {
					return platform.Change{}, f.pruneFail
				}
				f.writes = append(f.writes, "delete "+id)
				return platform.Change{}, nil
			}})
	}
	return steps, nil
}

// batchDeployer is a fakeDeployer that updates groups in one write.
type batchDeployer struct{ *fakeDeployer }

// deployHarness runs Deploy against fake deployers and a fake store.
type deployHarness struct {
	t        *testing.T
	env      *DeployEnv
	bundles  map[string]*Bundle
	ensured  []string
	ensureFn func(root string, days int) (*Result, error)
	notified []app.Failure
	history  []HistoryEntry
	written  []string
	confirm  []string
	answer   bool
}

func newDeployHarness(t *testing.T, profiles ...string) *deployHarness {
	h := &deployHarness{t: t, bundles: map[string]*Bundle{}, answer: true}
	var refs []config.AccountRef
	for _, p := range profiles {
		refs = append(refs, config.AccountRef{Profile: p, Platform: platform.AWS})
	}
	h.env = &DeployEnv{
		Accounts: refs,
		Open: func(ctx context.Context, ref config.AccountRef) (platform.Client, error) {
			if ref.Profile == "broken" {
				return nil, fmt.Errorf("%w: token rejected", platform.ErrUnauthorized)
			}
			return nil, nil
		},
		Ensure: func(ctx context.Context, root string, days int) (*Result, error) {
			h.ensured = append(h.ensured, fmt.Sprintf("%s:%d", root, days))
			if h.ensureFn != nil {
				return h.ensureFn(root, days)
			}
			b := h.bundles[root]
			if b == nil {
				return nil, fmt.Errorf("%w: no DNS account hosts %s", app.ErrDomainUnknown, root)
			}
			return &Result{Bundle: b, Changes: []platform.Change{{Resource: "cert/" + root, Action: platform.Unchanged}}}, nil
		},
		Stored:  func(root string) *Bundle { return h.bundles[root] },
		History: func(e HistoryEntry) { h.history = append(h.history, e) },
		Notify:  func(ctx context.Context, f app.Failure) { h.notified = append(h.notified, f) },
		ConfirmPrune: func(ctx context.Context, res []string) (bool, error) {
			h.confirm = append(h.confirm, res...)
			return h.answer, nil
		},
		Written: func(ctx context.Context, ref config.AccountRef, c platform.Client) {
			h.written = append(h.written, ref.Profile)
		},
		Now: func() time.Time { return deployNow },
	}
	return h
}

func (h *deployHarness) run(o DeployOptions, deps ...platform.CertDeployer) (*DeployReport, error) {
	h.t.Helper()
	h.ensured, h.notified, h.history, h.written, h.confirm = nil, nil, nil, nil, nil
	o.Deployers = deps
	if o.Days == 0 {
		o.Days = 30
	}
	return Deploy(context.Background(), h.env, o)
}

func deployRows(rep *DeployReport) []string {
	var out []string
	for _, c := range rep.Changes {
		out = append(out, c.Resource+" "+string(c.Action)+" "+c.Detail)
	}
	return out
}

func days(n int) time.Time { return deployNow.Add(time.Duration(n)*24*time.Hour + time.Hour) }

func TestDeployAllUpdatesOnlyDueTargetsAndIsIdempotent(t *testing.T) {
	h := newDeployHarness(t, "acme")
	h.bundles["example.com"] = deployBundle(t, "example.com", 90)
	d := &fakeDeployer{id: "fake-lb", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": {
		{id: "l1", name: "lb-1", domains: []string{"example.com", "*.example.com"}, notAfter: days(12), serial: "01"},
		{id: "l2", name: "lb-2", domains: []string{"*.example.com"}, notAfter: days(60), serial: "02"},
		{id: "l3", name: "lb-3", domains: []string{"www.example.com"}, notAfter: days(30), serial: "03"},
	}}}
	rep, err := h.run(DeployOptions{All: true}, d)
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if !slices.Equal(h.ensured, []string{"example.com:35"}) {
		t.Errorf("ensured = %v", h.ensured)
	}
	// One upload for both due targets of the account, one bind each.
	if !slices.Equal(d.writes, []string{"upload acme example.com", "bind acme l1", "bind acme l3"}) {
		t.Errorf("writes = %v", d.writes)
	}
	rows := deployRows(rep)
	want := []string{
		"fake-lb/acme/stopped skipped stopped",
		"cert/example.com unchanged ",
		"fake-lb/acme/cert created upload example.com",
		"fake-lb/acme/lb-1 updated cert_id=c-" + h.bundles["example.com"].Serial,
		"fake-lb/acme/lb-2 unchanged days_left=60",
		"fake-lb/acme/lb-3 updated cert_id=c-" + h.bundles["example.com"].Serial,
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows =\n%s\nwant\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}
	c := rep.Changes[3]
	if c.Attrs["deployer"] != "fake-lb" || c.Attrs["domain"] != "example.com" || c.Attrs["old_days_left"] != "12" ||
		c.Attrs["old_cert_id"] != "c-01" || c.Attrs["cert_name"] != "n-example.com" || c.Attrs["new_not_after"] == "" {
		t.Errorf("attrs = %v", c.Attrs)
	}
	if len(h.history) != 3 || h.history[1].Target != "fake-lb/acme/lb-1" || h.history[1].CertName != "n-example.com" || h.history[1].DaysLeft == nil {
		t.Errorf("history = %+v", h.history)
	}
	if !slices.Equal(h.written, []string{"acme"}) {
		t.Errorf("written = %v", h.written)
	}
	// The second run finds everything fresh: no store access, no write.
	d.writes = nil
	rep, err = h.run(DeployOptions{All: true}, d)
	if err != nil || len(d.writes) != 0 || len(h.ensured) != 0 || len(h.written) != 0 {
		t.Errorf("second run: %v writes %v ensured %v", err, d.writes, h.ensured)
	}
	for _, c := range rep.Changes {
		if c.Action.Writes() {
			t.Errorf("second run change %+v", c)
		}
	}
}

func TestDeployDryRunWritesNothing(t *testing.T) {
	h := newDeployHarness(t, "acme")
	h.ensureFn = func(root string, days int) (*Result, error) {
		return &Result{DryRun: true, Changes: []platform.Change{{Resource: "cert/" + root, Action: platform.WouldUpdate, Detail: "3 days left <= 35"}}}, nil
	}
	d := &fakeDeployer{id: "fake-lb", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": {
		{id: "l1", name: "lb-1", domains: []string{"example.com"}, notAfter: days(3), serial: "01", fail: errors.New("never called")},
	}}}
	rep, err := h.run(DeployOptions{All: true, DryRun: true}, d)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if len(d.writes) != 0 || len(h.notified) != 0 || len(h.history) != 0 || len(h.written) != 0 {
		t.Errorf("dry run wrote: %v %v %v %v", d.writes, h.notified, h.history, h.written)
	}
	rows := deployRows(rep)
	if !slices.Contains(rows, "cert/example.com would_update 3 days left <= 35") ||
		!slices.Contains(rows, "fake-lb/acme/cert would_create upload example.com") ||
		!slices.Contains(rows, "fake-lb/acme/lb-1 would_update cert_id=(pending)") || !rep.DryRun {
		t.Errorf("rows = %v", rows)
	}
}

func TestDeployFailuresAreIsolated(t *testing.T) {
	h := newDeployHarness(t, "acme", "other")
	h.bundles["example.com"] = deployBundle(t, "example.com", 90)
	h.bundles["example.org"] = deployBundle(t, "example.org", 90)
	d := &fakeDeployer{id: "fake-lb", platform: platform.AWS, targets: map[string][]*fakeTarget{
		"acme": {
			{id: "l1", name: "lb-1", domains: []string{"example.com"}, notAfter: days(5), serial: "01", fail: errors.New("IncorrectStatus.Listener")},
			{id: "l2", name: "lb-2", domains: []string{"example.org"}, notAfter: days(5), serial: "02"},
		},
		"other": {{id: "l3", name: "lb-3", domains: []string{"example.com"}, notAfter: days(5), serial: "03"}},
	}}
	rep, err := h.run(DeployOptions{All: true}, d)
	var partial *platform.PartialError
	if !errors.As(err, &partial) || partial.Failed != 1 {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(d.writes, []string{"upload acme example.com", "upload acme example.org", "bind acme l2", "upload other example.com", "bind other l3"}) {
		t.Errorf("writes = %v", d.writes)
	}
	if len(h.notified) != 1 || h.notified[0].Event != "cert.deploy.failed" || h.notified[0].Target != "lb-1" ||
		h.notified[0].Deployer != "fake-lb" || h.notified[0].Domain != "example.com" || h.notified[0].Profile != "acme" {
		t.Errorf("notified = %+v", h.notified)
	}
	if !slices.Contains(deployRows(rep), "fake-lb/acme/lb-1 failed IncorrectStatus.Listener") {
		t.Errorf("rows = %v", deployRows(rep))
	}
	// The store is asked once per root domain, whatever the accounts.
	if !slices.Equal(h.ensured, []string{"example.com:35", "example.org:35"}) {
		t.Errorf("ensured = %v", h.ensured)
	}
}

func TestDeployEnsureOutcomes(t *testing.T) {
	h := newDeployHarness(t, "acme")
	d := &fakeDeployer{id: "fake-lb", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": {
		{id: "l1", name: "lb-1", domains: []string{"nodns.com"}, notAfter: days(5), serial: "01"},
		{id: "l2", name: "lb-2", domains: []string{"broken.com"}, notAfter: days(5), serial: "02"},
		{id: "l3", name: "lb-3", domains: []string{"www.broken.com"}, notAfter: days(5), serial: "03"},
	}}}
	h.ensureFn = func(root string, days int) (*Result, error) {
		if root == "broken.com" {
			return nil, errors.New("rate limited")
		}
		return nil, fmt.Errorf("%w: no DNS account hosts %s", app.ErrDomainUnknown, root)
	}
	rep, err := h.run(DeployOptions{All: true}, d)
	var partial *platform.PartialError
	if !errors.As(err, &partial) || partial.Failed != 3 {
		t.Fatalf("err = %v", err)
	}
	rows := deployRows(rep)
	if !slices.ContainsFunc(rows, func(r string) bool {
		return strings.HasPrefix(r, "fake-lb/acme/lb-1 skipped no DNS account hosts nodns.com")
	}) {
		t.Errorf("rows = %v", rows)
	}
	// One notification for the certificate of broken.com, none for the
	// skipped domain nor per target.
	if len(h.notified) != 1 || h.notified[0].Domain != "broken.com" || h.notified[0].Target != "cert/broken.com" {
		t.Errorf("notified = %+v", h.notified)
	}
	if !slices.Equal(h.ensured, []string{"nodns.com:35", "broken.com:35"}) || len(d.writes) != 0 {
		t.Errorf("ensured %v writes %v", h.ensured, d.writes)
	}
}

func TestDeployDomainMode(t *testing.T) {
	h := newDeployHarness(t, "acme")
	b := deployBundle(t, "example.com", 90)
	h.bundles["example.com"] = b
	d := &fakeDeployer{id: "fake-lb", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": {
		{id: "l1", name: "lb-1", domains: []string{"example.com"}, notAfter: days(80), serial: "00" + b.Serial},
		{id: "l2", name: "lb-2", domains: []string{"www.example.com"}, notAfter: days(80), serial: "77"},
		{id: "l3", name: "lb-3", domains: []string{"other.com"}, notAfter: days(1), serial: "88"},
		{id: "l4", name: "lb-4", domains: []string{"example.com"}, notAfter: days(80), serial: "99", host: "a.b.example.com"},
	}}}
	rep, err := h.run(DeployOptions{Domain: "example.com"}, d)
	if err != nil {
		t.Fatal(err)
	}
	rows := deployRows(rep)
	// Not limited by --days; the serial decides, other roots are ignored,
	// a host the certificate does not cover is skipped.
	if !slices.Equal(d.writes, []string{"upload acme example.com", "bind acme l2"}) {
		t.Errorf("writes = %v rows %v", d.writes, rows)
	}
	if !slices.ContainsFunc(rows, func(r string) bool {
		return strings.HasPrefix(r, "fake-lb/acme/lb-1 unchanged holds the current certificate")
	}) ||
		!slices.ContainsFunc(rows, func(r string) bool {
			return strings.Contains(r, "lb-4 skipped") && strings.Contains(r, "does not cover a.b.example.com")
		}) ||
		slices.ContainsFunc(rows, func(r string) bool { return strings.Contains(r, "lb-3") }) {
		t.Errorf("rows = %v", rows)
	}
	if rep.Target.Scope != "domain" || rep.Target.Domain != "example.com" {
		t.Errorf("target = %+v", rep.Target)
	}
	// --force rebinds even the current one.
	d.writes = nil
	if _, err := h.run(DeployOptions{Domain: "example.com", Force: true}, d); err != nil || !slices.Contains(d.writes, "bind acme l1") {
		t.Errorf("force: %v %v", err, d.writes)
	}
	// A domain neither in the store nor hosted by a DNS account.
	if _, err := h.run(DeployOptions{Domain: "unknown.com"}, d); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown domain = %v", err)
	}
}

func TestDeploySkipAccountsAndAccountFailures(t *testing.T) {
	h := newDeployHarness(t, "acme", "other", "broken")
	h.bundles["example.com"] = deployBundle(t, "example.com", 90)
	tg := func() []*fakeTarget {
		return []*fakeTarget{{id: "l", name: "lb", domains: []string{"example.com"}, notAfter: days(5), serial: "01"}}
	}
	a := &fakeDeployer{id: "fake-a", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": tg(), "other": tg()}}
	b := &fakeDeployer{id: "fake-b", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": tg(), "other": tg()},
		discoverErr: map[string]error{"other": fmt.Errorf("%w: Forbidden.RAM", platform.ErrForbidden)}}
	h.env.SkipAccounts = []string{"acme:fake-a", "broken"}
	_, err := h.run(DeployOptions{All: true}, a, b)
	// fake-b fails in other for lack of permission: the only failure, so
	// the run is an authentication failure.
	if !errors.Is(err, platform.ErrForbidden) {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(a.writes, []string{"upload other example.com", "bind other l"}) || !slices.Equal(b.writes, []string{"upload acme example.com", "bind acme l"}) {
		t.Errorf("writes a %v b %v", a.writes, b.writes)
	}
	// An account that cannot be opened fails its deployers; mixed with a
	// general failure the run is a partial failure.
	h.env.SkipAccounts = nil
	a.targets["acme"][0].fail = errors.New("api error")
	_, err = h.run(DeployOptions{All: true, Force: true}, a, b)
	var partial *platform.PartialError
	if !errors.As(err, &partial) {
		t.Errorf("mixed failures = %v", err)
	}
}

func TestDeployBatchesAndPanics(t *testing.T) {
	h := newDeployHarness(t, "acme")
	h.bundles["example.com"] = deployBundle(t, "example.com", 90)
	h.bundles["example.org"] = deployBundle(t, "example.org", 90)
	bd := batchDeployer{&fakeDeployer{id: "fake-proxy", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": {
		{id: "c1", name: "global/p", group: "global/p", domains: []string{"example.com"}, notAfter: days(5), serial: "01"},
		{id: "c2", name: "global/p", group: "global/p", domains: []string{"example.org"}, notAfter: days(5), serial: "02"},
		{id: "c3", name: "global/q", group: "global/q", domains: []string{"example.org"}, notAfter: days(90), serial: "03"},
	}}}}
	if _, err := h.run(DeployOptions{All: true}, bd); err != nil {
		t.Fatal(err)
	}
	if len(bd.batches) != 1 || !slices.Equal(bd.batches[0], []string{"c1", "c2"}) || !slices.Equal(bd.writes, []string{"batch c1,c2"}) {
		t.Errorf("batches %v writes %v", bd.batches, bd.writes)
	}
	p := &fakeDeployer{id: "fake-panic", platform: platform.AWS, panics: true}
	rep, err := h.run(DeployOptions{All: true}, p)
	var partial *platform.PartialError
	if !errors.As(err, &partial) || !strings.Contains(partial.First.Error(), "internal error in deployer fake-panic: boom") || len(rep.Changes) != 1 {
		t.Errorf("panic = %v %+v", err, rep.Changes)
	}
}

func TestDeployPrune(t *testing.T) {
	h := newDeployHarness(t, "acme")
	d := &fakeDeployer{id: "fake-lb", platform: platform.AWS, expired: []string{"111", "222"}}
	// Declined: nothing deleted, reported as skipped.
	h.answer = false
	rep, err := h.run(DeployOptions{All: true, Prune: true}, d)
	if err != nil || len(d.writes) != 0 || !slices.Equal(h.confirm, []string{"fake-lb/acme/cert/111", "fake-lb/acme/cert/222"}) {
		t.Fatalf("declined: %v %v %v", err, d.writes, h.confirm)
	}
	if rows := deployRows(rep); !slices.Contains(rows, "fake-lb/acme/cert/111 skipped expired, not deleted (not confirmed)") {
		t.Errorf("rows = %v", rows)
	}
	h.answer = true
	if _, err := h.run(DeployOptions{All: true, Prune: true}, d); err != nil || !slices.Equal(d.writes, []string{"delete 111", "delete 222"}) || !slices.Equal(h.written, []string{"acme"}) {
		t.Errorf("confirmed: %v %v %v", err, d.writes, h.written)
	}
	// A deletion that fails is a warning, not a failure.
	d.writes, d.pruneFail = nil, errors.New("NotFound")
	rep, err = h.run(DeployOptions{All: true, Prune: true}, d)
	if err != nil || !slices.Contains(deployRows(rep), "fake-lb/acme/cert/111 skipped not deleted: NotFound") {
		t.Errorf("failed delete: %v %v", err, deployRows(rep))
	}
	// A dry run asks nothing.
	rep, err = h.run(DeployOptions{All: true, Prune: true, DryRun: true}, d)
	if err != nil || len(h.confirm) != 0 || !slices.Contains(deployRows(rep), "fake-lb/acme/cert/111 would_delete expired") {
		t.Errorf("dry run: %v %v %v", err, h.confirm, deployRows(rep))
	}
}

// skipDeployer reports skipped changes of several domains on top of the
// targets of fakeDeployer.
type skipDeployer struct{ *fakeDeployer }

func (s skipDeployer) Discover(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.DeployTarget, []platform.Change, error) {
	targets, _, err := s.fakeDeployer.Discover(ctx, acct, o)
	return targets, []platform.Change{
		{Resource: "fake-lb/acme/managed-example", Action: platform.Skipped, Attrs: map[string]string{"domain": "www.example.com"}},
		{Resource: "fake-lb/acme/managed-other", Action: platform.Skipped, Attrs: map[string]string{"domain": "other.com"}},
		{Resource: "fake-lb/acme/stopped", Action: platform.Skipped},
	}, err
}

func TestDeployUnknownExpiryNotFoundAndDomainSkips(t *testing.T) {
	h := newDeployHarness(t, "acme")
	h.bundles["example.com"] = deployBundle(t, "example.com", 90)
	d := &fakeDeployer{id: "fake-lb", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": {
		{id: "l1", name: "lb-1", domains: []string{"example.com"}, serial: "01"},
	}}}
	// --all: a certificate whose expiry is unknown is not taken as due.
	rep, err := h.run(DeployOptions{All: true}, d)
	if err != nil || len(d.writes) != 0 || len(h.ensured) != 0 {
		t.Fatalf("err %v writes %v ensured %v", err, d.writes, h.ensured)
	}
	if !slices.ContainsFunc(deployRows(rep), func(r string) bool { return strings.HasPrefix(r, "fake-lb/acme/lb-1 skipped the expiry") }) {
		t.Errorf("rows = %v", deployRows(rep))
	}
	// A not-found error of cert ensure that is not about the DNS account
	// is a failure, not a skip.
	d.targets["acme"][0].notAfter = days(3)
	h.ensureFn = func(root string, days int) (*Result, error) {
		return nil, fmt.Errorf("%w: TXT record", platform.ErrNotFound)
	}
	if _, err := h.run(DeployOptions{All: true}, d); !errors.As(err, new(*platform.PartialError)) || len(h.notified) != 1 {
		t.Errorf("err %v notified %v", err, h.notified)
	}
	// With a named domain, skips of other root domains are left out.
	h.ensureFn = nil
	rep, err = h.run(DeployOptions{Domain: "example.com"}, skipDeployer{d})
	if err != nil {
		t.Fatal(err)
	}
	rows := deployRows(rep)
	if !slices.ContainsFunc(rows, func(r string) bool { return strings.HasPrefix(r, "fake-lb/acme/managed-example ") }) ||
		!slices.ContainsFunc(rows, func(r string) bool { return strings.HasPrefix(r, "fake-lb/acme/stopped ") }) ||
		slices.ContainsFunc(rows, func(r string) bool { return strings.Contains(r, "managed-other") }) {
		t.Errorf("rows = %v", rows)
	}
}

// A target whose certificate holds names the store's certificate does not
// cover (a deeper subdomain, another root domain) is skipped, --force or
// not, in both modes.
func TestDeploySkipsTargetsTheCertificateDoesNotCover(t *testing.T) {
	h := newDeployHarness(t, "acme")
	h.bundles["example.com"] = deployBundle(t, "example.com", 90)
	d := &fakeDeployer{id: "fake-lb", platform: platform.AWS, targets: map[string][]*fakeTarget{"acme": {
		{id: "l1", name: "lb-1", domains: []string{"api.staging.example.com"}, notAfter: days(3), serial: "01"},
		{id: "l2", name: "lb-2", domains: []string{"example.com", "example.net", "*.example.com"}, notAfter: days(3), serial: "02"},
		{id: "l3", name: "lb-3", domains: []string{"*.example.com", "www.example.com"}, notAfter: days(3), serial: "03"},
	}}}
	for _, o := range []DeployOptions{{All: true}, {Domain: "example.com"}, {Domain: "example.com", Force: true}} {
		d.writes = nil
		d.targets["acme"][2].serial = "03"
		rep, err := h.run(o, d)
		if err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		if !slices.Equal(d.writes, []string{"upload acme example.com", "bind acme l3"}) {
			t.Errorf("%+v: writes = %v", o, d.writes)
		}
		rows := deployRows(rep)
		for _, want := range []string{
			"fake-lb/acme/lb-1 skipped the certificate of example.com does not cover api.staging.example.com; it needs a certificate of its own",
			"fake-lb/acme/lb-2 skipped the certificate of example.com does not cover example.net; it needs a certificate of its own",
		} {
			if !slices.Contains(rows, want) {
				t.Errorf("%+v: rows = %v, want %q", o, rows, want)
			}
		}
	}
}
