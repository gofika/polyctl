package cert

import (
	"bufio"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/fsutil"
	"github.com/gofika/polyctl/internal/platform"
)

// fakeIssuer is a CA in memory: it presents and cleans up both challenges
// through the provider, then signs the request's key.
type fakeIssuer struct {
	ca       *certtest.CA
	validity time.Duration
	// names overrides the names of issued certificates; wrongKey signs
	// another key; err fails Obtain; resolveErr fails ResolveAccount.
	names      []string
	wrongKey   bool
	err        error
	resolveErr error
	// hold, when set, blocks Obtain until it is closed.
	hold chan struct{}

	mu                           sync.Mutex
	accounts                     map[string]string
	resolves, registers, obtains int
	keys                         []string
}

func newFakeIssuer() *fakeIssuer {
	return &fakeIssuer{ca: certtest.New("Fake R1"), validity: 64 * 24 * time.Hour, accounts: map[string]string{}}
}

func pubID(a *Account) string {
	der, _ := x509.MarshalPKIXPublicKey(a.Key.Public())
	return string(der)
}

func (f *fakeIssuer) ResolveAccount(ctx context.Context, a *Account) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolves++
	if f.resolveErr != nil {
		return "", f.resolveErr
	}
	if u, ok := f.accounts[pubID(a)]; ok {
		return u, nil
	}
	return "", ErrAccountNotFound
}

func (f *fakeIssuer) Register(ctx context.Context, a *Account) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a.URI != "" {
		// A CA refuses a newAccount request signed with an account URI (kid)
		// instead of the key itself (RFC 8555 section 7.3).
		return "", errors.New("malformed: newAccount must be signed with a JWK, not a kid")
	}
	f.registers++
	u := fmt.Sprintf("https://ca.test/acme/acct/%d", 100+f.registers)
	f.accounts[pubID(a)] = u
	return u, nil
}

func (f *fakeIssuer) Obtain(ctx context.Context, a *Account, req ObtainRequest) ([]byte, error) {
	if f.hold != nil {
		<-f.hold
	}
	f.mu.Lock()
	f.obtains++
	der, _ := x509.MarshalPKIXPublicKey(req.Key.Public())
	f.keys = append(f.keys, string(der))
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	root := req.Domains[0]
	for i := range req.Domains {
		if err := req.Provider.Present(root, fmt.Sprint("t", i), fmt.Sprint("ka", i)); err != nil {
			return nil, err
		}
	}
	for i := range req.Domains {
		_ = req.Provider.CleanUp(root, fmt.Sprint("t", i), fmt.Sprint("ka", i))
	}
	pub := req.Key.Public()
	if f.wrongKey {
		pub = certtest.Key().Public()
	}
	names := []string{"*." + root, root}
	if f.names != nil {
		names = f.names
	}
	now := time.Now()
	return f.ca.Issue(pub, names, now.Add(-time.Minute), now.Add(f.validity)), nil
}

type ensureFixture struct {
	env    *Env
	dns    *fakeDNS
	iss    *fakeIssuer
	routes int
	infos  []string
}

func newEnsureFixture(t *testing.T) *ensureFixture {
	t.Helper()
	fx := &ensureFixture{dns: &fakeDNS{zones: []platform.Zone{{ID: "z1", Name: "example.com"}}}, iss: newFakeIssuer()}
	st := OpenStore(filepath.Join(t.TempDir(), "certs"), LetsEncryptProduction)
	var mu sync.Mutex
	st.Warnf = func(f string, a ...any) { mu.Lock(); fx.infos = append(fx.infos, fmt.Sprintf(f, a...)); mu.Unlock() }
	fx.env = &Env{
		Store:  st,
		Issuer: fx.iss,
		DNS:    DNSSettings{Resolvers: []string{"r1", "r2"}, MinResolvers: 2, PropagationTimeout: time.Second, PollInterval: time.Millisecond, SettleDelay: 20 * time.Second},
		Route: func(ctx context.Context, root string) (*Route, error) {
			mu.Lock()
			fx.routes++
			mu.Unlock()
			return &Route{DNS: fx.dns, Platform: platform.Cloudflare, Profile: "acme", ZoneID: "z1", Zone: "example.com", ZoneNS: []string{"a.ns.cloudflare.com"}}, nil
		},
		LiveNS: func(ctx context.Context, root string) []string { return []string{"a.ns.cloudflare.com"} },
		Sleep:  func(ctx context.Context, d time.Duration) error { return nil },
		Infof:  st.Warnf,
	}
	return fx
}

func (fx *ensureFixture) opts() EnsureOptions {
	return EnsureOptions{Domain: "www.example.com", Days: 30, KeyType: KeyEC256, Email: "ops@example.net", AgreeTOS: true}
}

// seedCert puts a certificate valid for left into the store.
func (fx *ensureFixture) seedCert(t *testing.T, names []string, left time.Duration, keyType string) *Bundle {
	t.Helper()
	key, err := GenerateKey(keyType)
	if err != nil {
		t.Fatal(err)
	}
	chain := fx.iss.ca.Issue(key.Public(), names, time.Now().Add(-time.Hour), time.Now().Add(left))
	b, err := NewBundle("example.com", chain, mustPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.env.Store.Save(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func historyLines(t *testing.T, st *Store) []string {
	t.Helper()
	f, err := os.Open(st.historyPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func TestEnsureCreatesThenIsUnchanged(t *testing.T) {
	fx := newEnsureFixture(t)
	res, err := Ensure(context.Background(), fx.env, fx.opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 2 || res.Changes[0].Resource != "acme-account/letsencrypt" || res.Changes[0].Action != platform.Created || res.Changes[0].ID != "101" {
		t.Fatalf("changes = %+v", res.Changes)
	}
	c := res.Changes[1]
	if c.Resource != "cert/example.com" || c.Action != platform.Created || c.ID != res.Bundle.Serial || c.Attrs["days_left"] != "63" ||
		c.Attrs["names"] != "example.com,*.example.com" || !strings.HasPrefix(c.Detail, "names=example.com,*.example.com not_after=") {
		t.Fatalf("cert change = %+v", c)
	}
	if res.Target.DNS != "cloudflare/acme" || res.Target.ACME != LetsEncryptProduction || res.Target.Store != fx.env.Store.Dir {
		t.Errorf("target = %+v", res.Target)
	}
	live := fx.env.Store.LivePath("example.com")
	if runtime.GOOS != "windows" && (mode(t, filepath.Join(live, filePrivKey)) != 0o600 || mode(t, live) != 0o700) {
		t.Error("modes")
	}
	if h := historyLines(t, fx.env.Store); len(h) != 1 || !strings.Contains(h[0], `"action":"created"`) || !strings.Contains(h[0], `"domain":"example.com"`) {
		t.Errorf("history = %v", h)
	}
	if n := len(fx.dns.writes); n != 4 {
		t.Errorf("dns writes = %v", fx.dns.writes)
	}
	// Second and third runs: nothing written, not even routed.
	for range 2 {
		res, err = Ensure(context.Background(), fx.env, fx.opts())
		if err != nil || len(res.Changes) != 1 || res.Changes[0].Action != platform.Unchanged {
			t.Fatalf("again = %+v, %v", res, err)
		}
	}
	if fx.iss.obtains != 1 || fx.iss.resolves != 0 || fx.routes != 1 || len(fx.dns.writes) != 4 || len(historyLines(t, fx.env.Store)) != 1 {
		t.Errorf("writes on unchanged runs: obtains %d resolves %d routes %d", fx.iss.obtains, fx.iss.resolves, fx.routes)
	}
}

func TestEnsureThreshold(t *testing.T) {
	for _, c := range []struct {
		left time.Duration
		want platform.Action
	}{
		{30*24*time.Hour + 23*time.Hour, platform.Updated},
		{31*24*time.Hour + time.Hour, platform.Unchanged},
		{-time.Hour, platform.Updated},
	} {
		fx := newEnsureFixture(t)
		fx.seedCert(t, Names("example.com"), c.left, KeyEC256)
		res, err := Ensure(context.Background(), fx.env, fx.opts())
		if err != nil {
			t.Fatal(err)
		}
		if got := res.Changes[len(res.Changes)-1].Action; got != c.want {
			t.Errorf("left %s: %s, want %s", c.left, got, c.want)
		}
	}
}

func TestEnsureRenewsIncompleteCertificates(t *testing.T) {
	fx := newEnsureFixture(t)
	fx.seedCert(t, []string{"example.com"}, 80*24*time.Hour, KeyEC256)
	res, err := Ensure(context.Background(), fx.env, fx.opts())
	if err != nil || res.Changes[1].Action != platform.Updated {
		t.Fatalf("root only: %+v %v", res, err)
	}
	if h := historyLines(t, fx.env.Store); len(h) != 1 || !strings.Contains(h[0], `"action":"updated"`) {
		t.Errorf("history = %v", h)
	}
	fx = newEnsureFixture(t)
	fx.seedCert(t, Names("example.com"), 80*24*time.Hour, KeyEC256)
	o := fx.opts()
	o.KeyType = KeyEC384
	res, err = Ensure(context.Background(), fx.env, o)
	if err != nil || res.Changes[1].Action != platform.Updated || res.Bundle.KeyType != KeyEC384 {
		t.Fatalf("key type: %+v %v", res, err)
	}
	// --force renews a good certificate.
	o = fx.opts()
	o.KeyType = KeyEC384
	o.Force = true
	if res, err = Ensure(context.Background(), fx.env, o); err != nil || res.Changes[1].Action != platform.Updated {
		t.Fatalf("force: %+v %v", res, err)
	}
}

func TestEnsureRestoresArchiveUnderLock(t *testing.T) {
	fx := newEnsureFixture(t)
	fx.seedCert(t, Names("example.com"), 80*24*time.Hour, KeyEC256)
	fx.seedCert(t, Names("example.com"), 80*24*time.Hour, KeyEC256)
	live := fx.env.Store.LivePath("example.com")
	if err := os.RemoveAll(live); err != nil {
		t.Fatal(err)
	}
	res, err := Ensure(context.Background(), fx.env, fx.opts())
	if err != nil || res.Changes[0].Action != platform.Unchanged {
		t.Fatalf("ensure = %+v %v", res, err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("live not restored")
	}
	if !strings.Contains(strings.Join(fx.infos, "\n"), "restored it from") {
		t.Errorf("no warning: %v", fx.infos)
	}
}

func TestEnsureDryRunWritesNothing(t *testing.T) {
	fx := newEnsureFixture(t)
	o := fx.opts()
	o.DryRun = true
	res, err := Ensure(context.Background(), fx.env, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 2 || res.Changes[0].Action != platform.WouldCreate || res.Changes[0].Resource != "acme-account/letsencrypt" ||
		res.Changes[1].Action != platform.WouldCreate || !strings.Contains(res.Changes[1].Detail, "DNS account cloudflare/acme") || res.Changes[1].ID != "" {
		t.Fatalf("dry run = %+v", res.Changes)
	}
	if _, err := os.Stat(fx.env.Store.Dir); !os.IsNotExist(err) || len(fx.dns.writes) != 0 || fx.iss.registers+fx.iss.obtains+fx.iss.resolves != 0 {
		t.Fatalf("dry run wrote: dir %v dns %v issuer %d/%d/%d", err, fx.dns.writes, fx.iss.registers, fx.iss.obtains, fx.iss.resolves)
	}
	// With an account and an expiring certificate: one row, would update.
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err != nil {
		t.Fatal(err)
	}
	o.Force = true
	before := len(fx.dns.writes)
	res, err = Ensure(context.Background(), fx.env, o)
	if err != nil || len(res.Changes) != 1 || res.Changes[0].Action != platform.WouldUpdate || !strings.HasPrefix(res.Changes[0].Detail, "--force") {
		t.Fatalf("dry run update = %+v %v", res, err)
	}
	if len(fx.dns.writes) != before {
		t.Error("dry run wrote DNS records")
	}
	// A key whose registration failed is registered by the real run.
	fx2 := newEnsureFixture(t)
	if _, err := fx2.env.Store.NewAccount("ops@example.net"); err != nil {
		t.Fatal(err)
	}
	res, err = Ensure(context.Background(), fx2.env, fx2.dryOpts())
	if err != nil || len(res.Changes) != 2 || res.Changes[0].Resource != "acme-account/letsencrypt" || res.Changes[0].Action != platform.WouldCreate {
		t.Fatalf("dry run with an unregistered key = %+v %v", res, err)
	}
}

func (fx *ensureFixture) dryOpts() EnsureOptions {
	o := fx.opts()
	o.DryRun = true
	return o
}

func TestEnsureNSWarningAndCNAME(t *testing.T) {
	fx := newEnsureFixture(t)
	fx.env.LiveNS = func(ctx context.Context, root string) []string { return []string{"ns1.other.net"} }
	o := fx.opts()
	o.DryRun = true
	if _, err := Ensure(context.Background(), fx.env, o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(fx.infos, "\n"), "most likely fail") {
		t.Errorf("no NS warning: %v", fx.infos)
	}
	fx.dns.records = []platform.Record{{ID: "c1", Name: "_acme-challenge.example.com", Type: "CNAME", Value: "x.acme.example.net."}}
	if _, err := Ensure(context.Background(), fx.env, o); err == nil || !strings.Contains(err.Error(), "delegated DNS-01") {
		t.Fatalf("cname: %v", err)
	}
}

func TestEnsureAccountQuestions(t *testing.T) {
	fx := newEnsureFixture(t)
	o := fx.opts()
	o.Email = ""
	if _, err := Ensure(context.Background(), fx.env, o); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "--email") {
		t.Fatalf("missing email: %v", err)
	}
	o = fx.opts()
	o.AgreeTOS = false
	if _, err := Ensure(context.Background(), fx.env, o); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "--agree-tos") {
		t.Fatalf("missing agreement: %v", err)
	}
	if fx.iss.registers+fx.iss.obtains != 0 {
		t.Fatal("issued without the questions answered")
	}
	// Interactive answers.
	asked := 0
	fx.env.AskEmail = func(ctx context.Context) (string, error) { asked++; return "me@example.net", nil }
	fx.env.ConfirmTOS = func(ctx context.Context, dir string) (bool, error) { asked++; return false, nil }
	o.Email = ""
	if _, err := Ensure(context.Background(), fx.env, o); !errors.Is(err, platform.ErrNothingToDo) || asked != 2 {
		t.Fatalf("declined: %v (asked %d)", err, asked)
	}
	fx.env.ConfirmTOS = func(ctx context.Context, dir string) (bool, error) { return true, nil }
	res, err := Ensure(context.Background(), fx.env, o)
	if err != nil || res.Changes[0].Action != platform.Created {
		t.Fatalf("interactive: %+v %v", res, err)
	}
	// The only account is found without an address next time.
	o.Force = true
	res, err = Ensure(context.Background(), fx.env, o)
	if err != nil || res.Changes[0].Action != platform.Unchanged || fx.iss.registers != 1 || fx.iss.resolves != 1 {
		t.Fatalf("existing account: %+v %v", res, err)
	}
	// An account the CA forgot is registered again.
	fx.iss.accounts = map[string]string{}
	res, err = Ensure(context.Background(), fx.env, o)
	if err != nil || res.Changes[0].Action != platform.Created || fx.iss.registers != 2 {
		t.Fatalf("forgotten account: %+v %v", res, err)
	}
	// A key whose registration the CA refused does not make the registered
	// account ambiguous.
	if _, err := fx.env.Store.NewAccount("refused@example.org"); err != nil {
		t.Fatal(err)
	}
	res, err = Ensure(context.Background(), fx.env, o)
	if err != nil || res.Changes[0].Action != platform.Unchanged || res.Changes[0].ID == "" {
		t.Fatalf("unregistered key next to the account: %+v %v", res, err)
	}
	if _, err := fx.env.Store.NewAccount("second@example.net"); err != nil {
		t.Fatal(err)
	}
	acct, _ := fx.env.Store.LoadAccount("second@example.net")
	acct.URI = "https://ca.test/acme/acct/999"
	if err := fx.env.Store.SaveAccount(acct); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(context.Background(), fx.env, o); !errors.Is(err, platform.ErrInvalidInput) {
		t.Fatalf("two registered accounts: %v", err)
	}
}

// Declining the terms when the CA forgot the account reports no failed row.
func TestEnsureDeclinedReRegistrationHasNoFailedRow(t *testing.T) {
	fx := newEnsureFixture(t)
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err != nil {
		t.Fatal(err)
	}
	fx.iss.accounts = map[string]string{}
	fx.env.ConfirmTOS = func(ctx context.Context, dir string) (bool, error) { return false, nil }
	o := fx.opts()
	o.Force, o.AgreeTOS = true, false
	res, err := Ensure(context.Background(), fx.env, o)
	if !errors.Is(err, platform.ErrNothingToDo) {
		t.Fatalf("err = %v", err)
	}
	for _, c := range res.Changes {
		if c.Action == platform.Failed {
			t.Fatalf("changes = %+v", res.Changes)
		}
	}
}

// A key left without account.json does not swallow the address asked for:
// the account is registered under that address.
func TestEnsureAskedEmailFillsKeyWithoutAddress(t *testing.T) {
	fx := newEnsureFixture(t)
	a, err := fx.env.Store.NewAccount("lost@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a.Dir, fileAccountJSON)); err != nil {
		t.Fatal(err)
	}
	fx.env.AskEmail = func(ctx context.Context) (string, error) { return "me@example.net", nil }
	o := fx.opts()
	o.Email = ""
	if _, err := Ensure(context.Background(), fx.env, o); err != nil {
		t.Fatal(err)
	}
	got, err := fx.env.Store.LoadAccount("me@example.net")
	if err != nil || got == nil || got.Email != "me@example.net" || got.URI == "" {
		t.Fatalf("account = %+v %v", got, err)
	}
}

func TestEnsureConcurrentRunsIssueOnce(t *testing.T) {
	old := lockRetry
	lockRetry = 5 * time.Millisecond
	t.Cleanup(func() { lockRetry = old })
	fx := newEnsureFixture(t)
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err != nil {
		t.Fatal(err)
	}
	fx.seedCert(t, Names("example.com"), 10*24*time.Hour, KeyEC256)
	fx.iss.obtains = 0
	fx.iss.hold = make(chan struct{})
	var wg sync.WaitGroup
	results := make([]*Result, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = Ensure(context.Background(), fx.env, fx.opts())
		}(i)
	}
	time.Sleep(100 * time.Millisecond)
	close(fx.iss.hold)
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || fx.iss.obtains != 1 {
		t.Fatalf("errs %v %v, obtains %d", errs[0], errs[1], fx.iss.obtains)
	}
	actions := []platform.Action{results[0].Changes[len(results[0].Changes)-1].Action, results[1].Changes[len(results[1].Changes)-1].Action}
	if !(actions[0] == platform.Updated && actions[1] == platform.Unchanged) && !(actions[1] == platform.Updated && actions[0] == platform.Unchanged) {
		t.Errorf("actions = %v", actions)
	}
}

func TestEnsureLockTimeout(t *testing.T) {
	old := lockRetry
	lockRetry = 5 * time.Millisecond
	t.Cleanup(func() { lockRetry = old })
	fx := newEnsureFixture(t)
	unlock, err := fx.env.Store.Lock(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Ensure(ctx, fx.env, fx.opts()); err == nil || !strings.Contains(err.Error(), "another polyctl process") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnsurePendingKeyAndFailures(t *testing.T) {
	fx := newEnsureFixture(t)
	old := fx.seedCert(t, Names("example.com"), 5*24*time.Hour, KeyEC256)
	fx.iss.err = errors.New("CA unavailable")
	_, err := Ensure(context.Background(), fx.env, fx.opts())
	if err == nil || !strings.Contains(err.Error(), "pending") || fx.iss.obtains != 1 {
		t.Fatalf("failure: %v (obtains %d)", err, fx.iss.obtains)
	}
	if _, serr := os.Stat(fx.env.Store.PendingKeyPath("example.com")); serr != nil {
		t.Fatal("no pending key after a failure")
	}
	firstKey := fx.iss.keys[0]
	// The store is unchanged.
	if b, _ := fx.env.Store.Load("example.com", false); b.Serial != old.Serial {
		t.Error("live changed by a failure")
	}
	// The next run uses the pending key.
	fx.iss.err = nil
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err != nil {
		t.Fatal(err)
	}
	if fx.iss.keys[1] != firstKey {
		t.Error("pending key not reused")
	}
	if _, serr := os.Stat(fx.env.Store.PendingKeyPath("example.com")); !os.IsNotExist(serr) {
		t.Error("pending key kept after success")
	}
	for _, mut := range []func(){func() { fx.iss.wrongKey = true }, func() { fx.iss.names = []string{"example.com"} }} {
		fx.iss.wrongKey, fx.iss.names = false, nil
		mut()
		o := fx.opts()
		o.Force = true
		before, _ := fx.env.Store.Load("example.com", false)
		if _, err := Ensure(context.Background(), fx.env, o); err == nil || !strings.Contains(err.Error(), "store was not changed") {
			t.Fatalf("bad certificate accepted: %v", err)
		}
		if after, _ := fx.env.Store.Load("example.com", false); after.Serial != before.Serial {
			t.Error("live changed by a bad certificate")
		}
	}
}

func TestEnsureReuseKey(t *testing.T) {
	fx := newEnsureFixture(t)
	cur := fx.seedCert(t, Names("example.com"), 5*24*time.Hour, KeyEC256)
	o := fx.opts()
	o.ReuseKey = true
	res, err := Ensure(context.Background(), fx.env, o)
	if err != nil {
		t.Fatal(err)
	}
	if !samePublicKey(res.Bundle.Key.Public(), cur.Key.Public()) {
		t.Error("key not reused")
	}
	o.ReuseKey = false
	o.Force = true
	if res, err = Ensure(context.Background(), fx.env, o); err != nil || samePublicKey(res.Bundle.Key.Public(), cur.Key.Public()) {
		t.Errorf("key not rotated: %v", err)
	}
}

func TestEnsureUsageAndOffline(t *testing.T) {
	fx := newEnsureFixture(t)
	for _, o := range []EnsureOptions{
		{Domain: "com", Days: 30},
		{Domain: "example.com", Days: -1},
		{Domain: "example.com", Days: 30, KeyType: "ec521"},
	} {
		if _, err := Ensure(context.Background(), fx.env, o); !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("%+v: %v", o, err)
		}
	}
	fx.env.DNS.MinResolvers = 3
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("min_resolvers: %v", err)
	}
	fx.env.DNS.MinResolvers = 2
	o := fx.opts()
	o.Offline = true
	if _, err := Ensure(context.Background(), fx.env, o); !errors.Is(err, app.ErrOffline) {
		t.Errorf("offline: %v", err)
	}
	fx.seedCert(t, Names("example.com"), 80*24*time.Hour, KeyEC256)
	if res, err := Ensure(context.Background(), fx.env, o); err != nil || res.Changes[0].Action != platform.Unchanged {
		t.Errorf("offline with a good certificate: %v", err)
	}
}

// An account the CA forgot (a reset staging CA, a deactivated account) is
// registered again with the key itself, not with the URI the store kept,
// and the certificate is issued in the same run.
func TestEnsureWithLegoRegistersForgottenAccount(t *testing.T) {
	s := newACMESetup(t)
	fx := newEnsureFixture(t)
	fx.dns = s.dns
	iss := s.acme.issuer()
	fx.env.Issuer = iss
	fx.env.Store = OpenStore(fx.env.Store.Dir, iss.Directory)
	fx.env.DNS.SettleDelay = 0
	fx.env.Lookup = func(ctx context.Context, r, fqdn string) txtAnswer {
		return txtAnswer{Kind: platform.NSOK, Values: s.dns.values(strings.TrimSuffix(fqdn, "."))}
	}
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err != nil {
		t.Fatal(err)
	}
	before, _ := fx.env.Store.LoadAccount("ops@example.net")
	s.acme.forgetAccounts()
	o := fx.opts()
	o.Force = true
	res, err := Ensure(context.Background(), fx.env, o)
	if err != nil {
		t.Fatalf("ensure after the CA forgot the account: %v", err)
	}
	if res.Changes[0].Action != platform.Created || res.Changes[1].Action != platform.Updated {
		t.Fatalf("changes = %+v", res.Changes)
	}
	after, _ := fx.env.Store.LoadAccount("ops@example.net")
	if after.URI == "" || after.URI == before.URI {
		t.Errorf("account URI %q, was %q", after.URI, before.URI)
	}
}

// The terms are asked before the lock when the CA forgot the account.
func TestEnsureAsksTermsForForgottenAccountBeforeLock(t *testing.T) {
	fx := newEnsureFixture(t)
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err != nil {
		t.Fatal(err)
	}
	fx.iss.accounts = map[string]string{}
	locked := false
	fx.env.ConfirmTOS = func(ctx context.Context, dir string) (bool, error) {
		tctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		unlock, err := fx.env.Store.Lock(tctx, "example.com")
		if err != nil {
			locked = true
		} else {
			unlock()
		}
		return true, nil
	}
	o := fx.opts()
	o.Force, o.AgreeTOS = true, false
	if _, err := Ensure(context.Background(), fx.env, o); err != nil {
		t.Fatal(err)
	}
	if locked {
		t.Error("the terms were asked while holding the lock")
	}
}

func TestEnsureWithLego(t *testing.T) {
	s := newACMESetup(t)
	fx := newEnsureFixture(t)
	fx.dns = s.dns
	iss := s.acme.issuer()
	fx.env.Issuer = iss
	fx.env.Store = OpenStore(fx.env.Store.Dir, iss.Directory)
	fx.env.DNS.SettleDelay = 0
	fx.env.Lookup = func(ctx context.Context, r, fqdn string) txtAnswer {
		return txtAnswer{Kind: platform.NSOK, Values: s.dns.values(strings.TrimSuffix(fqdn, "."))}
	}
	res, err := Ensure(context.Background(), fx.env, fx.opts())
	if err != nil {
		t.Fatal(err)
	}
	if res.Changes[0].Action != platform.Created || res.Changes[1].Action != platform.Created || !res.Bundle.CoversRoot() {
		t.Fatalf("changes = %+v", res.Changes)
	}
	if !strings.Contains(res.Bundle.Path, filepath.Join("ca", "127.0.0.1_")) {
		t.Errorf("path = %s", res.Bundle.Path)
	}
	if len(s.dns.records) != 0 || s.acme.challenges != 2 {
		t.Errorf("records left %v, challenges %d", s.dns.records, s.acme.challenges)
	}
}

// A DNS account that refuses the challenge records is named in the error,
// which keeps its authentication or unsupported cause (exit codes 3, 7).
func TestEnsureNamesRefusingDNSAccount(t *testing.T) {
	for _, cause := range []error{platform.ErrUnauthorized, platform.ErrNotSupported} {
		fx := newEnsureFixture(t)
		fx.dns.createErr = fmt.Errorf("%w: refused", cause)
		_, err := Ensure(context.Background(), fx.env, fx.opts())
		if !errors.Is(err, cause) || !strings.Contains(err.Error(), "DNS account cloudflare/acme") {
			t.Fatalf("%v: err = %v", cause, err)
		}
	}
}

// failRename makes renameDir fail for the moves match accepts, until the
// test ends.
func failRename(t *testing.T, match func(from, to string) bool) {
	t.Helper()
	old := renameDir
	renameDir = func(from, to string) error {
		if match(from, to) {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: os.ErrPermission}
		}
		return old(from, to)
	}
	t.Cleanup(func() { renameDir = old })
}

func restoreRename(t *testing.T) {
	t.Helper()
	renameDir = fsutil.Rename
}

// A certificate the CA issued but Save could not install (the archive
// cannot be written) is installed by the next run, without a new order.
func TestEnsureInstallsKeptCertificateAfterSaveFailure(t *testing.T) {
	fx := newEnsureFixture(t)
	old := fx.seedCert(t, Names("example.com"), 5*24*time.Hour, KeyEC256)
	failRename(t, func(from, to string) bool { return strings.Contains(to, "archive") })
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err == nil || !strings.Contains(err.Error(), "without a new order") {
		t.Fatalf("save failure: %v", err)
	}
	kept, err := fx.env.Store.LoadPendingBundle("example.com")
	if err != nil || kept == nil || kept.Serial == old.Serial {
		t.Fatalf("kept = %+v, %v", kept, err)
	}
	if staging, _ := fx.env.Store.stagingDirs("example.com"); len(staging) != 0 {
		t.Errorf("staging left: %v", staging)
	}
	restoreRename(t)
	res, err := Ensure(context.Background(), fx.env, fx.opts())
	if err != nil {
		t.Fatal(err)
	}
	if fx.iss.obtains != 1 || res.Bundle.Serial != kept.Serial || res.Changes[len(res.Changes)-1].Action != platform.Updated {
		t.Fatalf("obtains %d, serial %s want %s, changes %+v", fx.iss.obtains, res.Bundle.Serial, kept.Serial, res.Changes)
	}
	if _, err := os.Stat(filepath.Dir(fx.env.Store.PendingKeyPath("example.com"))); !os.IsNotExist(err) {
		t.Error("pending directory kept after the install")
	}
	if h := historyLines(t, fx.env.Store); len(h) != 1 || !strings.Contains(h[0], kept.Serial) {
		t.Errorf("history = %v", h)
	}
}

// --force orders a new certificate instead of installing the kept one.
func TestEnsureForceIgnoresKeptCertificate(t *testing.T) {
	fx := newEnsureFixture(t)
	fx.seedCert(t, Names("example.com"), 5*24*time.Hour, KeyEC256)
	failRename(t, func(from, to string) bool { return strings.Contains(to, "archive") })
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err == nil {
		t.Fatal("save did not fail")
	}
	restoreRename(t)
	o := fx.opts()
	o.Force = true
	if _, err := Ensure(context.Background(), fx.env, o); err != nil || fx.iss.obtains != 2 {
		t.Fatalf("force: %v, obtains %d", err, fx.iss.obtains)
	}
}

// Interrupted between the two renames of Save (live archived, the new
// bundle still in staging): the next run restores the new bundle, not the
// archived one, and orders nothing.
func TestEnsureRestoresStagingAfterInterruptedInstall(t *testing.T) {
	fx := newEnsureFixture(t)
	fx.seedCert(t, Names("example.com"), 5*24*time.Hour, KeyEC256)
	failRename(t, func(from, to string) bool { return strings.Contains(from, ".staging-") })
	if _, err := Ensure(context.Background(), fx.env, fx.opts()); err == nil {
		t.Fatal("install did not fail")
	}
	staging, _ := fx.env.Store.stagingDirs("example.com")
	if len(staging) != 1 {
		t.Fatalf("staging = %v", staging)
	}
	issued, err := fx.env.Store.loadDir("example.com", staging[0], false)
	if err != nil {
		t.Fatal(err)
	}
	restoreRename(t)
	var remembered []string
	fx.env.Remember = func(ctx context.Context, b *Bundle) { remembered = append(remembered, b.Serial) }
	res, err := Ensure(context.Background(), fx.env, fx.opts())
	if err != nil {
		t.Fatal(err)
	}
	// The run that obtained it could not record it: this one does.
	if fx.iss.obtains != 1 || res.Bundle.Serial != issued.Serial || len(res.Changes) != 1 || res.Changes[0].Action != platform.Updated {
		t.Fatalf("obtains %d, serial %s want %s, changes %+v", fx.iss.obtains, res.Bundle.Serial, issued.Serial, res.Changes)
	}
	if h := historyLines(t, fx.env.Store); len(h) != 1 || !strings.Contains(h[0], issued.Serial) || !strings.Contains(h[0], `"updated"`) {
		t.Errorf("history = %v", h)
	}
	if len(remembered) != 1 || remembered[0] != issued.Serial {
		t.Errorf("inventory records = %v", remembered)
	}
	// A later run has nothing to record.
	if res, err = Ensure(context.Background(), fx.env, fx.opts()); err != nil || res.Changes[0].Action != platform.Unchanged || len(remembered) != 1 {
		t.Fatalf("second run: %+v, %v, records %v", res.Changes, err, remembered)
	}
	if left, _ := fx.env.Store.stagingDirs("example.com"); len(left) != 0 {
		t.Errorf("staging left: %v", left)
	}
	if _, err := os.Stat(filepath.Dir(fx.env.Store.PendingKeyPath("example.com"))); !os.IsNotExist(err) {
		t.Error("pending directory of the restored certificate kept")
	}
	if !strings.Contains(strings.Join(fx.infos, "\n"), "restored it from") {
		t.Errorf("no warning: %v", fx.infos)
	}
}
