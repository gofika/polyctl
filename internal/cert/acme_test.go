package cert

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"

	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/dnstest"
	"github.com/gofika/polyctl/internal/platform"
)

// acmeSetup is a fake CA, a fake DNS zone, and the request parts that tie
// them together, with no real DNS involved.
type acmeSetup struct {
	acme *fakeACME
	dns  *fakeDNS
	req  func() ObtainRequest
}

func newACMESetup(t *testing.T) *acmeSetup {
	t.Helper()
	// lego follows CNAMEs of the challenge name through its recursive
	// resolvers: point them at a local resolver that knows nothing.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	local := dnstest.Start(t, nil)
	f := &fakeDNS{zones: []platform.Zone{{ID: "z1", Name: "example.com"}}}
	s := &acmeSetup{dns: f}
	s.acme = newFakeACME(t, certtest.New("Fake R1"), f.values)
	s.req = func() ObtainRequest {
		key, err := GenerateKey(KeyEC256)
		if err != nil {
			t.Fatal(err)
		}
		return ObtainRequest{
			Domains:   Names("example.com"),
			Key:       key,
			KeyType:   KeyEC256,
			Provider:  &DNSProvider{DNS: f, ZoneID: "z1", Zone: "example.com", TTL: 60, PropagationTimeout: 2 * time.Second, PollInterval: time.Millisecond},
			Resolvers: []string{local.Addr},
			Propagation: &Propagation{Resolvers: []string{"fake"}, Min: 1, Lookup: func(ctx context.Context, r, fqdn string) txtAnswer {
				return txtAnswer{Kind: platform.NSOK, Values: f.values(strings.TrimSuffix(fqdn, "."))}
			}},
		}
	}
	return s
}

func TestLegoIssuerRegistersAndObtains(t *testing.T) {
	s := newACMESetup(t)
	iss := s.acme.issuer()
	store := OpenStore(t.TempDir(), iss.Directory)
	ctx := context.Background()
	acct, err := store.NewAccount("ops@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.ResolveAccount(ctx, acct); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("resolve before register: %v", err)
	}
	uri, err := iss.Register(ctx, acct)
	if err != nil || !strings.Contains(uri, "/acme/acct/") {
		t.Fatalf("register = %q, %v", uri, err)
	}
	acct.URI = uri
	if got, err := iss.ResolveAccount(ctx, acct); err != nil || got != uri {
		t.Fatalf("resolve = %q, %v", got, err)
	}
	req := s.req()
	chain, err := iss.Obtain(ctx, acct, req)
	if err != nil {
		t.Fatalf("obtain: %v", err)
	}
	b, err := NewBundle("example.com", chain, mustPEM(t, req.Key))
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if !b.CoversRoot() || strings.Count(string(b.ChainPEM), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("bundle names %v chain %d", b.Names, strings.Count(string(b.ChainPEM), "BEGIN"))
	}
	if req.Provider.Presented != 2 || len(s.dns.records) != 0 {
		t.Errorf("presented %d, left %v", req.Provider.Presented, s.dns.records)
	}
	// Authorizations are reused: a second order writes no record.
	req2 := s.req()
	if _, err := iss.Obtain(ctx, acct, req2); err != nil {
		t.Fatal(err)
	}
	if req2.Provider.Presented != 0 {
		t.Errorf("reused authorizations presented %d records", req2.Provider.Presented)
	}
}

func mustPEM(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	b, err := MarshalPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLegoIssuerErrors(t *testing.T) {
	s := newACMESetup(t)
	iss := s.acme.issuer()
	store := OpenStore(t.TempDir(), iss.Directory)
	ctx := context.Background()
	bad, _ := store.NewAccount("ops@example.com")
	if _, err := iss.Register(ctx, bad); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "forbidden domain") {
		t.Fatalf("forbidden contact: %v", err)
	}
	acct, _ := store.NewAccount("ops@example.net")
	acct.URI, _ = iss.Register(ctx, acct)

	// Validation fails: the record is never visible to the CA.
	req := s.req()
	req.Propagation.Lookup = func(ctx context.Context, r, fqdn string) txtAnswer {
		return txtAnswer{Kind: platform.NSOK, Values: []string{"whatever"}}
	}
	req.Propagation.Min = 0
	s.acme.lookup = func(string) []string { return nil }
	_, err := iss.Obtain(ctx, acct, req)
	if err == nil || !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Fatalf("validation failure: %v", err)
	}
	if d := describeObtainError(err, req.Propagation, "/x/pending/privkey.pem"); !strings.Contains(d.Error(), "urn:ietf:params:acme:error:dns") || !strings.Contains(d.Error(), "/x/pending/privkey.pem") {
		t.Errorf("described = %v", d)
	}

	// Propagation timeout: the resolvers never see the record.
	s.acme.lookup = s.dns.values
	req = s.req()
	req.Provider.PropagationTimeout = 20 * time.Millisecond
	req.Propagation.Lookup = func(ctx context.Context, r, fqdn string) txtAnswer { return txtAnswer{Kind: platform.NSNXDomain} }
	_, err = iss.Obtain(ctx, acct, req)
	if err == nil || !strings.Contains(err.Error(), "time limit exceeded") {
		t.Fatalf("propagation timeout: %v", err)
	}
	if d := describeObtainError(err, req.Propagation, ""); !strings.Contains(d.Error(), "fake=NXDOMAIN") {
		t.Errorf("described = %v", d)
	}

	// Rate limit: reported with Retry-After, and not retried.
	s.acme.rateLimit = true
	before := s.acme.newOrders
	_, err = iss.Obtain(ctx, acct, s.req())
	d := describeObtainError(err, nil, "")
	if err == nil || !strings.Contains(d.Error(), "retry after 3600") || s.acme.newOrders != before+1 {
		t.Fatalf("rate limit: %v (%d orders)", d, s.acme.newOrders-before)
	}
}

func TestDescribeDNSSEC(t *testing.T) {
	err := describeObtainError(&acme.ProblemDetails{Type: "urn:ietf:params:acme:error:dns", Detail: "DNSSEC: DNSKEY Missing", HTTPStatus: 400}, nil, "")
	if !strings.Contains(err.Error(), "DNSSEC misconfiguration") || !strings.Contains(err.Error(), "DS record") {
		t.Errorf("dnssec = %v", err)
	}
}

func TestRunCtxStopsAtDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := runCtx(ctx, func() (int, error) { time.Sleep(time.Second); return 1, nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}
