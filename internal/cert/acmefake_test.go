package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/cert/certtest"
)

// fakeACME is a minimal ACME (RFC 8555) server over TLS for the tests of
// the lego issuer: directory, nonces, accounts, orders, DNS-01
// authorizations, finalization and certificate download. Signatures are
// not checked, but newAccount must carry the key (jwk) and no kid. Challenges are validated by looking the expected TXT value
// up with lookup (the fake DNS of the test).
type fakeACME struct {
	t      *testing.T
	srv    *httptest.Server
	ca     *certtest.CA
	lookup func(name string) []string
	// validity of issued certificates.
	validity time.Duration
	// rateLimit makes newOrder fail with a rateLimited problem.
	rateLimit bool

	mu       sync.Mutex
	nonce    int
	accounts map[string]string // jwk thumbprint -> account URL
	contacts map[string][]string
	thumbs   map[string]string // account URL -> thumbprint
	orders   map[string]*fakeOrder
	authzs   map[string]*fakeAuthz
	valid    map[string]bool // account URL + identifier -> validated before
	certs    map[string][]byte
	next     int
	// newOrders counts newOrder requests; challenges the challenge POSTs.
	newOrders, challenges int
}

type fakeOrder struct {
	account     string
	identifiers []map[string]string
	authzs      []string
	status      string
	cert        string
}

type fakeAuthz struct {
	account  string
	value    string
	wildcard bool
	token    string
	status   string
	chErr    map[string]any
}

func newFakeACME(t *testing.T, ca *certtest.CA, lookup func(string) []string) *fakeACME {
	f := &fakeACME{t: t, ca: ca, lookup: lookup, validity: 64 * 24 * time.Hour,
		accounts: map[string]string{}, contacts: map[string][]string{}, thumbs: map[string]string{},
		orders: map[string]*fakeOrder{}, authzs: map[string]*fakeAuthz{}, valid: map[string]bool{}, certs: map[string][]byte{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// forgetAccounts makes the CA forget every account, like a reset staging
// CA or deactivated accounts.
func (f *fakeACME) forgetAccounts() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.accounts = map[string]string{}
}

func (f *fakeACME) url(p string) string { return f.srv.URL + p }

func (f *fakeACME) issuer() *LegoIssuer {
	return &LegoIssuer{Directory: f.url("/dir"), HTTPClient: f.srv.Client()}
}

type jwsReq struct {
	jwk     map[string]any
	kid     string
	payload []byte
}

func b64(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// thumbprint is the RFC 7638 thumbprint of an EC JWK.
func thumbprint(jwk map[string]any) string {
	canon := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *fakeACME) problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status})
}

func (f *fakeACME) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeACME) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", f.nonce))
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/dir" {
		f.reply(w, 200, map[string]any{
			"newNonce": f.url("/nonce"), "newAccount": f.url("/new-account"), "newOrder": f.url("/new-order"),
			"revokeCert": f.url("/revoke"), "keyChange": f.url("/key-change"),
			"meta": map[string]any{"termsOfService": f.url("/terms")},
		})
		return
	}
	if r.URL.Path == "/nonce" {
		w.WriteHeader(http.StatusOK)
		return
	}
	var env struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		f.problem(w, 400, "malformed", "bad JWS")
		return
	}
	var prot struct {
		JWK map[string]any `json:"jwk"`
		KID string         `json:"kid"`
	}
	_ = json.Unmarshal(b64(env.Protected), &prot)
	req := jwsReq{jwk: prot.JWK, kid: prot.KID}
	if env.Payload != "" {
		req.payload = b64(env.Payload)
	}
	p := r.URL.Path
	switch {
	case p == "/new-account":
		f.newAccount(w, req)
	case p == "/new-order":
		f.newOrder(w, req)
	case strings.HasPrefix(p, "/authz/"):
		f.reply(w, 200, f.authzJSON(p))
	case strings.HasPrefix(p, "/chall/"):
		f.challenge(w, strings.TrimPrefix(p, "/chall/"))
	case strings.HasPrefix(p, "/finalize/"):
		f.finalize(w, strings.TrimPrefix(p, "/finalize/"), req)
	case strings.HasPrefix(p, "/order/"):
		f.reply(w, 200, f.orderJSON(strings.TrimPrefix(p, "/order/")))
	case strings.HasPrefix(p, "/cert/"):
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(f.certs[strings.TrimPrefix(p, "/cert/")])
	default:
		f.problem(w, 404, "malformed", "no such resource "+p)
	}
}

func (f *fakeACME) newAccount(w http.ResponseWriter, req jwsReq) {
	var body struct {
		Contact              []string `json:"contact"`
		TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
		OnlyReturnExisting   bool     `json:"onlyReturnExisting"`
	}
	_ = json.Unmarshal(req.payload, &body)
	if req.jwk == nil || req.kid != "" {
		// RFC 8555 section 7.3: newAccount is signed with "jwk", never "kid".
		f.problem(w, 400, "malformed", "newAccount must be signed with a JWK, not a kid")
		return
	}
	th := thumbprint(req.jwk)
	if acct, ok := f.accounts[th]; ok {
		w.Header().Set("Location", acct)
		f.reply(w, 200, map[string]any{"status": "valid", "contact": f.contacts[acct]})
		return
	}
	if body.OnlyReturnExisting {
		f.problem(w, 400, "accountDoesNotExist", "No account exists with the provided key")
		return
	}
	if !body.TermsOfServiceAgreed {
		f.problem(w, 400, "malformed", "must agree to terms of service")
		return
	}
	for _, c := range body.Contact {
		if strings.HasSuffix(c, "@example.com") {
			f.problem(w, 400, "invalidContact", "Error validating contact(s) :: contact email has forbidden domain \"example.com\"")
			return
		}
	}
	f.next++
	acct := f.url(fmt.Sprintf("/acme/acct/%d", 1000+f.next))
	f.accounts[th], f.thumbs[acct], f.contacts[acct] = acct, th, body.Contact
	w.Header().Set("Location", acct)
	f.reply(w, 201, map[string]any{"status": "valid", "contact": body.Contact})
}

func (f *fakeACME) newOrder(w http.ResponseWriter, req jwsReq) {
	f.newOrders++
	if f.rateLimit {
		w.Header().Set("Retry-After", "3600")
		f.problem(w, 429, "rateLimited", "too many certificates already issued for this exact set of domains")
		return
	}
	var body struct {
		Identifiers []map[string]string `json:"identifiers"`
	}
	_ = json.Unmarshal(req.payload, &body)
	f.next++
	id := fmt.Sprint(f.next)
	o := &fakeOrder{account: req.kid, identifiers: body.Identifiers, status: "pending"}
	ready := true
	for _, ident := range body.Identifiers {
		f.next++
		aid := fmt.Sprint(f.next)
		value, wildcard := strings.CutPrefix(ident["value"], "*.")
		a := &fakeAuthz{account: req.kid, value: value, wildcard: wildcard, token: "token-" + aid, status: "pending"}
		if f.valid[req.kid+"|"+ident["value"]] {
			a.status = "valid"
		} else {
			ready = false
		}
		f.authzs[aid] = a
		o.authzs = append(o.authzs, f.url("/authz/"+aid))
	}
	if ready {
		o.status = "ready"
	}
	f.orders[id] = o
	w.Header().Set("Location", f.url("/order/"+id))
	f.reply(w, 201, f.orderJSON(id))
}

func (f *fakeACME) orderJSON(id string) map[string]any {
	o := f.orders[id]
	m := map[string]any{"status": o.status, "identifiers": o.identifiers, "authorizations": o.authzs, "finalize": f.url("/finalize/" + id)}
	if o.cert != "" {
		m["certificate"] = f.url("/cert/" + o.cert)
	}
	return m
}

func (f *fakeACME) authzJSON(p string) map[string]any {
	id := strings.TrimPrefix(p, "/authz/")
	a := f.authzs[id]
	ch := map[string]any{"type": "dns-01", "url": f.url("/chall/" + id), "token": a.token, "status": a.status}
	if a.chErr != nil {
		ch["error"] = a.chErr
	}
	m := map[string]any{"status": a.status, "identifier": map[string]string{"type": "dns", "value": a.value}, "challenges": []any{ch}}
	if a.wildcard {
		m["wildcard"] = true
	}
	return m
}

func (f *fakeACME) challenge(w http.ResponseWriter, id string) {
	f.challenges++
	a := f.authzs[id]
	keyAuth := a.token + "." + f.thumbs[a.account]
	want := ChallengeValue(keyAuth)
	if slices.Contains(f.lookup("_acme-challenge."+a.value), want) {
		a.status = "valid"
		name := a.value
		if a.wildcard {
			name = "*." + name
		}
		f.valid[a.account+"|"+name] = true
	} else {
		a.status = "invalid"
		a.chErr = map[string]any{"type": "urn:ietf:params:acme:error:dns", "status": 400,
			"detail": "DNS problem: NXDOMAIN looking up TXT for _acme-challenge." + a.value + " - check that a DNS record exists for this domain"}
	}
	for _, o := range f.orders {
		if slices.Contains(o.authzs, f.url("/authz/"+id)) {
			all := true
			for _, u := range o.authzs {
				if f.authzs[strings.TrimPrefix(u, f.url("/authz/"))].status != "valid" {
					all = false
				}
			}
			if all {
				o.status = "ready"
			}
		}
	}
	ch := map[string]any{"type": "dns-01", "url": f.url("/chall/" + id), "token": a.token, "status": a.status}
	if a.chErr != nil {
		ch["error"] = a.chErr
	}
	f.reply(w, 200, ch)
}

func (f *fakeACME) finalize(w http.ResponseWriter, id string, req jwsReq) {
	var body struct {
		CSR string `json:"csr"`
	}
	_ = json.Unmarshal(req.payload, &body)
	csr, err := x509.ParseCertificateRequest(b64(body.CSR))
	if err != nil {
		f.problem(w, 400, "badCSR", err.Error())
		return
	}
	// Let's Encrypt lists the wildcard first.
	names := slices.Clone(csr.DNSNames)
	slices.SortFunc(names, func(a, b string) int {
		return strings.Compare(strings.Replace(a, "*", "!", 1), strings.Replace(b, "*", "!", 1))
	})
	f.next++
	cid := fmt.Sprint(f.next)
	now := time.Now()
	f.certs[cid] = f.ca.Issue(csr.PublicKey, names, now.Add(-time.Minute), now.Add(f.validity))
	o := f.orders[id]
	o.status, o.cert = "valid", cid
	f.reply(w, 200, f.orderJSON(id))
}
