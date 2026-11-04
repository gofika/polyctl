package namecom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

const (
	testUser  = "alice"
	testToken = "tok-secret"
)

// fakeServer is a minimal in-memory name.com v4 API.
type fakeServer struct {
	t       *testing.T
	mu      sync.Mutex
	domains map[string]*apiDomain
	records map[string][]apiRecord // keyed by domain
	nextID  int64
	// pageSize forces pagination of list endpoints.
	pageSize int
	// lastBody captures the most recent request body for assertions.
	lastBody   string
	lastMethod string
	lastPath   string
	// availabilityCalls counts accepted checkAvailability requests.
	availabilityCalls int
}

func newFakeServer(t *testing.T) (*fakeServer, *httptest.Server) {
	fs := &fakeServer{
		t:        t,
		domains:  map[string]*apiDomain{},
		records:  map[string][]apiRecord{},
		nextID:   100,
		pageSize: 2,
	}
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	return fs, srv
}

func (fs *fakeServer) addDomain(name string, ns ...string) {
	fs.domains[name] = &apiDomain{DomainName: name, Nameservers: ns, Locked: true, AutorenewEnabled: true,
		ExpireDate: "2030-01-02T03:04:05Z", CreateDate: "2020-01-02T03:04:05Z", RenewalPrice: 12.99}
}

func (fs *fakeServer) addRecord(domain string, r apiRecord) apiRecord {
	fs.nextID++
	r.ID = fs.nextID
	r.DomainName = domain
	if r.Host == "" {
		r.FQDN = domain + "."
	} else {
		r.FQDN = r.Host + "." + domain + "."
	}
	fs.records[domain] = append(fs.records[domain], r)
	return r
}

func (fs *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	user, pass, ok := r.BasicAuth()
	// Login appends the "-test" suffix for the test environment; accept both.
	if !ok || (user != testUser && user != testUser+testUserSuffix) || pass != testToken {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"Unauthenticated","details":"invalid credentials"}`)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	fs.lastBody = string(raw)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	fs.lastMethod, fs.lastPath = r.Method, r.URL.Path
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	path := r.URL.Path
	switch {
	case path == "/v4/hello":
		writeJSON(w, map[string]string{"serverName": "fake", "motd": "hi", "username": testUser, "serverTime": "2026-11-04T00:00:00Z"})
	case path == "/v4/domains" && r.Method == http.MethodGet:
		names := sortedKeys(fs.domains)
		start, end, next := pageBounds(len(names), page, fs.pageSize)
		var out []apiDomain
		for _, n := range names[start:end] {
			out = append(out, *fs.domains[n])
		}
		writeJSON(w, domainsPage{Domains: out, NextPage: next})
	case path == "/v4/domains:checkAvailability" && r.Method == http.MethodPost:
		names, _ := body["domainNames"].([]any)
		if len(names) > maxAvailabilityNames {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"message":"Invalid Argument","details":"A Maximum of 50 domains can be specified"}`)
			return
		}
		fs.availabilityCalls++
		var results []map[string]any
		for _, n := range names {
			name := n.(string)
			_, taken := fs.domains[name]
			results = append(results, map[string]any{"domainName": name, "purchasable": !taken, "premium": false, "purchasePrice": 9.99, "purchaseType": "registration", "renewalPrice": 12.99})
		}
		writeJSON(w, map[string]any{"results": results})
	case strings.HasPrefix(path, "/v4/domains/"):
		rest := strings.TrimPrefix(path, "/v4/domains/")
		// records
		if i := strings.Index(rest, "/records"); i >= 0 {
			domain := rest[:i]
			if _, ok := fs.domains[domain]; !ok {
				notFound(w)
				return
			}
			idPart := strings.TrimPrefix(rest[i+len("/records"):], "/")
			switch {
			case idPart == "" && r.Method == http.MethodGet:
				recs := fs.records[domain]
				start, end, next := pageBounds(len(recs), page, fs.pageSize)
				writeJSON(w, recordsPage{Records: recs[start:end], NextPage: next})
			case idPart == "" && r.Method == http.MethodPost:
				var in apiRecordWrite
				_ = json.Unmarshal([]byte(fs.lastBody), &in)
				rec := fs.addRecord(domain, apiRecord{Host: in.Host, Type: in.Type, Answer: in.Answer, TTL: in.TTL, Priority: in.Priority})
				writeJSON(w, rec)
			default:
				id, _ := strconv.ParseInt(idPart, 10, 64)
				recs := fs.records[domain]
				idx := -1
				for i := range recs {
					if recs[i].ID == id {
						idx = i
					}
				}
				if idx < 0 {
					notFound(w)
					return
				}
				switch r.Method {
				case http.MethodGet:
					writeJSON(w, recs[idx])
				case http.MethodPut:
					var in apiRecordWrite
					_ = json.Unmarshal([]byte(fs.lastBody), &in)
					rec := recs[idx]
					rec.Host, rec.Type, rec.Answer, rec.TTL, rec.Priority = in.Host, in.Type, in.Answer, in.TTL, in.Priority
					if rec.Host == "" {
						rec.FQDN = domain + "."
					} else {
						rec.FQDN = rec.Host + "." + domain + "."
					}
					recs[idx] = rec
					writeJSON(w, rec)
				case http.MethodDelete:
					fs.records[domain] = append(recs[:idx], recs[idx+1:]...)
					writeJSON(w, map[string]any{})
				}
			}
			return
		}
		// domain actions
		name, action := rest, ""
		if i := strings.Index(rest, ":"); i >= 0 {
			name, action = rest[:i], rest[i+1:]
		}
		d, ok := fs.domains[name]
		if !ok {
			notFound(w)
			return
		}
		switch action {
		case "":
			writeJSON(w, d)
		case "setNameservers":
			d.Nameservers = nil
			for _, n := range body["nameservers"].([]any) {
				d.Nameservers = append(d.Nameservers, n.(string))
			}
			writeJSON(w, d)
		case "lock":
			d.Locked = true
			writeJSON(w, d)
		case "unlock":
			d.Locked = false
			writeJSON(w, d)
		case "enableAutorenew":
			d.AutorenewEnabled = true
			writeJSON(w, d)
		case "disableAutorenew":
			d.AutorenewEnabled = false
			writeJSON(w, map[string]any{}) // empty body: client must re-read
		default:
			notFound(w)
		}
	default:
		notFound(w)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `{"message":"Not Found","details":"no such object"}`)
}

func sortedKeys(m map[string]*apiDomain) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func pageBounds(n, page, size int) (start, end, next int) {
	start = (page - 1) * size
	if start > n {
		start = n
	}
	end = start + size
	if end > n {
		end = n
	}
	if end < n {
		next = page + 1
	}
	return
}

func testClient(srv *httptest.Server) *Client {
	c := newClient(srv.URL, envTest, testUser, testToken)
	c.api.MaxRetries = 0
	c.now = func() time.Time { return time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC) }
	return c
}

func intp(i int) *int { return &i }

// --- tests ----------------------------------------------------------------

func TestListDomainsPaginates(t *testing.T) {
	fs, srv := newFakeServer(t)
	fs.addDomain("a.com", "ns1.name.com", "ns2.name.com")
	fs.addDomain("b.com")
	fs.addDomain("c.com")
	fs.addDomain("d.com")
	fs.addDomain("e.com")
	c := testClient(srv)
	domains, err := c.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 5 {
		t.Fatalf("got %d domains, want 5", len(domains))
	}
	d := domains[0]
	if d.Name != "a.com" || d.ExpiresAt != "2030-01-02T03:04:05Z" || !*d.AutoRenew || !*d.Locked || *d.Privacy {
		t.Errorf("unexpected domain mapping: %+v", d)
	}
	if d.Status != "active" || d.Extra["createDate"] != "2020-01-02T03:04:05Z" || d.Extra["renewalPrice"] != 12.99 {
		t.Errorf("unexpected status/extra: %+v", d)
	}
	if len(d.Nameservers) != 2 {
		t.Errorf("nameservers not mapped: %v", d.Nameservers)
	}
}

func TestListRecordsConversionAndPagination(t *testing.T) {
	fs, srv := newFakeServer(t)
	fs.addDomain("example.com")
	fs.addRecord("example.com", apiRecord{Host: "", Type: "A", Answer: "1.2.3.4", TTL: 300})
	fs.addRecord("example.com", apiRecord{Host: "www", Type: "CNAME", Answer: "example.com", TTL: 300})
	fs.addRecord("example.com", apiRecord{Host: "", Type: "MX", Answer: "mail.example.com", TTL: 3600, Priority: intp(10)})
	c := testClient(srv)
	recs, err := c.ListRecords(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3 (pagination)", len(recs))
	}
	if recs[0].Name != "example.com" || recs[0].ID != "101" || recs[0].ZoneID != "example.com" || recs[0].Priority != nil {
		t.Errorf("apex record mapped wrongly: %+v", recs[0])
	}
	if recs[1].Name != "www.example.com" || recs[1].Type != "CNAME" {
		t.Errorf("sub record mapped wrongly: %+v", recs[1])
	}
	if recs[2].Priority == nil || *recs[2].Priority != 10 || recs[2].Content != "mail.example.com" {
		t.Errorf("MX priority not mapped: %+v", recs[2])
	}
}

func TestCreateUpdateDeleteRecord(t *testing.T) {
	fs, srv := newFakeServer(t)
	fs.addDomain("example.com")
	c := testClient(srv)
	ctx := context.Background()

	out, err := c.CreateRecord(ctx, "example.com", platform.Record{Name: "example.com", Type: "a", Content: "1.1.1.1", TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fs.lastBody, `"host":""`) {
		t.Errorf("apex must be sent as empty host, body: %s", fs.lastBody)
	}
	if out.Name != "example.com" || out.Type != "A" || out.ID == "" {
		t.Errorf("unexpected created record: %+v", out)
	}

	out2, err := c.CreateRecord(ctx, "example.com", platform.Record{Name: "mail.sub.example.com", Type: "MX", Content: "mx.example.com", Priority: intp(20)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fs.lastBody, `"host":"mail.sub"`) || !strings.Contains(fs.lastBody, `"priority":20`) {
		t.Errorf("relative host/priority not sent, body: %s", fs.lastBody)
	}
	if out2.Name != "mail.sub.example.com" || *out2.Priority != 20 {
		t.Errorf("unexpected MX record: %+v", out2)
	}

	upd, err := c.UpdateRecord(ctx, "example.com", platform.Record{ID: out.ID, Name: "www.example.com", Type: "A", Content: "2.2.2.2", TTL: 600})
	if err != nil {
		t.Fatal(err)
	}
	if fs.lastMethod != http.MethodPut || fs.lastPath != "/v4/domains/example.com/records/"+out.ID {
		t.Errorf("unexpected update call %s %s", fs.lastMethod, fs.lastPath)
	}
	if upd.ID != out.ID || upd.Name != "www.example.com" || upd.Content != "2.2.2.2" || upd.TTL != 600 {
		t.Errorf("unexpected updated record: %+v", upd)
	}

	if err := c.DeleteRecord(ctx, "example.com", out.ID); err != nil {
		t.Fatal(err)
	}
	recs, err := c.ListRecords(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ID != out2.ID {
		t.Errorf("delete did not remove record: %+v", recs)
	}

	if _, err := c.CreateRecord(ctx, "example.com", platform.Record{Name: "www.other.com", Type: "A", Content: "1.1.1.1"}); err == nil {
		t.Error("record outside zone must be rejected")
	}
	if err := c.DeleteRecord(ctx, "example.com", "abc"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("invalid id should map to ErrNotFound, got %v", err)
	}
	if err := c.DeleteRecord(ctx, "example.com", "999999"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing record should map to ErrNotFound, got %v", err)
	}
}

func TestRegistrarActions(t *testing.T) {
	fs, srv := newFakeServer(t)
	fs.addDomain("example.com", "ns1.name.com")
	c := testClient(srv)
	ctx := context.Background()

	if err := c.SetNameservers(ctx, "example.com", []string{"NS1.Example.net.", "ns2.example.net"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fs.lastBody, `["ns1.example.net","ns2.example.net"]`) {
		t.Errorf("nameservers not normalized: %s", fs.lastBody)
	}
	d, err := c.GetDomain(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Nameservers) != 2 {
		t.Errorf("nameservers not updated: %+v", d)
	}
	if d, err = c.SetLock(ctx, "example.com", false); err != nil || *d.Locked {
		t.Errorf("unlock failed: %v %+v", err, d)
	}
	// disableAutorenew returns an empty body in the fake; the client re-reads.
	if d, err = c.SetAutorenew(ctx, "example.com", false); err != nil || *d.AutoRenew {
		t.Errorf("disable autorenew failed: %v %+v", err, d)
	}
	if _, err := c.GetDomain(ctx, "missing.com"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing domain should be ErrNotFound, got %v", err)
	}
	av, err := c.CheckAvailability(ctx, []string{"example.com", "free.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(av) != 2 || av[0].Purchasable || !av[1].Purchasable || av[1].PurchasePrice != 9.99 {
		t.Errorf("unexpected availability: %+v", av)
	}
}

func TestCheckAvailabilityChunks(t *testing.T) {
	fs, srv := newFakeServer(t)
	fs.addDomain("taken.com", "ns1.name.com")
	c := testClient(srv)

	// 2*max + 1 names (plus blanks that are dropped) must be sent in three
	// requests of at most max names, with results in input order.
	names := []string{"", "taken.com"}
	for i := 1; i < 2*maxAvailabilityNames+1; i++ {
		names = append(names, fmt.Sprintf("free%03d.com", i))
	}
	av, err := c.CheckAvailability(context.Background(), names)
	if err != nil {
		t.Fatal(err)
	}
	if fs.availabilityCalls != 3 {
		t.Errorf("got %d requests, want 3", fs.availabilityCalls)
	}
	if len(av) != 2*maxAvailabilityNames+1 {
		t.Fatalf("got %d results, want %d", len(av), 2*maxAvailabilityNames+1)
	}
	if av[0].DomainName != "taken.com" || av[0].Purchasable {
		t.Errorf("first result out of order: %+v", av[0])
	}
	if last := av[len(av)-1]; last.DomainName != fmt.Sprintf("free%03d.com", 2*maxAvailabilityNames) || !last.Purchasable {
		t.Errorf("last result out of order: %+v", last)
	}
	for i := 1; i < len(av); i++ {
		if av[i].DomainName != fmt.Sprintf("free%03d.com", i) {
			t.Fatalf("result %d out of order: %q", i, av[i].DomainName)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.CheckAvailability(ctx, names); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context should abort chunked check, got %v", err)
	}
}

func TestSyncRecordsAcrossZones(t *testing.T) {
	fs, srv := newFakeServer(t)
	fs.addDomain("a.com", "ns1.name.com")
	fs.addDomain("b.com", "NS1ABC.Name.COM.", "ns2abc.name.com")
	// elsewhere.com is registered at name.com but its DNS is served by
	// Cloudflare: it is a domain, not a zone, and its dormant records must
	// not be synced.
	fs.addDomain("elsewhere.com", "ns1.cloudflare.com", "ns2.cloudflare.com")
	fs.addRecord("a.com", apiRecord{Host: "www", Type: "A", Answer: "1.1.1.1"})
	fs.addRecord("b.com", apiRecord{Host: "", Type: "TXT", Answer: "v=spf1"})
	fs.addRecord("elsewhere.com", apiRecord{Host: "", Type: "A", Answer: "9.9.9.9"})
	c := testClient(srv)
	ctx := context.Background()

	res, err := c.Sync(ctx, platform.ResDNSRecord)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d record resources, want 2", len(res))
	}
	for _, r := range res {
		if r.Type != platform.ResDNSRecord || r.ParentID == "" || r.Domain != r.ParentID {
			t.Errorf("record resource missing parent/domain: %+v", r)
		}
		if r.Domain == "elsewhere.com" {
			t.Errorf("records of a domain not hosted at name.com must not be synced: %+v", r)
		}
	}
	zones, err := c.Sync(ctx, platform.ResZone)
	if err != nil || len(zones) != 2 || zones[0].ID != "a.com" || zones[0].Domain != "a.com" || zones[1].ID != "b.com" {
		t.Errorf("zone sync: %v %+v", err, zones)
	}
	for _, z := range zones {
		if z.ID == "elsewhere.com" {
			t.Errorf("domain with Cloudflare nameservers must be absent from zone sync: %+v", z)
		}
	}
	all, err := c.ListZones(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListZones: %v %+v", err, all)
	}
	if all[2].Name != "elsewhere.com" || all[2].Status != zoneInactive || all[0].Status != zoneActive || all[1].Status != zoneActive {
		t.Errorf("zone statuses: %+v", all)
	}
	domains, err := c.Sync(ctx, platform.ResDomain)
	if err != nil || len(domains) != 3 || domains[1].Domain != "b.com" || domains[1].ID != "b.com" || domains[2].ID != "elsewhere.com" {
		t.Errorf("domain sync: %v %+v", err, domains)
	}
	if _, err := c.Sync(ctx, platform.ResInstance); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("instance sync should be ErrNotSupported, got %v", err)
	}
}

func TestUnauthorizedMapping(t *testing.T) {
	_, srv := newFakeServer(t)
	c := newClient(srv.URL, envTest, testUser, "wrong")
	c.api.MaxRetries = 0
	if _, err := c.Verify(context.Background()); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("bad token should be ErrUnauthorized, got %v", err)
	}
	ok := testClient(srv)
	id, err := ok.Verify(context.Background())
	if err != nil || id.User != testUser || id.Extra["env"] != envTest {
		t.Errorf("verify: %v %+v", err, id)
	}
}

func TestLoginNonInteractiveAndInteractive(t *testing.T) {
	_, srv := newFakeServer(t)
	orig := baseURLs[envTest]
	baseURLs[envTest] = srv.URL
	t.Cleanup(func() { baseURLs[envTest] = orig })
	p := &provider{}
	ctx := context.Background()

	var errBuf strings.Builder
	res, err := p.Login(ctx, platform.LoginInput{
		Options: map[string]string{"username": testUser, "token": testToken, "env": "test"},
		Stdin:   strings.NewReader(""), Stdout: &strings.Builder{}, Stderr: &errBuf,
		NoBrowser: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The test environment requires the "-test" suffix; Login adds it and says so.
	if res.Secret[secretToken] != testToken || res.Metadata[metaUsername] != testUser+testUserSuffix || res.Metadata[metaEnv] != envTest || res.Metadata[metaMethod] != methodAPIToken {
		t.Errorf("unexpected login result: %+v", res)
	}
	if !strings.Contains(errBuf.String(), testUser+testUserSuffix) {
		t.Errorf("stderr should announce the suffixed username: %q", errBuf.String())
	}
	if !strings.Contains(res.Label, testUser) {
		t.Errorf("label should name the account: %q", res.Label)
	}
	if strings.Contains(errBuf.String(), testToken) {
		t.Error("token must never be printed")
	}

	// A username that already carries the suffix is left alone.
	errBuf.Reset()
	res, err = p.Login(ctx, platform.LoginInput{
		Options: map[string]string{"username": testUser + testUserSuffix, "token": testToken, "env": "test"},
		Stdin:   strings.NewReader(""), Stdout: &strings.Builder{}, Stderr: &errBuf,
	})
	if err != nil || res.Metadata[metaUsername] != testUser+testUserSuffix {
		t.Errorf("suffixed username must be kept: %v %+v", err, res)
	}
	if strings.Contains(errBuf.String(), "Using username") {
		t.Errorf("no suffix notice expected: %q", errBuf.String())
	}

	// Wrong token is rejected by verification, with the test-environment hint.
	_, err = p.Login(ctx, platform.LoginInput{
		Options: map[string]string{"username": testUser, "token": "bad", "env": "test"},
		Stdin:   strings.NewReader(""), Stdout: &strings.Builder{}, Stderr: &strings.Builder{},
	})
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("bad token should fail login with ErrUnauthorized, got %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), testUserSuffix) || !strings.Contains(err.Error(), "api.dev.name.com") {
		t.Errorf("test environment 401 should carry the -test hint, got %v", err)
	}
	if u, added := testEnvUsername(envProduction, testUser); u != testUser || added {
		t.Errorf("production username must not be suffixed: %q %v", u, added)
	}

	// Interactive: username and token read from stdin, browser opened for guidance.
	opened := ""
	errBuf.Reset()
	res, err = p.Login(ctx, platform.LoginInput{
		Options:     map[string]string{"env": "dev"},
		Stdin:       strings.NewReader(testUser + "\n" + testToken + "\n"),
		Stdout:      &strings.Builder{},
		Stderr:      &errBuf,
		OpenBrowser: func(u string) error { opened = u; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if opened != apiTokenURL || !strings.Contains(errBuf.String(), apiTokenURL) {
		t.Errorf("guidance missing: opened=%q stderr=%q", opened, errBuf.String())
	}
	if res.Metadata[metaUsername] != testUser+testUserSuffix || res.Secret[secretToken] != testToken {
		t.Errorf("interactive login result: %+v", res)
	}

	// Open rebuilds a working client from the stored profile.
	c, err := p.Open(ctx, platform.Profile{Name: "nc", Platform: platform.NameCom, Metadata: res.Metadata, Secret: res.Secret})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(ctx); err != nil {
		t.Errorf("opened client should verify: %v", err)
	}
	if _, err := p.Open(ctx, platform.Profile{Name: "nc", Metadata: res.Metadata}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("missing secret should be ErrUnauthorized, got %v", err)
	}
}

func TestConversions(t *testing.T) {
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	d := toDomain(apiDomain{DomainName: "Old.COM", ExpireDate: "2020-01-01T00:00:00Z"}, now)
	if d.Name != "old.com" || d.Status != "expired" || d.Extra != nil {
		t.Errorf("expired domain mapping: %+v", d)
	}
	for _, tc := range []struct {
		ns     []string
		hosted bool
	}{
		{[]string{"ns1.name.com", "ns2.name.com"}, true},
		{[]string{"NS1ABC.Name.COM."}, true},
		{[]string{"ns1.cloudflare.com", "ns1.name.com"}, true},
		{[]string{"ns1.cloudflare.com", "ns2.cloudflare.com"}, false},
		{[]string{"name.com"}, false},
		{[]string{"ns1.notname.com"}, false},
		{nil, false},
	} {
		z := toZone(apiDomain{DomainName: "Example.COM.", Nameservers: tc.ns})
		if z.ID != "example.com" || z.Name != "example.com" || (z.Status == zoneActive) != tc.hosted {
			t.Errorf("toZone(%v) = %+v, want hosted=%v", tc.ns, z, tc.hosted)
		}
	}
	for _, in := range []string{"123", " 123 ", "0123"} {
		if n, err := parseRecordID(in); err != nil || n != 123 {
			t.Errorf("parseRecordID(%q) = %d, %v", in, n, err)
		}
	}
	for _, in := range []string{"", "0", "-1", "abc", "12a"} {
		if _, err := parseRecordID(in); !errors.Is(err, platform.ErrNotFound) {
			t.Errorf("parseRecordID(%q) should be ErrNotFound, got %v", in, err)
		}
	}
	r := toRecord(apiRecord{ID: 7, Host: "", Type: "a", Answer: "1.1.1.1"}, "example.com")
	if r.Name != "example.com" || r.ID != "7" || r.Type != "A" {
		t.Errorf("apex without fqdn: %+v", r)
	}
	r = toRecord(apiRecord{ID: 8, FQDN: "Www.Example.com.", Host: "www", Type: "A", Answer: "1.1.1.1", Priority: intp(5)}, "example.com")
	if r.Name != "www.example.com" || r.Priority != nil {
		t.Errorf("priority must only apply to MX/SRV: %+v", r)
	}
	w, err := fromRecord(platform.Record{Name: "@", Type: "txt", Content: "x"}, "example.com")
	if err != nil || w.Host != "" || w.Type != "TXT" {
		t.Errorf("'@' should become empty host: %+v %v", w, err)
	}
	w, err = fromRecord(platform.Record{Name: "a.b.example.com.", Type: "SRV", Content: "x", Priority: intp(1)}, "example.com")
	if err != nil || w.Host != "a.b" || w.Priority == nil {
		t.Errorf("relative host: %+v %v", w, err)
	}
	for _, in := range []string{"", "prod", "Production"} {
		if e, err := normalizeEnv(in); err != nil || e != envProduction {
			t.Errorf("normalizeEnv(%q) = %q, %v", in, e, err)
		}
	}
	if e, _ := normalizeEnv("test"); e != envTest {
		t.Errorf("normalizeEnv(test) = %q", e)
	}
	if _, err := normalizeEnv("staging"); err == nil {
		t.Error("unknown env must be rejected")
	}
}

func TestContextCancellation(t *testing.T) {
	fs, srv := newFakeServer(t)
	fs.addDomain("a.com")
	c := testClient(srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ListDomains(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context should abort, got %v", err)
	}
}
