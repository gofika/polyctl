package godaddy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeGoDaddy is an in-memory stand-in for the GoDaddy REST API.
type fakeGoDaddy struct {
	t *testing.T

	mu           sync.Mutex
	auth         []string // accepted Authorization header values
	accessDenied bool     // answer 403 ACCESS_DENIED to everything
	// rateLimitOnce makes the next matching request (method+path prefix)
	// answer 429 with RateLimit-Reset: 1 and an empty body, once.
	rateLimitOnce string
	rateLimited   int  // number of 429s served
	failPatch     bool // PATCH /records answers 422
	failPut       bool // PUT /records/{type}/{name} answers 500
	domains       map[string]*apiDomain
	records       map[string][]apiRecord
	calls         []string // "METHOD path?query"
}

// newFake accepts the legacy key pair (sso-key) and the test PAT (Bearer).
func newFake(t *testing.T, key, secret string) (*fakeGoDaddy, *httptest.Server) {
	t.Helper()
	f := &fakeGoDaddy{t: t, auth: []string{"sso-key " + key + ":" + secret, "Bearer " + testToken}, domains: map[string]*apiDomain{}, records: map[string][]apiRecord{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeGoDaddy) addDomain(name string, ns ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, l, r := true, true, false
	f.domains[name] = &apiDomain{Domain: name, DomainID: int64(len(f.domains) + 1), Status: "ACTIVE", Expires: "2030-01-02T03:04:05Z", CreatedAt: "2020-01-01T00:00:00Z", NameServers: ns, RenewAuto: &r, Locked: &l, Privacy: &t}
}

func (f *fakeGoDaddy) setRecords(domain string, recs ...apiRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[domain] = append([]apiRecord(nil), recs...)
}

func (f *fakeGoDaddy) getRecords(domain string) []apiRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]apiRecord(nil), f.records[domain]...)
}

func (f *fakeGoDaddy) callsMatching(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func apiErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"code": code, "message": msg})
}

func (f *fakeGoDaddy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call := r.Method + " " + r.URL.RequestURI()
	f.mu.Lock()
	f.calls = append(f.calls, call)
	authOK := false
	for _, a := range f.auth {
		if r.Header.Get("Authorization") == a {
			authOK = true
		}
	}
	limited := f.rateLimitOnce != "" && strings.HasPrefix(call, f.rateLimitOnce)
	if limited {
		f.rateLimitOnce = ""
		f.rateLimited++
	}
	f.mu.Unlock()

	if !authOK {
		apiErr(w, http.StatusUnauthorized, "UNABLE_TO_AUTHENTICATE", "Unauthorized : Credentials must be specified")
		return
	}
	if limited {
		w.Header().Set("RateLimit-Reset", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if f.accessDenied {
		apiErr(w, http.StatusForbidden, "ACCESS_DENIED", "Authenticated user is not allowed access")
		return
	}
	q := r.URL.Query()
	path := strings.TrimPrefix(r.URL.Path, "/v1/domains")
	switch {
	case path == "" && r.Method == http.MethodGet:
		f.listDomains(w, q)
	case path == "/available" && r.Method == http.MethodGet:
		d := q.Get("domain")
		writeJSON(w, 200, apiAvailability{Domain: d, Available: strings.HasPrefix(d, "free-"), Definitive: true, Price: 12990000, Currency: "USD", Period: 1})
	default:
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		for i := range parts {
			parts[i], _ = url.PathUnescape(parts[i])
		}
		f.mu.Lock()
		dom, ok := f.domains[parts[0]]
		f.mu.Unlock()
		if !ok {
			apiErr(w, http.StatusNotFound, "UNKNOWN_DOMAIN", "The given domain is not registered, or does not have a zone file")
			return
		}
		switch {
		case len(parts) == 1 && r.Method == http.MethodGet:
			writeJSON(w, 200, dom)
		case len(parts) == 1 && r.Method == http.MethodPatch:
			var p domainPatch
			_ = json.NewDecoder(r.Body).Decode(&p)
			f.mu.Lock()
			if p.NameServers != nil {
				dom.NameServers = p.NameServers
			}
			if p.Locked != nil {
				dom.Locked = p.Locked
			}
			if p.RenewAuto != nil {
				dom.RenewAuto = p.RenewAuto
			}
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case len(parts) == 2 && parts[1] == "records" && r.Method == http.MethodGet:
			f.page(w, q, f.getRecords(parts[0]))
		case len(parts) == 2 && parts[1] == "records" && r.Method == http.MethodPatch:
			if f.failPatch {
				apiErr(w, 422, "INVALID_BODY", "simulated PATCH failure")
				return
			}
			var recs []apiRecord
			if err := json.NewDecoder(r.Body).Decode(&recs); err != nil {
				apiErr(w, 422, "INVALID_BODY", err.Error())
				return
			}
			for _, rec := range recs {
				if rec.Type == "" || rec.Name == "" || rec.Data == "" {
					apiErr(w, 422, "INVALID_BODY", "type, name and data are required")
					return
				}
			}
			f.mu.Lock()
			f.records[parts[0]] = append(f.records[parts[0]], recs...)
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case len(parts) == 4 && parts[1] == "records":
			f.recordSet(w, r, q, parts[0], parts[2], parts[3])
		default:
			apiErr(w, http.StatusNotFound, "NOT_FOUND", "no such route")
		}
	}
}

func (f *fakeGoDaddy) listDomains(w http.ResponseWriter, q url.Values) {
	f.mu.Lock()
	names := make([]string, 0, len(f.domains))
	for n := range f.domains {
		names = append(names, n)
	}
	sort.Strings(names)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 1000
	}
	marker := q.Get("marker")
	var out []apiDomain
	for _, n := range names {
		// GoDaddy's marker is the first domain of the page (inclusive).
		if marker != "" && n < marker {
			continue
		}
		d := *f.domains[n]
		if !strings.Contains(q.Get("includes"), "nameServers") {
			d.NameServers = nil
		}
		out = append(out, d)
		if len(out) == limit {
			break
		}
	}
	f.mu.Unlock()
	if out == nil {
		out = []apiDomain{}
	}
	writeJSON(w, 200, out)
}

func (f *fakeGoDaddy) page(w http.ResponseWriter, q url.Values, recs []apiRecord) {
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 500
	}
	if offset > len(recs) {
		offset = len(recs)
	}
	end := offset + limit
	if end > len(recs) {
		end = len(recs)
	}
	out := recs[offset:end]
	if out == nil {
		out = []apiRecord{}
	}
	writeJSON(w, 200, out)
}

func (f *fakeGoDaddy) recordSet(w http.ResponseWriter, r *http.Request, q url.Values, domain, typ, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keep, set []apiRecord
	for _, rec := range f.records[domain] {
		if rec.Type == typ && rec.Name == name {
			set = append(set, rec)
		} else {
			keep = append(keep, rec)
		}
	}
	switch r.Method {
	case http.MethodGet:
		f.page(w, q, set)
	case http.MethodPut:
		if f.failPut {
			apiErr(w, 500, "INTERNAL", "simulated PUT failure")
			return
		}
		var body []apiRecord
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) == 0 {
			apiErr(w, 422, "INVALID_BODY", "body must be a non-empty array")
			return
		}
		for _, rec := range body {
			if rec.Type != "" || rec.Name != "" {
				apiErr(w, 422, "INVALID_BODY", "type and name are read-only in a PUT body")
				return
			}
			rec.Type, rec.Name = typ, name
			keep = append(keep, rec)
		}
		f.records[domain] = keep
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		f.records[domain] = keep
		w.WriteHeader(http.StatusNoContent)
	default:
		apiErr(w, 405, "METHOD_NOT_ALLOWED", "")
	}
}
