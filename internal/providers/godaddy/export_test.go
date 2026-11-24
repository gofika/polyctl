package godaddy

import "testing"

// Fake gives the external tests of this package (which run the whole
// command line, and so cannot live in the package itself) the fake GoDaddy
// API.
type Fake struct {
	f   *fakeGoDaddy
	URL string
}

// TestToken is the personal access token the fake accepts.
const TestToken = testToken

// NewFake starts the fake API with one domain.
func NewFake(t *testing.T, domain string) *Fake {
	t.Helper()
	f, srv := newFake(t, testKey, testSecret)
	f.addDomain(domain)
	return &Fake{f: f, URL: srv.URL}
}

// Reset forgets every record and every call.
func (x *Fake) Reset() {
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	x.f.records = map[string][]apiRecord{}
	x.f.calls = nil
}

// SetRecord adds a record (type, name relative to the domain, data).
func (x *Fake) SetRecord(domain, typ, name, data string) {
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	x.f.records[domain] = append(x.f.records[domain], apiRecord{Type: typ, Name: name, Data: data, TTL: 600})
}

// Records lists the records of domain as "TYPE name data".
func (x *Fake) Records(domain string) []string {
	var out []string
	for _, r := range x.f.getRecords(domain) {
		out = append(out, r.Type+" "+r.Name+" "+r.Data)
	}
	return out
}

// Writes lists the calls that changed something (anything but GET).
func (x *Fake) Writes() []string {
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	var out []string
	for _, c := range x.f.calls {
		if len(c) < 4 || c[:4] != "GET " {
			out = append(out, c)
		}
	}
	return out
}

// SetSRV adds an SRV record of the apex (service and protocol such as
// "_sip" and "_tcp").
func (x *Fake) SetSRV(domain, service, protocol, target string, port int) {
	x.f.mu.Lock()
	defer x.f.mu.Unlock()
	zero := 0
	x.f.records[domain] = append(x.f.records[domain], apiRecord{Type: "SRV", Name: "@", Data: target, TTL: 600, Service: service, Protocol: protocol, Port: &port, Weight: &zero, Priority: &zero})
}
