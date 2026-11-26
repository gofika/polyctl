package namecom

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// Fake gives the external tests of this package (which run the whole
// command line, and so cannot live in the package itself) the fake name.com
// API, with the test environment of the registered provider pointed at it.
type Fake struct {
	fs *fakeServer
}

// TestUser and TestToken are the credentials the fake accepts.
const (
	TestUser  = testUser
	TestToken = testToken
)

// NewFake starts the fake API with one domain.
func NewFake(t *testing.T, domain string) *Fake {
	t.Helper()
	fs, srv := newFakeServer(t)
	fs.addDomain(domain)
	orig := baseURLs[envTest]
	baseURLs[envTest] = srv.URL
	t.Cleanup(func() { baseURLs[envTest] = orig })
	return &Fake{fs: fs}
}

// Reset forgets every record.
func (x *Fake) Reset() {
	x.fs.mu.Lock()
	defer x.fs.mu.Unlock()
	x.fs.records = map[string][]apiRecord{}
}

// Requests is the number of requests the fake has served.
func (x *Fake) Requests() int {
	x.fs.mu.Lock()
	defer x.fs.mu.Unlock()
	return x.fs.requests
}

// Records lists the records of domain as "host TYPE answer ttl priority"
// (host "@" for the apex, priority "-" when there is none).
func (x *Fake) Records(domain string) []string {
	x.fs.mu.Lock()
	defer x.fs.mu.Unlock()
	var out []string
	for _, r := range x.fs.records[domain] {
		host, prio := r.Host, "-"
		if host == "" {
			host = "@"
		}
		if r.Priority != nil {
			prio = fmt.Sprint(*r.Priority)
		}
		out = append(out, fmt.Sprintf("%s %s %s %d %s", host, r.Type, r.Answer, r.TTL, prio))
	}
	return out
}

// Add puts a record into domain (host "" or "@" for the apex) and returns
// its id.
func (x *Fake) Add(domain, host, typ, answer string) string {
	x.fs.mu.Lock()
	defer x.fs.mu.Unlock()
	if host == "@" {
		host = ""
	}
	return strconv.FormatInt(x.fs.addRecord(domain, apiRecord{Host: host, Type: typ, Answer: answer, TTL: 300}).ID, 10)
}

// IDs lists the ids of the records of domain, separated by spaces.
func (x *Fake) IDs(domain string) string {
	x.fs.mu.Lock()
	defer x.fs.mu.Unlock()
	var ids []string
	for _, r := range x.fs.records[domain] {
		ids = append(ids, strconv.FormatInt(r.ID, 10))
	}
	return strings.Join(ids, " ")
}
