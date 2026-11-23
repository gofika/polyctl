package platform

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestParseFindQuery(t *testing.T) {
	for _, tc := range []struct {
		in, kind, value string
		bad             bool
	}{
		{in: "203.0.113.10", kind: "ip", value: "203.0.113.10"},
		{in: " 10.0.1.100 ", kind: "ip", value: "10.0.1.100"},
		{in: "2001:DB8:0:0:0:0:0:1", kind: "ip", value: "2001:db8::1"},
		{in: "::ffff:192.0.2.1", kind: "ip", value: "192.0.2.1"},
		{in: "fe80::1%eth0", kind: "ip", value: "fe80::1"},
		{in: "MyDB.abc123.ap-east-1.RDS.amazonaws.com.", kind: "dns", value: "mydb.abc123.ap-east-1.rds.amazonaws.com"},
		{in: "net-lb-1234.elb.us-east-1.amazonaws.com", kind: "dns", value: "net-lb-1234.elb.us-east-1.amazonaws.com"},
		{in: "", bad: true},
		{in: "  ", bad: true},
		{in: "a b", bad: true},
		{in: "https://example.com", bad: true},
		{in: "example..com", bad: true},
		{in: "10.0.0.1/24", bad: true},
		{in: ".", bad: true},
	} {
		q, err := ParseFindQuery(tc.in)
		if tc.bad {
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("%q: err = %v, want invalid input", tc.in, err)
			}
			continue
		}
		if err != nil || string(q.Kind) != tc.kind || q.Value != tc.value {
			t.Errorf("%q = %+v, %v", tc.in, q, err)
		}
	}
}

func TestIPAddrAndSet(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1":            "10.0.0.1",
		"10.1.2.3/24":         "10.1.2.0/24",
		"10.2.3.4/32":         "10.2.3.4",
		"2600:1900:4000::/96": "2600:1900:4000::/96",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
	} {
		r, ok := IPAddr(IPInternal, in)
		if !ok || r.Value != want {
			t.Errorf("%q = %v, %v; want %q", in, r, ok, want)
		}
	}
	for _, in := range []string{"", "/24", "nope"} {
		if _, ok := IPAddr(IPInternal, in); ok {
			t.Errorf("%q accepted", in)
		}
	}
	var s IPSet
	s.Add(IPInternal, "10.0.0.1", "", "10.0.0.1", "10.0.0.2")
	s.Add(IPExternal, "203.0.113.1")
	s.AddDNS("A.example.com.", "")
	if got := s.Values(IPInternal); len(got) != 2 {
		t.Errorf("internal = %v", got)
	}
	if got := s.Refs(); len(got) != 4 || got[3].Value != "a.example.com" {
		t.Errorf("refs = %v", got)
	}
}

func TestMatchedField(t *testing.T) {
	if MatchedField(IPDNS, ResDBInstance) != MatchedEndpoint || MatchedField(IPDNS, ResLoadBalancer) != MatchedDNSName ||
		MatchedField(IPInternal, ResInstance) != MatchedInternalIP || MatchedField(IPExternal, ResEIP) != MatchedExternalIP {
		t.Error("matched field mapping")
	}
}

func TestSyncRegions(t *testing.T) {
	ctx := context.Background()
	fn := func(fail map[string]error) func(context.Context, string) ([]Resource, error) {
		return func(_ context.Context, r string) ([]Resource, error) {
			if err := fail[r]; err != nil {
				return nil, err
			}
			return []Resource{{Type: ResInstance, ID: r}}, nil
		}
	}
	res, err := SyncRegions(ctx, []string{"a", "b", "c"}, 2, fn(nil))
	if err != nil || len(res) != 3 {
		t.Fatalf("all ok = %v, %v", res, err)
	}
	res, err = SyncRegions(ctx, []string{"a", "b", "c"}, 2, fn(map[string]error{"b": errors.New("dns failure")}))
	rse := AsRegionSyncError(err)
	if len(res) != 2 || rse == nil || len(rse.Failures) != 1 || rse.Failures[0].Region != "b" {
		t.Fatalf("partial = %v, %v", res, err)
	}
	res, err = SyncRegions(ctx, []string{"a", "b"}, 2, fn(map[string]error{
		"a": fmt.Errorf("%w: denied", ErrUnauthorized), "b": fmt.Errorf("%w: denied", ErrUnauthorized)}))
	if res != nil || !errors.Is(err, ErrUnauthorized) || AsRegionSyncError(err) != nil {
		t.Fatalf("all failed = %v, %v", res, err)
	}
}

func TestFindMatchHolds(t *testing.T) {
	m := &FindMatch{Matched: "10.1.2.7"}
	if !m.Holds("10.1.2.7") || !m.Holds("10.1.2.0/24") || m.Holds("10.1.3.0/24") || m.Holds("") {
		t.Error("holds by address")
	}
	m.Matched = "2600:1900:4000:1::/96"
	if !m.Holds("2600:1900:4000:1::/96") || m.Holds("10.0.0.1") {
		t.Error("holds by prefix")
	}
}
