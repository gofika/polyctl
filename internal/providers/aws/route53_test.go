package aws

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/gofika/polyctl/internal/platform"
)

// fakeRoute53 is an in-memory Route 53 that supports paging and change batches.
type fakeRoute53 struct {
	zones        []r53types.HostedZone
	sets         map[string][]r53types.ResourceRecordSet // by zone id
	pageSize     int
	changes      []r53types.Change
	getZoneErr   error
	listCalls    int
	getZoneCalls int
}

func newFakeRoute53() *fakeRoute53 {
	return &fakeRoute53{sets: map[string][]r53types.ResourceRecordSet{}, pageSize: 2}
}

func (f *fakeRoute53) ListHostedZones(ctx context.Context, in *route53.ListHostedZonesInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	start := 0
	if in.Marker != nil {
		for i, z := range f.zones {
			if awssdk.ToString(z.Id) == *in.Marker {
				start = i
			}
		}
	}
	end := start + f.pageSize
	out := &route53.ListHostedZonesOutput{}
	if end >= len(f.zones) {
		end = len(f.zones)
	} else {
		out.IsTruncated = true
		out.NextMarker = f.zones[end].Id
	}
	out.HostedZones = f.zones[start:end]
	return out, nil
}

func (f *fakeRoute53) GetHostedZone(ctx context.Context, in *route53.GetHostedZoneInput, _ ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error) {
	f.getZoneCalls++
	if f.getZoneErr != nil {
		return nil, f.getZoneErr
	}
	for _, z := range f.zones {
		if zoneID(awssdk.ToString(z.Id)) == zoneID(awssdk.ToString(in.Id)) {
			zz := z
			return &route53.GetHostedZoneOutput{HostedZone: &zz, DelegationSet: &r53types.DelegationSet{NameServers: []string{"ns-1.awsdns-00.org", "ns-2.awsdns-00.com"}}}, nil
		}
	}
	return nil, &r53types.NoSuchHostedZone{Message: awssdk.String("no such zone")}
}

func setLess(a, b r53types.ResourceRecordSet) bool {
	an, bn := awssdk.ToString(a.Name), awssdk.ToString(b.Name)
	if an != bn {
		return an < bn
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	return awssdk.ToString(a.SetIdentifier) < awssdk.ToString(b.SetIdentifier)
}

func (f *fakeRoute53) ListResourceRecordSets(ctx context.Context, in *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	f.listCalls++
	sets := append([]r53types.ResourceRecordSet(nil), f.sets[awssdk.ToString(in.HostedZoneId)]...)
	sort.Slice(sets, func(i, j int) bool { return setLess(sets[i], sets[j]) })
	start := 0
	if in.StartRecordName != nil {
		probe := r53types.ResourceRecordSet{Name: in.StartRecordName, Type: in.StartRecordType, SetIdentifier: in.StartRecordIdentifier}
		for start < len(sets) && setLess(sets[start], probe) {
			start++
		}
	}
	end := start + f.pageSize
	out := &route53.ListResourceRecordSetsOutput{}
	if end >= len(sets) {
		end = len(sets)
	} else {
		out.IsTruncated = true
		out.NextRecordName = sets[end].Name
		out.NextRecordType = sets[end].Type
		out.NextRecordIdentifier = sets[end].SetIdentifier
	}
	out.ResourceRecordSets = sets[start:end]
	return out, nil
}

func (f *fakeRoute53) ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	zone := awssdk.ToString(in.HostedZoneId)
	for _, ch := range in.ChangeBatch.Changes {
		rs := *ch.ResourceRecordSet
		if ch.Action != r53types.ChangeActionDelete && !validRoutingPolicy(rs) {
			return nil, &r53types.InvalidChangeBatch{Messages: []string{"set identifier without a routing policy"}}
		}
		f.changes = append(f.changes, ch)
		idx := -1
		for i, s := range f.sets[zone] {
			if awssdk.ToString(s.Name) == awssdk.ToString(rs.Name) && s.Type == rs.Type && awssdk.ToString(s.SetIdentifier) == awssdk.ToString(rs.SetIdentifier) {
				idx = i
			}
		}
		switch ch.Action {
		case r53types.ChangeActionDelete:
			if idx < 0 {
				return nil, &r53types.InvalidChangeBatch{Messages: []string{"delete of missing set"}}
			}
			f.sets[zone] = append(f.sets[zone][:idx], f.sets[zone][idx+1:]...)
		case r53types.ChangeActionCreate:
			if idx >= 0 {
				return nil, &r53types.InvalidChangeBatch{Messages: []string{"set already exists"}}
			}
			f.sets[zone] = append(f.sets[zone], rs)
		case r53types.ChangeActionUpsert:
			if idx >= 0 {
				f.sets[zone][idx] = rs
			} else {
				f.sets[zone] = append(f.sets[zone], rs)
			}
		}
	}
	return &route53.ChangeResourceRecordSetsOutput{ChangeInfo: &r53types.ChangeInfo{Id: awssdk.String("/change/C1")}}, nil
}

// validRoutingPolicy mirrors the Route 53 rule that a set with a set
// identifier must carry exactly one routing policy.
func validRoutingPolicy(rs r53types.ResourceRecordSet) bool {
	if awssdk.ToString(rs.SetIdentifier) == "" {
		return true
	}
	return rs.Weight != nil || rs.Region != "" || rs.Failover != "" || rs.GeoLocation != nil || (rs.MultiValueAnswer != nil && *rs.MultiValueAnswer)
}

func (f *fakeRoute53) values(zone, name, typ string) []string {
	for _, s := range f.sets[zone] {
		if awssdk.ToString(s.Name) == name && string(s.Type) == typ && s.SetIdentifier == nil {
			return setValues(&s)
		}
	}
	return nil
}

func valueSet(name, typ string, ttl int64, values ...string) r53types.ResourceRecordSet {
	rs := r53types.ResourceRecordSet{Name: awssdk.String(name), Type: r53types.RRType(typ), TTL: awssdk.Int64(ttl)}
	for _, v := range values {
		rs.ResourceRecords = append(rs.ResourceRecords, r53types.ResourceRecord{Value: awssdk.String(v)})
	}
	return rs
}

func testClient(f *fakeRoute53) *client {
	return &client{region: "us-east-1", r53: f}
}

func TestRecordIDRoundTrip(t *testing.T) {
	cases := []struct{ zone, typ, name, set, value string }{
		{"Z1", "A", "www.example.com", "", "1.2.3.4"},
		{"/hostedzone/Z1", "txt", "Example.com.", "", `"v=spf1 include:_spf.example.com ~all"`},
		{"Z1", "MX", "example.com", "", "10 mail.example.com"},
		{"Z2", "A", "api.example.com", "weighted|west", "5.6.7.8"},
		{"Z2", "TXT", "x.example.com", "", "a|b c%d+e"},
	}
	for _, c := range cases {
		id := encodeRecordID(c.zone, c.typ, c.name, c.set, c.value)
		if strings.Count(id, recordIDSep) != 4 {
			t.Fatalf("id %q must contain exactly four separators", id)
		}
		zone, typ, name, set, value, err := decodeRecordID(id)
		if err != nil {
			t.Fatalf("decode %q: %v", id, err)
		}
		if zone != zoneID(c.zone) || typ != strings.ToUpper(c.typ) || name != platform.NormalizeDomain(c.name) || set != c.set || value != c.value {
			t.Fatalf("round trip mismatch: got %q %q %q %q %q", zone, typ, name, set, value)
		}
	}
	if _, _, _, _, _, err := decodeRecordID("A|only-two"); err == nil {
		t.Fatal("expected an error for a malformed id")
	}
	if _, _, _, _, _, err := decodeRecordID("A|www.example.com||1.2.3.4"); err == nil {
		t.Fatal("expected an error for an id without zone")
	}
	// Same record key in two zones (split horizon) yields distinct ids.
	pub := encodeRecordID("Z1", "A", "www.example.com", "", "1.2.3.4")
	priv := encodeRecordID("Z2", "A", "www.example.com", "", "1.2.3.4")
	if pub == priv {
		t.Fatalf("ids must differ per zone: %q", pub)
	}
	if _, _, _, _, err := decodeRecordIDIn("Z1", priv); err == nil {
		t.Fatal("expected an error for a record id of another zone")
	}
	if _, _, _, _, err := decodeRecordIDIn("/hostedzone/Z2", priv); err != nil {
		t.Fatalf("id of the right zone rejected: %v", err)
	}
}

func TestTXTQuoting(t *testing.T) {
	cases := map[string]string{
		"v=spf1 -all":            `"v=spf1 -all"`,
		`say "hi" \ bye`:         `"say \"hi\" \\ bye"`,
		`"already quoted"`:       `"already quoted"`,
		`"a" "b"`:                `"a" "b"`,
		"":                       `""`,
		strings.Repeat("x", 300): `"` + strings.Repeat("x", 255) + `" "` + strings.Repeat("x", 45) + `"`,
	}
	for in, want := range cases {
		if got := quoteTXT("txt", in); got != want {
			t.Errorf("quoteTXT(%q) = %q, want %q", in, got, want)
		}
		plain := in
		if strings.HasPrefix(in, `"`) {
			plain = unquoteTXT("TXT", in)
		}
		if got := unquoteTXT("TXT", quoteTXT("TXT", in)); got != plain {
			t.Errorf("round trip of %q = %q, want %q", in, got, plain)
		}
	}
	if got := quoteTXT("SPF", "v=spf1 -all"); got != `"v=spf1 -all"` {
		t.Errorf("SPF must be quoted too, got %q", got)
	}
	if got := quoteTXT("A", "1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("other types must not be quoted, got %q", got)
	}
	if got := unquoteTXT("TXT", `"a" "b"`); got != "ab" {
		t.Errorf("multi-string TXT must be concatenated, got %q", got)
	}
	if got := unquoteTXT("TXT", `"tab\011here"`); got != "tab\there" {
		t.Errorf("octal escapes must be decoded, got %q", got)
	}
	if got := unquoteTXT("TXT", "v=spf1 -all"); got != "v=spf1 -all" {
		t.Errorf("unquoted values must pass through, got %q", got)
	}
	// Escaped chunks never exceed 255 characters.
	long := strings.Repeat(`a"`, 150)
	for _, chunk := range strings.Split(quoteTXT("TXT", long), `" "`) {
		if n := len(strings.Trim(chunk, `"`)); n > txtChunk {
			t.Fatalf("chunk of %d characters", n)
		}
	}
	if got := unquoteTXT("TXT", quoteTXT("TXT", long)); got != long {
		t.Fatal("quote-heavy value did not round trip")
	}

	// Write path quotes, read path unquotes, ids keep the raw value.
	f := newFakeRoute53()
	c := testClient(f)
	ctx := context.Background()
	rec, err := c.CreateRecord(ctx, "Z1", platform.Record{Name: "example.com", Type: "TXT", Content: "v=spf1 -all"})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "example.com.", "TXT"); strings.Join(got, ",") != `"v=spf1 -all"` {
		t.Fatalf("stored TXT must be quoted: %v", got)
	}
	if rec.Content != "v=spf1 -all" || rec.ID != encodeRecordID("Z1", "TXT", "example.com", "", `"v=spf1 -all"`) {
		t.Fatalf("unexpected TXT record %+v", rec)
	}
	recs, err := c.ListRecords(ctx, "Z1")
	if err != nil || len(recs) != 1 || recs[0].Content != "v=spf1 -all" {
		t.Fatalf("listed TXT must be plain: %v %+v", err, recs)
	}
	upd, err := c.UpdateRecord(ctx, "Z1", platform.Record{ID: rec.ID, Name: "example.com", Type: "TXT", Content: "v=spf1 include:_spf.example.com -all"})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "example.com.", "TXT"); strings.Join(got, ",") != `"v=spf1 include:_spf.example.com -all"` {
		t.Fatalf("updated TXT must be quoted: %v", got)
	}
	if err := c.DeleteRecord(ctx, "Z1", upd.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "example.com.", "TXT"); got != nil {
		t.Fatalf("TXT set should be gone: %v", got)
	}
	replaced, err := c.ReplaceSet(ctx, "Z1", "_dmarc.example.com", "txt", []string{"v=DMARC1; p=none", `"pre-quoted"`}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "_dmarc.example.com.", "TXT"); strings.Join(got, ",") != `"v=DMARC1; p=none","pre-quoted"` {
		t.Fatalf("replaced TXT set must be quoted: %v", got)
	}
	if len(replaced) != 2 || replaced[0].Content != "v=DMARC1; p=none" || replaced[1].Content != "pre-quoted" {
		t.Fatalf("unexpected replaced records %+v", replaced)
	}
}

func TestUnescapeRRName(t *testing.T) {
	cases := map[string]string{
		`\052.example.com.`:        "*.example.com",
		"Example.COM.":             "example.com",
		`a\100b.example.com.`:      "a@b.example.com",
		`weird\.name.example.com.`: "weird.name.example.com",
	}
	for in, want := range cases {
		if got := unescapeRRName(in); got != want {
			t.Errorf("unescapeRRName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRecordsFromSet(t *testing.T) {
	mx := valueSet("example.com.", "MX", 3600, "10 mail.example.com", "20 mail2.example.com")
	recs := recordsFromSet("Z1", mx)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	if recs[0].Priority == nil || *recs[0].Priority != 10 || recs[0].Content != "mail.example.com" || recs[0].TTL != 3600 {
		t.Fatalf("unexpected MX record %+v", recs[0])
	}
	if recs[0].Name != "example.com" || recs[0].ID != encodeRecordID("Z1", "MX", "example.com", "", "10 mail.example.com") {
		t.Fatalf("unexpected name/id %+v", recs[0])
	}

	srv := valueSet("_sip._tcp.example.com.", "SRV", 60, "10 60 5060 sip.example.com")
	s := recordsFromSet("Z1", srv)[0]
	if s.Priority == nil || *s.Priority != 10 || s.Content != "60 5060 sip.example.com" {
		t.Fatalf("unexpected SRV record %+v", s)
	}

	txt := valueSet("example.com.", "TXT", 300, `"v=spf1 -all"`, `"part one" "part two"`)
	txtRecs := recordsFromSet("Z1", txt)
	if got := txtRecs[0].Content; got != "v=spf1 -all" {
		t.Fatalf("TXT content must be unquoted, got %q", got)
	}
	if got := txtRecs[1].Content; got != "part onepart two" {
		t.Fatalf("multi-string TXT content must be joined, got %q", got)
	}
	if txtRecs[0].ID != encodeRecordID("Z1", "TXT", "example.com", "", `"v=spf1 -all"`) {
		t.Fatalf("TXT id must keep the raw value: %s", txtRecs[0].ID)
	}

	alias := r53types.ResourceRecordSet{
		Name: awssdk.String("example.com."), Type: r53types.RRTypeA,
		AliasTarget: &r53types.AliasTarget{DNSName: awssdk.String("d123.cloudfront.net."), HostedZoneId: awssdk.String("Z2FDTNDATAQYW2"), EvaluateTargetHealth: true},
	}
	a := recordsFromSet("Z1", alias)
	if len(a) != 1 || a[0].Content != "d123.cloudfront.net" || !extraBool(a[0].Extra, "alias") || extraString(a[0].Extra, "alias_zone_id") != "Z2FDTNDATAQYW2" {
		t.Fatalf("unexpected alias record %+v", a)
	}
	if a[0].Extra["evaluate_target_health"] != true {
		t.Fatalf("evaluate_target_health not carried over: %+v", a[0].Extra)
	}

	weighted := valueSet("api.example.com.", "A", 60, "1.1.1.1")
	weighted.SetIdentifier = awssdk.String("west")
	weighted.Weight = awssdk.Int64(10)
	w := recordsFromSet("Z1", weighted)[0]
	if extraString(w.Extra, "set_identifier") != "west" || w.Extra["weight"] != int64(10) {
		t.Fatalf("routing attributes missing: %+v", w.Extra)
	}
	if zone, _, _, set, _, _ := decodeRecordID(w.ID); set != "west" || zone != "Z1" {
		t.Fatalf("zone or set identifier not in id: %s", w.ID)
	}
}

func TestZoneFromHosted(t *testing.T) {
	z := zoneFromHosted(r53types.HostedZone{
		Id: awssdk.String("/hostedzone/Z123"), Name: awssdk.String("example.com."),
		Config: &r53types.HostedZoneConfig{PrivateZone: true, Comment: awssdk.String("internal")}, ResourceRecordSetCount: awssdk.Int64(7),
	})
	if z.ID != "Z123" || z.Name != "example.com" || z.Status != "private" || z.Extra["comment"] != "internal" || z.Extra["record_count"] != int64(7) {
		t.Fatalf("unexpected zone %+v", z)
	}
}

func TestListZonesPaginatesAndExposesDelegationFailure(t *testing.T) {
	f := newFakeRoute53()
	for _, n := range []string{"a.com.", "b.com.", "c.com."} {
		f.zones = append(f.zones, r53types.HostedZone{Id: awssdk.String("/hostedzone/Z" + strings.ToUpper(n[:1])), Name: awssdk.String(n)})
	}
	c := testClient(f)
	// The plain listing never calls GetHostedZone (no N+1).
	zones, err := c.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 3 || zones[0].ID != "ZA" || zones[0].Nameservers != nil || f.getZoneCalls != 0 {
		t.Fatalf("unexpected zones %+v (GetHostedZone calls: %d)", zones, f.getZoneCalls)
	}
	zones, err = c.listZonesWithNameservers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 3 || zones[0].ID != "ZA" || len(zones[0].Nameservers) != 2 || f.getZoneCalls != 3 {
		t.Fatalf("unexpected zones %+v (GetHostedZone calls: %d)", zones, f.getZoneCalls)
	}
	f.getZoneErr = &fakeAPIError{"Throttling", "slow down"}
	if _, err := c.listZonesWithNameservers(context.Background()); err == nil || !strings.Contains(err.Error(), "Throttling") {
		t.Fatalf("delegation set failure must be reported, got %v", err)
	}
	if _, err := c.ListZones(context.Background()); err != nil {
		t.Fatalf("plain listing must not depend on GetHostedZone: %v", err)
	}
}

func TestListZonesSortsPublicBeforePrivate(t *testing.T) {
	f := newFakeRoute53()
	f.pageSize = 10
	f.zones = []r53types.HostedZone{
		{Id: awssdk.String("/hostedzone/ZPRIV"), Name: awssdk.String("example.com."), Config: &r53types.HostedZoneConfig{PrivateZone: true}},
		{Id: awssdk.String("/hostedzone/ZPUB"), Name: awssdk.String("example.com.")},
		{Id: awssdk.String("/hostedzone/ZA"), Name: awssdk.String("a.com.")},
	}
	zones, err := testClient(f).ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 3 || zones[0].ID != "ZA" || zones[1].ID != "ZPUB" || zones[2].ID != "ZPRIV" {
		t.Fatalf("unexpected order %+v", zones)
	}
	if zones[2].Extra["private"] != true || zones[1].Extra["private"] != false {
		t.Fatalf("private flag missing from extra: %+v", zones)
	}
}

func TestUpdateWeightedRecordRename(t *testing.T) {
	f := newFakeRoute53()
	west := valueSet("api.example.com.", "A", 60, "1.1.1.1")
	west.SetIdentifier = awssdk.String("west")
	west.Weight = awssdk.Int64(10)
	f.sets["Z1"] = []r53types.ResourceRecordSet{west}
	c := testClient(f)
	ctx := context.Background()

	// The fake enforces the routing-policy rule.
	bare := valueSet("x.example.com.", "A", 60, "1.1.1.1")
	bare.SetIdentifier = awssdk.String("bare")
	if _, err := f.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{HostedZoneId: awssdk.String("Z1"), ChangeBatch: &r53types.ChangeBatch{Changes: []r53types.Change{upsert(bare)}}}); err == nil {
		t.Fatal("fake must reject a set identifier without routing policy")
	}

	recs, err := c.ListRecords(ctx, "Z1")
	if err != nil || len(recs) != 1 {
		t.Fatalf("list: %v %+v", err, recs)
	}
	moved, err := c.UpdateRecord(ctx, "Z1", platform.Record{ID: recs[0].ID, Name: "api2.example.com", Type: "A", Content: "1.1.1.1", Extra: recs[0].Extra})
	if err != nil {
		t.Fatalf("rename of a weighted record failed: %v", err)
	}
	if moved.Name != "api2.example.com" || moved.Extra["weight"] != int64(10) || extraString(moved.Extra, "set_identifier") != "west" {
		t.Fatalf("routing policy lost on rename: %+v", moved)
	}
	var found bool
	for _, s := range f.sets["Z1"] {
		if awssdk.ToString(s.Name) == "api2.example.com." {
			found = true
			if s.Weight == nil || *s.Weight != 10 || awssdk.ToString(s.SetIdentifier) != "west" {
				t.Fatalf("new set lacks the weight: %+v", s)
			}
		}
		if awssdk.ToString(s.Name) == "api.example.com." {
			t.Fatalf("old set should be gone: %+v", s)
		}
	}
	if !found {
		t.Fatalf("new set missing: %+v", f.sets["Z1"])
	}
}

func TestListRecordsPaginates(t *testing.T) {
	f := newFakeRoute53()
	f.sets["Z1"] = []r53types.ResourceRecordSet{
		valueSet("example.com.", "NS", 172800, "ns1.", "ns2."),
		valueSet("example.com.", "SOA", 900, "ns1. hostmaster. 1 7200 900 1209600 86400"),
		valueSet("a.example.com.", "A", 300, "1.1.1.1", "2.2.2.2"),
		valueSet("b.example.com.", "A", 300, "3.3.3.3"),
		valueSet("c.example.com.", "CNAME", 300, "a.example.com"),
	}
	recs, err := testClient(f).ListRecords(context.Background(), "/hostedzone/Z1")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 7 {
		t.Fatalf("expected 7 records (one per value), got %d", len(recs))
	}
	if f.listCalls != 3 {
		t.Fatalf("expected 3 pages of 2, got %d calls", f.listCalls)
	}
	for _, r := range recs {
		if r.ZoneID != "Z1" || strings.HasSuffix(r.Name, ".") {
			t.Fatalf("bad record %+v", r)
		}
	}
}

func TestCreateUpdateDeleteRecord(t *testing.T) {
	f := newFakeRoute53()
	f.sets["Z1"] = []r53types.ResourceRecordSet{valueSet("www.example.com.", "A", 600, "1.1.1.1")}
	c := testClient(f)
	ctx := context.Background()

	// Create adds a value to the existing set and keeps its TTL.
	rec, err := c.CreateRecord(ctx, "Z1", platform.Record{Name: "www.example.com", Type: "a", Content: "2.2.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "www.example.com.", "A"); strings.Join(got, ",") != "1.1.1.1,2.2.2.2" {
		t.Fatalf("values after create: %v", got)
	}
	if rec.TTL != 600 || rec.Content != "2.2.2.2" || rec.ID != encodeRecordID("Z1", "A", "www.example.com", "", "2.2.2.2") {
		t.Fatalf("unexpected created record %+v", rec)
	}

	// Create of a brand-new MX set uses the priority and default TTL.
	p := 10
	mx, err := c.CreateRecord(ctx, "Z1", platform.Record{Name: "example.com", Type: "MX", Content: "mail.example.com", Priority: &p})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "example.com.", "MX"); strings.Join(got, ",") != "10 mail.example.com" {
		t.Fatalf("MX values: %v", got)
	}
	if mx.TTL != defaultTTL || mx.Priority == nil || *mx.Priority != 10 || mx.Content != "mail.example.com" {
		t.Fatalf("unexpected MX record %+v", mx)
	}

	// Update replaces one value in place.
	upd, err := c.UpdateRecord(ctx, "Z1", platform.Record{ID: rec.ID, Name: "www.example.com", Type: "A", Content: "9.9.9.9", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "www.example.com.", "A"); strings.Join(got, ",") != "1.1.1.1,9.9.9.9" {
		t.Fatalf("values after update: %v", got)
	}
	if upd.TTL != 60 || upd.Content != "9.9.9.9" {
		t.Fatalf("unexpected updated record %+v", upd)
	}

	// Update that moves the value to another name: old set keeps the rest, new set is created.
	moved, err := c.UpdateRecord(ctx, "Z1", platform.Record{ID: upd.ID, Name: "api.example.com", Type: "A", Content: "9.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "www.example.com.", "A"); strings.Join(got, ",") != "1.1.1.1" {
		t.Fatalf("old set after move: %v", got)
	}
	if got := f.values("Z1", "api.example.com.", "A"); strings.Join(got, ",") != "9.9.9.9" {
		t.Fatalf("new set after move: %v", got)
	}
	if moved.Name != "api.example.com" || moved.TTL != 60 {
		t.Fatalf("moved record should inherit the TTL: %+v", moved)
	}

	// Moving the last value deletes the old set entirely.
	last := f.values("Z1", "www.example.com.", "A")[0]
	if _, err := c.UpdateRecord(ctx, "Z1", platform.Record{ID: encodeRecordID("Z1", "A", "www.example.com", "", last), Name: "api.example.com", Type: "A", Content: last}); err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "www.example.com.", "A"); got != nil {
		t.Fatalf("old set should be gone: %v", got)
	}
	if got := f.values("Z1", "api.example.com.", "A"); strings.Join(got, ",") != "9.9.9.9,1.1.1.1" {
		t.Fatalf("merged set: %v", got)
	}
	if f.changes[len(f.changes)-2].Action != r53types.ChangeActionDelete {
		t.Fatalf("expected a DELETE of the emptied set, got %v", f.changes[len(f.changes)-2].Action)
	}

	// Delete one value keeps the set; deleting the last value deletes the set.
	// A record id of another zone is refused before anything is touched.
	if err := c.DeleteRecord(ctx, "Z1", encodeRecordID("Z2", "A", "api.example.com", "", "9.9.9.9")); err == nil || !strings.Contains(err.Error(), "Z2") {
		t.Fatalf("expected a zone mismatch error, got %v", err)
	}
	if err := c.DeleteRecord(ctx, "Z1", encodeRecordID("Z1", "A", "api.example.com", "", "9.9.9.9")); err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "api.example.com.", "A"); strings.Join(got, ",") != "1.1.1.1" {
		t.Fatalf("after single delete: %v", got)
	}
	if err := c.DeleteRecord(ctx, "/hostedzone/Z1", encodeRecordID("Z1", "A", "api.example.com", "", "1.1.1.1")); err != nil {
		t.Fatal(err)
	}
	if got := f.values("Z1", "api.example.com.", "A"); got != nil {
		t.Fatalf("set should be deleted: %v", got)
	}
	if f.changes[len(f.changes)-1].Action != r53types.ChangeActionDelete {
		t.Fatalf("last change should be DELETE")
	}

	// Unknown value -> ErrNotFound.
	err = c.DeleteRecord(ctx, "Z1", encodeRecordID("Z1", "MX", "example.com", "", "99 nope"))
	if !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	err = c.DeleteRecord(ctx, "Z1", encodeRecordID("Z1", "A", "missing.example.com", "", "1.1.1.1"))
	if !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing set, got %v", err)
	}
}

func TestAliasRecords(t *testing.T) {
	f := newFakeRoute53()
	c := testClient(f)
	ctx := context.Background()
	rec, err := c.CreateRecord(ctx, "Z1", platform.Record{Name: "example.com", Type: "A", Content: "d1.cloudfront.net",
		Extra: map[string]any{"alias": true, "alias_zone_id": "Z2FDTNDATAQYW2"}})
	if err != nil {
		t.Fatal(err)
	}
	if !extraBool(rec.Extra, "alias") || rec.Content != "d1.cloudfront.net" {
		t.Fatalf("unexpected alias record %+v", rec)
	}
	if rs := f.sets["Z1"][0]; rs.AliasTarget == nil || awssdk.ToString(rs.AliasTarget.DNSName) != "d1.cloudfront.net." || rs.TTL != nil {
		t.Fatalf("alias set not stored properly: %+v", rs)
	}
	// Plain values cannot be added to an alias set.
	if _, err := c.CreateRecord(ctx, "Z1", platform.Record{Name: "example.com", Type: "A", Content: "1.1.1.1"}); err == nil {
		t.Fatal("expected an error adding a plain value to an alias set")
	}
	// Update keeps the alias target zone when not given.
	upd, err := c.UpdateRecord(ctx, "Z1", platform.Record{ID: rec.ID, Name: "example.com", Type: "A", Content: "d2.cloudfront.net", Extra: rec.Extra})
	if err != nil {
		t.Fatal(err)
	}
	if upd.Content != "d2.cloudfront.net" || extraString(upd.Extra, "alias_zone_id") != "Z2FDTNDATAQYW2" {
		t.Fatalf("unexpected updated alias %+v", upd)
	}
	// Delete removes the whole set.
	if err := c.DeleteRecord(ctx, "Z1", upd.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.sets["Z1"]) != 0 {
		t.Fatalf("alias set should be deleted: %+v", f.sets["Z1"])
	}
}

func TestReplaceAndDeleteSet(t *testing.T) {
	f := newFakeRoute53()
	f.sets["Z1"] = []r53types.ResourceRecordSet{valueSet("www.example.com.", "A", 600, "1.1.1.1", "2.2.2.2")}
	c := testClient(f)
	recs, err := c.ReplaceSet(context.Background(), "Z1", "www.example.com", "a", []string{"3.3.3.3"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Content != "3.3.3.3" || recs[0].TTL != 600 {
		t.Fatalf("unexpected replaced set %+v", recs)
	}
	deleted, err := c.DeleteSet(context.Background(), "Z1", "www.example.com", "A")
	if err != nil || len(deleted) != 1 || len(f.sets["Z1"]) != 0 {
		t.Fatalf("delete set: %v %+v %+v", err, deleted, f.sets["Z1"])
	}
	if _, err := c.DeleteSet(context.Background(), "Z1", "www.example.com", "A"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestLooksLikeZoneID(t *testing.T) {
	if !looksLikeZoneID("Z0123456789ABCDEFGHIJ") || !looksLikeZoneID("/hostedzone/Z123") {
		t.Fatal("ids not detected")
	}
	if looksLikeZoneID("example.com") || looksLikeZoneID("zone") {
		t.Fatal("names detected as ids")
	}
}
