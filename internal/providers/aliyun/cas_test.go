package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

// casFake is the CAS store of one endpoint, answering as verified on real
// accounts: pages of ShowSize, no CertificateOrderList when empty,
// NameRepeat for a taken name, NotFound (HTTP 400) for a missing id.
type casFake struct {
	t       *testing.T
	certs   []map[string]any
	nextID  int64
	uploads []url.Values
	deletes []string
	// zeroID makes UploadUserCertificate answer CertId 0.
	zeroID bool
	// failList / failDelete answer these error codes (with status).
	failList   string
	failStatus int
	failDelete map[string]string
}

func newCASFake(t *testing.T, api *fakeAPI) *casFake {
	f := &casFake{t: t, nextID: 9000001, failDelete: map[string]string{}}
	api.on("ListUserCertificateOrder", f.list)
	api.on("UploadUserCertificate", f.upload)
	api.on("DeleteUserCertificate", f.delete)
	return f
}

func (f *casFake) add(id int64, name, end string) map[string]any {
	c := map[string]any{"CertificateId": id, "Name": name, "CommonName": "example.com", "StartDate": "2026-11-03", "EndDate": end,
		"Fingerprint": "FEFD0123456789ABCDEF0123456789ABCDEF0123", "Sha2": "00ff", "Sans": "example.com,www.example.com",
		"SerialNo": "0a1b", "Expired": false, "Status": "ISSUED", "Upload": true, "InstanceId": fmt.Sprintf("cas-upload-%d", id)}
	f.certs = append(f.certs, c)
	return c
}

func (f *casFake) list(q url.Values) (int, any) {
	if f.failList != "" {
		return f.failStatus, apiErr(f.failList, "refused")
	}
	if q.Get("OrderType") != "UPLOAD" {
		f.t.Errorf("ListUserCertificateOrder OrderType = %q", q.Get("OrderType"))
	}
	size, _ := strconv.Atoi(q.Get("ShowSize"))
	page, _ := strconv.Atoi(q.Get("CurrentPage"))
	if size != 100 || page < 1 {
		f.t.Errorf("ListUserCertificateOrder page %q size %q", q.Get("CurrentPage"), q.Get("ShowSize"))
		size, page = 100, 1
	}
	body := map[string]any{"TotalCount": len(f.certs), "CurrentPage": page, "ShowSize": size, "RequestId": "r"}
	start := min((page-1)*size, len(f.certs))
	end := min(start+size, len(f.certs))
	if end > start {
		body["CertificateOrderList"] = f.certs[start:end]
	}
	return 200, body
}

func (f *casFake) upload(q url.Values) (int, any) {
	f.uploads = append(f.uploads, q)
	for _, c := range f.certs {
		if c["Name"] == q.Get("Name") {
			return 400, apiErr("NameRepeat", "name repeat")
		}
	}
	if f.zeroID {
		return 200, map[string]any{"RequestId": "r"}
	}
	id := f.nextID
	f.nextID++
	f.add(id, q.Get("Name"), "2027-02-01")
	return 200, map[string]any{"CertId": id, "RequestId": "r", "ResourceId": fmt.Sprintf("cas-upload-%d", id)}
}

func (f *casFake) delete(q url.Values) (int, any) {
	id := q.Get("CertId")
	if code := f.failDelete[id]; code != "" {
		return 400, apiErr(code, "refused")
	}
	for i, c := range f.certs {
		if fmt.Sprint(c["CertificateId"]) == id {
			f.deletes = append(f.deletes, id)
			f.certs = append(f.certs[:i], f.certs[i+1:]...)
			return 200, map[string]any{"RequestId": "r"}
		}
	}
	return 400, apiErr("NotFound", "not found")
}

func TestCASStoreFollowsTheRegion(t *testing.T) {
	for _, tc := range []struct {
		region, casRegion, endpoint, listener string
	}{
		{"cn-hongkong", "ap-southeast-1", "cas.ap-southeast-1.aliyuncs.com", "1234567-ap-southeast-1"},
		{"cn-hangzhou", "", "cas.aliyuncs.com", "1234567"},
		{"cn-shanghai", "", "cas.aliyuncs.com", "1234567"},
		{"ap-southeast-1", "", "cas.aliyuncs.com", "1234567"},
	} {
		c := newClient(tc.region, "id", "secret")
		s, err := c.cas()
		if err != nil || s.Region != tc.casRegion || s.Endpoint != tc.endpoint {
			t.Errorf("%s: cas = %+v, %v", tc.region, s, err)
		}
		if got := listenerCertID(s.Region, "1234567"); got != tc.listener {
			t.Errorf("%s: listener certificate id = %q", tc.region, got)
		}
	}
	// config.yaml wins over the mapping.
	c := newClient("cn-hongkong", "id", "secret")
	settings := map[string]string{"cas_endpoint": "cas.example.test"}
	c.SetSettings(func(key string) (string, error) { return settings[key], nil })
	if s, _ := c.cas(); s.Region != "ap-southeast-1" || s.Endpoint != "cas.example.test" {
		t.Errorf("endpoint override = %+v", s)
	}
	settings = map[string]string{"cas_region": "cn-hangzhou"}
	if s, _ := c.cas(); s.Region != "cn-hangzhou" || s.Endpoint != "cas.aliyuncs.com" || listenerCertID(s.Region, "7") != "7" {
		t.Errorf("region override = %+v", s)
	}
	settings = map[string]string{"cas_region": "ap-southeast-1"}
	c.region = "cn-shanghai"
	if s, _ := c.cas(); s.Endpoint != "cas.ap-southeast-1.aliyuncs.com" {
		t.Errorf("region override endpoint = %+v", s)
	}
	c.SetSettings(func(string) (string, error) { return "", errors.New("bad config") })
	if _, err := c.cas(); err == nil {
		t.Error("a settings error is returned")
	}

	for in, want := range map[string]string{"1234567-ap-southeast-1": "1234567", "1234567": "1234567", " 42-cn-hangzhou ": "42"} {
		if got := casIDOfListenerCert(in); got != want {
			t.Errorf("casIDOfListenerCert(%q) = %q", in, got)
		}
	}
	na := time.Date(2027, 2, 1, 16, 8, 0, 0, time.UTC)
	if got := casCertName("Example.com", na); got != "upload_example.com_2027-02-01" {
		t.Errorf("casCertName = %q", got)
	}
	// NotAfter is taken in UTC, like the EndDate of CAS.
	if got := casCertName("example.com", na.In(time.FixedZone("UTC+8", 8*3600))); got != "upload_example.com_2027-02-01" {
		t.Errorf("casCertName in another zone = %q", got)
	}
}

func TestCASListPaginatesAndMaps(t *testing.T) {
	api := newFakeAPI(t)
	f := newCASFake(t, api)
	for i := range 250 {
		f.add(int64(1000+i), fmt.Sprintf("cert-%03d", i), "2027-02-01")
	}
	f.certs[249]["EndDate"] = ""
	certs, s, err := api.client().listCASCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 250 || len(api.callsFor("ListUserCertificateOrder")) != 3 {
		t.Fatalf("%d certificates in %d pages", len(certs), len(api.callsFor("ListUserCertificateOrder")))
	}
	if s.Endpoint != "cas.aliyuncs.com" {
		t.Errorf("scope = %+v", s)
	}
	want := casCertificate{ID: "1000", Name: "cert-000", CommonName: "example.com", StartDate: "2026-11-03", EndDate: "2027-02-01", NotAfter: "2027-02-01",
		Fingerprint: "FEFD0123456789ABCDEF0123456789ABCDEF0123", Sans: "example.com,www.example.com", SerialNo: "0a1b", Endpoint: "cas.aliyuncs.com", Source: "cas"}
	if certs[0] != want {
		t.Errorf("first = %+v", certs[0])
	}
	now := time.Date(2026, 11, 17, 23, 0, 0, 0, time.UTC)
	if d := certs[0].daysToExpire(now); d != 76 || certs[0].expired(now) {
		t.Errorf("days = %d, expired %v", d, certs[0].expired(now))
	}
	// An empty EndDate is today: 0 days, expired.
	if d := certs[249].daysToExpire(now); d != 0 || !certs[249].expired(now) {
		t.Errorf("empty end date: days = %d, expired %v", d, certs[249].expired(now))
	}
	// The last day counts as expired (from 00:00 UTC of EndDate on).
	last := casCertificate{EndDate: "2026-11-17"}
	if !last.expired(now) || last.daysToExpire(now) != 0 {
		t.Error("a certificate is expired on its EndDate")
	}
	if (casCertificate{EndDate: "2026-11-18"}).expired(now) {
		t.Error("a certificate is not expired the day before its EndDate")
	}
}

// An empty store has no CertificateOrderList and no TotalCount pages.
func TestCASListEmpty(t *testing.T) {
	api := newFakeAPI(t)
	newCASFake(t, api)
	certs, _, err := api.client().listCASCertificates(context.Background())
	if err != nil || len(certs) != 0 || len(api.callsFor("ListUserCertificateOrder")) != 1 {
		t.Fatalf("certs = %v, %v", certs, err)
	}
}

func TestCASErrorMapping(t *testing.T) {
	api := newFakeAPI(t)
	f := newCASFake(t, api)
	c := api.client()
	ctx := context.Background()
	for _, tc := range []struct {
		code   string
		status int
		want   error
	}{
		{"API.Forbidden", 400, platform.ErrNotSupported},
		{"NoPermission", 403, platform.ErrForbidden},
		{"SomethingElse", 403, platform.ErrForbidden},
		{"InvalidAccessKeyId.NotFound", 404, platform.ErrUnauthorized},
	} {
		f.failList, f.failStatus = tc.code, tc.status
		_, _, err := c.listCASCertificates(ctx)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.code, err, tc.want)
		}
		if tc.code == "API.Forbidden" && !strings.Contains(err.Error(), "cas_endpoint") {
			t.Errorf("API.Forbidden names the setting: %v", err)
		}
		if tc.want == platform.ErrForbidden && !strings.Contains(err.Error(), "yundun-cert") {
			t.Errorf("a denial names the permission: %v", err)
		}
	}
	f.failList = ""
	if err := c.deleteCASCertificate(ctx, "123"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("delete of a missing id = %v", err)
	}
	if err := c.deleteCASCertificate(ctx, "12x"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("delete of a malformed id = %v", err)
	}
	api.on("UploadUserCertificate", func(url.Values) (int, any) {
		return 400, apiErr("NotMatch.CertificateAndPrivateKey", "mismatch")
	})
	if _, err := c.uploadCASCertificate(ctx, "n", "c", "k"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("mismatched key = %v", err)
	}
}

func TestCASUploadSendsThePEMInTheBody(t *testing.T) {
	api := newFakeAPI(t)
	f := newCASFake(t, api)
	c := api.client()
	id, err := c.uploadCASCertificate(context.Background(), "upload_example.com_2027-02-01", "CERT PEM", "KEY PEM")
	if err != nil || id != "9000001" {
		t.Fatalf("upload = %q, %v", id, err)
	}
	q := f.uploads[0]
	if q.Get("Name") != "upload_example.com_2027-02-01" || q.Get("Cert") != "CERT PEM" || q.Get("Key") != "KEY PEM" || q.Get("PrivateKey") != "" {
		t.Errorf("upload = %v", q)
	}
	f.zeroID = true
	if _, err := c.uploadCASCertificate(context.Background(), "other", "c", "k"); err == nil || errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("CertId 0 = %v", err)
	}
}

func TestCASReferencesReadEveryHTTPSListener(t *testing.T) {
	api := newFakeAPI(t)
	f := &albFake{
		lbs: map[string][]map[string]any{
			"cn-hongkong": {{"LoadBalancerId": "alb-hk1", "LoadBalancerName": "lb-one"}, {"LoadBalancerId": "alb-hk2", "LoadBalancerName": "lb-two"}},
			"cn-shanghai": {{"LoadBalancerId": "alb-sh1", "LoadBalancerName": "lb-sh"}},
		},
		listeners: map[string][]map[string]any{
			"alb-hk1": {
				{"ListenerId": "lsn-http", "ListenerProtocol": "HTTP", "ListenerPort": 80},
				{"ListenerId": "lsn-https", "ListenerProtocol": "HTTPS", "ListenerPort": 443},
			},
			"alb-hk2": {{"ListenerId": "lsn-quic", "ListenerProtocol": "QUIC", "ListenerPort": 443}},
			"alb-sh1": {{"ListenerId": "lsn-sh", "ListenerProtocol": "HTTPS", "ListenerPort": 443}},
		},
		certs: map[string][]string{
			"lsn-https": {"1234567-ap-southeast-1"},
			"lsn-quic":  {"1234567-ap-southeast-1", "7777"},
			"lsn-sh":    {"1234567"},
		},
	}
	f.install(api)
	c := api.client()
	ctx := context.Background()
	refs, err := c.casCertificateInUse(ctx, "1234567", []string{"cn-shanghai", "cn-hongkong", "cn-hongkong"})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 3 {
		t.Fatalf("refs = %+v", refs)
	}
	got := map[string]casReference{}
	for _, r := range refs {
		got[r.ListenerID] = r
	}
	if r := got["lsn-https"]; r.LoadBalancerName != "lb-one" || r.Region != "cn-hongkong" || r.ListenerCertID != "1234567-ap-southeast-1" ||
		r.String() != "listener lsn-https of load balancer lb-one (cn-hongkong)" {
		t.Errorf("https ref = %+v", r)
	}
	if r := got["lsn-sh"]; r.ListenerCertID != "1234567" || r.Region != "cn-shanghai" {
		t.Errorf("bare id ref = %+v", r)
	}
	if n := len(api.callsFor("GetListenerAttribute")); n != 3 {
		t.Errorf("GetListenerAttribute called %d times: HTTP listeners are not read", n)
	}
	// Without regions, every region of the account (DescribeRegions).
	if _, err := c.casCertificateInUse(ctx, "7777", nil); err != nil || len(api.callsFor("DescribeRegions")) != 1 {
		t.Errorf("all regions: %v, DescribeRegions %d", err, len(api.callsFor("DescribeRegions")))
	}

	// A region that cannot be read fails the check; a denial keeps its
	// exit code.
	f.fail = map[string]string{"cn-shanghai": "Forbidden.LoadBalancer"}
	_, err = c.casCertificateInUse(ctx, "1234567", []string{"cn-hongkong", "cn-shanghai"})
	var ce *casCheckError
	if !errors.As(err, &ce) || !errors.Is(err, platform.ErrForbidden) || !strings.Contains(err.Error(), "cn-shanghai") || !strings.Contains(err.Error(), "--force") {
		t.Errorf("forbidden region = %v", err)
	}
	f.fail = map[string]string{"cn-shanghai": "ServiceUnavailable"}
	_, err = c.casCertificateInUse(ctx, "1234567", []string{"cn-shanghai"})
	if !errors.As(err, &ce) || errors.Is(err, platform.ErrForbidden) {
		t.Errorf("failed region = %v", err)
	}
}
