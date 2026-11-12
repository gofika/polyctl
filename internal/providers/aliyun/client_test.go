package aliyun

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/domain"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// fakeAPI is an httptest server that answers Alibaba Cloud RPC actions.
type fakeAPI struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	handlers map[string]func(q url.Values) (int, any)
	calls    []url.Values
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{t: t, handlers: map[string]func(q url.Values) (int, any){}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.calls = append(f.calls, q)
		h := f.handlers[q.Get("Action")]
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if h == nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"Code": "InvalidAction.NotFound", "Message": "no handler for " + q.Get("Action")})
			return
		}
		status, body := h(q)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) on(action string, h func(q url.Values) (int, any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[action] = h
}

func (f *fakeAPI) callsFor(action string) []url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []url.Values
	for _, c := range f.calls {
		if c.Get("Action") == action {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeAPI) client() *client {
	u, _ := url.Parse(f.srv.URL)
	c := newClient("cn-hangzhou", "LTAItestkeyid000", "testsecret")
	c.endpoint = u.Host
	c.scheme = "http"
	return c
}

func apiErr(code, msg string) map[string]string {
	return map[string]string{"Code": code, "Message": msg, "RequestId": "req-1"}
}

func TestListZonesPaginatesAndMaps(t *testing.T) {
	f := newFakeAPI(t)
	f.on("DescribeDomains", func(q url.Values) (int, any) {
		page, _ := strconv.Atoi(q.Get("PageNumber"))
		if q.Get("PageSize") != "100" {
			t.Errorf("PageSize = %q, want 100", q.Get("PageSize"))
		}
		var domains []map[string]any
		start, end := (page-1)*100, page*100
		if end > 150 {
			end = 150
		}
		for i := start; i < end; i++ {
			domains = append(domains, map[string]any{
				"DomainName": fmt.Sprintf("Zone%d.Example.com", i), "DomainId": fmt.Sprint(i), "RecordCount": i,
				"VersionCode": "mianfei", "VersionName": "Free",
				"DnsServers": map[string]any{"DnsServer": []string{"dns1.hichina.com", "dns2.hichina.com"}},
			})
		}
		return 200, map[string]any{"TotalCount": 150, "PageNumber": page, "PageSize": 100, "Domains": map[string]any{"Domain": domains}}
	})
	zones, err := f.client().ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 150 {
		t.Fatalf("got %d zones, want 150", len(zones))
	}
	if n := len(f.callsFor("DescribeDomains")); n != 2 {
		t.Fatalf("DescribeDomains called %d times, want 2", n)
	}
	z := zones[0]
	if z.ID != "zone0.example.com" || z.Name != "zone0.example.com" {
		t.Errorf("zone id/name = %q/%q, want normalized zone0.example.com", z.ID, z.Name)
	}
	if z.Status != "mianfei" || len(z.Nameservers) != 2 || z.Extra["domain_id"] != "0" {
		t.Errorf("unexpected zone mapping: %+v", z)
	}
	if f.callsFor("DescribeDomains")[0].Get("AccessKeyId") != "LTAItestkeyid000" {
		t.Errorf("request was not signed with the profile key")
	}
}

func recordsHandler(t *testing.T) func(q url.Values) (int, any) {
	return func(q url.Values) (int, any) {
		if q.Get("DomainName") != "example.com" {
			t.Errorf("DomainName = %q, want example.com", q.Get("DomainName"))
		}
		switch q.Get("PageNumber") {
		case "1":
			var recs []map[string]any
			for i := 0; i < 100; i++ {
				recs = append(recs, map[string]any{"RecordId": fmt.Sprint(1000 + i), "RR": fmt.Sprintf("h%d", i), "Type": "A", "Value": "10.0.0.1", "TTL": 600, "DomainName": "example.com", "Status": "ENABLE", "Line": "default"})
			}
			return 200, map[string]any{"TotalCount": 103, "DomainRecords": map[string]any{"Record": recs}}
		case "2":
			return 200, map[string]any{"TotalCount": 103, "DomainRecords": map[string]any{"Record": []map[string]any{
				{"RecordId": "1", "RR": "@", "Type": "A", "Value": "1.2.3.4", "TTL": 600, "DomainName": "example.com", "Status": "ENABLE", "Line": "default"},
				{"RecordId": "2", "RR": "www", "Type": "CNAME", "Value": "example.com", "TTL": 300, "DomainName": "example.com", "Status": "ENABLE", "Line": "default", "Locked": true},
				{"RecordId": "3", "RR": "@", "Type": "MX", "Value": "mx.example.com", "TTL": 600, "Priority": 10, "DomainName": "example.com", "Status": "ENABLE", "Line": "default"},
			}}}
		}
		t.Errorf("unexpected page %q", q.Get("PageNumber"))
		return 400, apiErr("InvalidParameter", "page")
	}
}

func TestListRecordsFQDNAndPriority(t *testing.T) {
	f := newFakeAPI(t)
	f.on("DescribeDomainRecords", recordsHandler(t))
	recs, err := f.client().ListRecords(context.Background(), "Example.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 103 {
		t.Fatalf("got %d records, want 103", len(recs))
	}
	byID := map[string]platform.Record{}
	for _, r := range recs {
		byID[r.ID] = r
	}
	if r := byID["1"]; r.Name != "example.com" || r.Type != "A" || r.Content != "1.2.3.4" || r.TTL != 600 || r.Priority != nil {
		t.Errorf("apex record mapped wrong: %+v", r)
	}
	if r := byID["2"]; r.Name != "www.example.com" || r.Extra["locked"] != true || r.ZoneID != "example.com" {
		t.Errorf("www record mapped wrong: %+v", r)
	}
	if r := byID["3"]; r.Priority == nil || *r.Priority != 10 || r.Content != "mx.example.com" {
		t.Errorf("MX record should carry priority separately: %+v", r)
	}
	if r := byID["1050"]; r.Name != "h50.example.com" {
		t.Errorf("paged record mapped wrong: %+v", r)
	}
}

func TestCreateUpdateDeleteRecord(t *testing.T) {
	f := newFakeAPI(t)
	var added url.Values
	f.on("AddDomainRecord", func(q url.Values) (int, any) {
		added = q
		return 200, map[string]any{"RecordId": "9001"}
	})
	f.on("DescribeDomainRecordInfo", func(q url.Values) (int, any) {
		return 200, map[string]any{"RecordId": q.Get("RecordId"), "RR": "@", "Type": "MX", "Value": "mx.example.com", "TTL": 600, "Priority": 20, "DomainName": "example.com", "Status": "ENABLE", "Line": "default"}
	})
	c := f.client()
	prio := 20
	out, err := c.CreateRecord(context.Background(), "example.com", platform.Record{Name: "example.com", Type: "mx", Content: "mx.example.com", Priority: &prio})
	if err != nil {
		t.Fatal(err)
	}
	if added.Get("RR") != "@" || added.Get("Type") != "MX" || added.Get("Priority") != "20" || added.Get("DomainName") != "example.com" {
		t.Errorf("AddDomainRecord params wrong: %v", added)
	}
	if added.Get("TTL") != "" {
		t.Errorf("TTL should be omitted when zero, got %q", added.Get("TTL"))
	}
	if out.ID != "9001" || out.Name != "example.com" || out.Priority == nil || *out.Priority != 20 {
		t.Errorf("created record wrong: %+v", out)
	}

	var updated url.Values
	f.on("UpdateDomainRecord", func(q url.Values) (int, any) {
		updated = q
		return 200, map[string]any{"RecordId": q.Get("RecordId")}
	})
	f.on("DescribeDomainRecordInfo", func(q url.Values) (int, any) {
		return 400, apiErr("DomainRecordNotBelongToUser", "simulated read failure")
	})
	out, err = c.UpdateRecord(context.Background(), "example.com", platform.Record{ID: "9001", Name: "www.example.com", Type: "A", Content: "5.6.7.8", Extra: map[string]any{"line": "telecom"}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Get("RecordId") != "9001" || updated.Get("RR") != "www" || updated.Get("TTL") != "600" || updated.Get("Line") != "telecom" {
		t.Errorf("UpdateDomainRecord params wrong: %v", updated)
	}
	if out.ID != "9001" || out.Name != "www.example.com" || out.TTL != 600 || out.Extra["line"] != "telecom" {
		t.Errorf("reconstructed record wrong: %+v", out)
	}

	f.on("DeleteDomainRecord", func(q url.Values) (int, any) {
		if q.Get("RecordId") != "9001" {
			return 400, apiErr("DomainRecordNotBelongToUser", "wrong id")
		}
		return 200, map[string]any{"RecordId": "9001"}
	})
	if err := c.DeleteRecord(context.Background(), "example.com", "9001"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateRecord(context.Background(), "example.com", platform.Record{Name: "x.example.com"}); err == nil {
		t.Error("UpdateRecord without id should fail")
	}
}

func TestErrorMapping(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client()
	cases := []struct {
		status int
		code   string
		want   error
	}{
		// RAM policy denials are not authentication failures: no sentinel.
		{403, "Forbidden.RAM", nil},
		{403, "NoPermission.Domain", nil},
		{403, "AccessDenied", nil},
		{404, "InvalidAccessKeyId.NotFound", platform.ErrUnauthorized},
		{401, "", platform.ErrUnauthorized},
		{400, "SignatureDoesNotMatch", platform.ErrUnauthorized},
		{400, "InvalidDomainName.NoExist", platform.ErrNotFound},
		{404, "InvalidInstanceId.NotFound", platform.ErrNotFound},
		{400, "Throttling.User", nil},
	}
	for _, tc := range cases {
		f.on("DescribeDomains", func(q url.Values) (int, any) { return tc.status, apiErr(tc.code, "message for "+tc.code) })
		_, err := c.ListZones(context.Background())
		if err == nil {
			t.Fatalf("%s: expected error", tc.code)
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: error %v does not wrap %v", tc.code, err, tc.want)
		}
		if tc.want == nil && (errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrNotFound)) {
			t.Errorf("%s: should not map to a sentinel: %v", tc.code, err)
		}
		if !strings.Contains(err.Error(), tc.code) || !strings.Contains(err.Error(), "alidns DescribeDomains") {
			t.Errorf("%s: message should carry action and code: %v", tc.code, err)
		}
		if strings.Contains(err.Error(), "testsecret") {
			t.Errorf("error message leaks the secret: %v", err)
		}
	}
}

func TestSyncReportsRegistrarForbidden(t *testing.T) {
	f := newFakeAPI(t)
	c := f.client()
	f.on("QueryDomainList", func(q url.Values) (int, any) { return 403, apiErr("Forbidden.RAM", "User not authorized") })
	res, err := c.Sync(context.Background(), platform.ResDomain)
	if err == nil || res != nil {
		t.Fatalf("Sync(domain) with forbidden registrar = %v, %v; want nil, error", res, err)
	}
	if errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "Forbidden.RAM") {
		t.Errorf("RAM denial must be a plain API error carrying the code, got %v", err)
	}
	if _, err := c.ListDomains(context.Background()); err == nil || errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("explicit ListDomains should surface a plain error, got %v", err)
	}
	f.on("QueryDomainList", func(q url.Values) (int, any) { return 400, apiErr("InvalidAccessKeyId.NotFound", "bad key") })
	if _, err := c.Sync(context.Background(), platform.ResDomain); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("authentication failure must map to ErrUnauthorized, got %v", err)
	}
	if _, err := c.Sync(context.Background(), platform.ResourceType("bucket")); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("unsupported type = %v, want ErrNotSupported", err)
	}
}

func TestSyncRecordsCoversEveryZone(t *testing.T) {
	f := newFakeAPI(t)
	f.on("DescribeDomains", func(q url.Values) (int, any) {
		return 200, map[string]any{"TotalCount": 2, "Domains": map[string]any{"Domain": []map[string]any{{"DomainName": "a.com"}, {"DomainName": "b.com"}}}}
	})
	f.on("DescribeDomainRecords", func(q url.Values) (int, any) {
		return 200, map[string]any{"TotalCount": 1, "DomainRecords": map[string]any{"Record": []map[string]any{
			{"RecordId": "r-" + q.Get("DomainName"), "RR": "www", "Type": "A", "Value": "1.1.1.1", "TTL": 600, "DomainName": q.Get("DomainName")},
		}}}
	})
	res, err := f.client().Sync(context.Background(), platform.ResDNSRecord)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d resources, want 2", len(res))
	}
	for _, r := range res {
		if r.Type != platform.ResDNSRecord || r.ParentID != r.Domain || r.ParentID == "" || !strings.HasSuffix(r.Name, "."+r.Domain) {
			t.Errorf("bad record resource: %+v", r)
		}
	}
	zones, err := f.client().Sync(context.Background(), platform.ResZone)
	if err != nil || len(zones) != 2 || zones[0].Domain != "a.com" || zones[0].Type != platform.ResZone {
		t.Errorf("Sync(zone) = %+v, %v", zones, err)
	}
}

func TestRegistrarPaginationAndMapping(t *testing.T) {
	f := newFakeAPI(t)
	f.on("QueryDomainList", func(q url.Values) (int, any) {
		page, _ := strconv.Atoi(q.Get("PageNum"))
		return 200, map[string]any{
			"TotalPageNum": 2, "CurrentPageNum": page, "NextPage": page < 2, "TotalItemNum": 2,
			"Data": map[string]any{"Domain": []map[string]any{{
				"DomainName": fmt.Sprintf("D%d.example", page), "DomainStatus": "3", "ExpirationDate": "2030-01-01 00:00:00",
				"RegistrantType": "1", "Premium": false, "DnsList": map[string]any{"Dns": []string{"ns1.x", "ns2.x"}},
			}}},
		}
	})
	domains, err := f.client().ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[1].Name != "d2.example" || domains[0].Status != "normal" || len(domains[0].Nameservers) != 2 || domains[0].ExpiresAt != "2030-01-01 00:00:00" {
		t.Errorf("domains = %+v", domains)
	}
	f.on("QueryDomainByDomainName", func(q url.Values) (int, any) {
		if q.Get("DomainName") != "d1.example" {
			return 400, apiErr("InvalidDomainName.NoExist", "no such domain")
		}
		return 200, map[string]any{"DomainName": "d1.example", "DomainStatus": "1", "TransferProhibitionLock": "OPEN", "DomainNameProxyService": true, "ExpirationDate": "2030-01-01 00:00:00", "DnsList": map[string]any{"Dns": []string{"ns1.x"}}}
	})
	d, err := f.client().GetDomain(context.Background(), "D1.example")
	if err != nil {
		t.Fatal(err)
	}
	if d.Locked == nil || !*d.Locked || d.Privacy == nil || !*d.Privacy || d.Status != "renewal required" {
		t.Errorf("detail mapping wrong: %+v", d)
	}
	if _, err := f.client().GetDomain(context.Background(), "nope.example"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing domain = %v, want ErrNotFound", err)
	}
	shortTaskWait(t)
	var task url.Values
	f.on("SaveBatchTaskForModifyingDomainDns", func(q url.Values) (int, any) { task = q; return 200, map[string]any{"TaskNo": "t1"} })
	polls := 0
	f.on("QueryTaskDetailList", func(q url.Values) (int, any) {
		if q.Get("TaskNo") != "t1" || q.Get("DomainName") != "d1.example" {
			t.Errorf("QueryTaskDetailList params wrong: %v", q)
		}
		polls++
		status, code := "EXECUTING", 1
		if polls >= 3 {
			status, code = "EXECUTE_SUCCESS", 2
		}
		return 200, map[string]any{"TotalItemNum": 1, "Data": map[string]any{"TaskDetail": []map[string]any{
			{"TaskNo": "t1", "DomainName": "d1.example", "TaskStatus": status, "TaskStatusCode": code, "TaskType": "MODIFY_DOMAIN_DNS"},
		}}}
	})
	if err := f.client().SetNameservers(context.Background(), "d1.example", []string{"NS1.Example.net.", "ns2.example.net"}); err != nil {
		t.Fatal(err)
	}
	if task.Get("DomainName.1") != "d1.example" || task.Get("DomainNameServer.1") != "ns1.example.net" || task.Get("DomainNameServer.2") != "ns2.example.net" || task.Get("AliyunDns") != "false" {
		t.Errorf("SaveBatchTaskForModifyingDomainDns params wrong: %v", task)
	}
	if polls != 3 {
		t.Errorf("task polled %d times, want 3 (until EXECUTE_SUCCESS)", polls)
	}
	if err := f.client().SetNameservers(context.Background(), "d1.example", nil); err == nil {
		t.Error("empty nameserver list should fail")
	}
}

// shortTaskWait makes SetNameservers poll quickly and give up fast.
func shortTaskWait(t *testing.T) {
	t.Helper()
	oldT, oldI := nsTaskTimeout, nsTaskInterval
	nsTaskTimeout, nsTaskInterval = 200*time.Millisecond, time.Millisecond
	t.Cleanup(func() { nsTaskTimeout, nsTaskInterval = oldT, oldI })
}

func TestSetNameserversTaskFailureAndTimeout(t *testing.T) {
	f := newFakeAPI(t)
	shortTaskWait(t)
	f.on("SaveBatchTaskForModifyingDomainDns", func(q url.Values) (int, any) { return 200, map[string]any{"TaskNo": "t2"} })
	f.on("QueryTaskDetailList", func(q url.Values) (int, any) {
		return 200, map[string]any{"Data": map[string]any{"TaskDetail": []map[string]any{
			{"TaskNo": "t2", "DomainName": "d1.example", "TaskStatus": "EXECUTE_FAILURE", "TaskStatusCode": 3, "FailReason": "invalid dns host ns1.example.net"},
		}}}
	})
	err := f.client().SetNameservers(context.Background(), "d1.example", []string{"ns1.example.net"})
	if err == nil || !strings.Contains(err.Error(), "invalid dns host") || errors.Is(err, ErrTaskPending) {
		t.Errorf("failed task should surface FailReason, got %v", err)
	}

	// Never completes: a distinct pending error names the task.
	f.on("QueryTaskDetailList", func(q url.Values) (int, any) {
		return 200, map[string]any{"Data": map[string]any{"TaskDetail": []map[string]any{
			{"TaskNo": "t2", "DomainName": "d1.example", "TaskStatus": "WAITING_EXECUTE", "TaskStatusCode": 0},
		}}}
	})
	err = f.client().SetNameservers(context.Background(), "d1.example", []string{"ns1.example.net"})
	if !errors.Is(err, ErrTaskPending) || !strings.Contains(err.Error(), "t2") {
		t.Errorf("timeout = %v, want ErrTaskPending naming the task", err)
	}

	// Task list not visible yet, then success.
	seen := 0
	f.on("QueryTaskDetailList", func(q url.Values) (int, any) {
		seen++
		if seen == 1 {
			return 200, map[string]any{"Data": map[string]any{"TaskDetail": []map[string]any{}}}
		}
		return 200, map[string]any{"Data": map[string]any{"TaskDetail": []map[string]any{
			{"TaskNo": "t2", "DomainName": "d1.example", "TaskStatus": "EXECUTE_SUCCESS", "TaskStatusCode": 2},
		}}}
	})
	if err := f.client().SetNameservers(context.Background(), "d1.example", []string{"ns1.example.net"}); err != nil {
		t.Errorf("late task should succeed, got %v", err)
	}

	// Cancelled context stops the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.on("QueryTaskDetailList", func(q url.Values) (int, any) {
		return 200, map[string]any{"Data": map[string]any{"TaskDetail": []map[string]any{
			{"TaskNo": "t2", "DomainName": "d1.example", "TaskStatus": "EXECUTING", "TaskStatusCode": 1},
		}}}
	})
	if err := f.client().SetNameservers(ctx, "d1.example", []string{"ns1.example.net"}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled wait = %v, want context.Canceled", err)
	}

	// No task number: cannot confirm, reported as pending.
	f.on("SaveBatchTaskForModifyingDomainDns", func(q url.Values) (int, any) { return 200, map[string]any{} })
	if err := f.client().SetNameservers(context.Background(), "d1.example", []string{"ns1.example.net"}); !errors.Is(err, ErrTaskPending) {
		t.Errorf("missing TaskNo = %v, want ErrTaskPending", err)
	}
}

func TestRegistrarEndpointFollowsSite(t *testing.T) {
	cases := []struct {
		region, site string
		wantRegion   string
		wantHost     string
	}{
		{"cn-hangzhou", "", domainRegionCN, endpointDomainCN},
		{"cn-shenzhen", "", domainRegionCN, endpointDomainCN},
		{"ap-southeast-1", "", domainRegionIntl, endpointDomainIntl},
		{"us-west-1", "", domainRegionIntl, endpointDomainIntl},
		{"eu-central-1", "", domainRegionIntl, endpointDomainIntl},
		{"cn-hangzhou", siteIntl, domainRegionIntl, endpointDomainIntl},
		{"ap-southeast-1", siteCN, domainRegionCN, endpointDomainCN},
	}
	for _, tc := range cases {
		c := newClient(tc.region, "k", "s")
		c.site = tc.site
		region, host := c.registrarEndpoint()
		if region != tc.wantRegion || host != tc.wantHost {
			t.Errorf("region %s site %q: endpoint = %s/%s, want %s/%s", tc.region, tc.site, region, host, tc.wantRegion, tc.wantHost)
		}
		req := domainRequestFor(c)
		if req.GetDomain() != tc.wantHost || req.GetScheme() != "https" {
			t.Errorf("region %s site %q: request host = %s://%s, want https://%s", tc.region, tc.site, req.GetScheme(), req.GetDomain(), tc.wantHost)
		}
	}
	// The DNS/STS/ECS endpoints are not affected by the site.
	c := newClient("ap-southeast-1", "k", "s")
	if _, host := c.registrarEndpoint(); host != endpointDomainIntl {
		t.Fatal("intl client expected")
	}

	// Through the fake: the signed RegionId of registrar calls follows the site.
	f := newFakeAPI(t)
	var seen string
	f.on("QueryDomainByDomainName", func(q url.Values) (int, any) {
		seen = q.Get("RegionId")
		return 200, map[string]any{"DomainName": "d.example", "DomainStatus": "3"}
	})
	intl := f.client()
	intl.region = "ap-southeast-1"
	if _, err := intl.GetDomain(context.Background(), "d.example"); err != nil {
		t.Fatal(err)
	}
	if seen != domainRegionIntl {
		t.Errorf("intl profile signed registrar call with RegionId %q, want %s", seen, domainRegionIntl)
	}
	if _, err := f.client().GetDomain(context.Background(), "d.example"); err != nil {
		t.Fatal(err)
	}
	if seen != domainRegionCN {
		t.Errorf("cn profile signed registrar call with RegionId %q, want %s", seen, domainRegionCN)
	}
}

// domainRequestFor builds a routed registrar request of a client (no override).
func domainRequestFor(c *client) *domain.QueryDomainByDomainNameRequest {
	req := domain.CreateQueryDomainByDomainNameRequest()
	c.routeRegistrar(req)
	return req
}

func TestListInstancesMapping(t *testing.T) {
	f := newFakeAPI(t)
	f.on("DescribeInstances", func(q url.Values) (int, any) {
		if q.Get("RegionId") != "cn-shanghai" {
			t.Errorf("RegionId = %q, want cn-shanghai", q.Get("RegionId"))
		}
		return 200, map[string]any{"TotalCount": 1, "Instances": map[string]any{"Instance": []map[string]any{{
			"InstanceId": "i-1", "InstanceName": "web", "Status": "Running", "InstanceType": "ecs.g6.large", "ZoneId": "cn-shanghai-b", "RegionId": "cn-shanghai",
			"CreationTime": "2024-01-01T00:00Z", "OSNameEn": "Ubuntu", "Cpu": 2, "Memory": 8192,
			"VpcAttributes": map[string]any{"PrivateIpAddress": map[string]any{"IpAddress": []string{"172.16.0.5"}}},
			"EipAddress":    map[string]any{"IpAddress": "47.1.2.3"},
			"Tags":          map[string]any{"Tag": []map[string]any{{"TagKey": "env", "TagValue": "prod"}}},
		}}}}
	})
	res, err := f.client().ListInstances(context.Background(), "cn-shanghai")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Type != platform.ResInstance || res[0].ID != "i-1" || res[0].Name != "web" || res[0].ParentID != "cn-shanghai" {
		t.Fatalf("resource = %+v", res)
	}
	in := res[0].Data.(Instance)
	if in.PrivateIP != "172.16.0.5" || in.PublicIP != "47.1.2.3" || in.Tags["env"] != "prod" || in.CPU != 2 || in.MemoryMB != 8192 || in.OS != "Ubuntu" {
		t.Errorf("instance = %+v", in)
	}
	b, _ := json.Marshal(in)
	for _, k := range []string{`"id":"i-1"`, `"status":"Running"`, `"private_ip":"172.16.0.5"`, `"creation_time"`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Errorf("json %s lacks %s", b, k)
		}
	}
}

func TestVerifyAndContextCancel(t *testing.T) {
	f := newFakeAPI(t)
	f.on("GetCallerIdentity", func(q url.Values) (int, any) {
		return 200, map[string]any{"AccountId": "1234567890", "Arn": "acs:ram::1234567890:user/polyctl", "IdentityType": "RAMUser", "PrincipalId": "p1", "UserId": "u1"}
	})
	id, err := f.client().Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.Account != "1234567890" || id.User != "acs:ram::1234567890:user/polyctl" || id.Extra["identity_type"] != "RAMUser" {
		t.Errorf("identity = %+v", id)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.client().Verify(ctx); err == nil || !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context should abort with context.Canceled, got %v", err)
	}
	if _, err := f.client().ListZones(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled ListZones = %v", err)
	}
}

func writeCLIConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const cliConfigJSON = `{"current":"work","profiles":[
 {"name":"default","mode":"AK","access_key_id":"LTAIdefault00001","access_key_secret":"s-default","region_id":"cn-beijing"},
 {"name":"work","mode":"AK","access_key_id":"LTAIwork00000001","access_key_secret":"s-work","region_id":"cn-shenzhen"},
 {"name":"sso","mode":"RamRoleArn","access_key_id":"x","access_key_secret":"y","region_id":"cn-hangzhou"}]}`

func TestLoadCLIProfile(t *testing.T) {
	p := writeCLIConfig(t, cliConfigJSON)
	cp, err := loadCLIProfile(p, "current")
	if err != nil || cp.Name != "work" || cp.RegionID != "cn-shenzhen" {
		t.Fatalf("current profile = %+v, %v", cp, err)
	}
	if cp, err := loadCLIProfile(p, "default"); err != nil || cp.AccessKeyID != "LTAIdefault00001" {
		t.Errorf("default profile = %+v, %v", cp, err)
	}
	if _, err := loadCLIProfile(p, "sso"); err == nil || !strings.Contains(err.Error(), "RamRoleArn") {
		t.Errorf("non-AK profile should be rejected, got %v", err)
	}
	if _, err := loadCLIProfile(p, "missing"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing profile = %v, want ErrNotFound", err)
	}
	if _, err := loadCLIProfile(filepath.Join(t.TempDir(), "nope.json"), "default"); err == nil {
		t.Error("missing file should fail")
	}
}

// withFakeEndpoint routes clients created by Login to the fake server.
func withFakeEndpoint(t *testing.T, f *fakeAPI) {
	t.Helper()
	u, _ := url.Parse(f.srv.URL)
	endpointOverride, schemeOverride = u.Host, "http"
	t.Cleanup(func() { endpointOverride, schemeOverride = "", "" })
}

func TestLoginFromCLIVerifiesAndFillsMetadata(t *testing.T) {
	f := newFakeAPI(t)
	withFakeEndpoint(t, f)
	var seenKey string
	f.on("GetCallerIdentity", func(q url.Values) (int, any) {
		seenKey = q.Get("AccessKeyId")
		return 200, map[string]any{"AccountId": "42", "Arn": "acs:ram::42:user/dev", "IdentityType": "RAMUser"}
	})
	t.Setenv("ALIBABA_CLOUD_CLI_CONFIG", writeCLIConfig(t, cliConfigJSON))
	var stderr bytes.Buffer
	res, err := (&provider{}).Login(context.Background(), platform.LoginInput{
		ProfileName: "ali", Options: map[string]string{"from_cli": "work"},
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr, NoBrowser: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if seenKey != "LTAIwork00000001" {
		t.Errorf("verified with key %q", seenKey)
	}
	if res.Secret[secretKeyID] != "LTAIwork00000001" || res.Secret[secretKeySecret] != "s-work" {
		t.Errorf("secret = %v", res.Secret)
	}
	want := map[string]string{metaMethod: "access_key", metaRegion: "cn-shenzhen", metaAccountID: "42", metaPrincipal: "acs:ram::42:user/dev", metaKeyPrefix: "LTAIwork"}
	for k, v := range want {
		if res.Metadata[k] != v {
			t.Errorf("metadata[%s] = %q, want %q", k, res.Metadata[k], v)
		}
	}
	for _, v := range res.Metadata {
		if strings.Contains(v, "s-work") {
			t.Errorf("metadata leaks the secret: %v", res.Metadata)
		}
	}
	if strings.Contains(stderr.String(), "s-work") {
		t.Errorf("stderr leaks the secret: %s", stderr.String())
	}
	if !strings.Contains(res.Label, "acs:ram::42:user/dev") {
		t.Errorf("label = %q", res.Label)
	}
	// Region option wins over the CLI region.
	res, err = (&provider{}).Login(context.Background(), platform.LoginInput{
		Options: map[string]string{"from_cli": "default", "region": "us-west-1"},
		Stdin:   strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, NoBrowser: true,
	})
	if err != nil || res.Metadata[metaRegion] != "us-west-1" {
		t.Errorf("region override: %v, %v", res, err)
	}
	if _, ok := res.Metadata[metaSite]; ok {
		t.Errorf("site must not be recorded unless given: %v", res.Metadata)
	}
	// --set site=intl is validated and recorded.
	res, err = (&provider{}).Login(context.Background(), platform.LoginInput{
		Options: map[string]string{"from_cli": "default", "site": "INTL"},
		Stdin:   strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, NoBrowser: true,
	})
	if err != nil || res.Metadata[metaSite] != siteIntl {
		t.Errorf("site option: %v, %v", res, err)
	}
	if _, err := (&provider{}).Login(context.Background(), platform.LoginInput{
		Options: map[string]string{"from_cli": "default", "site": "eu"},
		Stdin:   strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, NoBrowser: true,
	}); err == nil {
		t.Error("invalid site option should be rejected")
	}
}

func TestLoginInteractiveRejectsBadKey(t *testing.T) {
	f := newFakeAPI(t)
	withFakeEndpoint(t, f)
	f.on("GetCallerIdentity", func(q url.Values) (int, any) {
		if q.Get("AccessKeyId") != "LTAIgood" {
			return 404, apiErr("InvalidAccessKeyId.NotFound", "Specified access key is not found.")
		}
		return 200, map[string]any{"AccountId": "7", "Arn": "acs:ram::7:user/ok"}
	})
	var stderr bytes.Buffer
	var opened []string
	t.Setenv(envKeyID, "")
	t.Setenv(envKeySecret, "")
	in := platform.LoginInput{
		Interactive: true,
		Stdin:       strings.NewReader("LTAIbad\nverysecret\n\n"), Stdout: &bytes.Buffer{}, Stderr: &stderr,
		OpenBrowser: func(u string) error { opened = append(opened, u); return errors.New("no browser") },
		Existing:    map[string]string{metaRegion: "cn-shanghai"},
	}
	_, err := (&provider{}).Login(context.Background(), in)
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("bad key should fail with ErrUnauthorized, got %v", err)
	}
	if len(opened) != 1 || opened[0] != accessKeyURL {
		t.Errorf("browser should have been opened once with %s, got %v", accessKeyURL, opened)
	}
	out := stderr.String()
	if !strings.Contains(out, accessKeyURL) || !strings.Contains(out, "AccessKey ID") || !strings.Contains(out, "[cn-shanghai]") {
		t.Errorf("prompts missing: %s", out)
	}
	if strings.Contains(out, "verysecret") {
		t.Errorf("stderr echoed the secret: %s", out)
	}

	opened = nil
	in.Stdin = strings.NewReader("LTAIgood\nverysecret\nap-southeast-1\n")
	in.NoBrowser = true
	res, err := (&provider{}).Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != 0 {
		t.Error("--no-browser must not open the browser")
	}
	if res.Metadata[metaRegion] != "ap-southeast-1" || res.Metadata[metaAccountID] != "7" || res.Secret[secretKeySecret] != "verysecret" {
		t.Errorf("result = %+v", res)
	}
}

func TestOpenRequiresSecret(t *testing.T) {
	p := &provider{}
	if _, err := p.Open(context.Background(), platform.Profile{Name: "x", Platform: platform.Aliyun}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("Open without secret = %v, want ErrUnauthorized", err)
	}
	c, err := p.Open(context.Background(), platform.Profile{Name: "x", Secret: map[string]string{secretKeyID: "a", secretKeySecret: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.(*client).region != DefaultRegion {
		t.Errorf("region = %q, want default", c.(*client).region)
	}
	c, _ = p.Open(context.Background(), platform.Profile{Name: "x", Metadata: map[string]string{metaRegion: "eu-central-1"}, Secret: map[string]string{secretKeyID: "a", secretKeySecret: "b"}})
	if c.(*client).region != "eu-central-1" {
		t.Errorf("region from metadata not used")
	}
	if _, host := c.(*client).registrarEndpoint(); host != endpointDomainIntl {
		t.Errorf("eu-central-1 profile should use the intl registrar, got %s", host)
	}
	c, _ = p.Open(context.Background(), platform.Profile{Name: "x", Metadata: map[string]string{metaRegion: "eu-central-1", metaSite: "cn"}, Secret: map[string]string{secretKeyID: "a", secretKeySecret: "b"}})
	if _, host := c.(*client).registrarEndpoint(); host != endpointDomainCN {
		t.Errorf("site=cn metadata should force the China registrar, got %s", host)
	}
	if _, err := p.Open(context.Background(), platform.Profile{Name: "x", Metadata: map[string]string{metaSite: "eu"}, Secret: map[string]string{secretKeyID: "a", secretKeySecret: "b"}}); err == nil {
		t.Error("invalid site metadata should fail to open")
	}
}

// refusingReader fails the test when the login reads stdin.
type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}

// The non-interactive flow asks nothing and reads nothing: the AccessKey
// comes from --set or the environment, a missing one is a usage error, and
// the region falls back to its default.
func TestLoginNonInteractiveNeverAsks(t *testing.T) {
	f := newFakeAPI(t)
	withFakeEndpoint(t, f)
	var seenKey string
	f.on("GetCallerIdentity", func(q url.Values) (int, any) {
		seenKey = q.Get("AccessKeyId")
		return 200, map[string]any{"AccountId": "42", "Arn": "acs:ram::42:user/dev", "IdentityType": "RAMUser"}
	})
	t.Setenv(envKeyID, "")
	t.Setenv(envKeySecret, "")
	login := func(opts, existing map[string]string) (*platform.LoginResult, string, int, error) {
		var stderr bytes.Buffer
		opened := 0
		res, err := (&provider{}).Login(context.Background(), platform.LoginInput{
			Options: opts, Existing: existing,
			Stdin: refusingReader{t}, Stdout: &bytes.Buffer{}, Stderr: &stderr,
			OpenBrowser: func(string) error { opened++; return nil },
		})
		return res, stderr.String(), opened, err
	}

	for _, tc := range []struct {
		name    string
		opts    map[string]string
		want    []string
		wantNot string
	}{
		{"nothing", nil, []string{"--set access_key_id=<id>", "--set access_key_secret=-", envKeyID, envKeySecret, "--set from_cli=<profile>"}, ""},
		{"no secret", map[string]string{"access_key_id": "LTAIone"}, []string{"--set access_key_secret=-"}, "--set access_key_id"},
		{"no id", map[string]string{"access_key_secret": "s"}, []string{"--set access_key_id=<id>"}, "--set access_key_secret"},
	} {
		_, stderr, opened, err := login(tc.opts, nil)
		if !errors.Is(err, app.ErrUsage) {
			t.Errorf("%s: %v, want a usage error", tc.name, err)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: the error does not name %q: %v", tc.name, w, err)
			}
		}
		if tc.wantNot != "" && strings.Contains(err.Error(), tc.wantNot) {
			t.Errorf("%s: the error names %q, which was given: %v", tc.name, tc.wantNot, err)
		}
		if opened != 0 || stderr != "" || seenKey != "" {
			t.Errorf("%s: browser opened %d time(s), stderr %q, API called with %q; want none of it", tc.name, opened, stderr, seenKey)
		}
	}

	// --set values: no question, the region is the documented default.
	res, stderr, opened, err := login(map[string]string{"access_key_id": "LTAIset", "access_key_secret": "s"}, nil)
	if err != nil || seenKey != "LTAIset" || res.Metadata[metaRegion] != DefaultRegion || res.Secret[secretKeySecret] != "s" {
		t.Fatalf("--set key: %v %+v (key %q)", err, res, seenKey)
	}
	if opened != 0 || strings.Contains(stderr, "AccessKey ID") || strings.Contains(stderr, "Region id") || !strings.Contains(stderr, "using region "+DefaultRegion) {
		t.Errorf("--set key: browser opened %d time(s), stderr %q", opened, stderr)
	}
	// A re-authentication keeps its region; --set region wins.
	if res, _, _, err = login(map[string]string{"access_key_id": "LTAIset", "access_key_secret": "s"}, map[string]string{metaRegion: "cn-shanghai"}); err != nil || res.Metadata[metaRegion] != "cn-shanghai" {
		t.Errorf("existing region: %v %+v", err, res)
	}
	if res, _, _, err = login(map[string]string{"access_key_id": "LTAIset", "access_key_secret": "s", "region": "us-west-1"}, map[string]string{metaRegion: "cn-shanghai"}); err != nil || res.Metadata[metaRegion] != "us-west-1" {
		t.Errorf("--set region: %v %+v", err, res)
	}

	// The environment, as a pair; --set wins over it.
	t.Setenv(envKeyID, "LTAIenv")
	t.Setenv(envKeySecret, "envsecret")
	res, stderr, _, err = login(nil, nil)
	if err != nil || seenKey != "LTAIenv" || res.Secret[secretKeySecret] != "envsecret" || !strings.Contains(stderr, envKeyID) || strings.Contains(stderr, "envsecret") {
		t.Errorf("environment key: %v %+v (key %q, stderr %q)", err, res, seenKey, stderr)
	}
	if _, _, _, err = login(map[string]string{"access_key_id": "LTAIset", "access_key_secret": "s"}, nil); err != nil || seenKey != "LTAIset" {
		t.Errorf("--set over the environment: %v (key %q)", err, seenKey)
	}
	// Half a key from --set is never completed from the environment.
	if _, _, _, err = login(map[string]string{"access_key_id": "LTAIset"}, nil); !errors.Is(err, app.ErrUsage) {
		t.Errorf("half a key = %v, want a usage error", err)
	}
}
