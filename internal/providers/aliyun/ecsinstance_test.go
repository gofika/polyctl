package aliyun

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestInstanceAddresses(t *testing.T) {
	var onlyPublic ecs.Instance
	onlyPublic.PublicIpAddress.IpAddress = []string{"198.51.100.7"}
	if publicIP(onlyPublic) != "198.51.100.7" {
		t.Errorf("only PublicIpAddress: %q", publicIP(onlyPublic))
	}
	var onlyEIP ecs.Instance
	onlyEIP.PublicIpAddress.IpAddress = []string{}
	onlyEIP.EipAddress.IpAddress, onlyEIP.EipAddress.AllocationId = "203.0.113.10", "eip-1"
	if publicIP(onlyEIP) != "203.0.113.10" {
		t.Errorf("only EipAddress: %q", publicIP(onlyEIP))
	}
	var none ecs.Instance
	if publicIP(none) != "" || privateIP(none) != "" {
		t.Errorf("no addresses: %q %q", publicIP(none), privateIP(none))
	}
	// A VPC instance: empty InnerIpAddress, the primary interface holds it.
	var vpcInst ecs.Instance
	vpcInst.InnerIpAddress.IpAddress = []string{}
	vpcInst.NetworkInterfaces.NetworkInterface = []ecs.NetworkInterface{
		{Type: "Secondary", PrimaryIpAddress: "172.16.9.9"}, {Type: "Primary", PrimaryIpAddress: "172.16.8.12"}}
	if privateIP(vpcInst) != "172.16.8.12" {
		t.Errorf("network interfaces: %q", privateIP(vpcInst))
	}
	var classic ecs.Instance
	classic.InnerIpAddress.IpAddress = []string{"10.0.0.5"}
	if privateIP(classic) != "10.0.0.5" {
		t.Errorf("classic: %q", privateIP(classic))
	}
	var vpcOnly ecs.Instance
	vpcOnly.VpcAttributes.PrivateIpAddress.IpAddress = []string{"172.16.0.3"}
	if privateIP(vpcOnly) != "172.16.0.3" {
		t.Errorf("VpcAttributes: %q", privateIP(vpcOnly))
	}
}

func TestNormalizeHostName(t *testing.T) {
	for name, want := range map[string]string{
		"site-a":                       "site-a",
		"site_a":                       "site-a",
		"-web_1-":                      "web-1",
		strings.Repeat("a", 70):        strings.Repeat("a", 64),
		"web.example":                  "web.example",
		"ab":                           "ab",
		"éé-web":                       "web",
		strings.Repeat("b", 63) + "_c": strings.Repeat("b", 63),
	} {
		got, changed, err := normalizeHostName(name)
		if err != nil || got != want || changed != (got != name) {
			t.Errorf("normalizeHostName(%q) = %q, %v, %v; want %q", name, got, changed, err, want)
		}
	}
	for _, bad := range []string{"_", "-a-", "éé"} {
		if _, _, err := normalizeHostName(bad); !errors.Is(err, app.ErrUsage) {
			t.Errorf("normalizeHostName(%q) = %v, want a usage error", bad, err)
		}
	}
}

func TestCheckInstanceName(t *testing.T) {
	for _, ok := range []string{"site-a", "polyctl_verify_ins", "éé"} {
		if err := checkInstanceName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "web*", "i-0123", strings.Repeat("x", 129)} {
		if err := checkInstanceName(bad); !errors.Is(err, app.ErrUsage) {
			t.Errorf("%q = %v, want a usage error", bad, err)
		}
	}
}

func TestRunInstanceRequest(t *testing.T) {
	api := newFakeAPI(t)
	f := newFakeCompute(t, api)
	f.addVSwitch("vsw-b", "sw-b", "vpc-1", "cn-shanghai-b", "172.16.0.0/22")
	f.addGroup("sg-1", "sg-common", "vpc-1")
	f.addKeyPair("ops", "aa", "2026-11-17T16:10Z")
	c := api.client()
	spec := runSpec{Name: "site_a", HostName: "site-a", Type: "ecs.u1-c1m1.large", Image: "aliyun_4_x64", SecurityGroup: "sg-1",
		VSwitch: "vsw-b", KeyPair: "ops", DiskGiB: 20, DiskCategory: "cloud_essd_entry"}
	spec.ClientToken = spec.token("p", "cn-shanghai")
	id, err := c.runInstance(context.Background(), "cn-shanghai", spec)
	if err != nil {
		t.Fatal(err)
	}
	q := api.callsFor("RunInstances")[0]
	for k, want := range map[string]string{"InternetMaxBandwidthOut": "0", "InstanceChargeType": "PostPaid", "InternetChargeType": "PayByTraffic",
		"SystemDisk.Size": "20", "SystemDisk.Category": "cloud_essd_entry", "HostName": "site-a", "InstanceName": "site_a",
		"VSwitchId": "vsw-b", "SecurityGroupId": "sg-1", "KeyPairName": "ops", "ImageId": "aliyun_4_x64", "Amount": "1", "RegionId": "cn-shanghai"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("ClientToken")) != 64 {
		t.Errorf("ClientToken = %q", q.Get("ClientToken"))
	}
	// The same request again returns the same instance.
	again, err := c.runInstance(context.Background(), "cn-shanghai", spec)
	if err != nil || again != id {
		t.Errorf("retry = %q, %v; want %q", again, err, id)
	}
	other := spec
	other.Type = "ecs.u1-c1m2.large"
	if other.token("p", "cn-shanghai") == spec.ClientToken {
		t.Error("a different request reuses the token")
	}
}

// A Windows password travels in the form body, never in the URL query, and
// keys the client token: a new password is a new request.
func TestRunInstanceWindowsPassword(t *testing.T) {
	api := newFakeAPI(t)
	f := newFakeCompute(t, api)
	f.addVSwitch("vsw-b", "sw-b", "vpc-1", "cn-shanghai-b", "172.16.0.0/22")
	f.addGroup("sg-1", "sg-common", "vpc-1")
	c := api.client()
	const pw = "Kp7-tes7Password:abc"
	spec := runSpec{Name: "win-a", HostName: "win-a", Type: "ecs.u1-c1m2.large", Image: "win2025", SecurityGroup: "sg-1",
		VSwitch: "vsw-b", DiskGiB: 40, DiskCategory: "cloud_essd_entry", Password: pw}
	spec.ClientToken = spec.token("p", "cn-shanghai")
	if _, err := c.runInstance(context.Background(), "cn-shanghai", spec); err != nil {
		t.Fatal(err)
	}
	if q := api.callsFor("RunInstances")[0]; q.Get("Password") != pw || q.Has("KeyPairName") {
		t.Errorf("RunInstances = %v", q)
	}
	for _, raw := range api.queries {
		if strings.Contains(raw, "Password") || strings.Contains(raw, "Kp7") {
			t.Errorf("the password is in the URL: %s", raw)
		}
	}
	other := spec
	other.Password = "Zz9-otherPassword:xy"
	if other.token("p", "cn-shanghai") == spec.ClientToken || strings.Contains(spec.ClientToken, pw) {
		t.Error("the token does not follow the password")
	}
}

func TestFindInstancesComparesCase(t *testing.T) {
	api := newFakeAPI(t)
	f := newFakeCompute(t, api)
	f.addVM("i-1", "Site-A", instRunning, "t", "vpc-1", "vsw-1")
	f.addVM("i-2", "site-a", instRunning, "t", "vpc-1", "vsw-1")
	got, err := api.client().findInstances(context.Background(), "cn-shanghai", "site-a")
	if err != nil || len(got) != 1 || got[0].ID != "i-2" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got[0].PrivateIP != "172.16.0.10" || got[0].VSwitchID != "vsw-1" || got[0].KeyPair != "ops" {
		t.Errorf("instance = %+v", got[0])
	}
	if q := api.callsFor("DescribeInstances")[0]; q.Get("InstanceName") != "site-a" || q.Get("PageSize") != "100" {
		t.Errorf("query = %v", q)
	}
}

func waitScope(t *testing.T) (*ecsScope, *fakeECS, *fakeSleepClock) {
	t.Helper()
	api := newFakeAPI(t)
	f := newFakeCompute(t, api)
	clock := &fakeSleepClock{now: time.Unix(1_700_000_000, 0)}
	netWaitClock = clock
	t.Cleanup(func() { netWaitClock = nil })
	return &ecsScope{c: api.client(), profile: "p", region: "cn-shanghai"}, f, clock
}

func TestWaitInstanceRunning(t *testing.T) {
	ctx := context.Background()
	t.Run("not listed, then running", func(t *testing.T) {
		s, f, _ := waitScope(t)
		f.addVM("i-1", "a", statusNotFound, "t", "v", "s")
		f.seq["i-1"] = []string{statusNotFound, instPending, instStarting, instRunning}
		if _, err := waitInstanceRunning(ctx, s, "i-1", "a", time.Minute); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown id keeps waiting", func(t *testing.T) {
		s, _, _ := waitScope(t)
		err := func() error { _, err := waitInstanceRunning(ctx, s, "i-gone", "a", 10*time.Second); return err }()
		var te *platform.WaitTimeoutError
		if !errors.As(err, &te) || te.LastStatus != statusNotFound {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("transient stopped", func(t *testing.T) {
		s, f, _ := waitScope(t)
		f.addVM("i-1", "a", instPending, "t", "v", "s")
		f.seq["i-1"] = []string{instPending, instStopped, instStarting, instRunning}
		if _, err := waitInstanceRunning(ctx, s, "i-1", "a", time.Minute); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("starting forever", func(t *testing.T) {
		s, f, _ := waitScope(t)
		f.addVM("i-1", "a", instStarting, "t", "v", "s")
		_, err := waitInstanceRunning(ctx, s, "i-1", "a", time.Minute)
		var te *platform.WaitTimeoutError
		if !errors.As(err, &te) || te.LastStatus != instStarting || !strings.Contains(err.Error(), "instance/a") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("stopped after running", func(t *testing.T) {
		s, f, _ := waitScope(t)
		f.addVM("i-1", "a", instPending, "t", "v", "s")
		f.seq["i-1"] = []string{instPending, instRunning, instStopped}
		// Running is seen first: the wait is done before it stops.
		if _, err := waitInstanceRunning(ctx, s, "i-1", "a", time.Minute); err != nil {
			t.Fatal(err)
		}
		sw := &platform.StatusWait{Target: instRunning, Transient: map[string]time.Duration{instStopped: stoppedGrace}}
		now := time.Now()
		sw.Observe(now, instRunning)
		if sw.Observe(now, instStopped) != platform.WaitFailed {
			t.Error("Stopped after Running must fail")
		}
	})
	t.Run("stopped too long", func(t *testing.T) {
		s, f, _ := waitScope(t)
		f.addVM("i-1", "a", instStopped, "t", "v", "s")
		_, err := waitInstanceRunning(ctx, s, "i-1", "a", 10*time.Minute)
		var te *platform.WaitTimeoutError
		if err == nil || errors.As(err, &te) || !strings.Contains(err.Error(), "instance start i-1") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestWaitRebootedIgnoresTheFirstRunning(t *testing.T) {
	s, f, _ := waitScope(t)
	f.addVM("i-1", "a", instRunning, "t", "v", "s")
	f.seq["i-1"] = []string{instRunning, instStopping, instStarting, instRunning}
	if _, err := waitRebooted(context.Background(), s, "i-1", "a", time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(f.seq["i-1"]) != 1 {
		t.Errorf("the wait ended early, left %v", f.seq["i-1"])
	}
}

func TestRetryInitializing(t *testing.T) {
	s, f, clock := waitScope(t)
	f.addVM("i-1", "a", instStopped, "t", "v", "s")
	f.initializing["i-1"] = 3
	err := retryInitializing(context.Background(), func(ctx context.Context) error { return s.c.deleteInstance(ctx, s.region, "i-1", false) })
	if err != nil {
		t.Fatal(err)
	}
	if len(clock.sleeps) != 3 || clock.sleeps[0] != 3*time.Second || clock.sleeps[2] > 5*time.Second {
		t.Errorf("sleeps = %v", clock.sleeps)
	}
}

func TestRunInstanceParameterErrorsAreNotNotFound(t *testing.T) {
	// ECS answers these invalid parameters with HTTP 404.
	for _, code := range []string{"InvalidSystemDiskSize.LessThanImageSize", "HOSTNAME_ILLEGAL"} {
		if isNotFoundCode(code, 404) {
			t.Errorf("%s reads as not found", code)
		}
	}
	for _, code := range []string{"InvalidImageId.NotFound", "InvalidVSwitchId.NotExist", "InvalidKeyPairName.NotFound"} {
		if !isNotFoundCode(code, 404) {
			t.Errorf("%s does not read as not found", code)
		}
	}
}

// Each type change has a fresh client token, never one derived from the
// content: a change back to an earlier type (a -> b -> a -> b) would replay
// the answer of the first request and change nothing.
func TestModifyInstanceSpecTokenIsFreshPerChange(t *testing.T) {
	api := newFakeAPI(t)
	f := newFakeCompute(t, api)
	f.addVM("i-1", "a", instStopped, "ecs.u1-c1m1.large", "vpc-1", "vsw-1")
	for range 2 {
		if err := api.client().modifyInstanceSpec(context.Background(), "cn-shanghai", "i-1", "ecs.u1-c1m2.large"); err != nil {
			t.Fatal(err)
		}
	}
	calls := api.callsFor("ModifyInstanceSpec")
	if q := calls[0]; q.Get("ClientToken") == "" || q.Get("InstanceType") != "ecs.u1-c1m2.large" {
		t.Errorf("query = %v", q)
	}
	if calls[1].Get("ClientToken") == calls[0].Get("ClientToken") {
		t.Errorf("two changes share token %q", calls[0].Get("ClientToken"))
	}
}

func TestWaitRebootedStopped(t *testing.T) {
	t.Run("transient", func(t *testing.T) {
		s, f, _ := waitScope(t)
		f.addVM("i-1", "a", instRunning, "t", "v", "s")
		f.seq["i-1"] = []string{instStopping, instStopped, instStarting, instRunning}
		if _, err := waitRebooted(context.Background(), s, "i-1", "a", time.Minute); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("stays stopped", func(t *testing.T) {
		s, f, _ := waitScope(t)
		f.addVM("i-1", "a", instRunning, "t", "v", "s")
		f.seq["i-1"] = []string{instStopping, instStopped}
		_, err := waitRebooted(context.Background(), s, "i-1", "a", 10*time.Minute)
		var te *platform.WaitTimeoutError
		if err == nil || errors.As(err, &te) || !strings.Contains(err.Error(), "instance start i-1") {
			t.Fatalf("err = %v", err)
		}
	})
}
