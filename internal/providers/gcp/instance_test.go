package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/gofika/polyctl/internal/platform"
)

// computeClient is a client of project proj on the fake Compute Engine,
// with the fake clock.
func computeClient(t *testing.T) (*client, *fakeCompute) {
	t.Helper()
	f := newFakeCompute(t)
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	old := instanceClock
	instanceClock = clk
	t.Cleanup(func() { instanceClock = old })
	c, err := newClient(context.Background(), "proj", "", methodADC,
		append(f.options(), option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"})))...)
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestRegionOf(t *testing.T) {
	for in, want := range map[string]string{"us-central1-a": "us-central1", "europe-west12-c": "europe-west12", "asia-east2-ai1": "asia-east2", "x": "x"} {
		if got := regionOf(in); got != want {
			t.Errorf("regionOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestComputeErrors(t *testing.T) {
	c, f := computeClient(t)
	ctx := context.Background()
	// 404 at submission: not found.
	if _, err := c.getInstance(ctx, "us-central1-a", "nope"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing instance = %v", err)
	}
	if in, err := c.findInstance(ctx, "us-central1-a", "nope"); in != nil || err != nil {
		t.Errorf("findInstance = %v, %v", in, err)
	}
	// A machine type the zone lacks: not found, at Get (404) and at
	// SetMachineType (400 invalid) alike.
	if _, err := c.machineType(ctx, "us-central1-a", "n9-huge"); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "machine-types list") {
		t.Errorf("machine type = %v", err)
	}
	f.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	if err := c.setMachineType(ctx, "us-central1-a", "web-1", "n9-huge"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("set missing type = %v", err)
	}
	// SetMachineType on a running instance: accepted, the operation fails.
	err := c.setMachineType(ctx, "us-central1-a", "web-1", "e2-medium")
	var oe *OperationError
	if !errors.As(err, &oe) || platform.ErrorCode(err) != "UNSUPPORTED_OPERATION" {
		t.Errorf("running set type = %v", err)
	}
	// Reset of a stopped instance: resourceNotReady at submission.
	f.instance("us-central1-a", "web-1").Status = statusTerminated
	if err := c.resetInstance(ctx, "us-central1-a", "web-1", true); err == nil || !strings.Contains(err.Error(), "not running") || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("reset stopped = %v", err)
	}
	// Disabled API and missing permission are both authentication errors,
	// told apart in the message; quota is a general failure.
	for e, want := range map[fakeErr]string{
		{403, "accessNotConfigured", "Compute Engine API has not been used in project"}: "not enabled",
		{403, "forbidden", "Required 'compute.instances.get' permission"}:               "permission",
		// A missing quota project is a credentials problem, not a quota.
		{403, "forbidden", "The compute.googleapis.com API requires a quota project, which is not set by default."}: "permission",
	} {
		f.fail["GET /projects/proj/zones/us-central1-a/instances/web-1"] = e
		if _, err := c.getInstance(ctx, "us-central1-a", "web-1"); !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s = %v", e.reason, err)
		}
	}
	f.fail["GET /projects/proj/zones/us-central1-a/instances/web-1"] = fakeErr{403, "rateLimitExceeded", "Quota exceeded"}
	if _, err := c.getInstance(ctx, "us-central1-a", "web-1"); errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "not a permission problem") {
		t.Errorf("quota = %v", err)
	}
}

func TestWaitStatus(t *testing.T) {
	c, f := computeClient(t)
	ctx := context.Background()
	in := f.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	if got, err := c.waitStatus(ctx, "us-central1-a", "web-1", statusRunning, time.Minute); err != nil || got.Status != statusRunning {
		t.Errorf("running = %v, %v", got, err)
	}
	// Waiting for RUNNING on a stopped instance fails with its message.
	in.Status, in.StatusMessage = statusTerminated, "Instance was preempted."
	if _, err := c.waitStatus(ctx, "us-central1-a", "web-1", statusRunning, time.Minute); err == nil || !strings.Contains(err.Error(), "preempted") {
		t.Errorf("terminated = %v", err)
	}
	// A status that does not change: timeout.
	in.Status = statusStopping
	var to *platform.WaitTimeoutError
	if _, err := c.waitStatus(ctx, "us-central1-a", "web-1", statusTerminated, time.Minute); !errors.As(err, &to) || to.LastStatus != statusStopping {
		t.Errorf("stuck = %v", err)
	}
}

func TestAddressSteps(t *testing.T) {
	c, f := computeClient(t)
	ctx := context.Background()
	var ip string
	// Missing: reserved.
	step, err := c.externalAddressStep("us-central1", "web-1-external-ip", nil, &ip)
	if err != nil || step.Action != platform.Created {
		t.Fatalf("step = %+v, %v", step, err)
	}
	ch, err := step.Apply(ctx)
	if err != nil || ip == "" || ch.ID != ip || f.address("us-central1", "web-1-external-ip").NetworkTier != "PREMIUM" {
		t.Errorf("reserve = %+v, %v (%s)", ch, err, ip)
	}
	// Existing and reserved: unchanged.
	existing := f.address("us-central1", "web-1-external-ip")
	ip = ""
	if step, err := c.externalAddressStep("us-central1", "web-1-external-ip", existing, &ip); err != nil || step.Action != platform.Unchanged || ip != existing.Address {
		t.Errorf("existing = %+v, %v", step, err)
	}
	// An internal address of that name: refused.
	if _, err := c.externalAddressStep("us-central1", "x", &compute.Address{Name: "x", AddressType: "INTERNAL"}, &ip); err == nil {
		t.Error("internal as external accepted")
	}
	// Internal: always with the subnet.
	step, err = c.internalAddressStep("us-central1", "web-1-internal-ip", "default", nil, &ip)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := step.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if a := f.address("us-central1", "web-1-internal-ip"); a.Purpose != "GCE_ENDPOINT" || !strings.HasSuffix(a.Subnetwork, "projects/proj/regions/us-central1/subnetworks/default") {
		t.Errorf("internal = %+v", a)
	}
	// Release: RESERVED only.
	f.addInstance("proj", "us-central1-a", "web-2", "10.128.0.9", "")
	f.addAddress("us-central1", &compute.Address{Name: "used", Address: "10.128.0.9", AddressType: "INTERNAL", Subnetwork: "default"})
	used := f.address("us-central1", "used")
	if s := c.releaseStep("us-central1", "used", used, "instances/web-1"); s.Action != platform.Skipped || !strings.Contains(s.Desc, "web-2") {
		t.Errorf("release used = %+v", s)
	}
	if s := c.releaseStep("us-central1", "gone", nil, "instances/web-1"); s.Action != platform.Skipped {
		t.Errorf("release missing = %+v", s)
	}
	s := c.releaseStep("us-central1", "web-1-internal-ip", f.address("us-central1", "web-1-internal-ip"), "instances/web-1")
	if ch, err := s.Apply(ctx); err != nil || ch.Action != "" || f.address("us-central1", "web-1-internal-ip") != nil {
		t.Errorf("release reserved = %+v, %v", ch, err)
	}
	// Used meanwhile: skipped at apply time.
	s = c.releaseStep("us-central1", "used", &compute.Address{Name: "used", Address: "10.128.0.9", Status: addrReserved}, "instances/web-1")
	if ch, err := s.Apply(ctx); err != nil || ch.Action != platform.Skipped || f.address("us-central1", "used") == nil {
		t.Errorf("release in use at apply = %+v, %v", ch, err)
	}
}

func TestPromoteStep(t *testing.T) {
	c, f := computeClient(t)
	ctx := context.Background()
	f.addAddress("us-central1", &compute.Address{Name: "old-name", Address: "34.1.0.1", AddressType: "EXTERNAL"})
	list, _ := c.listAddresses(ctx, "us-central1")
	// Already static under any name: unchanged.
	if s, ok, err := c.promoteStep(promoteSpec{Region: "us-central1", Name: "web-1-external-ip", IP: "34.1.0.1", Type: addrExternal, Fatal: true, List: list}); err != nil || !ok ||
		s.Action != platform.Unchanged || s.Resource != "address/old-name" {
		t.Errorf("static = %+v %v %v", s, ok, err)
	}
	// No IP: no step.
	if _, ok, _ := c.promoteStep(promoteSpec{IP: ""}); ok {
		t.Error("empty ip has a step")
	}
	// The name holds another IP: external stops, internal is skipped.
	byName := &compute.Address{Name: "web-1-external-ip", Address: "34.1.0.2"}
	if _, _, err := c.promoteStep(promoteSpec{Region: "us-central1", Name: "web-1-external-ip", IP: "34.1.0.3", Type: addrExternal, Fatal: true, List: list, ByName: byName}); err == nil {
		t.Error("taken external name accepted")
	}
	if s, ok, err := c.promoteStep(promoteSpec{Region: "us-central1", Name: "web-1-internal-ip", IP: "10.0.0.3", Type: addrInternal, List: list, ByName: byName}); err != nil || !ok || s.Action != platform.Skipped {
		t.Errorf("taken internal name = %+v %v %v", s, ok, err)
	}
	// Promotion of an ephemeral IP keeps it.
	s, _, _ := c.promoteStep(promoteSpec{Region: "us-central1", Name: "web-1-external-ip", IP: "34.1.0.9", Type: addrExternal, Fatal: true, List: list})
	if _, err := s.Apply(ctx); err != nil || f.address("us-central1", "web-1-external-ip").Address != "34.1.0.9" {
		t.Errorf("promote = %v", err)
	}
	// A STANDARD tier IP stays in its tier.
	s, _, _ = c.promoteStep(promoteSpec{Region: "us-central1", Name: "std-ip", IP: "35.1.0.9", Type: addrExternal, NetworkTier: "STANDARD", Fatal: true, List: list})
	if _, err := s.Apply(ctx); err != nil || f.address("us-central1", "std-ip").NetworkTier != "STANDARD" {
		t.Errorf("promote standard = %v %+v", err, f.address("us-central1", "std-ip"))
	}
	in := &compute.Instance{NetworkInterfaces: []*compute.NetworkInterface{{AccessConfigs: []*compute.AccessConfig{{NatIP: "35.1.0.9", NetworkTier: "STANDARD"}}}}}
	if accessTier(in, "35.1.0.9") != "STANDARD" || accessTier(in, "") != "" {
		t.Error("accessTier")
	}
	// A failed internal promotion is a warning.
	var warned string
	f.opFail["insertAddress"] = compute.OperationErrorErrors{Code: "INTERNAL_ERROR", Message: "x"}
	s, _, _ = c.promoteStep(promoteSpec{Region: "us-central1", Name: "web-1-internal-ip", IP: "10.0.0.9", Type: addrInternal, SubnetURL: "x", List: list, Warn: func(m string) { warned = m }})
	if ch, err := s.Apply(ctx); err != nil || ch.Action != platform.Skipped || !strings.Contains(warned, "warning") {
		t.Errorf("failed internal = %+v, %v, %q", ch, err, warned)
	}
}

func TestWaitOpIsBounded(t *testing.T) {
	old := opWaitLimit
	opWaitLimit = 30 * time.Millisecond
	t.Cleanup(func() { opWaitLimit = old })
	pending := func(ctx context.Context, name string) (*compute.Operation, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
		return &compute.Operation{Name: name, Status: "RUNNING"}, nil
	}
	// No deadline on the context: the limit applies.
	var to *platform.WaitTimeoutError
	err := waitOp(context.Background(), &compute.Operation{Name: "op-1", Status: "RUNNING", OperationType: "insert"}, pending)
	if !errors.As(err, &to) || to.Resource != "operation/op-1" || to.Timeout != opWaitLimit {
		t.Errorf("unbounded op = %v", err)
	}
	// A deadline of the caller is left to the caller.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := waitOp(ctx, &compute.Operation{Name: "op-2", Status: "RUNNING"}, pending); !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &to) {
		t.Errorf("caller deadline = %v", err)
	}
	// A finished operation returns its error at once.
	done := &compute.Operation{Name: "op-3", Status: "DONE", Error: &compute.OperationError{Errors: []*compute.OperationErrorErrors{{Code: "IP_IN_USE_BY_ANOTHER_RESOURCE", Message: "in use"}}}}
	var oe *OperationError
	if err := waitOp(context.Background(), done, pending); !errors.As(err, &oe) || oe.ErrorCode() != "IP_IN_USE_BY_ANOTHER_RESOURCE" {
		t.Errorf("finished op = %v", err)
	}
}
