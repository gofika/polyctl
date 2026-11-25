package gcp

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// A zone an aggregated list cannot reach is a region failure of the sync,
// whether the API names it in unreachables (partial success) or flags its
// scope with warning UNREACHABLE; the instances it could read are kept.
func TestSyncInstancesReportsUnreachableZone(t *testing.T) {
	for _, warning := range []bool{false, true} {
		c, f := computeClient(t)
		f.addInstance("proj", "us-central1-a", "web-1", "10.0.0.1", "34.0.0.1")
		f.addInstance("proj", "europe-west1-b", "db-1", "10.0.0.2", "34.0.0.2")
		f.unreachable = "zones/europe-west1-b"
		f.unreachableWarning = warning
		res, err := c.syncInstances(context.Background())
		rse := platform.AsRegionSyncError(err)
		if rse == nil || len(rse.Failures) != 1 || rse.Failures[0].Region != "europe-west1-b" {
			t.Fatalf("warning=%v: err = %v, want a region failure of europe-west1-b", warning, err)
		}
		if len(res) != 1 || res[0].Name != "web-1" {
			t.Errorf("warning=%v: resources %+v", warning, res)
		}
		// ListInstances (the instance list cache) reports it the same way.
		if _, err := c.ListInstances(context.Background()); platform.AsRegionSyncError(err) == nil {
			t.Errorf("warning=%v: ListInstances err = %v", warning, err)
		}
	}
}

func TestSyncAddressesReportsUnreachableRegion(t *testing.T) {
	for _, warning := range []bool{false, true} {
		c, f := computeClient(t)
		f.addAddress("us-central1", &compute.Address{Name: "ip-1", Address: "34.1.1.1", AddressType: "EXTERNAL"})
		f.unreachable = "regions/europe-west1"
		f.unreachableWarning = warning
		res, err := c.syncAddresses(context.Background())
		rse := platform.AsRegionSyncError(err)
		if rse == nil || rse.Failures[0].Region != "europe-west1" || len(res) != 1 {
			t.Errorf("warning=%v: res %+v err %v", warning, res, err)
		}
	}
}

// A lookup that must see every scope fails rather than answer from a part.
func TestSubnetworksFailOnUnreachableRegion(t *testing.T) {
	c, f := computeClient(t)
	f.unreachable = "regions/europe-west1"
	f.unreachableWarning = true
	_, err := c.listSubnets(context.Background(), "", "")
	if err == nil || !strings.Contains(err.Error(), "regions/europe-west1") {
		t.Errorf("err = %v", err)
	}
}

func TestUniqueScopes(t *testing.T) {
	got := uniqueScopes([]string{"zones/b", "https://www.googleapis.com/compute/v1/projects/p/zones/b", "projects/p/regions/r", "zones/a", "global"})
	if want := []string{"global", "regions/r", "zones/a", "zones/b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("uniqueScopes = %v, want %v", got, want)
	}
}

// Global resources have no parent region in the inventory, so a region
// failure could not keep their rows: an unreachable global scope fails the
// sync of the type instead (nothing of it is replaced).
func TestSyncAddressesUnreachableGlobalFailsWhole(t *testing.T) {
	for _, warning := range []bool{false, true} {
		c, f := computeClient(t)
		f.addAddress("us-central1", &compute.Address{Name: "ip-1", Address: "34.1.1.1", AddressType: "EXTERNAL"})
		f.unreachable = "global"
		f.unreachableWarning = warning
		_, err := c.syncAddresses(context.Background())
		if err == nil || platform.AsRegionSyncError(err) != nil || !strings.Contains(err.Error(), "global") {
			t.Errorf("warning=%v: err = %v, want a whole-sync failure naming global", warning, err)
		}
	}
}
