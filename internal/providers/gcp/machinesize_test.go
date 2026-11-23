package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func mustSize(t *testing.T, v string) platform.TypeShorthand {
	t.Helper()
	s, ok, err := platform.ParseTypeShorthand(v)
	if !ok || err != nil {
		t.Fatalf("ParseTypeShorthand(%q) = %v, %v", v, ok, err)
	}
	return s
}

func TestE2PresetFor(t *testing.T) {
	for in, want := range map[string]string{
		"2H1G": "e2-micro", "2H2G": "e2-small", "2H4G": "e2-medium", "2H8G": "e2-standard-2", "4H16G": "e2-standard-4",
		"32H128G": "e2-standard-32", "4H4G": "e2-highcpu-4", "32H32G": "e2-highcpu-32", "2H16G": "e2-highmem-2",
		"16H128G": "e2-highmem-16", "2h2g": "e2-small", "2H2.0G": "e2-small",
		"2H3G": "", "1H1G": "", "32H256G": "", "8H16G": "", "2H0.5G": "",
	} {
		s := mustSize(t, in)
		if got := e2PresetFor(s.Cores, s.MemoryMiB()); got != want {
			t.Errorf("e2PresetFor(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestE2Custom(t *testing.T) {
	for _, tc := range []struct {
		cores, mem int
		fits       bool
		near       string
	}{
		{2, 3072, true, "2H3G"},
		{8, 16384, true, "8H16G"},
		{32, 131072, true, "32H128G"},
		{2, 768, false, "2H1G"},        // below 0.5 GiB per vCPU
		{1, 1024, false, "2H1G"},       // one vCPU
		{3, 6144, false, "4H6G"},       // odd vCPUs
		{64, 65536, false, "32H64G"},   // too many vCPUs
		{2, 20480, false, "2H16G"},     // above 8 GiB per vCPU
		{32, 262144, false, "32H128G"}, // above 128 GiB
		{2, 4198, false, "2H4.25G"},    // not a multiple of 256 MiB
		{1, 512, false, "2H1G"},
	} {
		if got := e2CustomFits(tc.cores, tc.mem); got != tc.fits {
			t.Errorf("e2CustomFits(%d, %d) = %v", tc.cores, tc.mem, got)
		}
		c, m := nearestE2Size(tc.cores, tc.mem)
		if got := sizeText(c, m); got != tc.near {
			t.Errorf("nearestE2Size(%d, %d) = %s, want %s", tc.cores, tc.mem, got, tc.near)
		}
		if !e2CustomFits(c, m) {
			t.Errorf("nearest %s of (%d, %d) does not fit", sizeText(c, m), tc.cores, tc.mem)
		}
	}
	if got := e2CustomName(2, 3072); got != "e2-custom-2-3072" {
		t.Errorf("e2CustomName = %s", got)
	}
}

func TestResolveMachineSize(t *testing.T) {
	c, f := computeClient(t)
	ctx := context.Background()
	zone := "us-central1-a"
	for _, tc := range []struct {
		size, typ string
		custom    bool
	}{
		{"2H2G", "e2-small", false},
		{"2H4G", "e2-medium", false},
		{"4H4G", "e2-highcpu-4", false},
		{"2H1G", "e2-micro", false},
		{"2H16G", "e2-highmem-2", false},
		{"2H3G", "e2-custom-2-3072", true},
		{"6H12G", "e2-custom-6-12288", true},
	} {
		ch, err := c.resolveMachineSize(ctx, zone, mustSize(t, tc.size))
		if err != nil || ch.Type != tc.typ || ch.Custom != tc.custom || ch.Zone != zone {
			t.Errorf("resolve %s = %+v, %v; want %s", tc.size, ch, err, tc.typ)
		}
	}
	ch, _ := c.resolveMachineSize(ctx, zone, mustSize(t, "2H4G"))
	if ch.note() != "2H4G -> e2-medium (us-central1-a, E2 predefined)" || ch.label() != "(2H4G)" {
		t.Errorf("note / label = %q / %q", ch.note(), ch.label())
	}
	ch, _ = c.resolveMachineSize(ctx, zone, mustSize(t, "2H3G"))
	if ch.label() != "(2H3G, E2 custom)" {
		t.Errorf("custom label = %q", ch.label())
	}

	// A preset the zone lacks: the custom type of the same shape.
	f.mu.Lock()
	delete(f.machineTypes, zone+"/e2-small")
	f.mu.Unlock()
	if ch, err := c.resolveMachineSize(ctx, zone, mustSize(t, "2H2G")); err != nil || ch.Type != "e2-custom-2-2048" || !ch.Custom {
		t.Errorf("missing preset = %+v, %v", ch, err)
	}

	// No E2 shape: not found, with the nearest size.
	_, err := c.resolveMachineSize(ctx, zone, mustSize(t, "1H1G"))
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "1H1G") || !strings.Contains(err.Error(), zone) ||
		!strings.Contains(err.Error(), "nearest E2 size is 2H1G (e2-micro)") {
		t.Errorf("1H1G = %v", err)
	}
	if _, err := c.resolveMachineSize(ctx, zone, mustSize(t, "2H4.1G")); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "2H4.25G (e2-custom-2-4352)") {
		t.Errorf("2H4.1G = %v", err)
	}

	// A zone without E2 types: not found, for a preset and a custom size.
	f.mu.Lock()
	for _, p := range e2Presets {
		delete(f.machineTypes, "europe-west1-b/"+p.Name)
	}
	f.mu.Unlock()
	for _, s := range []string{"2H4G", "2H3G"} {
		if _, err := c.resolveMachineSize(ctx, "europe-west1-b", mustSize(t, s)); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "offers no E2") {
			t.Errorf("no E2 %s = %v", s, err)
		}
	}

	// Another error of the lookup stops the resolution.
	f.mu.Lock()
	f.fail["machineTypes/e2-medium"] = fakeErr{403, "forbidden", "Required 'compute.machineTypes.get' permission"}
	f.mu.Unlock()
	if _, err := c.resolveMachineSize(ctx, zone, mustSize(t, "2H4G")); exitClass(err) != "auth" {
		t.Errorf("forbidden = %v", err)
	}
}
