package app_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestResolveResource(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	// By id, on one platform.
	r, err := h.rt.ResolveResource(ctx, platform.NameCom, platform.ResZone, "z-other")
	if err != nil || r.Profile != "b" || r.Name != "other.com" {
		t.Fatalf("by id = %+v, %v", r, err)
	}
	// By name, unique.
	if r, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "example.com"); err != nil || r.ID != "z-example" {
		t.Errorf("by name = %+v, %v", r, err)
	}
	// By name in two profiles: ambiguous, --profile chooses.
	_, err = h.rt.ResolveResource(ctx, platform.NameCom, platform.ResZone, "shared.com")
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) || len(amb.Candidates) != 2 || !strings.Contains(err.Error(), "--profile") {
		t.Errorf("ambiguous = %v", err)
	}
	h.rt.Flags.Profile = "a"
	if r, err := h.rt.ResolveResource(ctx, platform.NameCom, platform.ResZone, "shared.com"); err != nil || r.ID != "z-shared-a" {
		t.Errorf("--profile = %+v, %v", r, err)
	}
	// A platform without the account under --profile: nothing to search.
	if _, err := h.rt.ResolveResource(ctx, platform.GoDaddy, platform.ResZone, "x"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("no account = %v", err)
	}
	h.rt.Flags.Profile = "nobody"
	if _, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "x"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown profile = %v", err)
	}
	h.rt.Flags.Profile = ""
}

func TestResolveResourceSyncsOnAMiss(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	// Nothing synced yet: a miss syncs the candidate accounts once.
	h.client("c").zones = []platform.Zone{zone("z-new", "new.example")}
	r, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "new.example")
	if err != nil || r.Profile != "c" || r.ID != "z-new" {
		t.Fatalf("after sync = %+v, %v", r, err)
	}
	// Fresh sets are not synced again for a name nobody has.
	before := h.client("c").count("Sync")
	if _, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "missing.example"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	if h.client("c").count("Sync") != before {
		t.Error("fresh sets were synced again")
	}
	// --offline never syncs.
	h.rt.Flags.Offline = true
	if _, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "missing.example"); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "--offline") {
		t.Errorf("offline = %v", err)
	}
}

func TestResolveResourcePlatformFlagAndHints(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	h.seedZones("c", zone("z-shared-c", "shared.com"))
	// On several platforms: the hint names --platform too.
	_, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "shared.com")
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) || !strings.Contains(err.Error(), "--platform") {
		t.Errorf("cross-platform ambiguity = %v", err)
	}
	// --platform narrows a platform-neutral lookup.
	h.rt.Flags.Platform = "godaddy"
	if r, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "shared.com"); err != nil || r.ID != "z-shared-c" {
		t.Errorf("--platform = %+v, %v", r, err)
	}
	h.rt.Flags.Platform = "nosuch"
	if _, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "shared.com"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("unknown --platform = %v", err)
	}
	h.rt.Flags.Platform = ""
}

func TestResolveResourceReportsAFailedSync(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	// The only account able to say cannot be listed: that is its error,
	// not "not found".
	h.rt.Flags.Profile = "c"
	h.client("c").syncErr = platform.ErrForbidden
	_, err := h.rt.ResolveResource(ctx, "", platform.ResZone, "new.example")
	if !errors.Is(err, platform.ErrForbidden) || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("failed sync = %v", err)
	}
}
