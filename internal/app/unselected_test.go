package app_test

import (
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestUnselectedIgnoresTheSelection(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "a", Platform: "namecom"}, nil)
	h.seedStandard()
	u, err := h.rt.Unselected()
	if err != nil {
		t.Fatal(err)
	}
	if u.Flags.Profile != "" || u.Flags.Platform != "" || h.rt.Flags.Profile != "a" || h.rt.Flags.Platform != "namecom" {
		t.Errorf("flags = %+v / %+v", u.Flags, h.rt.Flags)
	}
	// It shares the configuration and the inventory of rt.
	c1, _ := h.rt.Config()
	c2, _ := u.Config()
	d1, _ := h.rt.DB()
	d2, _ := u.DB()
	if c1 != c2 || d1 != d2 {
		t.Error("the copy must share the config and the inventory")
	}
	// A domain of profile b routes through the copy only.
	if _, err := u.ResolveDomain(ctx, "other.com", platform.ResZone); err != nil {
		t.Errorf("unselected routing = %v", err)
	}
}
