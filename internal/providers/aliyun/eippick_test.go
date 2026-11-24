package aliyun

import (
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// eip address associate without the EIP and --instance offers the
// instances without a public address, then the idle EIPs of the region
// (bound, managed and busy ones left out) or a new one.
func TestEIPAssociatePicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := netHarness(t, app.Flags{})
	f.addInstance("i-1", "site-a", "vpc-main")
	f.addEIP("eip-1idle", "203.0.113.10", "Available", "", "", 0, "BGP_PRO")
	f.addEIP("eip-2used", "203.0.113.20", "InUse", "i-9", "EcsInstance", 0, "BGP_PRO")
	f.addEIP("eip-3managed", "203.0.113.30", "Available", "", "", 1, "BGP_PRO")
	p := prompttest.New(t, "i-1", "eip-1idle")
	h.rt.Picker = p
	if err := h.run("eip", "address", "associate"); err != nil {
		t.Fatalf("associate: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[1].Options); !strings.HasPrefix(v, "eip-1idle ") || strings.Contains(v, "eip-2used") || strings.Contains(v, "eip-3managed") {
		t.Errorf("EIPs offered %q", v)
	}
	if !slices.Equal(f.writes, []string{"AssociateEipAddress"}) {
		t.Errorf("writes = %v", f.writes)
	}
}

// "Allocate a new EIP..." allocates one and binds it; with no idle EIP the
// allocation is still a choice the user makes.
func TestEIPAssociateAllocates(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := netHarness(t, app.Flags{})
	f.addInstance("i-1", "site-a", "vpc-main")
	p := prompttest.New(t, prompttest.Label("Allocate a new EIP"))
	h.rt.Picker = p
	if err := h.run("eip", "address", "associate", "--instance", "site-a"); err != nil {
		t.Fatalf("associate: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if !slices.Equal(f.writes, []string{"AllocateEipAddress", "AssociateEipAddress"}) {
		t.Errorf("writes = %v", f.writes)
	}
}
