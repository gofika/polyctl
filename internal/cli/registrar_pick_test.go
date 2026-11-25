package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// The registrar commands without <domain> offer the domains of the profile
// they use; lock offers the unlocked ones only.
func TestRegistrarDomainPick(t *testing.T) {
	dir, cfgPath := setup(t, true)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["a"].Platforms[fakePlatform2] = &config.Account{CredentialBackend: "file"}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := creds.NewFile(dir).Set(creds.Key("a", string(fakePlatform2)), map[string]string{"token": "secret"}); err != nil {
		t.Fatal(err)
	}
	locked, open := true, false
	db := openInventory(t, dir)
	if err := db.Replace(t.Context(), inventory.Set{Platform: fakePlatform2, Profile: "a", Type: platform.ResDomain},
		app.DomainResources([]platform.Domain{{Name: "example.org", Status: "ACTIVE", Locked: &locked}, {Name: "open.org", Locked: &open}}), 3600e9); err != nil {
		t.Fatal(err)
	}
	db.Close()

	p := prompttest.New(t, "example.org")
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "godaddy", "domain", "get", "--offline")
	if r.err != nil || !strings.Contains(r.stdout, "example.org") {
		t.Fatalf("get: %v, %q", r.err, r.stderr)
	}
	if a := p.Find("Domain"); prompttest.Values(a.Options) != "example.org open.org" || a.Options[0].Label != "example.org  ACTIVE  -  locked  -  godaddy/a" || a.Options[1].Label != "open.org  -  -  -  -  godaddy/a" {
		t.Errorf("domain options %+v", a.Options)
	}
	p.Done()

	p = prompttest.New(t, "open.org")
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "godaddy", "domain", "lock", "--offline")
	if a := p.Find("Domain"); prompttest.Values(a.Options) != "open.org" {
		t.Errorf("lock options %+v (%v)", a.Options, r.err)
	}
	p.Done()

	// Non-interactive: unchanged.
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "godaddy", "domain", "get")
	if r.code != ExitUsage {
		t.Errorf("non-interactive: exit %d, %v", r.code, r.err)
	}
}
