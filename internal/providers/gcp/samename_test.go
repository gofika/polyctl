package gcp

import (
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// sameNameHarness holds the regional load balancer of ensureHTTP
// (lb-web-1, fr-web-1, bs-web-1, check-80 in us-central1) and a global
// load balancer whose components carry the same names.
func sameNameHarness(t *testing.T) *gcpHarness {
	t.Helper()
	h := lbHarness(t, app.Flags{})
	ensureHTTP(t, h)
	h.gce.addCheck("global", "check-80", 443)
	h.gce.addBackend("global", "bs-web-1", "HTTP", "http", "check-80")
	h.gce.addURLMapTo("global", "lb-web-1", "bs-web-1")
	h.gce.addHTTPProxy("global", "proxy-global", "lb-web-1")
	h.gce.addRule("global", "fr-web-1", "targetHttpProxies/proxy-global", "34.7.7.7", "80-80", nil)
	h.rt.Flags.Refresh = true
	return h
}

// The commands that find a load balancer or one of its components by name.
var sameNameCommands = []struct {
	group, name string
	// regional and global are in the JSON of get for the object of that
	// scope only.
	regional, global string
}{
	{"load-balancer", "lb-web-1", `"scope": "regional"`, `"scope": "global"`},
	{"backend-service", "bs-web-1", `"region": "us-central1"`, `"scope": "global"`},
	{"forwarding-rule", "fr-web-1", `"region": "us-central1"`, `"ip_address": "34.7.7.7"`},
	{"health-check", "check-80", `"port": "80"`, `"port": "443"`},
}

// A regional and a global object of one name are two candidates: get and
// delete take neither on their own. The non-interactive flow is exit code
// 5 naming both and "--region <r> or --global", and writes nothing, also
// with --yes; either flag names one.
func TestSameNameInRegionalAndGlobalScope(t *testing.T) {
	for _, c := range sameNameCommands {
		t.Run(c.group, func(t *testing.T) {
			h := sameNameHarness(t)
			for _, verb := range [][]string{{"get"}, {"delete", "--yes"}, {"delete", "--yes", "--dry-run"}} {
				args := append([]string{"compute", c.group, verb[0], c.name}, verb[1:]...)
				h.rt.Flags.DryRun = slices.Contains(verb, "--dry-run")
				err := h.run(slices.DeleteFunc(args, func(a string) bool { return a == "--dry-run" })...)
				if exitClass(err) != "ambiguous" || !has(err, c.name, "us-central1", "global", "--region <r> or --global") {
					t.Errorf("%s without a scope flag = %v", verb[0], err)
				}
				if ops := h.gce.lbOps(); len(ops) != 0 {
					t.Errorf("an ambiguous name wrote %v", ops)
				}
			}
			h.rt.Flags.DryRun = false
			if err := h.run("compute", c.group, "get", c.name, "--region", "us-central1"); err != nil || !strings.Contains(h.stdout.String(), c.regional) || strings.Contains(h.stdout.String(), c.global) {
				t.Errorf("get --region = %v %s", err, h.stdout.String())
			}
			if err := h.run("compute", c.group, "get", c.name, "--global"); err != nil || !strings.Contains(h.stdout.String(), c.global) {
				t.Errorf("get --global = %v %s", err, h.stdout.String())
			}
		})
	}
}

// delete --global removes the global object and leaves the regional one of
// the same name, and the other way round.
func TestSameNameDeleteNamesTheScope(t *testing.T) {
	h := sameNameHarness(t)
	if err := h.run("compute", "load-balancer", "delete", "lb-web-1", "--global", "--yes"); err != nil {
		t.Fatal(err)
	}
	if h.gce.rule("global", "fr-web-1") != nil || h.gce.rule("us-central1", "fr-web-1") == nil {
		t.Error("load-balancer delete --global did not delete exactly the global load balancer")
	}
	// The regional one is the only lb-web-1 left: no flag is needed.
	if err := h.run("compute", "load-balancer", "get", "lb-web-1"); err != nil || !strings.Contains(h.stdout.String(), `"scope": "regional"`) {
		t.Errorf("get of the one left = %v %s", err, h.stdout.String())
	}

	h = sameNameHarness(t)
	if err := h.run("compute", "forwarding-rule", "delete", "fr-web-1", "--global", "--yes"); err != nil {
		t.Fatal(err)
	}
	if h.gce.rule("global", "fr-web-1") != nil || h.gce.rule("us-central1", "fr-web-1") == nil {
		t.Error("forwarding-rule delete --global did not delete exactly the global rule")
	}
	if err := h.run("compute", "forwarding-rule", "delete", "fr-web-1", "--yes"); err != nil || h.gce.rule("us-central1", "fr-web-1") != nil {
		t.Errorf("delete of the one left = %v", err)
	}
}

// On a terminal the two are a list to choose from, for get and for delete;
// delete then confirms the one chosen.
func TestSameNameIsAListOnATerminal(t *testing.T) {
	for _, c := range sameNameCommands {
		t.Run(c.group, func(t *testing.T) {
			h := sameNameHarness(t)
			h.rt.Flags.NonInteractiveSet = true
			p := h.interactive(prompttest.Label("global"))
			if err := h.run("compute", c.group, "get", c.name); err != nil || !strings.Contains(h.stdout.String(), c.global) {
				t.Fatalf("get = %v %s", err, h.stdout.String())
			}
			a := p.Asked[0]
			if !strings.HasPrefix(a.Title, "Ambiguous") || len(a.Options) != 2 {
				t.Errorf("asked %q with %d options", a.Title, len(a.Options))
			}
			p.Done()

			// delete: the list, then the confirmation of the one chosen,
			// which the empty stdin declines.
			p = h.interactive(prompttest.Label("global"))
			if err := h.run("compute", c.group, "delete", c.name); exitClass(err) != "nothing" {
				t.Fatalf("delete declined = %v", err)
			}
			if !strings.HasPrefix(p.Asked[0].Title, "Ambiguous") || !strings.Contains(h.stderr.String(), "global") {
				t.Errorf("prompts: %v, stderr: %s", p.Titles(), h.stderr.String())
			}
			p.Done()
			if ops := h.gce.lbOps(); len(ops) != 0 {
				t.Errorf("a declined delete wrote %v", ops)
			}
		})
	}
}
