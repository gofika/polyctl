package gcp

import (
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
)

func TestInstanceCreateSize(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, defaultsUS())
	// A preset size: resolved, checked in the zone, created with that type.
	if err := h.run("compute", "instance", "create", "web-1", "--machine-type", "4H4G", "--static-ip=false"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if in := h.gce.instance("us-central1-a", "web-1"); in == nil || lastSegment(in.MachineType) != "e2-highcpu-4" {
		t.Fatalf("instance = %+v", in)
	}
	if !strings.Contains(h.stderr.String(), "4H4G -> e2-highcpu-4 (us-central1-a, E2 predefined)") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	if r := rows(h.report()); len(r) < 2 || !strings.HasPrefix(r[1], "instance/web-1 created e2-highcpu-4 (4H4G), boot 10GB") {
		t.Errorf("rows = %v", r)
	}

	// A custom size in a dry run: resolved, reported, nothing written.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "create", "web-2", "--machine-type", "2h3g", "--static-ip=false"); err != nil || len(h.gce.writes()) != 0 {
		t.Fatalf("dry run = %v, writes %v\n%s", err, h.gce.writes(), h.stderr.String())
	}
	if r := rows(h.report()); len(r) < 2 || !strings.HasPrefix(r[1], "instance/web-2 would_create e2-custom-2-3072 (2h3g, E2 custom), boot") {
		t.Errorf("dry run rows = %v", r)
	}
	if !strings.Contains(h.stderr.String(), "2h3g -> e2-custom-2-3072 (us-central1-a, E2 custom)") {
		t.Errorf("dry run stderr = %s", h.stderr.String())
	}
	h.rt.Flags.DryRun = false

	// The custom size created for real.
	if err := h.run("compute", "instance", "create", "web-2", "--machine-type", "2H3G", "--static-ip=false"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if in := h.gce.instance("us-central1-a", "web-2"); in == nil || lastSegment(in.MachineType) != "e2-custom-2-3072" {
		t.Errorf("custom instance = %+v", in)
	}

	// An exact type is used as it is, checked once, with no note.
	if err := h.run("compute", "instance", "create", "web-3", "--machine-type", "e2-standard-4", "--static-ip=false"); err != nil {
		t.Fatal(err)
	}
	var gets []string
	for _, c := range h.gce.calls {
		if strings.Contains(c, "/machineTypes/") {
			gets = append(gets, lastSegment(c))
		}
	}
	if !slices.Equal(gets, []string{"e2-standard-4?alt=json&prettyPrint=false"}) || strings.Contains(h.stderr.String(), " -> ") {
		t.Errorf("exact type lookups = %v, stderr %s", gets, h.stderr.String())
	}

	// No fit (exit code 4) and a malformed size (exit code 2): nothing written.
	for _, tc := range []struct{ typ, want, msg string }{
		{"1H1G", "notfound", "nearest E2 size is 2H1G"},
		{"64H64G", "notfound", "32H64G"},
		{"0H2G", "usage", "at least 1"},
		{"2H0G", "usage", "more than 0 GiB"},
	} {
		err := h.run("compute", "instance", "create", "web-9", "--machine-type", tc.typ)
		if exitClass(err) != tc.want || !strings.Contains(err.Error(), tc.msg) || len(h.gce.writes()) != 0 {
			t.Errorf("create %s = %v (%s), writes %v", tc.typ, err, exitClass(err), h.gce.writes())
		}
	}
	// A malformed size is a usage error before the offline check.
	h.rt.Flags.Offline = true
	if err := h.run("compute", "instance", "create", "web-9", "--machine-type", "0H2G"); exitClass(err) != "usage" {
		t.Errorf("offline malformed = %v", err)
	}
	h.rt.Flags.Offline = false
}

func TestInstanceCreateSizeDefault(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, map[string]any{"zone": "us-central1-a", "machine_type": "2H2G"})
	if err := h.run("compute", "instance", "create", "web-1", "--static-ip=false"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if r := rows(h.report()); len(r) < 2 || !strings.HasPrefix(r[1], "instance/web-1 would_create e2-small (2H2G)") {
		t.Errorf("rows = %v", r)
	}
}

func TestInstanceResizeSize(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	off := h.gce.addInstance("proj", "us-central1-a", "off-1", "10.128.0.8", "")
	off.Status = statusTerminated

	// The instance (e2-small) already has the size: unchanged, nothing written.
	if err := h.run("compute", "instance", "resize", "off-1", "--machine-type", "2H2G"); err != nil || len(h.gce.writes()) != 0 {
		t.Fatalf("same size = %v, writes %v", err, h.gce.writes())
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/off-1/machine-type unchanged e2-small (2H2G)"}) {
		t.Errorf("same size rows = %v", r)
	}

	// Dry run of a preset size: resolved and reported, nothing written.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "resize", "off-1", "--machine-type", "2H8G"); err != nil || len(h.gce.writes()) != 0 {
		t.Fatalf("dry run = %v, writes %v", err, h.gce.writes())
	}
	if r := rows(h.report()); !slices.Equal(r, []string{"instance/off-1/machine-type would_update e2-small -> e2-standard-2 (2H8G)"}) {
		t.Errorf("dry run rows = %v", r)
	}
	if !strings.Contains(h.stderr.String(), "2H8G -> e2-standard-2 (us-central1-a, E2 predefined)") {
		t.Errorf("dry run stderr = %s", h.stderr.String())
	}
	h.rt.Flags.DryRun = false

	// A custom size for real.
	if err := h.run("compute", "instance", "resize", "off-1", "--machine-type", "4H6G"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if got := h.gce.writes(); !slices.Equal(got, []string{"POST instances/off-1/setMachineType"}) {
		t.Errorf("writes = %v", got)
	}
	if in := h.gce.instance("us-central1-a", "off-1"); lastSegment(in.MachineType) != "e2-custom-4-6144" {
		t.Errorf("machine type = %s", in.MachineType)
	}

	// No fit: exit code 4; malformed: exit code 2; nothing written.
	if err := h.run("compute", "instance", "resize", "off-1", "--machine-type", "3H6G"); exitClass(err) != "notfound" || len(h.gce.writes()) != 0 {
		t.Errorf("no fit = %v, writes %v", err, h.gce.writes())
	}
	if err := h.run("compute", "instance", "resize", "off-1", "--machine-type", "0H6G"); exitClass(err) != "usage" || len(h.gce.writes()) != 0 {
		t.Errorf("malformed = %v, writes %v", err, h.gce.writes())
	}
}

func TestInstanceResizeSizeInteractive(t *testing.T) {
	h := newGCPHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = &scriptedPicker{t: t}
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.5", "")
	h.rt.Stdin = strings.NewReader("n\n")
	if err := h.run("compute", "instance", "resize", "web-1", "--machine-type", "2H4G"); exitClass(err) != "nothing" || len(h.gce.writes()) != 0 {
		t.Errorf("declined = %v, writes %v", err, h.gce.writes())
	}
	if !strings.Contains(h.stderr.String(), "from e2-small to e2-medium") {
		t.Errorf("confirmation = %s", h.stderr.String())
	}
}
