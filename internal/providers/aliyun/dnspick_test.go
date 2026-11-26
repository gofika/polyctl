package aliyun

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// seedZones records fresh alidns zones (and registered domains) of the
// harness account in the inventory, so the pickers read them without a
// sync.
func seedZones(t *testing.T, h *harness, kind platform.ResourceType, names ...string) {
	t.Helper()
	var res []platform.Resource
	if kind == platform.ResZone {
		var zones []platform.Zone
		for _, n := range names {
			zones = append(zones, platform.Zone{ID: n, Name: n})
		}
		res = app.ZoneResources(zones)
	} else {
		var ds []platform.Domain
		for _, n := range names {
			ds = append(ds, platform.Domain{Name: n, Status: "3"})
		}
		res = app.DomainResources(ds)
	}
	if err := h.db().Replace(context.Background(), inventory.Set{Platform: platform.Aliyun, Profile: "ali", Type: kind}, res, time.Hour); err != nil {
		t.Fatal(err)
	}
}

// On a terminal, dns record create without <domain>, --type and --value
// asks for the zone, the type and the value (checked as it is typed).
func TestDNSRecordCreateInteractive(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h := newHarness(t, app.Flags{})
	seedZones(t, h, platform.ResZone, "example.com", "other.example")
	var added url.Values
	h.api.on("AddDomainRecord", func(q url.Values) (int, any) {
		added = q
		return 200, map[string]any{"RecordId": "9001"}
	})
	h.api.on("DescribeDomainRecordInfo", func(q url.Values) (int, any) {
		return 200, map[string]any{"RecordId": "9001", "RR": "www", "Type": "A", "Value": "203.0.113.9", "TTL": 600, "DomainName": "example.com"}
	})
	p := prompttest.New(t, "example.com", "A", "not-an-ip", "203.0.113.9")
	h.rt.Picker = p
	if err := h.run("dns", "record", "create", "--name", "www"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if added.Get("DomainName") != "example.com" || added.Get("Type") != "A" || added.Get("Value") != "203.0.113.9" {
		t.Errorf("AddDomainRecord = %v", added)
	}

	// The non-interactive flow gets the usage of the positional record.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("dns", "record", "create", "example.com"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "usage: aliyun dns record create <domain> <name> <type> <value>") {
		t.Errorf("non-interactive = %v", err)
	}
	// cobra refuses the missing argument (the command tree reports it as a
	// usage error).
	if err := h.run("dns", "record", "list"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive list without <domain> = %v", err)
	}
}

// dns record delete without arguments asks for the zone and the record;
// leaving the list changes nothing.
func TestDNSRecordDeleteInteractive(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h := newHarness(t, app.Flags{})
	seedZones(t, h, platform.ResZone, "example.com")
	h.api.on("DescribeDomainRecords", func(q url.Values) (int, any) {
		return 200, map[string]any{"TotalCount": 1, "DomainRecords": map[string]any{"Record": []map[string]any{
			{"RecordId": "77", "RR": "www", "Type": "A", "Value": "203.0.113.9", "TTL": 600, "DomainName": "example.com"}}}}
	})
	deleted := ""
	h.api.on("DeleteDomainRecord", func(q url.Values) (int, any) {
		deleted = q.Get("RecordId")
		return 200, map[string]any{"RecordId": deleted}
	})
	p := prompttest.New(t, "example.com", "77")
	h.rt.Picker = p
	if err := h.run("dns", "record", "delete"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	p.Done()
	if deleted != "77" {
		t.Errorf("deleted %q", deleted)
	}
	if l := prompttest.Labels(p.Find("Record to delete").Options); !strings.Contains(l, "www.example.com  A  203.0.113.9") {
		t.Errorf("record labels: %s", l)
	}

	deleted = ""
	h.rt.Picker = prompttest.New(t, "example.com", prompttest.Abort{})
	if err := h.run("dns", "record", "delete"); !errors.Is(err, prompt.ErrAborted) || deleted != "" {
		t.Errorf("abort = %v (deleted %q)", err, deleted)
	}
}

// An empty zone list is nothing to do for a command reading a zone, and a
// usage error naming <domain> for create.
func TestDNSRecordPickEmpty(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h := newHarness(t, app.Flags{Offline: true})
	seedZones(t, h, platform.ResZone)
	h.rt.Picker = prompttest.New(t)
	if err := h.run("dns", "record", "list"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("list = %v, want nothing to do", err)
	}
	h.rt.Picker = prompttest.New(t)
	if err := h.run("dns", "record", "create", "--type", "A", "--value", "203.0.113.9"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "<domain>") {
		t.Errorf("create = %v, want a usage error naming <domain>", err)
	}
}

// domain get asks for the registered domain.
func TestDomainGetInteractive(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h := newHarness(t, app.Flags{Offline: true})
	seedZones(t, h, platform.ResDomain, "d1.example", "d2.example")
	p := prompttest.New(t, "d2.example")
	h.rt.Picker = p
	if err := h.run("domain", "get"); err != nil {
		t.Fatal(err)
	}
	p.Done()
	var out platform.Domain
	h.jsonOut(&out)
	if out.Name != "d2.example" {
		t.Errorf("got %+v", out)
	}
}
