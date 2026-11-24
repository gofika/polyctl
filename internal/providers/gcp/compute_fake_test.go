package gcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

const apiBase = "https://www.googleapis.com/compute/v1/"

// fakeErr is an error the fake answers at submission.
type fakeErr struct {
	code    int
	reason  string
	message string
}

// fakeCompute emulates the slice of the Compute Engine REST API the
// instance commands use, for one or more projects, in memory.
type fakeCompute struct {
	t   *testing.T
	srv *httptest.Server

	mu           sync.Mutex
	instances    map[string]*compute.Instance // project/zone/name
	addresses    map[string]*compute.Address  // project/region/name
	disks        map[string]*compute.Disk     // project/zone/name
	images       map[string][]*compute.Image  // image project
	machineTypes map[string]bool              // zone/type
	// machineArch is the Architecture the fake reports for a machine type
	// name (none by default, as the API leaves it out for some types).
	machineArch map[string]string
	networks    map[string]*compute.Network // project/name
	subnets     map[string][]*compute.Subnetwork
	projectMeta map[string]*compute.Metadata
	firewalls   map[string]*compute.Firewall // project/name
	// forwardingRules are listed by the aggregated list, per project, as
	// given (global rules have no region).
	forwardingRules map[string][]*compute.ForwardingRule
	// busy maps the operation of a firewall write that was not waited for
	// yet to the rule it writes (writes to a busy rule are not ready).
	busy  map[string]string
	ops   map[string]*compute.Operation
	calls []string
	// fail answers an error to requests whose "METHOD path" contains the key.
	fail map[string]fakeErr
	// opFail makes the operation of an action ("insert", "stop", ...) fail.
	opFail map[string]compute.OperationErrorErrors
	// staleFingerprints makes the next n Update calls see a stale fingerprint.
	staleFingerprints int
	// staleTags makes the next n SetTags calls see tags changed meanwhile.
	staleTags int
	// updates records the query of every instance Update.
	updates []string
	// stuck leaves instances in the status they reach after an action
	// ("stop" -> STOPPING) so waits time out.
	stuck map[string]string
	seq   int
	// lbState holds the load balancer resources (sslcert_fake_test.go).
	lbState *lbFake
	// lbParts holds the other load balancer components (lb_fake_test.go).
	lbParts *lbParts
}

func newFakeCompute(t *testing.T) *fakeCompute {
	f := &fakeCompute{t: t,
		instances: map[string]*compute.Instance{}, addresses: map[string]*compute.Address{}, disks: map[string]*compute.Disk{},
		images: map[string][]*compute.Image{}, machineTypes: map[string]bool{}, machineArch: map[string]string{}, networks: map[string]*compute.Network{},
		subnets: map[string][]*compute.Subnetwork{}, projectMeta: map[string]*compute.Metadata{}, ops: map[string]*compute.Operation{},
		firewalls: map[string]*compute.Firewall{}, busy: map[string]string{},
		fail: map[string]fakeErr{}, opFail: map[string]compute.OperationErrorErrors{}, stuck: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	// Like most projects, the fake one holds an SSH key in its metadata,
	// which a Linux instance created without a key of its own accepts.
	projectKey := "ops:" + testPublicKey(t, "ops")
	f.projectMeta["proj"] = &compute.Metadata{Items: []*compute.MetadataItems{{Key: "ssh-keys", Value: &projectKey}}}
	for _, z := range []string{"us-central1-a", "us-central1-b", "europe-west1-b"} {
		for _, p := range e2Presets {
			f.machineTypes[z+"/"+p.Name] = true
		}
	}
	f.networks["proj/default"] = &compute.Network{Name: "default", AutoCreateSubnetworks: true}
	f.subnets["proj/us-central1"] = []*compute.Subnetwork{{Name: "default", Network: apiBase + "projects/proj/global/networks/default", IpCidrRange: "10.128.0.0/20"}}
	f.images["debian-cloud"] = []*compute.Image{
		{Name: "debian-12-bookworm-v20261117", Architecture: "X86_64", DiskSizeGb: 10, CreationTimestamp: "2026-11-17T00:00:00.000-08:00"},
		{Name: "debian-13-trixie-v20261116", Architecture: "X86_64", DiskSizeGb: 10, CreationTimestamp: "2026-11-16T00:00:00.000-08:00"},
		{Name: "debian-13-trixie-arm64-v20261116", Architecture: "ARM64", DiskSizeGb: 10, CreationTimestamp: "2026-11-16T00:00:00.000-08:00"},
	}
	f.images["ubuntu-os-cloud"] = []*compute.Image{
		{Name: "ubuntu-2404-noble-amd64-v20261101", Architecture: "X86_64", DiskSizeGb: 10, CreationTimestamp: "2026-11-01T00:00:00.000-08:00"},
		{Name: "ubuntu-2604-resolute-amd64-v20261107", Architecture: "X86_64", DiskSizeGb: 10, CreationTimestamp: "2026-11-07T00:00:00.000-08:00"},
		{Name: "ubuntu-2610-interim-amd64-v20261110", Architecture: "X86_64", DiskSizeGb: 10, CreationTimestamp: "2026-11-10T00:00:00.000-08:00"},
	}
	f.images["windows-cloud"] = []*compute.Image{
		{Name: "windows-server-2025-dc-v20261101", Architecture: "X86_64", DiskSizeGb: 50, CreationTimestamp: "2026-11-01T00:00:00.000-08:00"},
	}
	return f
}

func (f *fakeCompute) options() []option.ClientOption {
	return []option.ClientOption{option.WithEndpoint(f.srv.URL + "/")}
}

func (f *fakeCompute) next() int { f.seq++; return f.seq }

// writes lists the write requests made so far ("POST .../instances").
func (f *fakeCompute) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if (strings.HasPrefix(c, "POST ") || strings.HasPrefix(c, "DELETE ") || strings.HasPrefix(c, "PUT ")) && !strings.Contains(c, "/wait") && !strings.Contains(c, "/token") {
			method, path, _ := strings.Cut(c, " ")
			path, _, _ = strings.Cut(path, "?")
			parts := strings.Split(strings.Trim(path, "/"), "/")
			tail := path
			for i, p := range parts {
				if p == "instances" || p == "addresses" {
					tail = strings.Join(parts[i:], "/")
					break
				}
			}
			out = append(out, method+" "+tail)
		}
	}
	return out
}

func (f *fakeCompute) instance(zone, name string) *compute.Instance {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.instances["proj/"+zone+"/"+name]
}

func (f *fakeCompute) address(region, name string) *compute.Address {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a := f.addresses["proj/"+region+"/"+name]; a != nil {
		cp := *a
		f.addressStatus("proj", &cp)
		return &cp
	}
	return nil
}

// addInstance puts a running instance with a boot disk into the fake.
func (f *fakeCompute) addInstance(project, zone, name, internal, external string) *compute.Instance {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uint64(1000 + f.next())
	region := regionOf(zone)
	boot := name + "-boot"
	f.disks[project+"/"+zone+"/"+boot] = &compute.Disk{Name: boot, SizeGb: 10, Type: apiBase + "projects/" + project + "/zones/" + zone + "/diskTypes/pd-balanced"}
	in := &compute.Instance{Name: name, Id: id, Status: statusRunning, Fingerprint: "fp-1",
		Zone:        apiBase + "projects/" + project + "/zones/" + zone,
		SelfLink:    apiBase + "projects/" + project + "/zones/" + zone + "/instances/" + name,
		MachineType: apiBase + "projects/" + project + "/zones/" + zone + "/machineTypes/e2-small",
		NetworkInterfaces: []*compute.NetworkInterface{{Network: apiBase + "projects/" + project + "/global/networks/default",
			Subnetwork: apiBase + "projects/" + project + "/regions/" + region + "/subnetworks/default", NetworkIP: internal,
			AccessConfigs: []*compute.AccessConfig{{Name: "External NAT", Type: "ONE_TO_ONE_NAT", NatIP: external}}}},
		Disks: []*compute.AttachedDisk{{Boot: true, AutoDelete: true, Type: "PERSISTENT", DiskSizeGb: 10,
			Source: apiBase + "projects/" + project + "/zones/" + zone + "/disks/" + boot}},
		Tags:              &compute.Tags{Items: []string{"web"}},
		CreationTimestamp: "2026-11-17T10:00:00.000-08:00",
	}
	f.instances[project+"/"+zone+"/"+name] = in
	return in
}

// addAddress reserves an address in the fake.
func (f *fakeCompute) addAddress(region string, a *compute.Address) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a.Subnetwork != "" && !strings.HasPrefix(a.Subnetwork, "https://") {
		a.Subnetwork = apiBase + "projects/proj/regions/" + region + "/subnetworks/" + a.Subnetwork
	}
	f.addresses["proj/"+region+"/"+a.Name] = a
}

func writeJSONStatus(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, e fakeErr) {
	body := map[string]any{"code": e.code, "message": e.message}
	if e.reason != "" {
		body["errors"] = []map[string]any{{"reason": e.reason, "message": e.message, "domain": "global"}}
	}
	writeJSONStatus(w, e.code, map[string]any{"error": body})
}

func notFound(w http.ResponseWriter, what string) {
	apiError(w, fakeErr{404, "notFound", "The resource '" + what + "' was not found"})
}

// op records a finished-later operation of an action.
func (f *fakeCompute) op(action, target string) *compute.Operation {
	op := &compute.Operation{Name: fmt.Sprintf("op-%d", f.next()), OperationType: action, Status: "RUNNING", TargetLink: target}
	if e, ok := f.opFail[action]; ok {
		ee := e
		op.Error = &compute.OperationError{Errors: []*compute.OperationErrorErrors{&ee}}
	}
	f.ops[op.Name] = op
	return op
}

// addressStatus fills in the status and users of an address from the
// instances that use its IP.
func (f *fakeCompute) addressStatus(project string, a *compute.Address) {
	a.Status, a.Users = addrReserved, nil
	for key, in := range f.instances {
		if !strings.HasPrefix(key, project+"/") {
			continue
		}
		for _, nic := range in.NetworkInterfaces {
			used := addressType(a) == addrInternal && nic.NetworkIP == a.Address
			for _, ac := range nic.AccessConfigs {
				if addressType(a) == addrExternal && ac.NatIP == a.Address {
					used = true
				}
			}
			if used {
				a.Status, a.Users = addrInUse, []string{in.SelfLink}
			}
		}
	}
}

func (f *fakeCompute) staticExternal(project, ip string) bool {
	for key, a := range f.addresses {
		if strings.HasPrefix(key, project+"/") && a.Address == ip && addressType(a) == addrExternal {
			return true
		}
	}
	return false
}

func (f *fakeCompute) internalInUse(project, ip, except string) bool {
	for key, in := range f.instances {
		if strings.HasPrefix(key, project+"/") && in.Name != except {
			for _, nic := range in.NetworkInterfaces {
				if nic.NetworkIP == ip {
					return true
				}
			}
		}
	}
	return false
}

func (f *fakeCompute) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := r.Method + " " + r.URL.RequestURI()
	f.calls = append(f.calls, call)
	path := r.URL.Path
	if path == "/token" {
		writeJSONStatus(w, 200, map[string]any{"access_token": "sa-token", "token_type": "Bearer", "expires_in": 3600})
		return
	}
	for key, e := range f.fail {
		if strings.Contains(r.Method+" "+path, key) {
			apiError(w, e)
			return
		}
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || parts[0] != "projects" {
		http.NotFound(w, r)
		return
	}
	project := parts[1]
	rest := parts[2:]
	if f.handleLB(w, r, project, rest) {
		return
	}
	switch {
	case len(rest) == 0:
		writeJSONStatus(w, 200, &compute.Project{Name: project, CommonInstanceMetadata: f.projectMeta[project]})
	case len(rest) >= 2 && rest[0] == "global" && rest[1] == "images":
		f.handleImages(w, project, rest[2:], r.URL.Query().Get("pageToken"))
	case len(rest) == 2 && rest[0] == "aggregated" && rest[1] == "instances":
		items := map[string]compute.InstancesScopedList{}
		for key, in := range f.instances {
			if strings.HasPrefix(key, project+"/") {
				z := "zones/" + lastSegment(in.Zone)
				l := items[z]
				l.Instances = append(l.Instances, in)
				items[z] = l
			}
		}
		writeJSONStatus(w, 200, &compute.InstanceAggregatedList{Items: items})
	case len(rest) == 2 && rest[0] == "aggregated" && rest[1] == "forwardingRules":
		items := map[string]compute.ForwardingRulesScopedList{}
		for _, fr := range f.forwardingRules[project] {
			scope := "global"
			if fr.Region != "" {
				scope = "regions/" + lastSegment(fr.Region)
			}
			l := items[scope]
			l.ForwardingRules = append(l.ForwardingRules, fr)
			items[scope] = l
		}
		items["regions/asia-east2"] = compute.ForwardingRulesScopedList{Warning: &compute.ForwardingRulesScopedListWarning{Code: "NO_RESULTS_ON_PAGE"}}
		writeJSONStatus(w, 200, &compute.ForwardingRuleAggregatedList{Items: items})
	case len(rest) == 2 && rest[0] == "aggregated" && rest[1] == "addresses":
		items := map[string]compute.AddressesScopedList{}
		for key, a := range f.addresses {
			p, region, _ := strings.Cut(key, "/")
			region, _, _ = strings.Cut(region, "/")
			if p != project {
				continue
			}
			cp := *a
			f.addressStatus(project, &cp)
			scope := "regions/" + region
			if region == "global" {
				scope = "global"
			}
			l := items[scope]
			l.Addresses = append(l.Addresses, &cp)
			items[scope] = l
		}
		writeJSONStatus(w, 200, &compute.AddressAggregatedList{Items: items})
	case len(rest) >= 2 && rest[0] == "global" && rest[1] == "firewalls":
		f.handleFirewalls(w, r, project, rest[2:])
	case len(rest) >= 3 && rest[0] == "global" && rest[1] == "operations":
		op := f.ops[rest[2]]
		if op == nil {
			notFound(w, "operations/"+rest[2])
			return
		}
		op.Status = "DONE"
		delete(f.busy, op.Name)
		writeJSONStatus(w, 200, op)
	case len(rest) == 2 && rest[0] == "global" && rest[1] == "networks":
		var keys []string
		for k := range f.networks {
			if strings.HasPrefix(k, project+"/") {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var items []*compute.Network
		for _, k := range keys {
			items = append(items, f.networks[k])
		}
		writeJSONStatus(w, 200, &compute.NetworkList{Items: items})
	case len(rest) == 2 && rest[0] == "aggregated" && rest[1] == "subnetworks":
		items := map[string]compute.SubnetworksScopedList{}
		for key, list := range f.subnets {
			if p, region, ok := strings.Cut(key, "/"); ok && p == project {
				items["regions/"+region] = compute.SubnetworksScopedList{Subnetworks: list}
			}
		}
		writeJSONStatus(w, 200, &compute.SubnetworkAggregatedList{Items: items})
	case len(rest) == 3 && rest[0] == "global" && rest[1] == "networks":
		if n := f.networks[project+"/"+rest[2]]; n != nil {
			writeJSONStatus(w, 200, n)
			return
		}
		notFound(w, "networks/"+rest[2])
	case len(rest) >= 4 && rest[0] == "zones" && rest[2] == "operations" || len(rest) >= 4 && rest[0] == "regions" && rest[2] == "operations":
		op := f.ops[rest[3]]
		if op == nil {
			notFound(w, "operations/"+rest[3])
			return
		}
		op.Status = "DONE"
		writeJSONStatus(w, 200, op)
	case len(rest) == 4 && rest[0] == "zones" && rest[2] == "machineTypes":
		if f.machineTypes[rest[1]+"/"+rest[3]] {
			cores, mem := fakeMachineShape(rest[3])
			writeJSONStatus(w, 200, &compute.MachineType{Name: rest[3], GuestCpus: int64(cores), MemoryMb: int64(mem), Architecture: f.machineArch[rest[3]]})
			return
		}
		notFound(w, "machineTypes/"+rest[3])
	case len(rest) == 4 && rest[0] == "zones" && rest[2] == "disks":
		if d := f.disks[project+"/"+rest[1]+"/"+rest[3]]; d != nil {
			writeJSONStatus(w, 200, d)
			return
		}
		notFound(w, "disks/"+rest[3])
	case len(rest) >= 3 && rest[0] == "zones" && rest[2] == "instances":
		f.handleInstances(w, r, project, rest[1], rest[3:])
	case len(rest) >= 3 && rest[0] == "regions" && rest[2] == "addresses":
		f.handleAddresses(w, r, project, rest[1], rest[3:])
	case len(rest) >= 3 && rest[0] == "regions" && rest[2] == "subnetworks":
		list := f.subnets[project+"/"+rest[1]]
		if len(rest) == 4 {
			for _, s := range list {
				if s.Name == rest[3] {
					writeJSONStatus(w, 200, s)
					return
				}
			}
			notFound(w, "subnetworks/"+rest[3])
			return
		}
		writeJSONStatus(w, 200, &compute.SubnetworkList{Items: list})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCompute) handleImages(w http.ResponseWriter, project string, rest []string, pageToken string) {
	list := f.images[project]
	switch {
	case len(rest) == 0:
		// Two pages, to exercise paging.
		half := (len(list) + 1) / 2
		if pageToken == "p2" {
			writeJSONStatus(w, 200, &compute.ImageList{Items: list[half:]})
			return
		}
		next := ""
		if half < len(list) {
			next = "p2"
		}
		writeJSONStatus(w, 200, &compute.ImageList{Items: list[:half], NextPageToken: next})
	case len(rest) == 1:
		for _, im := range list {
			if im.Name == rest[0] {
				writeJSONStatus(w, 200, im)
				return
			}
		}
		notFound(w, "images/"+rest[0])
	case len(rest) == 2 && rest[0] == "family":
		for _, im := range list {
			if strings.HasPrefix(im.Name, rest[1]) {
				writeJSONStatus(w, 200, im)
				return
			}
		}
		notFound(w, "images/family/"+rest[1])
	default:
		notFound(w, strings.Join(rest, "/"))
	}
}

func (f *fakeCompute) handleInstances(w http.ResponseWriter, r *http.Request, project, zone string, rest []string) {
	region := regionOf(zone)
	if len(rest) == 0 {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var in compute.Instance
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			apiError(w, fakeErr{400, "invalid", err.Error()})
			return
		}
		key := project + "/" + zone + "/" + in.Name
		if f.instances[key] != nil {
			apiError(w, fakeErr{409, "alreadyExists", "The resource 'instances/" + in.Name + "' already exists"})
			return
		}
		mt := lastSegment(in.MachineType)
		if !f.hasMachineType(zone, mt) {
			apiError(w, fakeErr{400, "invalid", "Invalid value for field 'resource.machineType': Machine type with name '" + mt + "' does not exist in zone '" + zone + "'."})
			return
		}
		op := f.op("insert", apiBase+"projects/"+project+"/zones/"+zone+"/instances/"+in.Name)
		if op.Error != nil {
			writeJSONStatus(w, 200, op)
			return
		}
		nic := in.NetworkInterfaces[0]
		if nic.NetworkIP != "" && f.internalInUse(project, nic.NetworkIP, "") {
			op.Error = &compute.OperationError{Errors: []*compute.OperationErrorErrors{{Code: "IP_IN_USE_BY_ANOTHER_RESOURCE", Message: "IP '" + nic.NetworkIP + "' is already being used by another resource."}}}
			writeJSONStatus(w, 200, op)
			return
		}
		in.Id = uint64(5000 + f.next())
		in.Status = statusRunning
		in.Fingerprint = "fp-1"
		in.Zone = apiBase + "projects/" + project + "/zones/" + zone
		in.SelfLink = in.Zone + "/instances/" + in.Name
		in.MachineType = in.Zone + "/machineTypes/" + mt
		in.CreationTimestamp = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		nic.Network = apiBase + "projects/" + project + "/" + nic.Network
		if nic.Subnetwork == "" {
			nic.Subnetwork = "regions/" + region + "/subnetworks/default"
		}
		nic.Subnetwork = apiBase + "projects/" + project + "/" + nic.Subnetwork
		if nic.NetworkIP == "" {
			nic.NetworkIP = fmt.Sprintf("10.128.0.%d", f.next())
		}
		for _, ac := range nic.AccessConfigs {
			if ac.NatIP == "" {
				ac.NatIP = fmt.Sprintf("34.1.0.%d", f.next())
			}
		}
		for _, d := range in.Disks {
			p := d.InitializeParams
			d.Source = in.Zone + "/disks/" + p.DiskName
			d.DiskSizeGb = p.DiskSizeGb
			f.disks[project+"/"+zone+"/"+p.DiskName] = &compute.Disk{Name: p.DiskName, SizeGb: p.DiskSizeGb, SourceImage: p.SourceImage,
				Type: apiBase + "projects/" + project + "/" + p.DiskType}
			d.InitializeParams = nil
		}
		if in.Tags != nil {
			sort.Strings(in.Tags.Items)
		}
		if s := f.stuck["insert"]; s != "" {
			in.Status = s
		}
		f.instances[key] = &in
		writeJSONStatus(w, 200, op)
		return
	}
	key := project + "/" + zone + "/" + rest[0]
	in := f.instances[key]
	if in == nil {
		for _, cand := range f.instances {
			if strconv.FormatUint(cand.Id, 10) == rest[0] && lastSegment(cand.Zone) == zone {
				in = cand
			}
		}
	}
	if in == nil {
		notFound(w, "projects/"+project+"/zones/"+zone+"/instances/"+rest[0])
		return
	}
	if in.Tags == nil {
		in.Tags = &compute.Tags{}
	}
	if in.Tags.Fingerprint == "" {
		in.Tags.Fingerprint = "tags-1"
	}
	if len(rest) == 1 {
		switch r.Method {
		case http.MethodGet:
			writeJSONStatus(w, 200, in)
		case http.MethodDelete:
			op := f.op("delete", in.SelfLink)
			if op.Error == nil {
				delete(f.instances, project+"/"+zone+"/"+in.Name)
				for _, d := range in.Disks {
					if d.AutoDelete {
						delete(f.disks, project+"/"+zone+"/"+lastSegment(d.Source))
					}
				}
			}
			writeJSONStatus(w, 200, op)
		case http.MethodPut:
			var body compute.Instance
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return
			}
			f.updates = append(f.updates, r.URL.RawQuery)
			if f.staleFingerprints > 0 {
				f.staleFingerprints--
				in.Fingerprint += "x"
			}
			if body.Fingerprint != in.Fingerprint {
				apiError(w, fakeErr{400, "invalid", "Fingerprint mismatch, some instance properties may have changed. Please retry."})
				return
			}
			if a := r.URL.Query().Get("mostDisruptiveAllowedAction"); a == "NO_EFFECT" {
				apiError(w, fakeErr{400, "invalid", "Invalid value for field 'mostDisruptiveAllowedAction': 'NO_EFFECT'. 'canIpForward' changed. Insufficient allowed action to perform the update. Required action: REFRESH."})
				return
			}
			in.CanIpForward = body.CanIpForward
			in.Fingerprint = fmt.Sprintf("fp-%d", f.next())
			writeJSONStatus(w, 200, f.op("update", in.SelfLink))
		default:
			http.NotFound(w, r)
		}
		return
	}
	action := rest[1]
	switch action {
	case "setTags":
		var body compute.Tags
		_ = json.NewDecoder(r.Body).Decode(&body)
		if f.staleTags > 0 {
			f.staleTags--
			in.Tags.Items = append(in.Tags.Items, "other")
			sort.Strings(in.Tags.Items)
			in.Tags.Fingerprint = fmt.Sprintf("tags-%d", f.next())
		}
		if body.Fingerprint != in.Tags.Fingerprint {
			apiError(w, fakeErr{412, "conditionNotMet", "Tags fingerprint either invalid or resource tags have changed"})
			return
		}
		items := append([]string(nil), body.Items...)
		sort.Strings(items)
		in.Tags = &compute.Tags{Items: items, Fingerprint: fmt.Sprintf("tags-%d", f.next())}
		writeJSONStatus(w, 200, f.op("setTags", in.SelfLink))
	case "stop":
		op := f.op("stop", in.SelfLink)
		if op.Error == nil {
			in.Status = statusTerminated
			if s := f.stuck["stop"]; s != "" {
				in.Status = s
			}
			for _, ac := range in.NetworkInterfaces[0].AccessConfigs {
				if !f.staticExternal(project, ac.NatIP) {
					ac.NatIP = ""
				}
			}
		}
		writeJSONStatus(w, 200, op)
	case "start":
		op := f.op("start", in.SelfLink)
		if op.Error == nil {
			in.Status = statusRunning
			for _, ac := range in.NetworkInterfaces[0].AccessConfigs {
				if ac.NatIP == "" {
					ac.NatIP = fmt.Sprintf("34.9.0.%d", f.next())
				}
			}
		}
		writeJSONStatus(w, 200, op)
	case "reset":
		if in.Status != statusRunning {
			apiError(w, fakeErr{400, "resourceNotReady", "The resource '" + in.SelfLink + "' is not ready"})
			return
		}
		writeJSONStatus(w, 200, f.op("reset", in.SelfLink))
	case "setMachineType":
		var body compute.InstancesSetMachineTypeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		mt := lastSegment(body.MachineType)
		if !f.hasMachineType(zone, mt) {
			apiError(w, fakeErr{400, "invalid", "Machine type with name '" + mt + "' does not exist in zone '" + zone + "'."})
			return
		}
		op := f.op("setMachineType", in.SelfLink)
		if in.Status == statusRunning {
			op.Error = &compute.OperationError{Errors: []*compute.OperationErrorErrors{{Code: "UNSUPPORTED_OPERATION", Message: "Instance is starting or running."}}}
		} else if op.Error == nil {
			in.MachineType = apiBase + "projects/" + project + "/zones/" + zone + "/machineTypes/" + mt
		}
		writeJSONStatus(w, 200, op)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCompute) handleAddresses(w http.ResponseWriter, r *http.Request, project, region string, rest []string) {
	prefix := project + "/" + region + "/"
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			var items []*compute.Address
			var keys []string
			for k := range f.addresses {
				if strings.HasPrefix(k, prefix) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				cp := *f.addresses[k]
				f.addressStatus(project, &cp)
				items = append(items, &cp)
			}
			writeJSONStatus(w, 200, &compute.AddressList{Items: items})
		case http.MethodPost:
			var a compute.Address
			if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return
			}
			if f.addresses[prefix+a.Name] != nil {
				apiError(w, fakeErr{409, "alreadyExists", "The resource 'addresses/" + a.Name + "' already exists"})
				return
			}
			op := f.op("insertAddress", apiBase+"projects/"+project+"/regions/"+region+"/addresses/"+a.Name)
			if op.Error == nil {
				if a.Address == "" {
					if addressType(&a) == addrInternal {
						a.Address = fmt.Sprintf("10.128.1.%d", f.next())
					} else {
						a.Address = fmt.Sprintf("198.51.100.%d", f.next())
					}
				}
				if a.Subnetwork != "" && !strings.HasPrefix(a.Subnetwork, "https://") {
					a.Subnetwork = apiBase + strings.TrimPrefix(a.Subnetwork, "/")
				}
				f.addresses[prefix+a.Name] = &a
			}
			writeJSONStatus(w, 200, op)
		default:
			http.NotFound(w, r)
		}
		return
	}
	a := f.addresses[prefix+rest[0]]
	if a == nil {
		notFound(w, "addresses/"+rest[0])
		return
	}
	switch r.Method {
	case http.MethodGet:
		cp := *a
		f.addressStatus(project, &cp)
		writeJSONStatus(w, 200, &cp)
	case http.MethodDelete:
		delete(f.addresses, prefix+rest[0])
		writeJSONStatus(w, 200, f.op("deleteAddress", apiBase+"projects/"+project+"/regions/"+region+"/addresses/"+rest[0]))
	default:
		http.NotFound(w, r)
	}
}

// ------------------------------------------------------------ harness

// fakeClock advances instantly.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	return nil
}

type gcpHarness struct {
	t      *testing.T
	rt     *app.Runtime
	gce    *fakeCompute
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	dir    string
}

// serviceAccountJSON is a throwaway key whose token_uri is the fake.
func serviceAccountJSON(t *testing.T, tokenURL string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	b, _ := json.Marshal(map[string]string{"type": "service_account", "project_id": "proj", "private_key": string(pemKey),
		"client_email": "sa@proj.iam.gserviceaccount.com", "client_id": "1234", "token_uri": tokenURL})
	return string(b)
}

// newGCPHarness is a runtime with the gcp profile "lab" (project proj) on
// the fake Compute Engine, a fake clock and defaults.gcp.
func newGCPHarness(t *testing.T, flags app.Flags, defaults map[string]any) *gcpHarness {
	t.Helper()
	t.Setenv(app.EnvNonInteractive, "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	f := newFakeCompute(t)
	old := extraOptions
	extraOptions = f.options()
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	oldClock, oldDial := instanceClock, dialTCP
	instanceClock = clk
	t.Cleanup(func() { extraOptions, instanceClock, dialTCP = old, oldClock, oldDial })

	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	cfg, err := config.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.CredentialStore = "file"
	cfg.Profiles = map[string]*config.Profile{"lab": {Platforms: map[platform.ID]*config.Account{
		platform.GCP: {Metadata: map[string]string{"method": methodServiceAccount, "project": "proj", "client_email": "sa@proj.iam.gserviceaccount.com"}},
	}}}
	if defaults != nil {
		cfg.Defaults = config.Defaults{string(platform.GCP): defaults}
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := creds.NewFile(dir).Set(creds.Key("lab", string(platform.GCP)), map[string]string{"service_account_json": serviceAccountJSON(t, f.srv.URL+"/token")}); err != nil {
		t.Fatal(err)
	}
	flags.ConfigDir = dir
	if flags.Output == "" {
		flags.Output = "json"
	}
	if !flags.NonInteractiveSet {
		flags.NonInteractive, flags.NonInteractiveSet = true, true
	}
	h := &gcpHarness{t: t, gce: f, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, dir: dir}
	h.rt = app.New(flags, strings.NewReader(""), h.stdout, h.stderr)
	if err := h.rt.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = h.rt.Close() })
	return h
}

// addProfile adds a second gcp account "prod" on project other.
func (h *gcpHarness) addProfile() {
	h.t.Helper()
	cfg, err := config.Load(filepath.Join(h.dir, "config.yaml"))
	if err != nil {
		h.t.Fatal(err)
	}
	cfg.Profiles["prod"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		platform.GCP: {Metadata: map[string]string{"method": methodServiceAccount, "project": "other", "client_email": "sa@other.iam.gserviceaccount.com"}},
	}}
	if err := cfg.Save(); err != nil {
		h.t.Fatal(err)
	}
	if err := creds.NewFile(h.dir).Set(creds.Key("prod", string(platform.GCP)), map[string]string{"service_account_json": serviceAccountJSON(h.t, h.gce.srv.URL+"/token")}); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.rt.ReloadConfig(); err != nil {
		h.t.Fatal(err)
	}
}

// run runs `polyctl gcp <args>`; --yes, a root flag, sets Flags.Yes for
// this run.
func (h *gcpHarness) run(args ...string) error {
	h.t.Helper()
	h.rt.Flags.Yes = false
	var kept []string
	for _, a := range args {
		if a == "--yes" || a == "-y" {
			h.rt.Flags.Yes = true
			continue
		}
		kept = append(kept, a)
	}
	args = kept
	h.stdout.Reset()
	h.stderr.Reset()
	h.gce.mu.Lock()
	h.gce.calls = nil
	h.gce.mu.Unlock()
	cmd := Command(h.rt)
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return cmd.ExecuteContext(context.Background())
}

func (h *gcpHarness) jsonOut(v any) {
	h.t.Helper()
	if err := json.Unmarshal(h.stdout.Bytes(), v); err != nil {
		h.t.Fatalf("stdout is not JSON: %v\n%s", err, h.stdout.String())
	}
}

func (h *gcpHarness) report() platform.Report {
	h.t.Helper()
	var rep platform.Report
	h.jsonOut(&rep)
	return rep
}

// rows renders the changes of a report as "resource action detail" lines.
func rows(rep platform.Report) []string {
	var out []string
	for _, c := range rep.Changes {
		out = append(out, strings.TrimSpace(c.Resource+" "+string(c.Action)+" "+c.Detail))
	}
	return out
}

// scriptedPicker answers the arrow-key questions of the interactive flow.
type scriptedPicker struct {
	t       *testing.T
	answers []string
	titles  []string
}

func (p *scriptedPicker) next(title string) (string, error) {
	p.titles = append(p.titles, title)
	if len(p.answers) == 0 {
		p.t.Errorf("unexpected question %q", title)
		return "", prompt.ErrAborted
	}
	v := p.answers[0]
	p.answers = p.answers[1:]
	return v, nil
}
func (p *scriptedPicker) Select(title string, _ []prompt.Option, _ string) (string, error) {
	return p.next(title)
}
func (p *scriptedPicker) MultiSelect(title string, _ []prompt.Option) ([]string, error) {
	v, err := p.next(title)
	return []string{v}, err
}
func (p *scriptedPicker) Confirm(title string, _ bool) (bool, error) {
	v, err := p.next(title)
	return v == "yes", err
}
func (p *scriptedPicker) Input(title, _ string, _ func(string) error) (string, error) {
	return p.next(title)
}

// hasMachineType reports whether a zone takes a machine type: one it
// lists, or an E2 custom type where it lists E2 types.
func (f *fakeCompute) hasMachineType(zone, mt string) bool {
	if f.machineTypes[zone+"/"+mt] {
		return true
	}
	var c, m int
	if n, _ := fmt.Sscanf(mt, "e2-custom-%d-%d", &c, &m); n == 2 {
		return f.machineTypes[zone+"/"+e2ProbeType] && e2CustomFits(c, m)
	}
	return false
}

// fakeMachineShape is the vCPUs and MiB of a machine type the fake
// lists: an E2 preset's shape, else 2 vCPUs and 2 GiB.
func fakeMachineShape(mt string) (int, int) {
	for _, p := range e2Presets {
		if p.Name == mt {
			return p.Cores, p.MemMiB
		}
	}
	return 2, 2048
}
