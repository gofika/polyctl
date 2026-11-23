package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"google.golang.org/api/compute/v1"
)

// handleFirewalls emulates the firewall rules of a project as observed:
// an ingress rule without source ranges gets 0.0.0.0/0, Patch replaces
// the list fields it carries and ignores empty ones, PUT replaces the
// whole rule (refusing a change of network or direction), and a write to
// a rule whose previous operation was not waited for is not ready.
func (f *fakeCompute) handleFirewalls(w http.ResponseWriter, r *http.Request, project string, rest []string) {
	prefix := project + "/"
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			var keys []string
			for k := range f.firewalls {
				if strings.HasPrefix(k, prefix) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			var items []*compute.Firewall
			for _, k := range keys {
				items = append(items, f.firewalls[k])
			}
			writeJSONStatus(w, 200, &compute.FirewallList{Items: items})
		case http.MethodPost:
			var fw compute.Firewall
			if err := json.NewDecoder(r.Body).Decode(&fw); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return
			}
			if f.firewalls[prefix+fw.Name] != nil {
				apiError(w, fakeErr{409, "alreadyExists", "The resource 'projects/" + project + "/global/firewalls/" + fw.Name + "' already exists"})
				return
			}
			if fw.Direction == "" {
				fw.Direction = dirIngress
			}
			if fw.Direction == dirIngress && len(fw.SourceRanges) == 0 && len(fw.SourceTags) == 0 {
				fw.SourceRanges = []string{"0.0.0.0/0"}
			}
			if fw.Direction == dirEgress && len(fw.DestinationRanges) == 0 {
				fw.DestinationRanges = []string{"0.0.0.0/0"}
			}
			if !strings.HasPrefix(fw.Network, "https://") {
				fw.Network = apiBase + strings.TrimPrefix(fw.Network, "/")
			}
			fw.SelfLink = apiBase + "projects/" + project + "/global/firewalls/" + fw.Name
			fw.CreationTimestamp = "2026-11-17T10:00:00.000-08:00"
			op := f.op("insertFirewall", fw.SelfLink)
			if op.Error == nil {
				f.firewalls[prefix+fw.Name] = &fw
				f.busy[op.Name] = prefix + fw.Name
			}
			writeJSONStatus(w, 200, op)
		default:
			http.NotFound(w, r)
		}
		return
	}
	key := prefix + rest[0]
	fw := f.firewalls[key]
	if fw == nil {
		notFound(w, "projects/"+project+"/global/firewalls/"+rest[0])
		return
	}
	if r.Method != http.MethodGet {
		for _, k := range f.busy {
			if k == key {
				apiError(w, fakeErr{400, "resourceNotReady", "The resource '" + fw.SelfLink + "' is not ready"})
				return
			}
		}
	}
	switch r.Method {
	case http.MethodGet:
		writeJSONStatus(w, 200, fw)
	case http.MethodDelete:
		op := f.op("deleteFirewall", fw.SelfLink)
		if op.Error == nil {
			delete(f.firewalls, key)
		}
		writeJSONStatus(w, 200, op)
	case http.MethodPatch:
		raw, _ := io.ReadAll(r.Body)
		var body compute.Firewall
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &body) != nil || json.Unmarshal(raw, &fields) != nil {
			apiError(w, fakeErr{400, "invalid", "bad body"})
			return
		}
		cp := *fw
		if len(body.Allowed) > 0 {
			cp.Allowed = body.Allowed
		}
		if len(body.SourceRanges) > 0 {
			cp.SourceRanges = body.SourceRanges
		}
		if len(body.DestinationRanges) > 0 {
			cp.DestinationRanges = body.DestinationRanges
		}
		if len(body.TargetTags) > 0 {
			cp.TargetTags = body.TargetTags
		}
		if _, ok := fields["description"]; ok {
			cp.Description = body.Description
		}
		if _, ok := fields["priority"]; ok {
			cp.Priority = body.Priority
		}
		if _, ok := fields["disabled"]; ok {
			cp.Disabled = body.Disabled
		}
		if body.Network != "" {
			cp.Network = body.Network
		}
		if body.Direction != "" {
			cp.Direction = body.Direction
		}
		op := f.op("patchFirewall", fw.SelfLink)
		if op.Error == nil {
			f.firewalls[key] = &cp
			f.busy[op.Name] = key
		}
		writeJSONStatus(w, 200, op)
	case http.MethodPut:
		var body compute.Firewall
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			apiError(w, fakeErr{400, "invalid", err.Error()})
			return
		}
		if lastSegment(body.Network) != lastSegment(fw.Network) || body.Direction != fw.Direction {
			apiError(w, fakeErr{400, "invalid", "Unsupported update operation. Please use firewall.patch API to update the firewall resource."})
			return
		}
		body.Name, body.SelfLink, body.CreationTimestamp, body.Network = fw.Name, fw.SelfLink, fw.CreationTimestamp, fw.Network
		op := f.op("updateFirewall", fw.SelfLink)
		if op.Error == nil {
			f.firewalls[key] = &body
			f.busy[op.Name] = key
		}
		writeJSONStatus(w, 200, op)
	default:
		http.NotFound(w, r)
	}
}

// addFirewall puts a rule into the fake (network given by name).
func (f *fakeCompute) addFirewall(fw *compute.Firewall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(fw.Network, "https://") {
		fw.Network = apiBase + "projects/proj/global/networks/" + fw.Network
	}
	if fw.Direction == "" {
		fw.Direction = dirIngress
	}
	if fw.Priority == 0 {
		fw.Priority = defaultFirewallPriority
	}
	fw.SelfLink = apiBase + "projects/proj/global/firewalls/" + fw.Name
	f.firewalls["proj/"+fw.Name] = fw
}

// firewall returns a copy of a rule of the fake, or nil.
func (f *fakeCompute) firewall(name string) *compute.Firewall {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fw := f.firewalls["proj/"+name]; fw != nil {
		cp := *fw
		return &cp
	}
	return nil
}

// firewallWrites lists the firewall and instance tag writes made since
// the last run ("PATCH firewalls/x", "POST setTags").
func (f *fakeCompute) firewallWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		method, path, _ := strings.Cut(c, " ")
		path, _, _ = strings.Cut(path, "?")
		if method == http.MethodGet || strings.Contains(path, "/operations/") || path == "/token" {
			continue
		}
		parts := strings.Split(strings.Trim(path, "/"), "/")
		switch {
		case len(parts) >= 4 && parts[3] == "firewalls":
			out = append(out, method+" "+strings.Join(parts[3:], "/"))
		case strings.HasSuffix(path, "/setTags"):
			out = append(out, method+" setTags")
		}
	}
	return out
}
