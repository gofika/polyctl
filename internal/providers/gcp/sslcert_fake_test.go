package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// lbFake is the load balancer side of the fake Compute Engine: SSL
// certificates, target HTTP(S) proxies, URL maps and forwarding rules, in
// both scopes, behaving as observed on a real project: certificates are
// immutable, a certificate a proxy uses cannot be deleted (400
// resourceInUseByAnotherResource at submission), SetSslCertificates
// replaces the list as a whole (1 to 15 certificates of the proxy's own
// scope, no duplicates), and the labels of a forwarding rule Insert are
// ignored.
type lbFake struct {
	certs        map[string]*compute.SslCertificate   // project/scope/name (scope: global or the region)
	httpsProxies map[string]*compute.TargetHttpsProxy // project/scope/name
	httpProxies  map[string]*compute.TargetHttpProxy  // project/scope/name
	urlMaps      map[string]*compute.UrlMap           // project/scope/name
	// inUseFails makes the next n certificate deletes fail as in use
	// whatever the references.
	inUseFails int
	// afterCertInsert runs (under the lock) after a certificate is
	// created: a change made by someone else meanwhile.
	afterCertInsert func(lb *lbFake)
}

func (f *fakeCompute) lb() *lbFake {
	if f.lbState == nil {
		f.lbState = &lbFake{certs: map[string]*compute.SslCertificate{}, httpsProxies: map[string]*compute.TargetHttpsProxy{},
			httpProxies: map[string]*compute.TargetHttpProxy{}, urlMaps: map[string]*compute.UrlMap{}}
	}
	return f.lbState
}

// scopePath is "global" or "regions/<region>".
func scopePath(scope string) string {
	if scope == "global" {
		return "global"
	}
	return "regions/" + scope
}

func selfLink(project, scope, kind, name string) string {
	return apiBase + "projects/" + project + "/" + scopePath(scope) + "/" + kind + "/" + name
}

// scopeOfURL returns the scope and name of a resource URL of kind.
func scopeOfURL(u, kind string) (project, scope, name string, ok bool) {
	k := resourceKey(u)
	parts := strings.Split(k, "/")
	switch {
	case len(parts) == 5 && parts[0] == "projects" && parts[2] == "global" && parts[3] == kind:
		return parts[1], "global", parts[4], true
	case len(parts) == 6 && parts[0] == "projects" && parts[2] == "regions" && parts[4] == kind:
		return parts[1], parts[3], parts[5], true
	}
	return "", "", "", false
}

// addCert puts a certificate with the leaf of chain into the fake.
func (f *fakeCompute) addCert(scope, name string, chain []byte) *compute.SslCertificate {
	f.mu.Lock()
	defer f.mu.Unlock()
	sc := &compute.SslCertificate{Name: name, Certificate: string(chain)}
	f.fillCert("proj", scope, sc)
	f.lb().certs["proj/"+scope+"/"+name] = sc
	return sc
}

// addManagedCert puts a Google-managed certificate into the fake.
func (f *fakeCompute) addManagedCert(scope, name string, domains []string, expire string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sc := &compute.SslCertificate{Name: name, Type: certManaged, SubjectAlternativeNames: domains, ExpireTime: expire,
		SelfLink: selfLink("proj", scope, "sslCertificates", name)}
	if scope != "global" {
		sc.Region = apiBase + "projects/proj/regions/" + scope
	}
	f.lb().certs["proj/"+scope+"/"+name] = sc
}

// fillCert sets the fields Compute Engine derives from the PEM.
func (f *fakeCompute) fillCert(project, scope string, sc *compute.SslCertificate) bool {
	leaf, _, err := platform.LeafOf(sc.Certificate)
	if err != nil {
		return false
	}
	sc.Type = certSelfManaged
	sc.SubjectAlternativeNames = leaf.DNSNames
	pst := time.FixedZone("PST", -8*3600)
	sc.ExpireTime = leaf.NotAfter.In(pst).Format("2006-01-02T15:04:05.000-07:00")
	sc.CreationTimestamp = "2026-11-17T10:00:00.000-08:00"
	sc.SelfLink = selfLink(project, scope, "sslCertificates", sc.Name)
	sc.PrivateKey = ""
	if scope != "global" {
		sc.Region = apiBase + "projects/" + project + "/regions/" + scope
	}
	return true
}

// addHTTPSProxy puts a target HTTPS proxy with certificates (names in
// its scope) into the fake.
func (f *fakeCompute) addHTTPSProxy(scope, name, urlMap string, certs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := &compute.TargetHttpsProxy{Name: name, UrlMap: selfLink("proj", scope, "urlMaps", urlMap), SelfLink: selfLink("proj", scope, "targetHttpsProxies", name)}
	for _, c := range certs {
		p.SslCertificates = append(p.SslCertificates, selfLink("proj", scope, "sslCertificates", c))
	}
	if scope != "global" {
		p.Region = apiBase + "projects/proj/regions/" + scope
	}
	f.lb().httpsProxies["proj/"+scope+"/"+name] = p
}

func (f *fakeCompute) addHTTPProxy(scope, name, urlMap string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := &compute.TargetHttpProxy{Name: name, UrlMap: selfLink("proj", scope, "urlMaps", urlMap), SelfLink: selfLink("proj", scope, "targetHttpProxies", name)}
	if scope != "global" {
		p.Region = apiBase + "projects/proj/regions/" + scope
	}
	f.lb().httpProxies["proj/"+scope+"/"+name] = p
}

func (f *fakeCompute) addURLMap(scope, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := &compute.UrlMap{Name: name, SelfLink: selfLink("proj", scope, "urlMaps", name)}
	if scope != "global" {
		m.Region = apiBase + "projects/proj/regions/" + scope
	}
	f.lb().urlMaps["proj/"+scope+"/"+name] = m
}

// addRule puts a forwarding rule into the fake; target is "<kind>/<name>"
// in the rule's scope.
func (f *fakeCompute) addRule(scope, name, target, ip, ports string, labels map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forwardingRules == nil {
		f.forwardingRules = map[string][]*compute.ForwardingRule{}
	}
	kind, tname, _ := strings.Cut(target, "/")
	fr := &compute.ForwardingRule{Name: name, IPAddress: ip, IPProtocol: "TCP", PortRange: ports, LoadBalancingScheme: "EXTERNAL_MANAGED",
		NetworkTier: "PREMIUM", Target: selfLink("proj", scope, kind, tname), SelfLink: selfLink("proj", scope, "forwardingRules", name),
		Network: apiBase + "projects/proj/global/networks/default", Labels: labels, LabelFingerprint: "lf-1"}
	if scope != "global" {
		fr.Region = apiBase + "projects/proj/regions/" + scope
	}
	f.forwardingRules["proj"] = append(f.forwardingRules["proj"], fr)
}

func (f *fakeCompute) cert(scope, name string) *compute.SslCertificate {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lb().certs["proj/"+scope+"/"+name]
}

// proxyCerts lists the certificate names of a proxy.
func (f *fakeCompute) proxyCerts(scope, name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.lb().httpsProxies["proj/"+scope+"/"+name]
	if p == nil {
		return nil
	}
	var out []string
	for _, u := range p.SslCertificates {
		out = append(out, lastSegment(u))
	}
	return out
}

func (f *fakeCompute) rule(scope, name string) *compute.ForwardingRule {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, fr := range f.forwardingRules["proj"] {
		frScope := "global"
		if fr.Region != "" {
			frScope = lastSegment(fr.Region)
		}
		if fr.Name == name && frScope == scope {
			return fr
		}
	}
	return nil
}

// lbWrites lists the write requests to load balancer resources as
// "METHOD scope/kind/name[/verb]".
func (f *fakeCompute) lbWrites() []string {
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
		if len(parts) < 3 {
			continue
		}
		rest := parts[2:]
		if rest[0] == "regions" && len(rest) > 1 {
			rest = append([]string{rest[1]}, rest[2:]...)
		}
		if rest[0] == "targetHttpsProxies" {
			rest = append([]string{"global"}, rest...)
		}
		out = append(out, method+" "+strings.Join(rest, "/"))
	}
	return out
}

// handleLB serves the load balancer resources; false when the path is
// not one of them.
func (f *fakeCompute) handleLB(w http.ResponseWriter, r *http.Request, project string, rest []string) bool {
	if f.handleLBParts(w, r, project, rest) {
		return true
	}
	if len(rest) == 2 && rest[0] == "aggregated" {
		switch rest[1] {
		case "sslCertificates":
			items := map[string]compute.SslCertificatesScopedList{}
			for _, k := range sortedKeys(f.lb().certs, project) {
				sc := f.lb().certs[k]
				scope := strings.Split(k, "/")[1]
				l := items[scopePath(scope)]
				l.SslCertificates = append(l.SslCertificates, sc)
				items[scopePath(scope)] = l
			}
			writeJSONStatus(w, 200, &compute.SslCertificateAggregatedList{Items: items})
			return true
		case "targetHttpsProxies":
			items := map[string]compute.TargetHttpsProxiesScopedList{}
			for _, k := range sortedKeys(f.lb().httpsProxies, project) {
				scope := strings.Split(k, "/")[1]
				l := items[scopePath(scope)]
				l.TargetHttpsProxies = append(l.TargetHttpsProxies, f.lb().httpsProxies[k])
				items[scopePath(scope)] = l
			}
			writeJSONStatus(w, 200, &compute.TargetHttpsProxyAggregatedList{Items: items})
			return true
		case "urlMaps":
			items := map[string]compute.UrlMapsScopedList{}
			for _, k := range sortedKeys(f.lb().urlMaps, project) {
				scope := strings.Split(k, "/")[1]
				l := items[scopePath(scope)]
				l.UrlMaps = append(l.UrlMaps, f.lb().urlMaps[k])
				items[scopePath(scope)] = l
			}
			writeJSONStatus(w, 200, &compute.UrlMapsAggregatedList{Items: items})
			return true
		}
		return false
	}
	var scope string
	var tail []string
	switch {
	case len(rest) >= 2 && rest[0] == "targetHttpsProxies":
		// The global setSslCertificates has no "global/" in its path.
		scope, tail = "global", rest
	case len(rest) >= 2 && rest[0] == "global":
		scope, tail = "global", rest[1:]
	case len(rest) >= 3 && rest[0] == "regions":
		scope, tail = rest[1], rest[2:]
	default:
		return false
	}
	switch tail[0] {
	case "sslCertificates":
		f.handleCerts(w, r, project, scope, tail[1:])
	case "targetHttpsProxies":
		f.handleHTTPSProxies(w, r, project, scope, tail[1:])
	case "targetHttpProxies":
		key := project + "/" + scope + "/"
		if len(tail) == 1 {
			var items []*compute.TargetHttpProxy
			for _, k := range sortedKeys(f.lb().httpProxies, project) {
				if strings.HasPrefix(k, key) {
					items = append(items, f.lb().httpProxies[k])
				}
			}
			writeJSONStatus(w, 200, &compute.TargetHttpProxyList{Items: items})
			return true
		}
		if p := f.lb().httpProxies[key+tail[1]]; p != nil {
			writeJSONStatus(w, 200, p)
			return true
		}
		notFound(w, "targetHttpProxies/"+tail[1])
	case "urlMaps":
		if len(tail) == 2 {
			if m := f.lb().urlMaps[project+"/"+scope+"/"+tail[1]]; m != nil {
				writeJSONStatus(w, 200, m)
				return true
			}
			notFound(w, "urlMaps/"+tail[1])
			return true
		}
		http.NotFound(w, r)
	case "forwardingRules":
		f.handleRules(w, r, project, scope, tail[1:])
	default:
		return false
	}
	return true
}

func sortedKeys[V any](m map[string]V, project string) []string {
	var keys []string
	for k := range m {
		if strings.HasPrefix(k, project+"/") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func (f *fakeCompute) handleCerts(w http.ResponseWriter, r *http.Request, project, scope string, rest []string) {
	lb := f.lb()
	prefix := project + "/" + scope + "/"
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			var items []*compute.SslCertificate
			for _, k := range sortedKeys(lb.certs, project) {
				if strings.HasPrefix(k, prefix) {
					items = append(items, lb.certs[k])
				}
			}
			writeJSONStatus(w, 200, &compute.SslCertificateList{Items: items})
		case http.MethodPost:
			var sc compute.SslCertificate
			if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return
			}
			if !certNameRe.MatchString(sc.Name) {
				apiError(w, fakeErr{400, "", "Invalid value for field 'resource.name': '" + sc.Name + "'. Must be a match of regex '[a-z]([-a-z0-9]{0,61}[a-z0-9])?'"})
				return
			}
			if lb.certs[prefix+sc.Name] != nil {
				apiError(w, fakeErr{409, "alreadyExists", "The resource 'projects/" + project + "/" + scopePath(scope) + "/sslCertificates/" + sc.Name + "' already exists"})
				return
			}
			if sc.Type == certSelfManaged {
				apiError(w, fakeErr{400, "", "Self-managed certificate details must be specified if type = SELF_MANAGED."})
				return
			}
			if sc.PrivateKey == "" {
				apiError(w, fakeErr{400, "", "A private key must be specified for SSL certificate creation."})
				return
			}
			if !f.fillCert(project, scope, &sc) {
				apiError(w, fakeErr{400, "", "The SSL certificate could not be parsed."})
				return
			}
			op := f.op("insertSslCertificate", sc.SelfLink)
			if op.Error == nil {
				lb.certs[prefix+sc.Name] = &sc
				if lb.afterCertInsert != nil {
					lb.afterCertInsert(lb)
				}
			}
			writeJSONStatus(w, 200, op)
		default:
			http.NotFound(w, r)
		}
		return
	}
	sc := lb.certs[prefix+rest[0]]
	if sc == nil {
		notFound(w, "projects/"+project+"/"+scopePath(scope)+"/sslCertificates/"+rest[0])
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSONStatus(w, 200, sc)
	case http.MethodDelete:
		inUse := ""
		for _, k := range sortedKeys(lb.httpsProxies, project) {
			for _, u := range lb.httpsProxies[k].SslCertificates {
				if resourceKey(u) == resourceKey(sc.SelfLink) {
					inUse = lb.httpsProxies[k].SelfLink
				}
			}
		}
		if inUse == "" && lb.inUseFails > 0 {
			lb.inUseFails--
			inUse = selfLink(project, scope, "targetHttpsProxies", "proxy-elsewhere")
		}
		if inUse != "" {
			apiError(w, fakeErr{400, reasonInUse, "The ssl_certificate resource '" + resourceKey(sc.SelfLink) + "' is already being used by '" + resourceKey(inUse) + "'"})
			return
		}
		delete(lb.certs, prefix+rest[0])
		writeJSONStatus(w, 200, f.op("deleteSslCertificate", sc.SelfLink))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCompute) handleHTTPSProxies(w http.ResponseWriter, r *http.Request, project, scope string, rest []string) {
	lb := f.lb()
	prefix := project + "/" + scope + "/"
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			var items []*compute.TargetHttpsProxy
			for _, k := range sortedKeys(lb.httpsProxies, project) {
				if strings.HasPrefix(k, prefix) {
					items = append(items, lb.httpsProxies[k])
				}
			}
			writeJSONStatus(w, 200, &compute.TargetHttpsProxyList{Items: items})
		case http.MethodPost:
			var p compute.TargetHttpsProxy
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return
			}
			if lb.httpsProxies[prefix+p.Name] != nil {
				apiError(w, fakeErr{409, "alreadyExists", "The resource 'targetHttpsProxies/" + p.Name + "' already exists"})
				return
			}
			urls, ferr := f.checkCertList(project, scope, p.SslCertificates)
			if ferr != nil {
				apiError(w, *ferr)
				return
			}
			p.SslCertificates = urls
			p.UrlMap = apiBase + resourceKey(p.UrlMap)
			p.SelfLink = selfLink(project, scope, "targetHttpsProxies", p.Name)
			if scope != "global" {
				p.Region = apiBase + "projects/" + project + "/regions/" + scope
			}
			lb.httpsProxies[prefix+p.Name] = &p
			writeJSONStatus(w, 200, f.op("insertTargetHttpsProxy", p.SelfLink))
		default:
			http.NotFound(w, r)
		}
		return
	}
	p := lb.httpsProxies[prefix+rest[0]]
	if p == nil {
		notFound(w, "projects/"+project+"/"+scopePath(scope)+"/targetHttpsProxies/"+rest[0])
		return
	}
	switch {
	case r.Method == http.MethodGet && len(rest) == 1:
		writeJSONStatus(w, 200, p)
	case r.Method == http.MethodPost && len(rest) == 2 && rest[1] == "setSslCertificates":
		var req struct {
			SslCertificates []string `json:"sslCertificates"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiError(w, fakeErr{400, "invalid", err.Error()})
			return
		}
		urls, ferr := f.checkCertList(project, scope, req.SslCertificates)
		if ferr != nil {
			apiError(w, *ferr)
			return
		}
		p.SslCertificates = urls
		writeJSONStatus(w, 200, f.op("setSslCertificates", p.SelfLink))
	default:
		http.NotFound(w, r)
	}
}

// checkCertList validates the certificates of a proxy as Compute Engine
// does and returns them as full URLs.
func (f *fakeCompute) checkCertList(project, scope string, urls []string) ([]string, *fakeErr) {
	switch {
	case len(urls) == 0:
		return nil, &fakeErr{400, "", "At least 1 SSL certificate must be specified for setting SSL certificates in TargetHttpsProxy."}
	case len(urls) > maxProxyCerts:
		return nil, &fakeErr{400, "", fmt.Sprintf("At most 15 SSL certificate(s) (%d in the request) can be specified for setting SSL certificates in TargetHttpsProxy.", len(urls))}
	}
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		p, s, name, ok := scopeOfURL(u, "sslCertificates")
		if !ok || p != project || s != scope || f.lb().certs[p+"/"+s+"/"+name] == nil {
			return nil, &fakeErr{400, "", "Must be a valid SslCertificate URL or a valid Certificate Manager certificate URL within the same scope and project."}
		}
		if seen[name] {
			return nil, &fakeErr{400, "", "No duplicate SSL certificates can be specified for setting SSL certificates in TargetHttpsProxy."}
		}
		seen[name] = true
		out = append(out, selfLink(project, scope, "sslCertificates", name))
	}
	return out, nil
}

func (f *fakeCompute) handleRules(w http.ResponseWriter, r *http.Request, project, scope string, rest []string) {
	inScope := func(fr *compute.ForwardingRule) bool {
		if scope == "global" {
			return fr.Region == ""
		}
		return lastSegment(fr.Region) == scope
	}
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			var items []*compute.ForwardingRule
			for _, fr := range f.forwardingRules[project] {
				if inScope(fr) {
					items = append(items, fr)
				}
			}
			writeJSONStatus(w, 200, &compute.ForwardingRuleList{Items: items})
		case http.MethodPost:
			var fr compute.ForwardingRule
			if err := json.NewDecoder(r.Body).Decode(&fr); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return
			}
			for _, x := range f.forwardingRules[project] {
				if x.Name == fr.Name && inScope(x) {
					apiError(w, fakeErr{409, "alreadyExists", "The resource 'forwardingRules/" + fr.Name + "' already exists"})
					return
				}
			}
			if fr.IPAddress == "" {
				fr.IPAddress = fmt.Sprintf("34.9.0.%d", f.next())
			}
			fr.Labels = nil // ignored on Insert, as observed
			fr.LabelFingerprint = "lf-0"
			fr.Target = apiBase + resourceKey(fr.Target)
			fr.SelfLink = selfLink(project, scope, "forwardingRules", fr.Name)
			if scope != "global" {
				fr.Region = apiBase + "projects/" + project + "/regions/" + scope
			}
			if f.forwardingRules == nil {
				f.forwardingRules = map[string][]*compute.ForwardingRule{}
			}
			f.forwardingRules[project] = append(f.forwardingRules[project], &fr)
			writeJSONStatus(w, 200, f.op("insertForwardingRule", fr.SelfLink))
		default:
			http.NotFound(w, r)
		}
		return
	}
	var fr *compute.ForwardingRule
	for _, x := range f.forwardingRules[project] {
		if x.Name == rest[0] && inScope(x) {
			fr = x
		}
	}
	if fr == nil {
		notFound(w, "forwardingRules/"+rest[0])
		return
	}
	switch {
	case r.Method == http.MethodGet && len(rest) == 1:
		writeJSONStatus(w, 200, fr)
	case r.Method == http.MethodPost && len(rest) == 2 && rest[1] == "setLabels":
		var req compute.RegionSetLabelsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apiError(w, fakeErr{400, "invalid", err.Error()})
			return
		}
		if req.LabelFingerprint != fr.LabelFingerprint {
			apiError(w, fakeErr{412, "conditionNotMet", "Labels fingerprint either invalid or resource labels have changed"})
			return
		}
		fr.Labels = req.Labels
		fr.LabelFingerprint = fr.LabelFingerprint + "x"
		writeJSONStatus(w, 200, f.op("setLabels", fr.SelfLink))
	default:
		http.NotFound(w, r)
	}
}
