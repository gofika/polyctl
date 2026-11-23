package aliyun

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cas"

	"github.com/gofika/polyctl/internal/platform"
)

// The aliyun-alb deployer of cert deploy. A CAS certificate cannot be
// changed, so a renewed certificate is uploaded to the CAS store once
// (named upload_<root>_<expiry date>, which finds it again on the next
// run) and every HTTPS listener whose default certificate is due is
// pointed at it, one listener at a time: a listener that is updating
// refuses the next write.

const albDeployerID = "aliyun-alb"

func init() { platform.RegisterDeployer(albDeployer{}) }

// albDeployer implements platform.CertDeployer for ALB HTTPS listeners.
type albDeployer struct{}

func (albDeployer) ID() string            { return albDeployerID }
func (albDeployer) Platform() platform.ID { return platform.Aliyun }

// albListenerUpdateRetry retries a certificate update that a listener
// still configuring refused (IncorrectStatus.Listener), three times.
var albListenerUpdateRetry = platform.RetryPolicy{Codes: []string{"IncorrectStatus.Listener"}, Initial: 5 * time.Second, Multiplier: 1, MaxAttempts: 4}

// deployClient is the aliyun client of a deploy account.
func deployClient(acct *platform.DeployAccount) (*client, error) {
	c, ok := acct.Client.(*client)
	if !ok {
		return nil, fmt.Errorf("%w: the client of %s is not an Alibaba Cloud client", platform.ErrNotSupported, acct.Profile)
	}
	return c, nil
}

// casStore is a CAS store as one deploy run sees it: listed once, then
// kept up to date with what the run uploads.
type casStore struct {
	scope casScope
	certs []casCertificate
	// uploaded maps root|serial to the certificate id of the run's upload
	// (or reuse), Pending in a dry run that would upload it.
	uploaded map[string]string
}

func (s *casStore) byID(id string) (casCertificate, bool) {
	for _, c := range s.certs {
		if c.ID == id {
			return c, true
		}
	}
	return casCertificate{}, false
}

func (s *casStore) byName(name string) (casCertificate, bool) {
	for _, c := range s.certs {
		if c.Name == name {
			return c, true
		}
	}
	return casCertificate{}, false
}

// deployStore returns the CAS store the listeners of region use, listed on
// first use. A store CAS refuses to list (HTTP 403) is a warning and taken
// as empty.
func deployStore(ctx context.Context, acct *platform.DeployAccount, c *client, region string, o platform.DeployOptions) (*casStore, error) {
	scope, err := c.casFor(region)
	if err != nil {
		return nil, err
	}
	stores := platform.Cached(acct, "aliyun-cas-stores", func() map[string]*casStore { return map[string]*casStore{} })
	if st, ok := stores[scope.Endpoint]; ok {
		return st, nil
	}
	certs, _, err := c.listCASCertificatesIn(ctx, scope)
	if errors.Is(err, platform.ErrForbidden) {
		o.Warnf("%s: the CAS certificates of %s cannot be listed (%v); taking the store as empty", acct.Profile, scope.Endpoint, err)
		certs, err = nil, nil
	}
	if err != nil {
		return nil, err
	}
	st := &casStore{scope: scope, certs: certs, uploaded: map[string]string{}}
	stores[scope.Endpoint] = st
	return st, nil
}

// casCertificateDetail reads one certificate of the store s
// (GetUserCertificateDetail): a certificate that is not an uploaded one,
// which the list leaves out. The dates and the serial number are read
// from the certificate itself when it parses. The private key it returns
// is dropped at once.
func (c *client) casCertificateDetail(ctx context.Context, s casScope, id string) (casCertificate, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return casCertificate{}, fmt.Errorf("%w: certificate id %q is not an integer", platform.ErrInvalidInput, id)
	}
	cl, s, err := c.casClientFor(ctx, s)
	if err != nil {
		return casCertificate{}, err
	}
	req := cas.CreateGetUserCertificateDetailRequest()
	c.route(req, s.Endpoint)
	req.CertId = requests.NewInteger64(n)
	resp, err := cl.GetUserCertificateDetail(req)
	if err != nil {
		return casCertificate{}, casErr("cas GetUserCertificateDetail", s, err)
	}
	resp.Key = ""
	out := casCertificate{ID: id, Name: resp.Name, CommonName: resp.Common, StartDate: resp.StartDate, EndDate: resp.EndDate, NotAfter: resp.EndDate,
		Fingerprint: resp.Fingerprint, Sans: resp.Sans, Endpoint: s.Endpoint, Source: "cas", Expired: resp.Expired}
	if leaf, _, err := platform.LeafOf(resp.Cert); err == nil {
		out.EndMillis = leaf.NotAfter.UnixMilli()
		out.SerialNo = leaf.SerialNumber.Text(16)
		if len(leaf.DNSNames) > 0 {
			out.Sans = strings.Join(leaf.DNSNames, ",")
		}
		if out.CommonName == "" {
			out.CommonName = leaf.Subject.CommonName
		}
	}
	return out, nil
}

// deployRegions are the regions the deployer scans: --region or
// cert.aliyun.regions, else the profile's region.
func deployRegions(acct *platform.DeployAccount, c *client) []string {
	if len(acct.Regions) > 0 {
		return acct.Regions
	}
	return []string{c.region}
}

// Discover lists the HTTPS listeners of every load balancer of the
// regions with the certificate each holds by default. A stopped listener,
// one that does not settle within a minute, one without a certificate and
// one whose certificate CAS does not know are skipped.
func (d albDeployer) Discover(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.DeployTarget, []platform.Change, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, nil, err
	}
	var targets []platform.DeployTarget
	var skipped []platform.Change
	for _, region := range deployRegions(acct, c) {
		a, err := c.albClient(ctx, region)
		if err != nil {
			return nil, nil, err
		}
		lbs, err := a.listLoadBalancers(ctx)
		if errors.Is(err, errNoALBEndpoint) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", region, err)
		}
		for _, lb := range lbs {
			listeners, err := a.listListenersOf(ctx, lb.ID, "HTTPS")
			if err != nil {
				return nil, nil, err
			}
			lbName := lb.Name
			if lbName == "" {
				lbName = lb.ID
			}
			for _, l := range listeners {
				name := fmt.Sprintf("%s(HTTPS:%d)", lbName, l.Port)
				skip := func(detail string) {
					skipped = append(skipped, platform.Change{Resource: platform.DeployResource(albDeployerID, acct.Profile, name), Action: platform.Skipped,
						ID: l.ID, Detail: detail, Attrs: map[string]string{"deployer": albDeployerID, "platform": string(platform.Aliyun), "profile": acct.Profile, "region": region}})
				}
				switch l.Status {
				case albListenerRunning:
				case "Stopped":
					skip("listener " + l.ID + " is stopped")
					continue
				default:
					if o.DryRun {
						skip(fmt.Sprintf("listener %s is %s (not waited for in a dry run)", l.ID, l.Status))
						continue
					}
					if err := waitListenerRunning(ctx, a, l.ID); err != nil {
						skip(fmt.Sprintf("listener %s is %s and did not become Running within a minute; try again on the next run", l.ID, l.Status))
						continue
					}
				}
				full, err := a.getListener(ctx, l.ID)
				if err != nil {
					return nil, nil, err
				}
				if full == nil {
					continue
				}
				if len(full.Certificates) == 0 || full.Certificates[0] == "" {
					o.Warnf("%s listener %s of %s has no certificate", acct.Profile, l.ID, lbName)
					skip("listener " + l.ID + " has no default certificate")
					continue
				}
				raw := full.Certificates[0]
				casID := casIDOfListenerCert(raw)
				st, err := deployStore(ctx, acct, c, region, o)
				if err != nil {
					return nil, nil, err
				}
				cc, ok := st.byID(casID)
				if !ok {
					if cc, err = c.casCertificateDetail(ctx, st.scope, casID); err != nil {
						o.Warnf("%s listener %s: certificate %s is not in the CAS store %s, its expiry is unknown: %v", acct.Profile, l.ID, raw, st.scope.Endpoint, err)
						skip(fmt.Sprintf("certificate %s is not in the CAS certificate list (deleted when it expired?); expiry unknown", raw))
						continue
					}
				}
				extra := 0
				if all, err := a.listenerCertificates(ctx, l.ID); err == nil {
					for _, id := range all {
						if id != raw {
							extra++
						}
					}
				}
				targets = append(targets, platform.DeployTarget{Deployer: albDeployerID, Platform: platform.Aliyun, Profile: acct.Profile, Region: region,
					Kind: "alb-listener", ID: l.ID, Name: name, CurrentCertID: casID, CurrentDomains: cc.names(), CurrentNotAfter: cc.notAfter(),
					CurrentSerial: cc.SerialNo, Attrs: map[string]string{"load_balancer_id": lb.ID, "listener_cert_id": raw, "additional": strconv.Itoa(extra)}})
			}
		}
	}
	return targets, skipped, nil
}

// Plan uploads the certificate to the CAS store of the listener's region
// unless the store holds it already (by name and serial number; once per
// run and store), then makes it the default certificate of the listener
// and waits until the listener is Running again.
func (d albDeployer) Plan(ctx context.Context, acct *platform.DeployAccount, t platform.DeployTarget, cert *platform.DeployCert, o platform.DeployOptions) ([]platform.Step, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, err
	}
	st, err := deployStore(ctx, acct, c, t.Region, o)
	if err != nil {
		return nil, err
	}
	var steps []platform.Step
	certRes := platform.DeployResource(albDeployerID, acct.Profile, "cert")
	certAttrs := map[string]string{"deployer": albDeployerID, "platform": string(platform.Aliyun), "profile": acct.Profile, "region": t.Region,
		"domain": cert.Root, "endpoint": st.scope.Endpoint}
	certID, name := "", ""
	if cert.Pending {
		name = "upload_" + cert.Root + "_" + platform.Pending
		key := cert.Root + "|" + platform.Pending
		certID = platform.Pending
		if _, ok := st.uploaded[key]; !ok {
			st.uploaded[key] = platform.Pending
			certAttrs["cert_name"] = name
			steps = append(steps, platform.Step{Resource: certRes, Action: platform.Created, ID: platform.Pending, Desc: name, Attrs: certAttrs,
				Apply: func(context.Context) (platform.Change, error) {
					return platform.Change{}, errors.New("the certificate was not issued")
				}})
		}
	} else {
		key := cert.Root + "|" + platform.SerialKey(cert.Serial)
		name = casCertName(cert.Root, cert.NotAfter)
		existing, found := st.byName(name)
		if found && platform.SerialKey(existing.SerialNo) != platform.SerialKey(cert.Serial) {
			// Another certificate of the same day holds the name (a
			// renewal with --force): the serial number tells them apart.
			name += "-" + serialPrefix(cert.Serial)
			if existing, found = st.byName(name); found && platform.SerialKey(existing.SerialNo) != platform.SerialKey(cert.Serial) {
				return nil, fmt.Errorf("the CAS certificate name %s is taken by another certificate (%s)", name, existing.ID)
			}
		}
		certAttrs["cert_name"] = name
		switch id, done := st.uploaded[key]; {
		case done:
			certID = id
		case found:
			certID = existing.ID
			st.uploaded[key] = certID
			steps = append(steps, platform.Step{Resource: certRes, Action: platform.Unchanged, ID: certID, Desc: name + " cert_id=" + certID, Attrs: certAttrs})
		default:
			if o.DryRun {
				st.uploaded[key] = platform.Pending
				certID = platform.Pending
			}
			material := cert
			steps = append(steps, platform.Step{Resource: certRes, Action: platform.Created, Desc: name, Attrs: certAttrs,
				Apply: func(ctx context.Context) (platform.Change, error) {
					id, err := c.uploadCASCertificateIn(ctx, st.scope, name, string(material.Fullchain), string(material.Key))
					if err != nil {
						return platform.Change{}, err
					}
					certID = id
					st.uploaded[key] = id
					st.certs = append(st.certs, casCertificate{ID: id, Name: name, SerialNo: material.Serial, EndMillis: material.NotAfter.UnixMilli(),
						EndDate: material.NotAfter.UTC().Format("2006-01-02"), Endpoint: st.scope.Endpoint})
					return platform.Change{ID: id, Detail: name + " -> cert_id=" + id}, nil
				}})
		}
	}
	raw := t.Attrs["listener_cert_id"]
	note := ""
	if n, _ := strconv.Atoi(t.Attrs["additional"]); n > 0 {
		note = fmt.Sprintf("; %d additional certificate(s) left alone", n)
	}
	attrs := map[string]string{"cert_name": name}
	if certID != "" && certID != platform.Pending && listenerCertID(st.scope.Region, certID) == raw {
		steps = append(steps, platform.Step{Resource: t.Resource(), Action: platform.Unchanged, ID: t.ID, Desc: "cert_id=" + raw + note, Attrs: attrs})
		return steps, nil
	}
	shown := platform.Pending
	if certID != "" && certID != platform.Pending {
		shown = listenerCertID(st.scope.Region, certID)
	}
	a, err := c.albClient(ctx, t.Region)
	if err != nil {
		return nil, err
	}
	steps = append(steps, platform.Step{Resource: t.Resource(), Action: platform.Updated, ID: t.ID, Desc: "cert_id=" + shown + note, Attrs: attrs,
		Apply: func(ctx context.Context) (platform.Change, error) {
			if certID == "" || certID == platform.Pending {
				return platform.Change{}, errors.New("no certificate id to bind")
			}
			want := listenerCertID(st.scope.Region, certID)
			p := albListenerUpdateRetry
			p.Clock = netClock()
			if err := platform.Retry(ctx, p, func(ctx context.Context) error { return a.updateListener(ctx, t.ID, want, "") }); err != nil {
				return platform.Change{}, err
			}
			// The next listener of the load balancer can only be
			// written once this one is Running again, so the wait is
			// made with --no-wait too.
			if err := waitListenerRunning(ctx, a, t.ID); err != nil {
				return platform.Change{}, fmt.Errorf("listener %s: certificate set to %s, but it did not become Running within a minute: %w", t.ID, want, err)
			}
			return platform.Change{Detail: fmt.Sprintf("cert_id=%s (was %s)%s", want, raw, note)}, nil
		}})
	return steps, nil
}

// serialPrefix is the first 8 digits of a serial number (lowercase hex).
func serialPrefix(serial string) string {
	s := strings.ToLower(strings.ReplaceAll(serial, ":", ""))
	if len(s) > 8 {
		s = s[:8]
	}
	return s
}

// Prune deletes the expired certificates of the CAS stores the scanned
// regions use, unless an ALB listener of any region of the account still
// holds one (CAS would delete it all the same and leave the listener with
// a dangling id). The check reads every region; when it cannot finish,
// nothing is deleted.
func (d albDeployer) Prune(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.Step, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, err
	}
	now := o.Clock()
	type expiredCert struct {
		st *casStore
		c  casCertificate
	}
	var expired []expiredCert
	seen := map[string]bool{}
	for _, region := range deployRegions(acct, c) {
		st, err := deployStore(ctx, acct, c, region, o)
		if err != nil {
			return nil, err
		}
		if seen[st.scope.Endpoint] {
			continue
		}
		seen[st.scope.Endpoint] = true
		for _, cc := range st.certs {
			if na := cc.notAfter(); cc.Expired || na.IsZero() || !now.Before(na) {
				expired = append(expired, expiredCert{st, cc})
			}
		}
	}
	if len(expired) == 0 {
		return nil, nil
	}
	regions, named, err := c.albRegions(ctx, nil)
	if err != nil {
		return nil, err
	}
	refs, err := c.casCertificateReferences(ctx, regions, named)
	if err != nil {
		return nil, err
	}
	var steps []platform.Step
	for _, e := range expired {
		res := platform.DeployResource(albDeployerID, acct.Profile, "cert/"+e.c.ID)
		date := e.c.EndDate
		if na := e.c.notAfter(); !na.IsZero() {
			date = na.Format("2006-01-02")
		}
		desc := fmt.Sprintf("cert=%s expired (%s) %s", e.c.ID, date, e.c.Name)
		if users := refs.of(e.c.ID); len(users) > 0 {
			steps = append(steps, platform.Step{Resource: res, Action: platform.Skipped, ID: e.c.ID, Desc: desc + "; still used by " + users[0].String()})
			continue
		}
		st, id := e.st, e.c.ID
		steps = append(steps, platform.Step{Resource: res, Action: platform.Deleted, ID: id, Desc: desc,
			Apply: func(ctx context.Context) (platform.Change, error) {
				return platform.Change{}, c.deleteCASCertificateIn(ctx, st.scope, id)
			}})
	}
	return steps, nil
}
