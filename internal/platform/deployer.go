package platform

import (
	"context"
	"crypto/x509"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Certificate deployment (cert deploy): a deployer finds the places of one
// platform that serve a certificate (an ALB listener, a target HTTPS
// proxy, an imported ACM certificate) and puts the certificate of the
// local store on them. Deployers register themselves from the init() of
// their provider package; cert deploy itself knows none of them, so a new
// platform only adds a deployer.

// DeployAccount is one account cert deploy works in. A deployer keeps what
// it learns during the run of the account in Cache (a certificate listing,
// an upload several targets share).
type DeployAccount struct {
	Platform ID
	Profile  string
	Client   Client
	// Regions limit the scan (--region, else cert.<platform>.regions);
	// empty means the deployer's default (the account's region, or every
	// region where the platform lists them all at once).
	Regions []string
	Cache   map[string]any
}

// Cached returns the value of key in the cache of the account, creating it
// with newValue on first use.
func Cached[T any](a *DeployAccount, key string, newValue func() T) T {
	if a.Cache == nil {
		a.Cache = map[string]any{}
	}
	if v, ok := a.Cache[key].(T); ok {
		return v
	}
	v := newValue()
	a.Cache[key] = v
	return v
}

// DeployCert is the certificate of the local store cert deploy puts on its
// targets.
type DeployCert struct {
	// Root is the root domain the certificate is stored under.
	Root string
	// Pending marks a dry run that would issue or renew the certificate
	// first: only Root is set, and every later step uses placeholders.
	Pending bool
	// Fullchain is the leaf followed by the intermediates, Cert the leaf,
	// Chain the intermediates and Key the unencrypted private key (PEM).
	Fullchain, Cert, Chain, Key []byte
	Leaf                        *x509.Certificate
	// Serial is the serial number in lowercase hex, Fingerprint the
	// SHA-256 of the leaf's DER (lowercase hex).
	Serial      string
	Fingerprint string
	NotAfter    time.Time
	Names       []string
}

// Material is the certificate as the platform helpers that upload
// certificates take it; nil while it is pending.
func (c *DeployCert) Material() *CertMaterial {
	if c == nil || c.Pending || c.Leaf == nil {
		return nil
	}
	return &CertMaterial{Fullchain: c.Fullchain, PrivKey: c.Key, Leaf: c.Leaf, Fingerprint: c.Fingerprint}
}

// Covers reports whether the certificate is valid for host (an exact name,
// or a wildcard of exactly one label: *.example.com covers a.example.com,
// not a.b.example.com). A pending certificate covers nothing yet.
func (c *DeployCert) Covers(host string) bool {
	if c == nil || c.Leaf == nil {
		return false
	}
	return c.Leaf.VerifyHostname(strings.TrimSuffix(strings.TrimSpace(host), ".")) == nil
}

// SerialKey is the form serial numbers are compared in: lowercase hex
// without colons and without leading zeros. ACM writes "0a:1b:...", CAS
// "0a1b...", polyctl one byte per two digits; all three agree in this form.
func SerialKey(s string) string {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	return strings.TrimLeft(s, "0")
}

// DeployTarget is one place that serves a certificate.
type DeployTarget struct {
	// Deployer is the id of the deployer that found it.
	Deployer string
	Platform ID
	Profile  string
	Region   string
	// Kind is the type of the target (alb-listener, gcp-https-proxy,
	// acm-certificate).
	Kind string
	// ID is the platform id of the target, Name how a report names it.
	ID   string
	Name string
	// Hostname is the name the target serves, when it has one (none of the
	// current deployers has): a certificate that does not cover it is not
	// deployed there.
	Hostname string
	// Group puts targets a BatchDeployer updates in one write (the
	// certificates of one target HTTPS proxy); empty: on its own.
	Group string
	// CurrentCertID, CurrentDomains, CurrentNotAfter and CurrentSerial
	// describe the certificate the target holds now.
	CurrentCertID   string
	CurrentDomains  []string
	CurrentNotAfter time.Time
	CurrentSerial   string
	// Attrs are private to the deployer.
	Attrs map[string]string
}

// DaysLeft is the number of whole days the current certificate has left,
// rounded down (negative once it expired).
func (t DeployTarget) DaysLeft(now time.Time) int {
	return int(math.Floor(t.CurrentNotAfter.Sub(now).Hours() / 24))
}

// Domain is the domain of the current certificate: its first name that is
// not a wildcard, else its first wildcard without "*.".
func (t DeployTarget) Domain() string { return CertDomain(t.CurrentDomains, "") }

// Resource is the name of the target in a change report:
// <deployer>/<profile>/<name>.
func (t DeployTarget) Resource() string { return DeployResource(t.Deployer, t.Profile, t.Name) }

// DeployResource names a resource of a deployer in a change report.
func DeployResource(deployer, profile, name string) string {
	return deployer + "/" + profile + "/" + name
}

// DeployOptions are the settings of a cert deploy run that deployers use.
type DeployOptions struct {
	// Days: in --all mode a target is updated when its certificate has at
	// most this many whole days left.
	Days int
	// Force updates every matching target, whatever its certificate.
	Force bool
	// All is the --all mode (else a domain was named).
	All    bool
	DryRun bool
	// NoWait skips the waits a deployer does not need for its own next
	// write; Timeout bounds each wait (0: the deployer's default).
	NoWait  bool
	Timeout time.Duration
	// Prune is --prune-expired.
	Prune bool
	// Now is the clock (nil: time.Now); Infof prints warnings and
	// progress on stderr (nil: silent).
	Now   func() time.Time
	Infof func(format string, args ...any)
}

// Clock returns the current time of the run.
func (o DeployOptions) Clock() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Warnf prints a warning.
func (o DeployOptions) Warnf(format string, args ...any) {
	if o.Infof != nil {
		o.Infof("warning: "+format, args...)
	}
}

// CertDeployer is a deployer of one platform.
type CertDeployer interface {
	// ID is the id of --deployer and cert.skip_accounts (aliyun-alb).
	ID() string
	Platform() ID
	// Discover is read-only: it lists the targets of the account and
	// reports the ones it leaves alone (a stopped listener, a managed
	// certificate) as Skipped changes. An error fails the deployer for the
	// account.
	Discover(ctx context.Context, acct *DeployAccount, o DeployOptions) ([]DeployTarget, []Change, error)
	// Plan returns the steps that put cert on the target (upload it, bind
	// it, wait). Every write is in a Step.Apply.
	Plan(ctx context.Context, acct *DeployAccount, t DeployTarget, cert *DeployCert, o DeployOptions) ([]Step, error)
	// Prune returns the steps that delete the expired certificates of the
	// account that nothing uses any more (--prune-expired).
	Prune(ctx context.Context, acct *DeployAccount, o DeployOptions) ([]Step, error)
}

// DeployItem is a target with the certificate it is to get.
type DeployItem struct {
	Target DeployTarget
	Cert   *DeployCert
}

// BatchDeployer is a deployer whose targets of one Group are updated in a
// single write: Plan is not called for them, PlanBatch is, once per group,
// after every target of the account was looked at.
type BatchDeployer interface {
	CertDeployer
	PlanBatch(ctx context.Context, acct *DeployAccount, group string, items []DeployItem, o DeployOptions) ([]Step, error)
}

var (
	deployerMu sync.RWMutex
	deployers  = map[string]CertDeployer{}
)

// RegisterDeployer adds a deployer. Called from provider packages' init().
func RegisterDeployer(d CertDeployer) {
	deployerMu.Lock()
	defer deployerMu.Unlock()
	if _, dup := deployers[d.ID()]; dup {
		panic(fmt.Sprintf("deployer %q registered twice", d.ID()))
	}
	deployers[d.ID()] = d
}

// OverrideDeployer replaces (or adds) a deployer and returns a function
// restoring the previous state. Intended for tests.
func OverrideDeployer(d CertDeployer) (restore func()) {
	deployerMu.Lock()
	defer deployerMu.Unlock()
	prev, had := deployers[d.ID()]
	deployers[d.ID()] = d
	return func() {
		deployerMu.Lock()
		defer deployerMu.Unlock()
		if had {
			deployers[d.ID()] = prev
		} else {
			delete(deployers, d.ID())
		}
	}
}

// Deployers returns every registered deployer, in platform order then by
// id.
func Deployers() []CertDeployer {
	deployerMu.RLock()
	defer deployerMu.RUnlock()
	out := make([]CertDeployer, 0, len(deployers))
	for _, d := range deployers {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := order(out[i].Platform()), order(out[j].Platform()); a != b {
			return a < b
		}
		return out[i].ID() < out[j].ID()
	})
	return out
}

// DeployerIDs returns the ids of the registered deployers, sorted as
// Deployers.
func DeployerIDs() []string {
	var ids []string
	for _, d := range Deployers() {
		ids = append(ids, d.ID())
	}
	return ids
}

// GetDeployer returns the deployer of an id.
func GetDeployer(id string) (CertDeployer, bool) {
	deployerMu.RLock()
	defer deployerMu.RUnlock()
	d, ok := deployers[id]
	return d, ok
}
