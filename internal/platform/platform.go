// Package platform defines the provider-neutral abstractions every
// supported platform (cloud, CDN/DNS, registrar) implements. Commands in
// internal/cli and the routing logic in internal/app depend only on these
// types; concrete implementations live under internal/providers.
package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/prompt"
)

// ID identifies a supported platform.
type ID string

const (
	AWS        ID = "aws"
	GCP        ID = "gcp"
	Aliyun     ID = "aliyun"
	Cloudflare ID = "cloudflare"
	NameCom    ID = "namecom"
	GoDaddy    ID = "godaddy"
)

// All lists every known platform in display order.
var All = []ID{Cloudflare, NameCom, GoDaddy, AWS, GCP, Aliyun}

// Parse resolves a user-supplied platform name (accepting common aliases).
func Parse(s string) (ID, error) {
	switch s {
	case "aws", "amazon":
		return AWS, nil
	case "gcp", "google", "gcloud":
		return GCP, nil
	case "aliyun", "alibaba", "alicloud":
		return Aliyun, nil
	case "cloudflare", "cf":
		return Cloudflare, nil
	case "namecom", "name.com", "name":
		return NameCom, nil
	case "godaddy", "gd":
		return GoDaddy, nil
	}
	return "", fmt.Errorf("unknown platform %q (expected one of: cloudflare, namecom, godaddy, aws, gcp, aliyun)", s)
}

// ResourceType classifies entries in the local inventory.
type ResourceType string

const (
	// ResDomain is a registered domain at a registrar.
	ResDomain ResourceType = "domain"
	// ResZone is a DNS zone (hosted zone, managed zone, Cloudflare zone, ...).
	ResZone ResourceType = "zone"
	// ResDNSRecord is a single DNS record inside a zone.
	ResDNSRecord ResourceType = "dns_record"
	// ResInstance is a compute instance (EC2, GCE, ECS).
	ResInstance ResourceType = "instance"
	// ResSecurityGroup is a security group or firewall rule set.
	ResSecurityGroup ResourceType = "security_group"
	// ResLoadBalancer is a load balancer (ELBv2, ALB, a GCP load balancer).
	ResLoadBalancer ResourceType = "load_balancer"
	// ResCertificate is a certificate held by a platform (ACM, CAS, GCP SSL
	// certificates).
	ResCertificate ResourceType = "certificate"
	// ResVolume is a block storage volume (EBS).
	ResVolume ResourceType = "volume"
	// ResDBInstance is a managed database instance (RDS).
	ResDBInstance ResourceType = "db_instance"
	// ResEIP is an elastic / static public IP address.
	ResEIP ResourceType = "eip"
	// ResKeyPair is an SSH key pair registered with a platform.
	ResKeyPair ResourceType = "key_pair"
)

// ResourceTypeInfo describes one inventory resource type.
type ResourceTypeInfo struct {
	Type ResourceType
	// DefaultTTL is how long a synced set of this type stays fresh unless
	// config.yaml says otherwise.
	DefaultTTL time.Duration
	// Description is a short help text.
	Description string
}

// resourceTypes is the table of known types, in display order. A new type
// is added here (and synced by the providers that list it in
// Provider.ResourceTypes); parsing, help, completion and TTLs follow.
var resourceTypes = []ResourceTypeInfo{
	{ResDomain, 24 * time.Hour, "registered domains"},
	{ResZone, 24 * time.Hour, "DNS zones"},
	{ResDNSRecord, time.Hour, "DNS records"},
	{ResInstance, 15 * time.Minute, "compute instances"},
	{ResSecurityGroup, time.Hour, "security groups and firewalls"},
	{ResLoadBalancer, time.Hour, "load balancers"},
	{ResCertificate, 24 * time.Hour, "certificates held by a platform"},
	{ResVolume, time.Hour, "block storage volumes"},
	{ResDBInstance, 15 * time.Minute, "managed database instances"},
	{ResEIP, time.Hour, "elastic / static public IP addresses"},
	{ResKeyPair, 24 * time.Hour, "SSH key pairs"},
}

// ResourceTypes returns every known inventory resource type, in display
// order.
func ResourceTypes() []ResourceTypeInfo { return append([]ResourceTypeInfo(nil), resourceTypes...) }

// ResourceTypeNames returns the names of every known resource type.
func ResourceTypeNames() []string {
	out := make([]string, 0, len(resourceTypes))
	for _, t := range resourceTypes {
		out = append(out, string(t.Type))
	}
	return out
}

// ParseResourceType validates a user-supplied resource type.
func ParseResourceType(s string) (ResourceType, error) {
	for _, t := range resourceTypes {
		if string(t.Type) == s {
			return t.Type, nil
		}
	}
	return "", fmt.Errorf("unknown resource type %q (expected one of: %s)", s, strings.Join(ResourceTypeNames(), ", "))
}

// Profile is a configured account on a platform together with its secret.
// Metadata is persisted in config.yaml; Secret lives in the credential store.
type Profile struct {
	Name     string
	Platform ID
	Metadata map[string]string
	Secret   map[string]string
	// UpdateSecret persists a replacement secret (e.g. refreshed tokens).
	// It is nil when the profile was not loaded from a credential store.
	UpdateSecret func(secret map[string]string) error
	// RefreshSecret replaces the secret in step with other polyctl
	// processes: fn runs while the credential store is locked and is given
	// the secret as it is stored at that moment, which another process may
	// have replaced since Secret was read. The map fn returns is stored;
	// nil stores nothing. It is how a rotating refresh token is renewed
	// without two processes spending the same one. It is nil when the
	// profile was not loaded from a credential store.
	RefreshSecret func(fn func(current map[string]string) (map[string]string, error)) error
}

// Meta returns a metadata value or "".
func (p Profile) Meta(key string) string { return p.Metadata[key] }

// LoginInput carries everything a login flow may need, in either flow.
type LoginInput struct {
	ProfileName string
	// Interactive is the flow of the command, as decided by the runtime.
	// When false the login must not ask, choose or confirm anything and must
	// not read a terminal: values come from Options, the documented
	// environment variables and, where a provider documents it, one value
	// piped on stdin; whatever is still missing is a usage error. Providers
	// branch on this value only, never on the kind of the streams.
	Interactive bool
	// Prompt is the shared line reader on Stdin, already in that flow. Nil
	// (tests) means one is built from the streams below.
	Prompt *prompt.IO
	// Picker asks choices with an arrow-key list in the interactive flow.
	// Nil (tests) means choices are asked as lines on Prompt.
	Picker prompt.Picker
	// Options are free-form key=value pairs from `auth login --set k=v`.
	Options map[string]string
	// Existing metadata when re-authenticating an existing profile.
	Existing map[string]string
	// IO for prompts.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// OpenBrowser opens a URL in the user's browser; it never fails the
	// login flow, callers should print the URL as a fallback.
	OpenBrowser func(url string) error
	// NoBrowser disables automatic browser launching. It is always set in
	// the non-interactive flow.
	NoBrowser bool
}

// IO returns the prompts of the login flow: the shared reader when there is
// one, in the flow of in.Interactive, ending with ctx.
func (in LoginInput) IO(ctx context.Context) *prompt.IO {
	p := in.Prompt
	if p == nil {
		p = prompt.New(in.Stdin, in.Stdout, in.Stderr)
	}
	return p.WithInteractive(in.Interactive).WithContext(ctx)
}

// MayOpenBrowser reports whether the login may launch a browser: only in
// the interactive flow, and not with --no-browser. Otherwise the URL is
// printed and that is all.
func (in LoginInput) MayOpenBrowser() bool {
	return in.Interactive && !in.NoBrowser && in.OpenBrowser != nil
}

// CheckLoginOption reports a login option key p does not accept, naming the
// keys it does.
func CheckLoginOption(p Provider, key string) error {
	valid := p.LoginOptions()
	for _, k := range valid {
		if k == key {
			return nil
		}
	}
	return fmt.Errorf("unknown login option %q for %s (valid: %s)", key, p.ID(), strings.Join(valid, ", "))
}

// Opt returns a login option or the default.
func (in LoginInput) Opt(key, def string) string {
	if v, ok := in.Options[key]; ok && v != "" {
		return v
	}
	return def
}

// LoginResult is what a successful login produces.
type LoginResult struct {
	// Secret is stored in the credential store (keychain or file).
	Secret map[string]string
	// Metadata is stored in config.yaml (non-sensitive: account id, email, region...).
	Metadata map[string]string
	// Label is a short human description shown after login (e.g. the account email).
	Label string
}

// Identity describes the authenticated principal, as returned by Verify.
type Identity struct {
	Account string            `json:"account,omitempty" yaml:"account,omitempty"`
	User    string            `json:"user,omitempty" yaml:"user,omitempty"`
	Extra   map[string]string `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// Provider is implemented once per platform and registered via Register.
type Provider interface {
	ID() ID
	DisplayName() string
	// LoginHelp is a short description of the login flow, shown in `auth login --help`.
	LoginHelp() string
	// LoginOptions lists the keys `auth login --set key=value` accepts for
	// this platform. Any other key is a usage error, so that a misspelled
	// or removed option is never silently ignored.
	LoginOptions() []string
	// Login runs the authentication flow (see LoginInput.Interactive).
	Login(ctx context.Context, in LoginInput) (*LoginResult, error)
	// Open creates an authenticated client for the profile.
	Open(ctx context.Context, p Profile) (Client, error)
	// ResourceTypes lists the inventory resource types this provider can sync.
	ResourceTypes() []ResourceType
}

// Revoker is implemented by providers whose logins create an authorization
// on the platform that outlives the stored secret (an OAuth grant). Removing
// such an account withdraws it there too, best effort: the account is
// removed whether or not the platform could be told.
type Revoker interface {
	// CanRevoke reports whether the profile holds such an authorization,
	// without using the network.
	CanRevoke(p Profile) bool
	// Revoke withdraws the authorization of the profile on the platform.
	Revoke(ctx context.Context, p Profile) error
}

// Client is an authenticated session with a platform. Clients may also
// implement DNSService and/or RegistrarService.
type Client interface {
	// Verify checks that the credentials still work.
	Verify(ctx context.Context) (*Identity, error)
	// Sync fetches all resources of a type. For ResDNSRecord implementations
	// must return records of every zone, with Resource.ParentID set to the zone id.
	Sync(ctx context.Context, rt ResourceType) ([]Resource, error)
}

// Resource is a platform object as stored in the inventory.
type Resource struct {
	Type ResourceType
	// ID is the platform-native identifier (zone id, record id, instance id,
	// or the domain name itself for ResDomain).
	ID   string
	Name string
	// ParentID links records to their zone (zone id). Empty otherwise.
	ParentID string
	// Domain is the apex/zone domain this resource is indexed under for
	// domain routing (zone name or registered domain). Empty for non-domain resources.
	Domain string
	// Data is the platform-native representation; it is JSON-encoded in the DB.
	Data any
}

// DNSService is implemented by clients that host DNS zones.
type DNSService interface {
	ListZones(ctx context.Context) ([]Zone, error)
	ListRecords(ctx context.Context, zoneID string) ([]Record, error)
	// CreateRecord creates a record. Name must be a FQDN (without trailing dot).
	CreateRecord(ctx context.Context, zoneID string, r Record) (*Record, error)
	// UpdateRecord replaces the record identified by r.ID.
	UpdateRecord(ctx context.Context, zoneID string, r Record) (*Record, error)
	DeleteRecord(ctx context.Context, zoneID, recordID string) error
}

// RegistrarService is implemented by clients that manage registered domains.
type RegistrarService interface {
	ListDomains(ctx context.Context) ([]Domain, error)
	GetDomain(ctx context.Context, name string) (*Domain, error)
	SetNameservers(ctx context.Context, name string, ns []string) error
}

// Zone is a DNS zone.
type Zone struct {
	ID          string         `json:"id" yaml:"id"`
	Name        string         `json:"name" yaml:"name"`
	Nameservers []string       `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
	Status      string         `json:"status,omitempty" yaml:"status,omitempty"`
	Extra       map[string]any `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// Record is a DNS record. Name is always the FQDN without trailing dot.
type Record struct {
	ID       string         `json:"id" yaml:"id"`
	ZoneID   string         `json:"zone_id" yaml:"zone_id"`
	Name     string         `json:"name" yaml:"name"`
	Type     string         `json:"type" yaml:"type"`
	Value    string         `json:"value" yaml:"value"`
	TTL      int            `json:"ttl" yaml:"ttl"`
	Priority *int           `json:"priority,omitempty" yaml:"priority,omitempty"`
	Proxied  *bool          `json:"proxied,omitempty" yaml:"proxied,omitempty"`
	Extra    map[string]any `json:"extra,omitempty" yaml:"extra,omitempty"`
	// Meta is what the platform says about the record itself, read-only:
	// on Cloudflare the meta object of the API, which names the R2 bucket
	// of a record created for a bucket's custom domain (r2_bucket) and
	// marks records that cannot be edited (read_only). Empty elsewhere.
	Meta map[string]any `json:"meta,omitempty" yaml:"meta,omitempty"`
}

// UnmarshalJSON reads a record, accepting the "content" key polyctl 0.1.x
// stored a record's value under when "value" is absent. A cached inventory
// row written by 0.1.x therefore never decodes to a record without a value.
// Records are only ever written with "value".
func (r *Record) UnmarshalJSON(b []byte) error {
	type plain Record
	aux := struct {
		*plain
		Content *string `json:"content"`
	}{plain: (*plain)(r)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if r.Value == "" && aux.Content != nil {
		r.Value = *aux.Content
	}
	return nil
}

// Domain is a registered domain.
type Domain struct {
	Name        string         `json:"name" yaml:"name"`
	Nameservers []string       `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
	Status      string         `json:"status,omitempty" yaml:"status,omitempty"`
	ExpiresAt   string         `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	AutoRenew   *bool          `json:"auto_renew,omitempty" yaml:"auto_renew,omitempty"`
	Locked      *bool          `json:"locked,omitempty" yaml:"locked,omitempty"`
	Privacy     *bool          `json:"privacy,omitempty" yaml:"privacy,omitempty"`
	Extra       map[string]any `json:"extra,omitempty" yaml:"extra,omitempty"`
}

// Sentinel errors. Providers wrap platform errors with these so the CLI can
// map them to exit codes.
var (
	ErrUnauthorized   = errors.New("unauthorized")
	ErrNotFound       = errors.New("not found")
	ErrNotSupported   = errors.New("not supported by this platform")
	ErrLoginCancelled = errors.New("login cancelled")
)
