package config

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

// Hooks are commands or URLs polyctl calls on events of unattended runs.
type Hooks struct {
	// OnFailure is a webhook URL (http:// or https://, which gets a POST with
	// a JSON body) or a shell command (run with the event in its environment
	// and as JSON on stdin), called when an ensure-style command fails.
	// Empty: no notification.
	OnFailure string `yaml:"on_failure,omitempty"`
}

// CertDNS configures the DNS propagation check of certificate issuance.
type CertDNS struct {
	Resolvers          []string `yaml:"resolvers,omitempty"`
	MinResolvers       int      `yaml:"min_resolvers,omitempty"`
	PropagationTimeout Duration `yaml:"propagation_timeout,omitempty"`
	PollInterval       Duration `yaml:"poll_interval,omitempty"`
	SettleDelay        Duration `yaml:"settle_delay,omitempty"`
}

// DNSSettings configures the live DNS queries of `domain ns check`.
type DNSSettings struct {
	// Resolvers are the recursive resolvers asked, in order: IP addresses
	// (port 53) or IP:port. Empty: platform.DefaultNSResolvers.
	Resolvers []string `yaml:"resolvers,omitempty"`
	// Timeout is the timeout of one query. Zero: platform.DefaultNSTimeout.
	Timeout Duration `yaml:"timeout,omitempty"`
}

// NSResolvers returns dns.resolvers, or the built-in public resolvers.
func (c *Config) NSResolvers() []string {
	if len(c.DNS.Resolvers) > 0 {
		return slices.Clone(c.DNS.Resolvers)
	}
	return slices.Clone(platform.DefaultNSResolvers)
}

// NSTimeout returns dns.timeout, or the built-in default.
func (c *Config) NSTimeout() time.Duration {
	if c.DNS.Timeout > 0 {
		return time.Duration(c.DNS.Timeout)
	}
	return platform.DefaultNSTimeout
}

// CertRegions lists the regions a certificate deployer scans.
type CertRegions struct {
	Regions []string `yaml:"regions,omitempty"`
}

// Cert configures the certificate commands.
type Cert struct {
	Email         string      `yaml:"email,omitempty"`
	AgreeTOS      bool        `yaml:"agree_tos,omitempty"`
	Dir           string      `yaml:"dir,omitempty"`
	ACMEDirectory string      `yaml:"acme_directory,omitempty"`
	KeyType       string      `yaml:"key_type,omitempty"`
	ReuseKey      bool        `yaml:"reuse_key,omitempty"`
	RenewDays     int         `yaml:"renew_days,omitempty"`
	NameTemplate  string      `yaml:"name_template,omitempty"`
	SkipAccounts  []string    `yaml:"skip_accounts,omitempty"`
	DNS           CertDNS     `yaml:"dns,omitempty"`
	AWS           CertRegions `yaml:"aws,omitempty"`
	Aliyun        CertRegions `yaml:"aliyun,omitempty"`
}

// Built-in defaults of the cert keys.
const (
	DefaultACMEDirectory    = "https://acme-v02.api.letsencrypt.org/directory"
	DefaultCertKeyType      = "ec256"
	DefaultCertRenewDays    = 30
	DefaultCertNameTemplate = "upload_{name}_{not_after}"
	DefaultMinResolvers     = 2
)

// DefaultResolvers are the public resolvers the propagation check asks:
// Cloudflare, Google, AliDNS and 114DNS. Only MinResolvers of them have to
// see a record.
var DefaultResolvers = []string{"1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53", "114.114.114.114:53"}

// CertKeyTypes are the accepted values of cert.key_type.
var CertKeyTypes = []string{"ec256", "ec384", "rsa2048", "rsa4096"}

// CertDir returns cert.dir (a leading ~ is the home directory), or
// <config dir>/certs.
func (c *Config) CertDir() string {
	if d := strings.TrimSpace(c.Cert.Dir); d != "" {
		return platform.ExpandHome(d)
	}
	return filepath.Join(filepath.Dir(c.path), "certs")
}

// CertSettings returns the cert keys with every unset value replaced by its
// built-in default.
func (c *Config) CertSettings() Cert {
	s := c.Cert
	s.Dir = c.CertDir()
	if s.ACMEDirectory == "" {
		s.ACMEDirectory = DefaultACMEDirectory
	}
	if s.KeyType == "" {
		s.KeyType = DefaultCertKeyType
	}
	if s.RenewDays == 0 {
		s.RenewDays = DefaultCertRenewDays
	}
	if s.NameTemplate == "" {
		s.NameTemplate = DefaultCertNameTemplate
	}
	if len(s.DNS.Resolvers) == 0 {
		s.DNS.Resolvers = slices.Clone(DefaultResolvers)
	}
	if s.DNS.MinResolvers == 0 {
		s.DNS.MinResolvers = DefaultMinResolvers
	}
	if s.DNS.PropagationTimeout == 0 {
		s.DNS.PropagationTimeout = Duration(5 * time.Minute)
	}
	if s.DNS.PollInterval == 0 {
		s.DNS.PollInterval = Duration(10 * time.Second)
	}
	if s.DNS.SettleDelay == 0 {
		s.DNS.SettleDelay = Duration(20 * time.Second)
	}
	return s
}

// Naming template keys and their built-in defaults. The variables a
// template may use are listed in NamingVars.
var DefaultNaming = map[string]string{
	"aws_elbv2_load_balancer":    "{name}-lb",
	"aws_elbv2_target_group":     "{name}-{port}-target",
	"aliyun_alb_load_balancer":   "lb-{name}",
	"aliyun_alb_server_group":    "{service}-{protocol}",
	"aliyun_vpc":                 "{region}-vpc",
	"aliyun_vswitch":             "{region}-switch-{zone}",
	"aliyun_ecs_security_group":  "sg-common",
	"gcp_lb_prefix":              "lb-",
	"gcp_instance_group_prefix":  "ig-",
	"gcp_backend_service_prefix": "bs-",
	"gcp_proxy_prefix":           "proxy-",
	"gcp_forwarding_rule_prefix": "fr-",
	"gcp_instance_external_ip":   "{name}-external-ip",
	"gcp_instance_internal_ip":   "{name}-internal-ip",
}

// NamingVars are the variables naming templates (and cert.name_template,
// which adds not_after) may use.
var NamingVars = []string{"name", "service", "protocol", "port", "region", "zone"}

// NamingTemplate returns naming.<key>, or its built-in default.
func (c *Config) NamingTemplate(key string) string {
	if v, ok := c.Naming[key]; ok && v != "" {
		return v
	}
	return DefaultNaming[key]
}

// Name renders the naming template of key with vars.
func (c *Config) Name(key string, vars map[string]string) (string, error) {
	tmpl := c.NamingTemplate(key)
	if tmpl == "" {
		return "", fmt.Errorf("unknown naming key %q", key)
	}
	return RenderTemplate(tmpl, vars)
}

// RenderTemplate replaces every {var} of tmpl with vars[var]. A variable
// that vars does not hold, or an unbalanced brace, is an error: a name is
// never produced with a hole in it.
func RenderTemplate(tmpl string, vars map[string]string) (string, error) {
	var b strings.Builder
	rest := tmpl
	for {
		i := strings.IndexAny(rest, "{}")
		if i < 0 {
			b.WriteString(rest)
			return b.String(), nil
		}
		if rest[i] == '}' {
			return "", fmt.Errorf("template %q: unbalanced }", tmpl)
		}
		b.WriteString(rest[:i])
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return "", fmt.Errorf("template %q: unbalanced {", tmpl)
		}
		name := rest[i+1 : i+j]
		v, ok := vars[name]
		if !ok {
			return "", fmt.Errorf("template %q: variable {%s} is not available here", tmpl, name)
		}
		b.WriteString(v)
		rest = rest[i+j+1:]
	}
}

// templateVars returns the variables of tmpl, or an error for an
// unbalanced brace.
func templateVars(tmpl string) ([]string, error) {
	var out []string
	rest := tmpl
	for {
		i := strings.IndexAny(rest, "{}")
		if i < 0 {
			return out, nil
		}
		if rest[i] == '}' {
			return nil, fmt.Errorf("unbalanced }")
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return nil, fmt.Errorf("unbalanced {")
		}
		out = append(out, rest[i+1:i+j])
		rest = rest[i+j+1:]
	}
}

// Defaults holds per-platform default values: defaults.<platform>.<key>.
// Values are scalars, lists or nested mappings (defaults.aws.rds.*).
type Defaults map[string]map[string]any

// validate checks the settings that have a fixed vocabulary, so that a
// typo is reported when the config is loaded and not silently ignored.
func (c *Config) validate() error {
	keys := make([]string, 0, len(c.Naming))
	for k := range c.Naming {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := DefaultNaming[k]; !ok {
			return fmt.Errorf("naming.%s: unknown naming key (valid: %s)", k, strings.Join(sortedKeys(DefaultNaming), ", "))
		}
		vars, err := templateVars(c.Naming[k])
		if err != nil {
			return fmt.Errorf("naming.%s: %v", k, err)
		}
		for _, v := range vars {
			if !slices.Contains(NamingVars, v) {
				return fmt.Errorf("naming.%s: unknown variable {%s} (valid: {%s})", k, v, strings.Join(NamingVars, "}, {"))
			}
		}
	}
	if c.Cert.KeyType != "" && !slices.Contains(CertKeyTypes, c.Cert.KeyType) {
		return fmt.Errorf("cert.key_type: %q is not one of %s", c.Cert.KeyType, strings.Join(CertKeyTypes, ", "))
	}
	if c.Cert.RenewDays < 0 {
		return fmt.Errorf("cert.renew_days: must not be negative, got %d", c.Cert.RenewDays)
	}
	if c.Cert.DNS.MinResolvers < 0 {
		return fmt.Errorf("cert.dns.min_resolvers: must not be negative, got %d", c.Cert.DNS.MinResolvers)
	}
	if t := c.Cert.NameTemplate; t != "" {
		if _, err := templateVars(t); err != nil {
			return fmt.Errorf("cert.name_template: %v", err)
		}
	}
	for _, r := range c.DNS.Resolvers {
		if _, err := platform.ParseResolver(r); err != nil {
			return fmt.Errorf("dns.resolvers: %v", err)
		}
	}
	if c.DNS.Timeout < 0 {
		return fmt.Errorf("dns.timeout: must not be negative, got %s", time.Duration(c.DNS.Timeout))
	}
	if err := validateDefaults("defaults", c.Defaults); err != nil {
		return err
	}
	for _, name := range c.ProfileNames() {
		if err := validateDefaults("profiles."+name+".defaults", c.Profiles[name].Defaults); err != nil {
			return err
		}
	}
	return nil
}

func validateDefaults(where string, d Defaults) error {
	names := make([]string, 0, len(d))
	for p := range d {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		if mustParse(p) != platform.ID(p) {
			return fmt.Errorf("%s.%s: unknown platform (expected one of: cloudflare, namecom, godaddy, aws, gcp, aliyun)", where, p)
		}
	}
	if v, ok := lookup(d["cloudflare"], "ssl"); ok {
		if s, isStr := v.(string); !isStr || !slices.Contains(CloudflareSSLModes, s) {
			return fmt.Errorf("%s.cloudflare.ssl: %v is not one of %s", where, v, strings.Join(CloudflareSSLModes, ", "))
		}
	}
	return nil
}

// mustParse returns the platform id of a valid name ("" otherwise).
func mustParse(s string) platform.ID {
	id, _ := platform.Parse(s)
	return id
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BuiltinDefaults are the defaults.<platform>.<key> values that have a
// neutral built-in default; every other key is unset unless configured.
var BuiltinDefaults = Defaults{
	"gcp":        {"lb_network_tag": "lb-health-check"},
	"cloudflare": {"ssl": "strict"},
}

// CloudflareSSLModes are the accepted values of defaults.cloudflare.ssl.
var CloudflareSSLModes = []string{"flexible", "full", "strict"}

// Default returns the default value of key for a platform:
// profiles.<profile>.defaults.<platform>.<key> when the profile sets it,
// else defaults.<platform>.<key>, else the built-in default of
// BuiltinDefaults. key may be a dotted path into a nested mapping
// ("rds.default_class"). The second result says whether a value was found.
func (c *Config) Default(profile string, id platform.ID, key string) (any, bool) {
	if p := c.Profiles[profile]; p != nil {
		if v, ok := lookup(p.Defaults[string(id)], key); ok {
			return v, true
		}
	}
	if v, ok := lookup(c.Defaults[string(id)], key); ok {
		return v, true
	}
	return lookup(BuiltinDefaults[string(id)], key)
}

func lookup(m map[string]any, key string) (any, bool) {
	if m == nil {
		return nil, false
	}
	parts := strings.Split(key, ".")
	var cur any = m
	for _, part := range parts {
		switch mm := cur.(type) {
		case map[string]any:
			v, ok := mm[part]
			if !ok {
				return nil, false
			}
			cur = v
		case map[any]any:
			v, ok := mm[part]
			if !ok {
				return nil, false
			}
			cur = v
		default:
			return nil, false
		}
	}
	if cur == nil {
		return nil, false
	}
	return cur, true
}

// DefaultString returns a default as a string ("" when unset). Numbers and
// booleans are formatted; a list or mapping is an error.
func (c *Config) DefaultString(profile string, id platform.ID, key string) (string, error) {
	v, ok := c.Default(profile, id, key)
	if !ok {
		return "", nil
	}
	switch x := v.(type) {
	case string:
		return x, nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(x), nil
	}
	return "", fmt.Errorf("%s: expected a single value, got %T", defaultKeyPath(id, key), v)
}

// DefaultStrings returns a default as a list: a YAML list, or a single
// value split at commas. Unset is an empty list.
func (c *Config) DefaultStrings(profile string, id platform.ID, key string) ([]string, error) {
	v, ok := c.Default(profile, id, key)
	if !ok {
		return nil, nil
	}
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			switch s := e.(type) {
			case string:
				out = append(out, s)
			case int, int64, float64, bool:
				out = append(out, fmt.Sprint(s))
			default:
				return nil, fmt.Errorf("%s: list entries must be single values, got %T", defaultKeyPath(id, key), e)
			}
		}
		return out, nil
	case string:
		var out []string
		for _, s := range strings.Split(x, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	}
	s, err := c.DefaultString(profile, id, key)
	if err != nil {
		return nil, fmt.Errorf("%s: expected a list, got %T", defaultKeyPath(id, key), v)
	}
	return []string{s}, nil
}

// DefaultMap returns a default mapping of single values (tags). Unset is
// nil.
func (c *Config) DefaultMap(profile string, id platform.ID, key string) (map[string]string, error) {
	v, ok := c.Default(profile, id, key)
	if !ok {
		return nil, nil
	}
	out := map[string]string{}
	add := func(k, val any) error {
		switch val.(type) {
		case string, int, int64, float64, bool:
			out[fmt.Sprint(k)] = fmt.Sprint(val)
			return nil
		}
		return fmt.Errorf("%s.%v: expected a single value, got %T", defaultKeyPath(id, key), k, val)
	}
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if err := add(k, val); err != nil {
				return nil, err
			}
		}
	case map[any]any:
		for k, val := range x {
			if err := add(k, val); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("%s: expected a mapping, got %T", defaultKeyPath(id, key), v)
	}
	return out, nil
}

func defaultKeyPath(id platform.ID, key string) string { return "defaults." + string(id) + "." + key }
