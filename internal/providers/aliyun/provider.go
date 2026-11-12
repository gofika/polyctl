// Package aliyun implements the Alibaba Cloud provider: Alibaba Cloud DNS
// (alidns) zones and records, the domain registrar and ECS instances,
// authenticated with a RAM AccessKey.
//
// Profile metadata keys (persisted in config.yaml, never sensitive):
//
//	method      always "access_key"
//	region      default region id used for ECS and signing (e.g. cn-hangzhou)
//	site        registrar site, "cn" (aliyun.com) or "intl" (alibabacloud.com);
//	            optional, derived from region when absent (cn-* = cn)
//	account_id  the Alibaba Cloud account id returned by STS
//	principal   the caller ARN (acs:ram::<account>:user/<name>)
//	key_prefix  first 8 characters of the AccessKey ID, to tell keys apart
//
// Secret keys (stored in the credential store):
//
//	access_key_id      the RAM AccessKey ID
//	access_key_secret  the RAM AccessKey Secret
package aliyun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func init() { platform.Register(&provider{}) }

const (
	// DefaultRegion is used when a profile does not name a region.
	DefaultRegion = "cn-hangzhou"
	accessKeyURL  = "https://ram.console.aliyun.com/manage/ak"

	metaMethod    = "method"
	metaRegion    = "region"
	metaSite      = "site"
	metaAccountID = "account_id"
	metaPrincipal = "principal"
	metaKeyPrefix = "key_prefix"

	secretKeyID     = "access_key_id"
	secretKeySecret = "access_key_secret"
)

type provider struct{}

func (*provider) ID() platform.ID     { return platform.Aliyun }
func (*provider) DisplayName() string { return "Alibaba Cloud" }

func (*provider) LoginHelp() string {
	return `RAM AccessKey. Opens ` + accessKeyURL + ` so you can create a RAM user with
AliyunDNSFullAccess / AliyunDomainFullAccess / AliyunECSReadOnlyAccess (as needed) and prompts
for the AccessKey ID and Secret. Options: --set region=<id> (default ` + DefaultRegion + `),
--set site=cn|intl to force the registrar site (default: cn for cn-* regions, intl otherwise),
--set from_cli=<profile> to import the key from ~/.aliyun/config.json (aliyun CLI).
Non-interactive: --set access_key_id=... --set access_key_secret=- (the secret on stdin),
or ` + envKeyID + ` / ` + envKeySecret + `, or --set from_cli=<profile>.`
}

func (*provider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResDomain, platform.ResInstance}
}

// Environment variables read for the AccessKey, the names the Alibaba Cloud
// SDKs and CLI use.
const (
	envKeyID     = "ALIBABA_CLOUD_ACCESS_KEY_ID"
	envKeySecret = "ALIBABA_CLOUD_ACCESS_KEY_SECRET"
)

// Login runs the AccessKey flow (or imports from the aliyun CLI). The key
// comes from --set from_cli, from --set access_key_id / access_key_secret,
// then from the environment. After that the interactive flow asks for what
// is missing; the non-interactive flow asks nothing: a missing value is a
// usage error, and the region falls back to its default.
func (p *provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	io := in.IO(ctx)
	region := in.Opt("region", "")
	keyID := strings.TrimSpace(in.Opt(secretKeyID, ""))
	keySecret := strings.TrimSpace(in.Opt(secretKeySecret, ""))

	if cliProfile := in.Opt("from_cli", ""); cliProfile != "" {
		cp, err := loadCLIProfile(cliConfigPath(), cliProfile)
		if err != nil {
			return nil, err
		}
		keyID, keySecret = cp.AccessKeyID, cp.AccessKeySecret
		if region == "" {
			region = cp.RegionID
		}
		fmt.Fprintf(io.Err, "Imported AccessKey %s... from aliyun CLI profile %q.\n", keyPrefix(keyID), cp.Name)
	} else if keyID == "" && keySecret == "" && strings.TrimSpace(os.Getenv(envKeyID)) != "" && strings.TrimSpace(os.Getenv(envKeySecret)) != "" {
		// As a whole only, so that halves of two keys are never mixed.
		keyID, keySecret = strings.TrimSpace(os.Getenv(envKeyID)), strings.TrimSpace(os.Getenv(envKeySecret))
		fmt.Fprintf(io.Err, "using the AccessKey from %s / %s\n", envKeyID, envKeySecret)
	}
	if (keyID == "" || keySecret == "") && !in.Interactive {
		var missing []string
		if keyID == "" {
			missing = append(missing, "--set access_key_id=<id>")
		}
		if keySecret == "" {
			missing = append(missing, "--set access_key_secret=- (the secret on stdin)")
		}
		return nil, app.UsageErrf("aliyun login needs an AccessKey: pass %s, or set %s and %s, or import one with --set from_cli=<profile>",
			strings.Join(missing, " and "), envKeyID, envKeySecret)
	}
	if keyID == "" || keySecret == "" {
		fmt.Fprintln(io.Err, "Alibaba Cloud has no browser login for third-party tools; a RAM AccessKey is used instead.")
		fmt.Fprintln(io.Err, "Create one (RAM user with AliyunDNSFullAccess, AliyunDomainFullAccess and/or AliyunECSReadOnlyAccess) at:")
		fmt.Fprintln(io.Err, "  "+accessKeyURL)
		if in.MayOpenBrowser() {
			if err := in.OpenBrowser(accessKeyURL); err != nil {
				fmt.Fprintf(io.Err, "(could not open the browser: %v)\n", err)
			}
		}
		var err error
		if keyID == "" {
			if keyID, err = io.Required("AccessKey ID"); err != nil {
				return nil, err
			}
		}
		if keySecret == "" {
			if keySecret, err = io.RequiredSecret("AccessKey Secret"); err != nil {
				return nil, err
			}
		}
	}
	if region == "" {
		def := in.Existing[metaRegion]
		if def == "" {
			def = DefaultRegion
		}
		if in.Interactive {
			var err error
			if region, err = io.Line("Region id", def); err != nil {
				return nil, err
			}
		} else {
			// The default of the question, taken without asking.
			region = def
			fmt.Fprintf(io.Err, "using region %s (pass --set region=<id> to choose another)\n", region)
		}
	}
	region = strings.TrimSpace(region)
	site, err := parseSite(in.Opt(metaSite, in.Existing[metaSite]))
	if err != nil {
		return nil, err
	}

	c := newClient(region, keyID, keySecret)
	c.site = site
	id, err := c.Verify(ctx)
	if err != nil {
		return nil, fmt.Errorf("verify AccessKey: %w", err)
	}
	meta := map[string]string{
		metaMethod:    "access_key",
		metaRegion:    region,
		metaAccountID: id.Account,
		metaPrincipal: id.User,
		metaKeyPrefix: keyPrefix(keyID),
	}
	if site != "" {
		meta[metaSite] = site
	}
	return &platform.LoginResult{
		Secret:   map[string]string{secretKeyID: keyID, secretKeySecret: keySecret},
		Metadata: meta,
		Label:    fmt.Sprintf("%s (account %s, region %s)", id.User, id.Account, region),
	}, nil
}

// parseSite validates the registrar site option ("" keeps the default).
func parseSite(v string) (string, error) {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "", siteCN, siteIntl:
		return v, nil
	}
	return "", fmt.Errorf("site must be %q or %q, got %q", siteCN, siteIntl, v)
}

// Open creates a client for a stored profile.
func (*provider) Open(ctx context.Context, p platform.Profile) (platform.Client, error) {
	keyID, keySecret := p.Secret[secretKeyID], p.Secret[secretKeySecret]
	if keyID == "" || keySecret == "" {
		return nil, fmt.Errorf("%w: profile %q has no AccessKey stored (run `polyctl auth login aliyun --profile %s`)", platform.ErrUnauthorized, p.Name, p.Name)
	}
	region := p.Meta(metaRegion)
	if region == "" {
		region = DefaultRegion
	}
	site, err := parseSite(p.Meta(metaSite))
	if err != nil {
		return nil, fmt.Errorf("profile %q: %w", p.Name, err)
	}
	c := newClient(region, keyID, keySecret)
	c.site = site
	return c, nil
}

func keyPrefix(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// cliProfile is one entry of the aliyun CLI configuration file.
type cliProfile struct {
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	RegionID        string `json:"region_id"`
}

type cliConfig struct {
	Current  string       `json:"current"`
	Profiles []cliProfile `json:"profiles"`
}

func cliConfigPath() string {
	if p := os.Getenv("ALIBABA_CLOUD_CLI_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aliyun", "config.json")
}

// loadCLIProfile reads an AccessKey profile from the aliyun CLI config.
// name "current" (or "") selects the CLI's current profile.
func loadCLIProfile(path, name string) (*cliProfile, error) {
	if path == "" {
		return nil, errors.New("aliyun CLI config path is unknown")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read aliyun CLI config: %w", err)
	}
	var cfg cliConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if name == "" || name == "current" {
		name = cfg.Current
	}
	var names []string
	for i := range cfg.Profiles {
		cp := &cfg.Profiles[i]
		names = append(names, cp.Name)
		if cp.Name != name {
			continue
		}
		if cp.Mode != "" && cp.Mode != "AK" {
			return nil, fmt.Errorf("aliyun CLI profile %q uses mode %s; only AK (AccessKey) profiles can be imported", name, cp.Mode)
		}
		if cp.AccessKeyID == "" || cp.AccessKeySecret == "" {
			return nil, fmt.Errorf("aliyun CLI profile %q has no access_key_id/access_key_secret", name)
		}
		return cp, nil
	}
	return nil, fmt.Errorf("%w: aliyun CLI profile %q in %s (available: %s)", platform.ErrNotFound, name, path, strings.Join(names, ", "))
}
