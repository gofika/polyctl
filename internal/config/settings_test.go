package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

func loadYAML(t *testing.T, body string) (*config.Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), config.FileName)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Load(p)
}

const settingsYAML = `
naming:
  aws_elbv2_load_balancer: "{name}-nlb"
hooks:
  on_failure: https://hooks.example.com/polyctl
cert:
  email: ops@example.com
  key_type: rsa2048
  dns:
    min_resolvers: 3
  aws:
    regions: [us-east-1, eu-west-1]
defaults:
  aws:
    instance_type: t3.small
    security_group_ids: [sg-1, sg-2]
    tags:
      team: ops
      cost: 7
    rds:
      default_class: db.t3.micro
  gcp:
    zone: europe-west1-b
profiles:
  acme:
    platforms:
      aws:
        metadata:
          region: eu-west-1
    defaults:
      aws:
        instance_type: t3.large
`

func TestSettingsLoadAndRoundTrip(t *testing.T) {
	cfg, err := loadYAML(t, settingsYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hooks.OnFailure != "https://hooks.example.com/polyctl" || cfg.Cert.Email != "ops@example.com" {
		t.Errorf("hooks/cert = %+v %+v", cfg.Hooks, cfg.Cert)
	}
	// The profile overrides the top-level default; other profiles do not.
	if v, _ := cfg.DefaultString("acme", platform.AWS, "instance_type"); v != "t3.large" {
		t.Errorf("profile override = %q", v)
	}
	if v, _ := cfg.DefaultString("other", platform.AWS, "instance_type"); v != "t3.small" {
		t.Errorf("top-level default = %q", v)
	}
	if v, _ := cfg.DefaultString("acme", platform.AWS, "rds.default_class"); v != "db.t3.micro" {
		t.Errorf("nested default = %q", v)
	}
	if v, _ := cfg.DefaultString("acme", platform.AWS, "vpc_id"); v != "" {
		t.Errorf("unset default = %q", v)
	}
	if l, err := cfg.DefaultStrings("acme", platform.AWS, "security_group_ids"); err != nil || strings.Join(l, ",") != "sg-1,sg-2" {
		t.Errorf("list = %v, %v", l, err)
	}
	if m, err := cfg.DefaultMap("acme", platform.AWS, "tags"); err != nil || m["team"] != "ops" || m["cost"] != "7" {
		t.Errorf("map = %v, %v", m, err)
	}
	if _, err := cfg.DefaultString("acme", platform.AWS, "tags"); err == nil {
		t.Error("a mapping is not a single value")
	}
	// Saving keeps every key.
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := config.Load(cfg.Path())
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := again.DefaultString("acme", platform.AWS, "instance_type"); v != "t3.large" || again.Naming["aws_elbv2_load_balancer"] != "{name}-nlb" ||
		again.Cert.DNS.MinResolvers != 3 || len(again.Cert.AWS.Regions) != 2 || again.Hooks.OnFailure == "" {
		t.Errorf("round trip lost keys: %+v", again)
	}
	// An empty config writes none of the new sections.
	empty, _ := config.Load(filepath.Join(t.TempDir(), config.FileName))
	if err := empty.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(empty.Path())
	for _, k := range []string{"naming", "hooks", "cert", "defaults"} {
		if strings.Contains(string(raw), k+":") {
			t.Errorf("empty config writes %s:\n%s", k, raw)
		}
	}
}

func TestCertSettingsDefaults(t *testing.T) {
	cfg, err := loadYAML(t, "cert:\n  email: a@example.com\n")
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.CertSettings()
	if s.ACMEDirectory != config.DefaultACMEDirectory || s.KeyType != "ec256" || s.RenewDays != 30 || s.DNS.MinResolvers != 2 ||
		len(s.DNS.Resolvers) != 4 || s.Dir != filepath.Join(filepath.Dir(cfg.Path()), "certs") || s.AgreeTOS || s.ReuseKey {
		t.Errorf("cert settings = %+v", s)
	}
}

func TestNamingTemplates(t *testing.T) {
	cfg, err := loadYAML(t, settingsYAML)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := cfg.Name("aws_elbv2_load_balancer", map[string]string{"name": "site"}); err != nil || n != "site-nlb" {
		t.Errorf("configured template = %q, %v", n, err)
	}
	if n, err := cfg.Name("aws_elbv2_target_group", map[string]string{"name": "site", "port": "443"}); err != nil || n != "site-443-target" {
		t.Errorf("default template = %q, %v", n, err)
	}
	if n, _ := cfg.Name("aliyun_ecs_security_group", nil); n != "sg-common" {
		t.Errorf("neutral default = %q", n)
	}
	if _, err := cfg.Name("aws_elbv2_target_group", map[string]string{"name": "site"}); err == nil || !strings.Contains(err.Error(), "{port}") {
		t.Errorf("missing variable = %v", err)
	}
	if _, err := cfg.Name("nope", nil); err == nil {
		t.Error("unknown key")
	}
	for _, bad := range []string{"{name", "name}", "a{b}c{"} {
		if _, err := config.RenderTemplate(bad, map[string]string{"name": "x", "b": "y"}); err == nil {
			t.Errorf("RenderTemplate(%q) accepted", bad)
		}
	}
}

func TestSettingsValidation(t *testing.T) {
	for body, want := range map[string]string{
		"naming:\n  aws_elb_lb: x\n":                        "unknown naming key",
		"naming:\n  aliyun_vpc: \"{regoin}-vpc\"\n":         "unknown variable {regoin}",
		"naming:\n  aliyun_vpc: \"{region-vpc\"\n":          "unbalanced",
		"cert:\n  key_type: ec384\n":                        "cert.key_type",
		"defaults:\n  amazon:\n    vpc_id: v\n":             "defaults.amazon: unknown platform",
		"profiles:\n  a:\n    defaults:\n      azure: {}\n": "profiles.a.defaults.azure",
	} {
		if _, err := loadYAML(t, body); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
}

func TestDefaultTTLsCoverEveryType(t *testing.T) {
	cfg, _ := config.Load(filepath.Join(t.TempDir(), config.FileName))
	for _, info := range platform.ResourceTypes() {
		if got := cfg.TTLFor(info.Type); got != info.DefaultTTL {
			t.Errorf("TTLFor(%s) = %s, want %s", info.Type, got, info.DefaultTTL)
		}
	}
}
