package platform

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/cert/certtest"
)

func TestSerialKey(t *testing.T) {
	for in, want := range map[string]string{
		"0a:1b:2c":  "a1b2c",
		"0A1B2C":    "a1b2c",
		"a1b2c":     "a1b2c",
		" 00ff:00 ": "ff00",
		"":          "",
	} {
		if got := SerialKey(in); got != want {
			t.Errorf("SerialKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDeployCertCovers(t *testing.T) {
	ca := certtest.New("Test Issuer")
	key := certtest.Key()
	now := time.Now()
	chain := ca.Issue(key.Public(), []string{"example.com", "*.example.com"}, now.Add(-time.Hour), now.Add(48*time.Hour))
	b, _ := pem.Decode(chain)
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	c := &DeployCert{Root: "example.com", Leaf: leaf, Fullchain: chain, Key: certtest.KeyPEM(key)}
	for host, want := range map[string]bool{"example.com": true, "a.example.com": true, "A.Example.com.": true, "a.b.example.com": false, "other.com": false} {
		if got := c.Covers(host); got != want {
			t.Errorf("Covers(%q) = %v", host, got)
		}
	}
	if m := c.Material(); m == nil || m.Leaf != leaf {
		t.Errorf("material = %+v", m)
	}
	pending := &DeployCert{Root: "example.com", Pending: true}
	if pending.Covers("example.com") || pending.Material() != nil {
		t.Error("a pending certificate covers nothing and has no material")
	}
}

func TestDeployTargetHelpers(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	tg := DeployTarget{Deployer: "aliyun-alb", Profile: "acme", Name: "lb-x(HTTPS:443)",
		CurrentDomains: []string{"*.example.com", "www.example.com"}, CurrentNotAfter: now.Add(30*24*time.Hour - time.Minute)}
	if got := tg.DaysLeft(now); got != 29 {
		t.Errorf("days left = %d", got)
	}
	if got := tg.Domain(); got != "www.example.com" {
		t.Errorf("domain = %q", got)
	}
	if got := tg.Resource(); got != "aliyun-alb/acme/lb-x(HTTPS:443)" {
		t.Errorf("resource = %q", got)
	}
	acct := &DeployAccount{}
	n := 0
	get := func() *int { return Cached(acct, "k", func() *int { n++; v := 7; return &v }) }
	if *get() != 7 || *get() != 7 || n != 1 {
		t.Errorf("cache built %d times", n)
	}
}

type stubDeployer struct {
	id string
	p  ID
}

func (s stubDeployer) ID() string   { return s.id }
func (s stubDeployer) Platform() ID { return s.p }
func (s stubDeployer) Discover(context.Context, *DeployAccount, DeployOptions) ([]DeployTarget, []Change, error) {
	return nil, nil, nil
}
func (s stubDeployer) Plan(context.Context, *DeployAccount, DeployTarget, *DeployCert, DeployOptions) ([]Step, error) {
	return nil, nil
}
func (s stubDeployer) Prune(context.Context, *DeployAccount, DeployOptions) ([]Step, error) {
	return nil, nil
}

func TestDeployerRegistry(t *testing.T) {
	restore1 := OverrideDeployer(stubDeployer{"zz-test", AWS})
	restore2 := OverrideDeployer(stubDeployer{"aa-test", Aliyun})
	defer restore1()
	defer restore2()
	ids := DeployerIDs()
	ia, iz := slices.Index(ids, "aa-test"), slices.Index(ids, "zz-test")
	if ia < 0 || iz < 0 || iz > ia {
		// AWS comes before Alibaba Cloud in platform order.
		t.Errorf("ids = %v", ids)
	}
	if d, ok := GetDeployer("aa-test"); !ok || d.Platform() != Aliyun {
		t.Errorf("get = %v %v", d, ok)
	}
	restore2()
	if _, ok := GetDeployer("aa-test"); ok {
		t.Error("restore did not remove the deployer")
	}
	defer func() {
		if recover() == nil {
			t.Error("a second registration of an id must panic")
		}
	}()
	RegisterDeployer(stubDeployer{"zz-test", AWS})
}
