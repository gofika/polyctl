package aliyun

import (
	"context"
	"net/url"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

// failFirst answers the first call with HTTP 500, which makes the SDK resend
// the request, and every later call with a client error that ends it.
func failFirst(f *fakeAPI, action string) {
	n := 0
	f.on(action, func(q url.Values) (int, any) {
		n++
		if n == 1 {
			return 500, apiErr("InternalError", "the answer was lost")
		}
		return 400, apiErr("InvalidParameter", "stop here")
	})
}

// A write that takes a ClientToken is resent by the SDK after a 5xx with
// the token of the first attempt, so the platform answers the resent
// request with the result of the first instead of acting twice.
func TestTokenWritesResendTheSameToken(t *testing.T) {
	ctx := context.Background()
	rules := []platform.IngressRule{{Protocol: "tcp", FromPort: 22, ToPort: 22, Source: "0.0.0.0/0"}}
	cases := map[string]func(c *client) error{
		"CreateSecurityGroup": func(c *client) error {
			_, err := c.createSecurityGroup(ctx, "cn-hangzhou", "web", "vpc-1", "")
			return err
		},
		"AuthorizeSecurityGroup": func(c *client) error {
			return c.authorizeIngress(ctx, "cn-hangzhou", "sg-1", rules, 1, "", false)
		},
		"RevokeSecurityGroup": func(c *client) error {
			return c.revokeIngress(ctx, "cn-hangzhou", "sg-1", []string{"sgr-1"})
		},
		"RunCommand": func(c *client) error {
			_, _, _, err := c.runShellCommand(ctx, "cn-hangzhou", "i-1", "true")
			return err
		},
		"ModifyInstanceSpec": func(c *client) error {
			return c.modifyInstanceSpec(ctx, "cn-hangzhou", "i-1", "ecs.u1-c1m2.large")
		},
	}
	for action, call := range cases {
		f := newFakeAPI(t)
		failFirst(f, action)
		if err := call(f.client()); err == nil {
			t.Errorf("%s: no error", action)
		}
		calls := f.callsFor(action)
		if len(calls) != 2 {
			t.Errorf("%s: %d calls, want the first and one resend", action, len(calls))
			continue
		}
		if tok := calls[0].Get("ClientToken"); tok == "" || calls[1].Get("ClientToken") != tok {
			t.Errorf("%s: tokens %q, %q", action, tok, calls[1].Get("ClientToken"))
		}
	}
	// Each logical call has a token of its own.
	f := newFakeAPI(t)
	f.on("CreateSecurityGroup", func(q url.Values) (int, any) {
		return 200, map[string]any{"SecurityGroupId": "sg-1"}
	})
	c := f.client()
	for range 2 {
		if _, err := c.createSecurityGroup(ctx, "cn-hangzhou", "web", "vpc-1", ""); err != nil {
			t.Fatal(err)
		}
	}
	if calls := f.callsFor("CreateSecurityGroup"); calls[0].Get("ClientToken") == calls[1].Get("ClientToken") {
		t.Errorf("two creates share token %q", calls[0].Get("ClientToken"))
	}
}

// A write without a ClientToken is sent once: a resent delete would answer
// NotFound and a resent create Duplicate although the first one succeeded.
func TestTokenlessWritesAreSentOnce(t *testing.T) {
	ctx := context.Background()
	key, err := platform.ParsePublicKey(testKey(t, "ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	store := casScope{Region: casRegionCentral, Endpoint: "cas.aliyuncs.com"}
	rec := platform.Record{ID: "r-1", Name: "www.example.com", Type: "A", Value: "192.0.2.1"}
	cases := map[string]func(c *client) error{
		"AddDomainRecord": func(c *client) error {
			_, err := c.CreateRecord(ctx, "example.com", rec)
			return err
		},
		"UpdateDomainRecord": func(c *client) error {
			_, err := c.UpdateRecord(ctx, "example.com", rec)
			return err
		},
		"DeleteDomainRecord": func(c *client) error { return c.DeleteRecord(ctx, "example.com", "r-1") },
		"DeleteInstance":     func(c *client) error { return c.deleteInstance(ctx, "cn-hangzhou", "i-1", false) },
		"RebootInstance":     func(c *client) error { return c.rebootInstance(ctx, "cn-hangzhou", "i-1", false) },
		"StartInstance":      func(c *client) error { return c.StartInstance(ctx, "cn-hangzhou", "i-1") },
		"StopInstance":       func(c *client) error { return c.StopInstance(ctx, "cn-hangzhou", "i-1", false) },
		"DeleteSecurityGroup": func(c *client) error {
			return c.deleteSecurityGroup(ctx, "cn-hangzhou", "sg-1")
		},
		"JoinSecurityGroup": func(c *client) error {
			return c.joinSecurityGroup(ctx, "cn-hangzhou", "i-1", "sg-1")
		},
		"ImportKeyPair": func(c *client) error {
			_, err := c.importKeyPair(ctx, "cn-hangzhou", "ops", key)
			return err
		},
		"UploadUserCertificate": func(c *client) error {
			_, err := c.uploadCASCertificateIn(ctx, store, "cert", "CERT", "KEY")
			return err
		},
		"DeleteUserCertificate": func(c *client) error { return c.deleteCASCertificateIn(ctx, store, "7") },
		"SaveBatchTaskForModifyingDomainDns": func(c *client) error {
			return c.SetNameservers(ctx, "example.com", []string{"ns1.example.net"})
		},
	}
	for action, call := range cases {
		f := newFakeAPI(t)
		failFirst(f, action)
		if err := call(f.client()); err == nil {
			t.Errorf("%s: no error", action)
		}
		if n := len(f.callsFor(action)); n != 1 {
			t.Errorf("%s: %d calls, want 1", action, n)
		}
	}
}

// Reads keep the SDK's retries.
func TestReadsAreResent(t *testing.T) {
	f := newFakeAPI(t)
	failFirst(f, "DescribeInstances")
	_, _ = f.client().describeInstance(context.Background(), "cn-hangzhou", "i-1")
	if n := len(f.callsFor("DescribeInstances")); n != 2 {
		t.Errorf("DescribeInstances: %d calls, want 2", n)
	}
}
