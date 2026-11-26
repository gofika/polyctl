package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"

	"github.com/gofika/polyctl/internal/platform"
)

// fakeSSOCreds answers GetRoleCredentials with role credentials that expire
// after ttl, and CreateToken with a fresh access token.
type fakeSSOCreds struct {
	ttl          time.Duration
	roleCalls    int
	tokenCalls   int
	accessTokens []string
	tokenErr     error
}

func (f *fakeSSOCreds) GetRoleCredentials(_ context.Context, in *sso.GetRoleCredentialsInput, _ ...func(*sso.Options)) (*sso.GetRoleCredentialsOutput, error) {
	f.roleCalls++
	f.accessTokens = append(f.accessTokens, awssdk.ToString(in.AccessToken))
	return &sso.GetRoleCredentialsOutput{RoleCredentials: &ssotypes.RoleCredentials{
		AccessKeyId:     awssdk.String(fmt.Sprintf("ASIATESTFAKE%04d", f.roleCalls)),
		SecretAccessKey: awssdk.String("test-secret"),
		SessionToken:    awssdk.String("test-session"),
		Expiration:      time.Now().Add(f.ttl).UnixMilli(),
	}}, nil
}

func (f *fakeSSOCreds) CreateToken(_ context.Context, _ *ssooidc.CreateTokenInput, _ ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error) {
	f.tokenCalls++
	if f.tokenErr != nil {
		return nil, f.tokenErr
	}
	return &ssooidc.CreateTokenOutput{AccessToken: awssdk.String(fmt.Sprintf("fresh-token-%d", f.tokenCalls)), ExpiresIn: 3600}, nil
}

func useFakeSSO(t *testing.T, f *fakeSSOCreds) {
	t.Helper()
	oldRole, oldToken := newSSORoleClient, newSSOTokenClient
	newSSORoleClient = func(awssdk.Config) ssoRoleAPI { return f }
	newSSOTokenClient = func(awssdk.Config) ssoTokenAPI { return f }
	t.Cleanup(func() { newSSORoleClient, newSSOTokenClient = oldRole, oldToken })
}

func ssoProfile(secret map[string]string) platform.Profile {
	return platform.Profile{Name: "lab", Platform: platform.AWS,
		Metadata: map[string]string{metaMethod: methodSSO, metaAccountID: "123456789012", metaRoleName: "Admin"}, Secret: secret}
}

// Role credentials that are about to expire are exchanged again on the next
// read; fresh ones are reused.
func TestSSORoleCredentialsRefresh(t *testing.T) {
	f := &fakeSSOCreds{ttl: time.Minute} // inside the expiry window at once
	useFakeSSO(t, f)
	creds, err := ssoRoleCredentials(context.Background(), ssoProfile(map[string]string{
		secretAccessToken: "token-0", secretTokenExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}))
	if err != nil {
		t.Fatal(err)
	}
	if f.roleCalls != 1 {
		t.Fatalf("open fetched %d times, want 1", f.roleCalls)
	}
	v, err := creds.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.roleCalls != 2 || v.AccessKeyID != "ASIATESTFAKE0002" || !v.CanExpire {
		t.Errorf("expiring credentials: %d calls, %+v", f.roleCalls, v)
	}

	f2 := &fakeSSOCreds{ttl: time.Hour}
	useFakeSSO(t, f2)
	creds, err = ssoRoleCredentials(context.Background(), ssoProfile(map[string]string{secretAccessToken: "token-0"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := creds.Retrieve(context.Background()); err != nil || f2.roleCalls != 1 {
		t.Errorf("fresh credentials: %v, %d calls", err, f2.roleCalls)
	}
}

// An access token that expires during the run is refreshed with the
// refresh token before role credentials are exchanged again, and persisted.
func TestSSORoleCredentialsRefreshAccessToken(t *testing.T) {
	f := &fakeSSOCreds{ttl: time.Minute}
	useFakeSSO(t, f)
	var saved map[string]string
	prof := ssoProfile(map[string]string{secretAccessToken: "token-0", secretRefreshToken: "refresh", secretClientID: "cid", secretClientSecret: "csec",
		secretTokenExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	prof.UpdateSecret = func(s map[string]string) error { saved = s; return nil }
	creds, err := ssoRoleCredentials(context.Background(), prof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := creds.Retrieve(context.Background()); err != nil {
		t.Fatal(err)
	}
	// One refresh: the new token is good for an hour.
	if f.tokenCalls != 1 || f.roleCalls != 2 || f.accessTokens[0] != "fresh-token-1" || f.accessTokens[1] != "fresh-token-1" {
		t.Errorf("token calls %d, role calls %d, tokens %v", f.tokenCalls, f.roleCalls, f.accessTokens)
	}
	if saved[secretAccessToken] != "fresh-token-1" || prof.Secret[secretAccessToken] != "token-0" {
		t.Errorf("saved %v, profile secret changed: %v", saved, prof.Secret)
	}
}

// A refresh Identity Center refuses means the session is over: the error
// is one of credentials, names the code and the login command, and carries
// neither the text of the SDK nor that of its credentials cache. A refresh
// that did not reach Identity Center says nothing about the session.
func TestSSOSessionRefreshFailure(t *testing.T) {
	expired := func() platform.Profile {
		return ssoProfile(map[string]string{secretAccessToken: "token-0", secretRefreshToken: "refresh", secretClientID: "cid", secretClientSecret: "csec",
			secretTokenExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	}
	f := &fakeSSOCreds{ttl: time.Hour, tokenErr: fmt.Errorf("operation error SSO OIDC: CreateToken, https response error StatusCode: 400, RequestID: r-1, %w",
		&fakeAPIError{code: "InvalidRequestException"})}
	useFakeSSO(t, f)
	_, err := ssoRoleCredentials(context.Background(), expired())
	want := "unauthorized: the SSO session has expired (InvalidRequestException); run `polyctl auth login aws --profile lab`"
	if !errors.Is(err, platform.ErrUnauthorized) || err.Error() != want {
		t.Errorf("refused refresh = %v, want %q", err, want)
	}
	if f.roleCalls != 0 {
		t.Errorf("role credentials asked %d time(s) after a refused refresh", f.roleCalls)
	}

	network := errors.New("dial tcp: no route to host")
	useFakeSSO(t, &fakeSSOCreds{ttl: time.Hour, tokenErr: network})
	_, err = ssoRoleCredentials(context.Background(), expired())
	if !errors.Is(err, network) || errors.Is(err, platform.ErrUnauthorized) || strings.Contains(err.Error(), "cached credentials") {
		t.Errorf("refresh without network = %v, want the network error and not one of credentials", err)
	}

	useFakeSSO(t, &fakeSSOCreds{ttl: time.Hour, tokenErr: context.Canceled})
	if _, err = ssoRoleCredentials(context.Background(), expired()); !errors.Is(err, context.Canceled) || errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("cancelled refresh = %v, want context.Canceled", err)
	}
}
