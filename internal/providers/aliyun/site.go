package aliyun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/bssopenapi"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// Billing (BSS) endpoints per site. The international site answers on
// business.ap-southeast-1 (verified: business.aliyuncs.com answers its
// accounts with AuthSiteFail); that the China site answers on
// business.aliyuncs.com is assumed, not verified.
const (
	endpointBSSIntl = "business.ap-southeast-1.aliyuncs.com"
	endpointBSSCN   = "business.aliyuncs.com"
	bssRegionIntl   = "ap-southeast-1"
	bssRegionCN     = "cn-hangzhou"
)

// siteLabels describe the two sites in questions and messages.
var siteLabels = map[string]string{
	siteCN:   "China site (aliyun.com)",
	siteIntl: "International site (alibabacloud.com)",
}

// errSiteMissing is the site a non-interactive login was not given. Login
// turns it into a usage error.
var errSiteMissing = errors.New("aliyun login needs the account's site: pass --set site=cn (China site, aliyun.com) or --set site=intl (International site, alibabacloud.com); an account usually belongs to one of them")

// loginSite decides the site of the account being logged in. The China and
// the international site are separate account systems, and nothing a key
// can call tells them apart reliably, so the user states it: the
// interactive flow asks (no default), the non-interactive flow needs
// --set site=cn|intl. A re-authentication keeps the site recorded at the
// first login; it never changes silently, since cached links and regions
// depend on it.
func loginSite(in platform.LoginInput, io *prompt.IO) (string, error) {
	given, err := parseSite(in.Opt(metaSite, ""))
	if err != nil {
		return "", app.UsageErrf("--set site: %v", err)
	}
	prev, _ := parseSite(in.Existing[metaSite])
	switch {
	case prev != "" && given != "" && given != prev:
		profile := in.ProfileName
		if profile == "" {
			profile = "<profile>"
		}
		return "", app.UsageErrf("this account was added for the %s (site=%s); the site of an account does not change on a new login: to use site=%s, remove the account with `polyctl auth logout aliyun --profile %s` and add it again with --set site=%s",
			siteLabels[prev], prev, given, profile, given)
	case prev != "":
		return prev, nil
	case given != "":
		return given, nil
	case !in.Interactive:
		return "", errSiteMissing
	}
	fmt.Fprintln(io.Err, "Alibaba Cloud has two sites with separate accounts; an account usually belongs to one of them.")
	if in.Picker != nil {
		return in.Picker.Select("Which site does this Alibaba Cloud account use?", []prompt.Option{
			{Label: prompt.Cells("cn", siteLabels[siteCN]), Value: siteCN},
			{Label: prompt.Cells("intl", siteLabels[siteIntl]), Value: siteIntl},
		}, "")
	}
	for {
		v, err := io.Required("Site: cn (" + siteLabels[siteCN] + ") or intl (" + siteLabels[siteIntl] + ")")
		if err != nil {
			return "", err
		}
		if s, err := parseSite(v); err == nil && s != "" {
			return s, nil
		}
		fmt.Fprintf(io.Err, "please answer cn or intl\n")
	}
}

// bssEndpoint returns the region and host of the billing API of a site.
func bssEndpoint(site string) (region, host string) {
	if site == siteIntl {
		return bssRegionIntl, endpointBSSIntl
	}
	return bssRegionCN, endpointBSSCN
}

// queryBalance calls QueryAccountBalance on the billing endpoint of site
// and returns the account's currency.
func (c *client) queryBalance(ctx context.Context, site string) (string, error) {
	region, host := bssEndpoint(site)
	cl, err := bssopenapi.NewClientWithOptions(region, sdkConfig(ctx), c.credential())
	if err != nil {
		return "", err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	req := bssopenapi.CreateQueryAccountBalanceRequest()
	c.route(req, host)
	resp, err := cl.QueryAccountBalance(req)
	if err != nil {
		return "", wrapErr("bss QueryAccountBalance", err)
	}
	if !resp.Success && resp.Code != "" && resp.Code != "200" {
		return "", &apiError{Action: "bss QueryAccountBalance", Code: resp.Code, Message: resp.Message}
	}
	return resp.Data.Currency, nil
}

// checkSite cross-checks the chosen site after the key was verified. It
// only informs: whatever it finds, the login goes on with the site the
// user chose. Only a main account (IdentityType Account) can be checked: a
// RAM user normally lacks the billing permission (NotAuthorized), and the
// permission check comes before the site check, so its answer says nothing
// about the site.
func (c *client) checkSite(ctx context.Context, identityType, site string, w io.Writer) {
	if identityType != "Account" {
		fmt.Fprintf(w, "note: the key belongs to a RAM identity, which usually has no billing permission, so the site cannot be confirmed with the balance API; continuing with site=%s\n", site)
		return
	}
	_, err := c.queryBalance(ctx, site)
	switch {
	case err == nil:
		return
	case platform.HasErrorCode(err, "AuthSiteFail"):
		other := siteCN
		if site == siteCN {
			other = siteIntl
		}
		fmt.Fprintf(w, "warning: the billing API of the %s refused this account (AuthSiteFail): the AccessKey may belong to the %s; if so, log out and add the account again with --set site=%s (saved with site=%s)\n",
			siteLabels[site], siteLabels[other], other, site)
	case platform.HasErrorCode(err, "NotAuthorized") || errors.Is(err, platform.ErrForbidden):
		fmt.Fprintf(w, "note: the key has no billing permission, so the site cannot be confirmed with the balance API; continuing with site=%s\n", site)
	case errors.Is(err, context.Canceled):
	default:
		fmt.Fprintf(w, "note: could not confirm the site (%s); continuing with site=%s\n", strings.TrimSpace(err.Error()), site)
	}
}
