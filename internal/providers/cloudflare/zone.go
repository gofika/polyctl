package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// extraPlanID is the key of platform.Zone.Extra holding the plan's legacy
// id (free, pro, business, enterprise): the plan polyctl's policies look at.
const extraPlanID = "plan_legacy_id"

// planEnterprise is the legacy id of the Enterprise plan.
const planEnterprise = "enterprise"

// Cloudflare error codes of the zone endpoints, as observed on the API.
const (
	codeInvalidZoneID    = 1001 // a zone that was deleted (HTTP 400); also "Request body is invalid."
	codeZoneExists       = 1061 // "<name> already exists" when creating a zone
	codeUndefinedSetting = 1003 // GET of a zone setting that does not exist (HTTP 400)
	codeUnknownSetting   = 1006 // PATCH of a zone setting that does not exist (HTTP 400)
	codeSettingNotOnPlan = 1015 // "Not allowed to edit zone setting" on the zone's plan (HTTP 400)
	codeNoFoundationDNS  = 1003 // on dns_settings: the account cannot use Foundation DNS (not verified)
	codeZoneIDUnknown    = 9109 // a well-formed id of a zone that never existed (HTTP 403); also "Invalid access token"
)

// zoneGone reports whether err says that the zone addressed by the request
// does not exist (any more). The API has three answers for it: HTTP 400 code
// 1001 for a deleted zone, HTTP 403 code 9109 "Invalid zone identifier" for
// an id that never existed (9109 is also the code of an invalid token, so
// the message decides) and HTTP 404 code 7003 for a malformed id.
func zoneGone(err error) bool {
	e := apiError(err)
	if e == nil {
		return false
	}
	switch e.Status {
	case http.StatusBadRequest, 0:
		return e.HasCode(codeInvalidZoneID) && e.messageContains("zone identifier")
	case http.StatusForbidden:
		return e.HasCode(codeZoneIDUnknown) && e.messageContains("zone identifier")
	case http.StatusNotFound:
		return e.HasCode(7003)
	}
	return false
}

// findZonesNamed returns the zones named name (exactly, without case) of the
// account accountID. The account filter keeps a zone of the same name in
// another account the token can see from being taken for this one.
func (a *api) findZonesNamed(ctx context.Context, name, accountID string) ([]apiZone, error) {
	name = platform.NormalizeDomain(name)
	q := url.Values{}
	q.Set("name", name)
	if accountID != "" {
		q.Set("account.id", accountID)
	}
	zs, err := paginate[apiZone](ctx, a, "/zones", q, zonesPerPage)
	if err != nil {
		return nil, err
	}
	var out []apiZone
	for _, z := range zs {
		if platform.NormalizeDomain(z.Name) != name {
			continue
		}
		if accountID != "" && z.Account.ID != "" && z.Account.ID != accountID {
			continue
		}
		out = append(out, z)
	}
	return out, nil
}

// createZone adds a full zone named name to the account.
func (a *api) createZone(ctx context.Context, name, accountID string) (*apiZone, error) {
	body := map[string]any{"name": name, "account": map[string]string{"id": accountID}, "type": "full"}
	var z apiZone
	if _, err := a.do(ctx, http.MethodPost, "/zones", nil, body, &z); err != nil {
		return nil, err
	}
	return &z, nil
}

func (a *api) deleteZone(ctx context.Context, id string) error {
	_, err := a.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(id), nil, nil, nil)
	return err
}

// countRecords returns the number of DNS records of a zone with one request
// (result_info.total_count of a one-record page); -1 when the API does not
// say.
func (a *api) countRecords(ctx context.Context, zoneID string) (int, error) {
	q := url.Values{}
	q.Set("per_page", "1")
	var recs []apiRecord
	info, err := a.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records", q, nil, &recs)
	if err != nil {
		return 0, err
	}
	if info == nil {
		return -1, nil
	}
	return info.TotalCount, nil
}

// downgradeToFree moves a zone to the Free plan (needed before an
// Enterprise zone can be deleted).
func (a *api) downgradeToFree(ctx context.Context, zoneID string) error {
	body := map[string]any{"rate_plan": map[string]string{"id": "free"}}
	_, err := a.do(ctx, http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/subscription", nil, body, nil)
	return err
}

// zoneDomainArg checks the <domain> of a new zone: a registered domain such
// as example.com, lower-cased and without the trailing dot. Only the obvious
// mistakes are caught here (no dot, a URL, an IP address, spaces); the API
// judges the rest.
func zoneDomainArg(arg string) (string, error) {
	d := platform.NormalizeDomain(arg)
	switch {
	case d == "":
		return "", app.UsageErrf("<domain> is empty")
	case strings.ContainsAny(d, " \t/:@?#*"):
		return "", app.UsageErrf("%q is not a domain name (give the bare name, such as example.com)", arg)
	case net.ParseIP(d) != nil:
		return "", app.UsageErrf("%q is an IP address, not a domain name", arg)
	case !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.Contains(d, ".."):
		return "", app.UsageErrf("%q is not a domain name (such as example.com)", arg)
	}
	return d, nil
}

// --- settings ----------------------------------------------------------------

// The two settings that live on endpoints of their own; `zone setting`
// accepts them as setting names.
const (
	settingArgo          = "argo_smart_routing"
	settingFoundationDNS = "foundation_dns"
)

func settingPath(zoneID, name string) string {
	return "/zones/" + url.PathEscape(zoneID) + "/settings/" + url.PathEscape(name)
}

// listSettings returns every setting of /zones/{id}/settings (one request,
// not paged). Some settings (rum) are not in it.
func (a *api) listSettings(ctx context.Context, zoneID string) ([]zoneSetting, error) {
	var out []zoneSetting
	if _, err := a.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/settings", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// getArgo reads Argo Smart Routing. Its id is smart_routing; it is reported
// under the name polyctl accepts for it.
func (a *api) getArgo(ctx context.Context, zoneID string) (*zoneSetting, error) {
	var s zoneSetting
	if _, err := a.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/argo/smart_routing", nil, nil, &s); err != nil {
		return nil, err
	}
	return normalizeArgo(&s), nil
}

func (a *api) setArgo(ctx context.Context, zoneID, value string) (*zoneSetting, error) {
	var s zoneSetting
	if _, err := a.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(zoneID)+"/argo/smart_routing", nil, map[string]string{"value": value}, &s); err != nil {
		return nil, err
	}
	return normalizeArgo(&s), nil
}

func normalizeArgo(s *zoneSetting) *zoneSetting {
	s.ID = settingArgo
	// A setting that was never changed reports the zero time.
	if strings.HasPrefix(s.ModifiedOn, "0001-01-01") {
		s.ModifiedOn = ""
	}
	return s
}

// dnsSettings is the part of /zones/{id}/dns_settings polyctl reads.
type dnsSettings struct {
	FoundationDNS bool `json:"foundation_dns"`
}

func (a *api) getFoundationDNS(ctx context.Context, zoneID string) (*zoneSetting, error) {
	var d dnsSettings
	if _, err := a.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_settings", nil, nil, &d); err != nil {
		return nil, err
	}
	return &zoneSetting{ID: settingFoundationDNS, Value: d.FoundationDNS, Editable: true}, nil
}

func (a *api) setFoundationDNS(ctx context.Context, zoneID string, on bool) (*zoneSetting, error) {
	var d dnsSettings
	if _, err := a.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(zoneID)+"/dns_settings", nil, map[string]bool{"foundation_dns": on}, &d); err != nil {
		return nil, err
	}
	return &zoneSetting{ID: settingFoundationDNS, Value: d.FoundationDNS, Editable: true}, nil
}

// foundationUnsupported reports whether a dns_settings request failed
// because the account cannot use Foundation DNS: code 1003 with HTTP 400 or
// 403, or any HTTP 403 (no permission for the feature). Any other failure
// (a malformed request answers HTTP 400 code 1001) is a real error. The
// answer of an account without the feature has not been observed.
func foundationUnsupported(err error) bool {
	e := apiError(err)
	if e == nil || zoneGone(err) {
		// A zone that does not exist (HTTP 403 code 9109 "Invalid zone
		// identifier") is not an account without the feature.
		return false
	}
	switch e.Status {
	case http.StatusForbidden:
		return true
	case http.StatusBadRequest, 0:
		return e.HasCode(codeNoFoundationDNS)
	}
	return false
}

// readSetting reads one setting by the name `zone setting` accepts.
func (a *api) readSetting(ctx context.Context, zoneID, name string) (*zoneSetting, error) {
	switch name {
	case settingArgo:
		return a.getArgo(ctx, zoneID)
	case settingFoundationDNS:
		return a.getFoundationDNS(ctx, zoneID)
	}
	s, err := a.getSetting(ctx, zoneID, name)
	return s, settingError(err, name, "")
}

// writeSetting writes one setting by the name `zone setting` accepts; value
// is already in the shape the endpoint takes.
func (a *api) writeSetting(ctx context.Context, zoneID, name string, value any, plan string) (*zoneSetting, error) {
	switch name {
	case settingArgo:
		v, _ := value.(string)
		return a.setArgo(ctx, zoneID, v)
	case settingFoundationDNS:
		v, _ := value.(bool)
		return a.setFoundationDNS(ctx, zoneID, v)
	}
	s, err := a.setSetting(ctx, zoneID, name, value)
	return s, settingError(err, name, plan)
}

// settingError maps the answers of the generic setting endpoints: an
// unknown setting (code 1003 on GET, 1006 on PATCH, both HTTP 400) is not
// found, one the plan cannot change (code 1015) is not supported.
func settingError(err error, name, plan string) error {
	e := apiError(err)
	if e == nil || zoneGone(err) {
		return err
	}
	switch {
	case e.HasCode(codeUndefinedSetting, codeUnknownSetting):
		return fmt.Errorf("%w: setting %s (see `polyctl cloudflare zone setting list <zone>`): %v", platform.ErrNotFound, name, err)
	case e.HasCode(codeSettingNotOnPlan):
		if plan == "" {
			plan = "unknown"
		}
		return fmt.Errorf("%w: setting %s is not supported on plan %s: %v", platform.ErrNotSupported, name, plan, err)
	}
	return err
}

// settingText is a setting value as compared and printed: strings as they
// are, booleans as true/false, numbers without a fraction when they have
// none, anything else as JSON.
func settingText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// errBadSettingValue marks a value a setting cannot take, found before any
// request.
var errBadSettingValue = errors.New("invalid setting value")

// settingValue converts the value given on the command line into the shape
// the setting's endpoint takes. Booleans are written on/off (true/false are
// accepted and converted); Foundation DNS takes a JSON boolean. When the
// current value is a number or an object, a value that reads as one is sent
// as one; anything else is sent as the string given, for the API to judge.
func settingValue(name, given string, current any) (any, error) {
	lower := strings.ToLower(strings.TrimSpace(given))
	onOff := map[string]string{"on": "on", "true": "on", "off": "off", "false": "off"}
	switch name {
	case settingFoundationDNS:
		switch onOff[lower] {
		case "on":
			return true, nil
		case "off":
			return false, nil
		}
		return nil, fmt.Errorf("%w: %s takes on or off (true / false), got %q", errBadSettingValue, name, given)
	case settingArgo:
		if v, ok := onOff[lower]; ok {
			return v, nil
		}
		return nil, fmt.Errorf("%w: %s takes on or off (true / false), got %q", errBadSettingValue, name, given)
	}
	if v, ok := onOff[lower]; ok {
		if _, isBool := current.(bool); isBool {
			return v == "on", nil
		}
		return v, nil
	}
	switch current.(type) {
	case float64:
		if n, err := strconv.ParseFloat(given, 64); err == nil {
			return n, nil
		}
	case map[string]any, []any:
		var v any
		if err := json.Unmarshal([]byte(given), &v); err == nil {
			return v, nil
		}
	}
	return given, nil
}
