package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/httpx"
	"github.com/gofika/polyctl/internal/platform"
)

const (
	zonesPerPage    = 50
	recordsPerPage  = 100
	accountsPerPage = 50
)

// api is the thin Cloudflare v4 REST layer. All responses share the
// {success, errors, messages, result, result_info} envelope.
type api struct {
	http      *httpx.Client
	accountID string
}

func newAPI(baseURL, token, accountID string) *api {
	return &api{
		http: httpx.New(baseURL, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+token)
		}),
		accountID: accountID,
	}
}

// message is an entry of the errors / messages arrays.
type message struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []message       `json:"errors"`
	Messages   []message       `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo *resultInfo     `json:"result_info"`
}

// Error is a Cloudflare API failure (HTTP or success:false). It unwraps to
// platform.ErrUnauthorized / platform.ErrNotFound when the status or the
// Cloudflare error codes indicate so.
type Error struct {
	Status int
	Method string
	Path   string
	Errors []message
	base   error
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "cloudflare: %s %s", e.Method, e.Path)
	if e.Status != 0 {
		fmt.Fprintf(&b, ": HTTP %d", e.Status)
	}
	if len(e.Errors) == 0 {
		b.WriteString(": request failed")
	}
	for i, m := range e.Errors {
		if i == 0 {
			b.WriteString(": ")
		} else {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s (code %d)", m.Message, m.Code)
	}
	return b.String()
}

// Unwrap returns the mapped sentinel error, if any.
func (e *Error) Unwrap() error { return e.base }

// Cloudflare error codes that mean the token is missing, invalid or lacks
// permission.
var authCodes = map[int]bool{
	10000: true, // Authentication error
	9109:  true, // Invalid access token
	9106:  true, // Missing X-Auth-Key, X-Auth-Email or Authorization headers
	9103:  true, // Unknown X-Auth-Key or X-Auth-Email
	6003:  true, // Invalid request headers
	6111:  true, // Invalid format for Authorization header
}

// Cloudflare error codes that mean the addressed object does not exist.
var notFoundCodes = map[int]bool{
	7003:  true, // Could not route to ..., perhaps your object identifier is invalid?
	81044: true, // Record does not exist
}

func classify(status int, msgs []message) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return platform.ErrUnauthorized
	case http.StatusNotFound:
		return platform.ErrNotFound
	}
	for _, m := range msgs {
		if authCodes[m.Code] || strings.Contains(strings.ToLower(m.Message), "authentication") {
			return platform.ErrUnauthorized
		}
	}
	for _, m := range msgs {
		if notFoundCodes[m.Code] {
			return platform.ErrNotFound
		}
	}
	return nil
}

func newError(status int, method, path string, msgs []message) *Error {
	return &Error{Status: status, Method: method, Path: path, Errors: msgs, base: classify(status, msgs)}
}

// do performs a request, validates the envelope and decodes result into out.
func (a *api) do(ctx context.Context, method, path string, query url.Values, in, out any) (*resultInfo, error) {
	var env envelope
	if err := a.http.Do(ctx, method, path, query, in, &env); err != nil {
		var he *httpx.Error
		if errors.As(err, &he) {
			var body envelope
			msgs := []message(nil)
			if json.Unmarshal([]byte(he.Body), &body) == nil {
				msgs = body.Errors
			}
			if len(msgs) == 0 {
				text := strings.TrimSpace(he.Body)
				if len(text) > 200 {
					text = text[:200] + "..."
				}
				if text != "" {
					msgs = []message{{Message: text}}
				}
			}
			return nil, newError(he.Status, method, path, msgs)
		}
		return nil, err
	}
	if !env.Success {
		return nil, newError(0, method, path, env.Errors)
	}
	if out != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, fmt.Errorf("cloudflare: decode %s %s result: %w", method, path, err)
		}
	}
	return env.ResultInfo, nil
}

// paginate walks a list endpoint until every page has been read.
func paginate[T any](ctx context.Context, a *api, path string, query url.Values, perPage int) ([]T, error) {
	var all []T
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("per_page", strconv.Itoa(perPage))
		q.Set("page", strconv.Itoa(page))
		var items []T
		info, err := a.do(ctx, http.MethodGet, path, q, nil, &items)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(items) == 0 {
			break
		}
		if info != nil && info.TotalPages > 0 {
			if page >= info.TotalPages {
				break
			}
			continue
		}
		if len(items) < perPage {
			break
		}
	}
	return all, nil
}

// --- tokens / user / accounts ---------------------------------------------

type tokenInfo struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresOn string `json:"expires_on,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	// AccountID is set for account-owned tokens: the account whose verify
	// endpoint accepted the token. Empty for user-owned tokens.
	AccountID string `json:"account_id,omitempty"`
}

// verifyToken checks the token against the endpoint that matches its owner.
// User-owned tokens verify at /user/tokens/verify. Account-owned tokens are
// rejected there ("Invalid API Token") and verify only at
// /accounts/{id}/tokens/verify, so on an authentication failure the accounts
// visible to the token are tried before the failure is reported.
func (a *api) verifyToken(ctx context.Context) (*tokenInfo, error) {
	var t tokenInfo
	_, userErr := a.do(ctx, http.MethodGet, "/user/tokens/verify", nil, nil, &t)
	if userErr == nil {
		return &t, nil
	}
	if !errors.Is(userErr, platform.ErrUnauthorized) {
		return nil, userErr
	}
	ids := []string{}
	if a.accountID != "" {
		ids = append(ids, a.accountID)
	} else if accounts, err := a.listAccounts(ctx); err == nil {
		for _, acc := range accounts {
			ids = append(ids, acc.ID)
		}
	}
	for _, id := range ids {
		var at tokenInfo
		if _, err := a.do(ctx, http.MethodGet, "/accounts/"+url.PathEscape(id)+"/tokens/verify", nil, nil, &at); err == nil {
			at.AccountID = id
			return &at, nil
		}
	}
	return nil, userErr
}

type user struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (a *api) getUser(ctx context.Context) (*user, error) {
	var u user
	if _, err := a.do(ctx, http.MethodGet, "/user", nil, nil, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

type account struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

func (a *api) listAccounts(ctx context.Context) ([]account, error) {
	return paginate[account](ctx, a, "/accounts", nil, accountsPerPage)
}

// --- zones -----------------------------------------------------------------

type apiZone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Paused      bool     `json:"paused"`
	Type        string   `json:"type,omitempty"`
	NameServers []string `json:"name_servers"`
	Account     struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
	Plan struct {
		Name string `json:"name"`
	} `json:"plan"`
	ModifiedOn string `json:"modified_on,omitempty"`
}

func (a *api) zoneQuery() url.Values {
	q := url.Values{}
	if a.accountID != "" {
		q.Set("account.id", a.accountID)
	}
	return q
}

func (a *api) listZones(ctx context.Context) ([]apiZone, error) {
	return paginate[apiZone](ctx, a, "/zones", a.zoneQuery(), zonesPerPage)
}

func (a *api) getZone(ctx context.Context, id string) (*apiZone, error) {
	var z apiZone
	if _, err := a.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(id), nil, nil, &z); err != nil {
		return nil, err
	}
	return &z, nil
}

// findZone resolves a zone by name (exact) or id.
func (a *api) findZone(ctx context.Context, idOrName string) (*apiZone, error) {
	name := platform.NormalizeDomain(idOrName)
	if strings.Contains(name, ".") {
		q := a.zoneQuery()
		q.Set("name", name)
		zs, err := paginate[apiZone](ctx, a, "/zones", q, zonesPerPage)
		if err != nil {
			return nil, err
		}
		for i := range zs {
			if platform.NormalizeDomain(zs[i].Name) == name {
				return &zs[i], nil
			}
		}
		return nil, fmt.Errorf("%w: zone %q", platform.ErrNotFound, name)
	}
	z, err := a.getZone(ctx, idOrName)
	if err != nil {
		return nil, err
	}
	return z, nil
}

func toZone(z apiZone) platform.Zone {
	extra := map[string]any{
		"paused":     z.Paused,
		"account_id": z.Account.ID,
	}
	if z.Plan.Name != "" {
		extra["plan"] = z.Plan.Name
	}
	if z.Account.Name != "" {
		extra["account_name"] = z.Account.Name
	}
	if z.Type != "" {
		extra["type"] = z.Type
	}
	return platform.Zone{
		ID:          z.ID,
		Name:        platform.NormalizeDomain(z.Name),
		Nameservers: z.NameServers,
		Status:      z.Status,
		Extra:       extra,
	}
}

// --- DNS records -----------------------------------------------------------

type apiRecord struct {
	ID         string         `json:"id"`
	ZoneID     string         `json:"zone_id,omitempty"`
	ZoneName   string         `json:"zone_name,omitempty"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Content    string         `json:"content"`
	TTL        int            `json:"ttl"`
	Priority   *int           `json:"priority,omitempty"`
	Proxied    *bool          `json:"proxied,omitempty"`
	Proxiable  bool           `json:"proxiable"`
	Comment    string         `json:"comment,omitempty"`
	Tags       []string       `json:"tags,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
	ModifiedOn string         `json:"modified_on,omitempty"`
}

// recordBody is the write payload for create/update. Content is omitted when
// Data carries the structured components of the record (see dataTypes).
type recordBody struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	Content  string         `json:"content,omitempty"`
	TTL      int            `json:"ttl"`
	Priority *int           `json:"priority,omitempty"`
	Proxied  *bool          `json:"proxied,omitempty"`
	Comment  *string        `json:"comment,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

// dataTypes are the record types whose components live in the `data`
// object of the API; their `content` is a read-only formatted rendering.
var dataTypes = map[string]bool{
	"CAA": true, "CERT": true, "DNSKEY": true, "DS": true, "HTTPS": true, "LOC": true, "NAPTR": true,
	"SMIMEA": true, "SRV": true, "SSHFP": true, "SVCB": true, "TLSA": true, "URI": true,
}

// isDataType reports whether records of the given (upper-case) type are
// written through `data` rather than `content`.
func isDataType(t string) bool { return dataTypes[strings.ToUpper(t)] }

func (a *api) listRecords(ctx context.Context, zoneID string) ([]apiRecord, error) {
	return paginate[apiRecord](ctx, a, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, recordsPerPage)
}

func (a *api) createRecord(ctx context.Context, zoneID string, body recordBody) (*apiRecord, error) {
	var r apiRecord
	if _, err := a.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/dns_records", nil, body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (a *api) updateRecord(ctx context.Context, zoneID, recordID string, body recordBody) (*apiRecord, error) {
	var r apiRecord
	if _, err := a.do(ctx, http.MethodPut, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (a *api) deleteRecord(ctx context.Context, zoneID, recordID string) error {
	_, err := a.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil, nil)
	return err
}

// toRecord converts the API shape to the neutral Record. Cloudflare already
// returns FQDNs; TTL 1 means "automatic".
func toRecord(r apiRecord) platform.Record {
	extra := map[string]any{"proxiable": r.Proxiable}
	if r.Comment != "" {
		extra["comment"] = r.Comment
	}
	if len(r.Tags) > 0 {
		extra["tags"] = r.Tags
	}
	if len(r.Data) > 0 {
		extra["data"] = r.Data
	}
	if r.ModifiedOn != "" {
		extra["modified_on"] = r.ModifiedOn
	}
	return platform.Record{
		ID:       r.ID,
		ZoneID:   r.ZoneID,
		Name:     platform.NormalizeDomain(r.Name),
		Type:     strings.ToUpper(r.Type),
		Content:  r.Content,
		TTL:      r.TTL,
		Priority: r.Priority,
		Proxied:  r.Proxied,
		Extra:    extra,
	}
}

// toBody converts a neutral Record into the write payload. TTL 0 becomes 1
// (automatic). Comment, tags and the structured data of SRV/CAA/LOC/... records
// are carried over from Extra when present; for those types `data` replaces
// `content` because the API only accepts the components, not the formatted
// string. Extra["data"] is a map[string]any both fresh from the API and after
// a JSON round-trip through the inventory.
func toBody(r platform.Record) recordBody {
	b := recordBody{
		Name:     platform.NormalizeDomain(r.Name),
		Type:     strings.ToUpper(r.Type),
		Content:  r.Content,
		TTL:      r.TTL,
		Priority: r.Priority,
		Proxied:  r.Proxied,
	}
	if b.TTL <= 0 {
		b.TTL = 1
	}
	if r.Extra != nil {
		if c, ok := r.Extra["comment"].(string); ok {
			b.Comment = &c
		}
		switch t := r.Extra["tags"].(type) {
		case []string:
			b.Tags = t
		case []any:
			for _, v := range t {
				if s, ok := v.(string); ok {
					b.Tags = append(b.Tags, s)
				}
			}
		}
		if d, ok := r.Extra["data"].(map[string]any); ok && len(d) > 0 && isDataType(b.Type) {
			b.Data = make(map[string]any, len(d))
			for k, v := range d {
				b.Data[k] = v
			}
			b.Content = ""
		}
	}
	return b
}

// --- zone operations used by native commands ------------------------------

// purgeRequest is the body of POST /zones/{id}/purge_cache.
type purgeRequest struct {
	PurgeEverything bool     `json:"purge_everything,omitempty"`
	Files           []string `json:"files,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	Hosts           []string `json:"hosts,omitempty"`
	Prefixes        []string `json:"prefixes,omitempty"`
}

type purgeResult struct {
	ID string `json:"id"`
}

func (a *api) purgeCache(ctx context.Context, zoneID string, req purgeRequest) (*purgeResult, error) {
	var res purgeResult
	if _, err := a.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zoneID)+"/purge_cache", nil, req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// zoneSetting is the shape of /zones/{id}/settings/{name}.
type zoneSetting struct {
	ID            string `json:"id"`
	Value         any    `json:"value"`
	Editable      bool   `json:"editable"`
	ModifiedOn    string `json:"modified_on,omitempty"`
	TimeRemaining int    `json:"time_remaining,omitempty"`
}

func (a *api) getSetting(ctx context.Context, zoneID, name string) (*zoneSetting, error) {
	var s zoneSetting
	if _, err := a.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/settings/"+name, nil, nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (a *api) setSetting(ctx context.Context, zoneID, name string, value any) (*zoneSetting, error) {
	var s zoneSetting
	body := map[string]any{"value": value}
	if _, err := a.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(zoneID)+"/settings/"+name, nil, body, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
