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
	http *httpx.Client
	// accountID is the account this copy is bound to: the default account
	// of the login, or the one inAccount / pin names. "" for a login
	// without a default account.
	accountID string
	// disabled are the accounts of the login that are kept out of every
	// sync, list and lookup (never the default account).
	disabled []string
	// pinned is set by --account: the lists and lookups read accountID
	// alone.
	pinned bool
	// oauth is set for browser logins: it supplies the access token and
	// renews it. API-token accounts leave it nil.
	oauth *oauthSession
}

func newAPI(baseURL, token, accountID string) *api {
	return &api{
		http: httpx.New(baseURL, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+token)
		}),
		accountID: accountID,
	}
}

// newOAuthAPI returns the API of a browser login. Every request carries the
// access token the session holds at that moment.
func newOAuthAPI(baseURL string, s *oauthSession, accountID string) *api {
	return &api{
		http: httpx.New(baseURL, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+s.current())
		}),
		accountID: accountID,
		oauth:     s,
	}
}

// message is an entry of the errors / messages arrays.
type message struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	// Source points at the part of the request body the error is about
	// (a JSON pointer such as /rules/0/expression), when the API says.
	Source *errorSource `json:"source,omitempty"`
}

type errorSource struct {
	Pointer string `json:"pointer"`
}

type resultInfo struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
	TotalPages int `json:"total_pages"`
	// Cursor is the opaque position of the next page of a cursor-paged
	// listing (R2 buckets); absent on the last page.
	Cursor string `json:"cursor,omitempty"`
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
	// RayID is the cf-ray header of the response, when there was one: the
	// id Cloudflare support asks for.
	RayID string
	// NotJSON is set when the response body was not the JSON envelope (an
	// HTML page of Cloudflare's edge, a proxy error).
	NotJSON bool
	base    error
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
		// Some errors carry a message only (no code); "code 0" would
		// only mislead.
		if m.Code == 0 {
			b.WriteString(m.Message)
		} else {
			fmt.Fprintf(&b, "%s (code %d)", m.Message, m.Code)
		}
	}
	// The request id is worth quoting when the failure is on Cloudflare's
	// side or not an API answer at all.
	if e.RayID != "" && (e.NotJSON || e.Status == http.StatusTooManyRequests || e.Status >= 500) {
		fmt.Fprintf(&b, " (cf-ray %s)", e.RayID)
	}
	return b.String()
}

// HasCode reports whether the API answered with one of codes.
func (e *Error) HasCode(codes ...int) bool {
	for _, m := range e.Errors {
		for _, c := range codes {
			if m.Code == c {
				return true
			}
		}
	}
	return false
}

// messageContains reports whether an error message contains s (any case).
func (e *Error) messageContains(s string) bool {
	for _, m := range e.Errors {
		if strings.Contains(strings.ToLower(m.Message), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// apiError returns the Cloudflare API error in err's chain, if any.
func apiError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
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
	70503: true, // account with given Tag doesn't exist (the pinned account id is wrong)
}

// Cloudflare error codes that mean the addressed object does not exist.
var notFoundCodes = map[int]bool{
	7003:  true, // Could not route to ..., perhaps your object identifier is invalid?
	81044: true, // Record does not exist
}

// codeR2NotEnabled is the answer of every R2 endpoint of an account that has
// not enabled R2 (HTTP 403).
const codeR2NotEnabled = 10042

func classify(status int, msgs []message) error {
	for _, m := range msgs {
		if m.Code == codeR2NotEnabled {
			// The account cannot serve R2 at all: not a credentials problem.
			return platform.ErrNotSupported
		}
	}
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
// For a browser login it first makes sure the access token is not about to
// expire, and when the API refuses the token all the same it renews it and
// repeats the request once. The refusal means the request was not carried
// out, so repeating it is safe for every method.
func (a *api) do(ctx context.Context, method, path string, query url.Values, in, out any) (*resultInfo, error) {
	if a.oauth == nil {
		return a.doOnce(ctx, method, path, query, in, out)
	}
	used, err := a.oauth.fresh(ctx)
	if err != nil {
		return nil, err
	}
	info, err := a.doOnce(ctx, method, path, query, in, out)
	if err != nil && a.oauth.mayBeExpired(err) {
		if rerr := a.oauth.renew(ctx, used); rerr != nil {
			if errors.Is(rerr, platform.ErrUnauthorized) {
				return nil, rerr
			}
			// Not renewed (no answer from the authorization server): the
			// refusal of the API is what there is to report.
			return nil, a.oauth.explain(method, path, err)
		}
		info, err = a.doOnce(ctx, method, path, query, in, out)
		if err != nil && errors.Is(err, platform.ErrUnauthorized) {
			a.oauth.setFutile(err)
		}
	}
	return info, a.oauth.explain(method, path, err)
}

// doOnce performs one request with the credentials as they are.
func (a *api) doOnce(ctx context.Context, method, path string, query url.Values, in, out any) (*resultInfo, error) {
	var env envelope
	if err := a.http.Do(ctx, method, path, query, in, &env); err != nil {
		var he *httpx.Error
		if errors.As(err, &he) {
			var body envelope
			msgs := []message(nil)
			isJSON := json.Unmarshal([]byte(he.Body), &body) == nil
			if isJSON {
				msgs = body.Errors
			}
			text := strings.TrimSpace(he.Body)
			if len(msgs) == 0 {
				if len(text) > 200 {
					text = text[:200] + "..."
				}
				if text != "" {
					msgs = []message{{Message: text}}
				}
			}
			e := newError(he.Status, method, path, msgs)
			e.RayID = he.Header.Get("cf-ray")
			if !isJSON && strings.HasPrefix(text, "<") {
				// An HTML page instead of the envelope: Cloudflare's edge
				// (or a proxy) answered, not the API. It says nothing about
				// the credentials or the object, so it is a plain failure.
				e.NotJSON = true
				e.Errors = []message{{Message: "the response is not the API's JSON (possibly blocked at Cloudflare's edge): " + text}}
				e.base = nil
			}
			return nil, e
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
// /accounts/{id}/tokens/verify, so on an authentication failure the default
// account and then the accounts visible to the token are tried before the
// failure is reported.
func (a *api) verifyToken(ctx context.Context) (*tokenInfo, error) {
	var t tokenInfo
	_, userErr := a.do(ctx, http.MethodGet, "/user/tokens/verify", nil, nil, &t)
	if userErr == nil {
		return &t, nil
	}
	if !errors.Is(userErr, platform.ErrUnauthorized) {
		return nil, userErr
	}
	// The account the copy is bound to first: an account-owned token is
	// most often the one of the default account, and that costs one
	// request. Then the accounts the token lists.
	try := func(id string) *tokenInfo {
		var at tokenInfo
		if _, err := a.do(ctx, http.MethodGet, "/accounts/"+url.PathEscape(id)+"/tokens/verify", nil, nil, &at); err != nil {
			return nil
		}
		at.AccountID = id
		return &at
	}
	if a.accountID != "" {
		if at := try(a.accountID); at != nil {
			return at, nil
		}
	}
	if accounts, err := a.listAccounts(ctx); err == nil {
		for _, acc := range accounts {
			if acc.ID == a.accountID {
				continue
			}
			if at := try(acc.ID); at != nil {
				return at, nil
			}
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
		Name     string `json:"name"`
		LegacyID string `json:"legacy_id,omitempty"`
	} `json:"plan"`
	// OriginalNameServers is null for a zone that was just created.
	OriginalNameServers []string       `json:"original_name_servers"`
	Meta                map[string]any `json:"meta,omitempty"`
	CreatedOn           string         `json:"created_on,omitempty"`
	ModifiedOn          string         `json:"modified_on,omitempty"`
}

func (a *api) zoneQuery() url.Values {
	q := url.Values{}
	if a.accountID != "" {
		q.Set("account.id", a.accountID)
	}
	return q
}

// listZonesOf returns the zones of one account ("" filters nothing).
func (a *api) listZonesOf(ctx context.Context, id string) ([]apiZone, error) {
	q := url.Values{}
	if id != "" {
		q.Set("account.id", id)
	}
	return paginate[apiZone](ctx, a, "/zones", q, zonesPerPage)
}

func (a *api) getZone(ctx context.Context, id string) (*apiZone, error) {
	var z apiZone
	if _, err := a.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(id), nil, nil, &z); err != nil {
		return nil, err
	}
	return &z, nil
}

// findZone resolves a zone by name (exact) or id, among the accounts the
// API covers. A name held by several of them is ambiguous; an id of a zone
// in a disabled account is not found, since nothing else of that account
// is worked on (a zone that names no account passes).
func (a *api) findZone(ctx context.Context, idOrName string) (*apiZone, error) {
	name := platform.NormalizeDomain(idOrName)
	if strings.Contains(name, ".") {
		zs, err := a.zonesNamed(ctx, name)
		if err != nil {
			return nil, err
		}
		switch len(zs) {
		case 0:
			return nil, fmt.Errorf("%w: zone %q", platform.ErrNotFound, name)
		case 1:
			return &zs[0], nil
		}
		held := make([]string, 0, len(zs))
		for _, z := range zs {
			held = append(held, fmt.Sprintf("%s in account %s", z.ID, accountLabel(z.Account.ID, z.Account.Name)))
		}
		return nil, fmt.Errorf("%w: zone %s is held by %d of the enabled accounts of this login (%s): name it by its zone id, or use the cloudflare commands with --account <id or name>",
			platform.ErrAmbiguous, name, len(zs), strings.Join(held, ", "))
	}
	z, err := a.getZone(ctx, idOrName)
	if err != nil {
		return nil, err
	}
	if acc := z.Account.ID; !a.covers(acc) {
		return nil, disabledZoneErr(z.Name, z.ID, acc)
	}
	return z, nil
}

// accountLabel names an account in a message: "id (name)", or the id.
func accountLabel(id, name string) string {
	switch {
	case id == "":
		return "(unknown)"
	case name == "":
		return id
	}
	return id + " (" + name + ")"
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
	if z.Plan.LegacyID != "" {
		extra[extraPlanID] = z.Plan.LegacyID
	}
	if z.CreatedOn != "" {
		extra["created_on"] = z.CreatedOn
	}
	if z.ModifiedOn != "" {
		extra["modified_on"] = z.ModifiedOn
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
	Meta       map[string]any `json:"meta,omitempty"`
	CreatedOn  string         `json:"created_on,omitempty"`
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

// listRecordsNamed returns the records of a zone with the exact name fqdn.
func (a *api) listRecordsNamed(ctx context.Context, zoneID, fqdn string) ([]apiRecord, error) {
	q := url.Values{}
	q.Set("name", fqdn)
	return paginate[apiRecord](ctx, a, "/zones/"+url.PathEscape(zoneID)+"/dns_records", q, recordsPerPage)
}

func (a *api) getRecord(ctx context.Context, zoneID, recordID string) (*apiRecord, error) {
	var r apiRecord
	if _, err := a.do(ctx, http.MethodGet, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
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

// patchRecord changes the fields in body only: the record keeps every
// field the body leaves out (ttl, proxied, comment, tags), where PUT would
// reset them.
func (a *api) patchRecord(ctx context.Context, zoneID, recordID string, body map[string]any) (*apiRecord, error) {
	var r apiRecord
	if _, err := a.do(ctx, http.MethodPatch, "/zones/"+url.PathEscape(zoneID)+"/dns_records/"+url.PathEscape(recordID), nil, body, &r); err != nil {
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
	if r.CreatedOn != "" {
		extra["created_on"] = r.CreatedOn
	}
	if r.ModifiedOn != "" {
		extra["modified_on"] = r.ModifiedOn
	}
	rec := platform.Record{
		ID:       r.ID,
		ZoneID:   r.ZoneID,
		Name:     platform.NormalizeDomain(r.Name),
		Type:     strings.ToUpper(r.Type),
		Value:    r.Content,
		TTL:      r.TTL,
		Priority: r.Priority,
		Proxied:  r.Proxied,
		Extra:    extra,
	}
	if len(r.Meta) > 0 {
		rec.Meta = r.Meta
	}
	return rec
}

// toBody converts a neutral Record into the write payload. TTL 0 becomes 1
// (automatic). Comment, tags and the structured data of SRV/CAA/LOC/... records
// are carried over from Extra when present; for those types `data` replaces
// `content` because the API only accepts the components, not the formatted
// string. Extra["data"] is a map[string]any both fresh from the API and after
// a JSON round-trip through the inventory. A value of such a type that can
// be read neither from its text nor from Extra is refused (ErrInvalidInput),
// not sent for the API to judge.
func toBody(r platform.Record) (recordBody, error) {
	b := recordBody{
		Name:     platform.NormalizeDomain(r.Name),
		Type:     strings.ToUpper(r.Type),
		Content:  r.Value,
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
		// The components of a record as listed are sent only when its
		// value is text they cannot be read from: a value that can be
		// read wins below, so a changed value is not undone by the old
		// components.
		if d, ok := r.Extra["data"].(map[string]any); ok && len(d) > 0 && isDataType(b.Type) && !canReadData(b.Type, b.Content, r.Priority) {
			b.Data = make(map[string]any, len(d))
			for k, v := range d {
				b.Data[k] = v
			}
			b.Content = ""
		}
	}
	if b.Data == nil && isDataType(b.Type) {
		// A record given as text ("10 5 5060 sip.example.com"): the API
		// takes the components only.
		d, prio, err := dataFromText(b.Type, b.Content, r.Priority)
		if err != nil {
			return recordBody{}, err
		}
		b.Data, b.Content = d, ""
		if prio != nil {
			b.Priority = prio
		}
	}
	return b, nil
}

// canReadData reports whether dataFromText can read text.
func canReadData(typ, text string, priority *int) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	_, _, err := dataFromText(typ, text, priority)
	return err == nil
}

// dataFromText reads the zone-file text of a record of a data type into
// the components of the API's data object, through the record type
// knowledge of polyctl (platform.RecordFields): a value it refuses is an
// ErrInvalidInput. The field names of SRV and CAA are confirmed against the
// API; those of the other types follow its documentation. URI keeps its
// priority outside data (returned separately). priority is the priority a
// listed SRV or URI record carries apart from its text, if any.
func dataFromText(typ, text string, priority *int) (map[string]any, *int, error) {
	typ = strings.ToUpper(typ)
	text = strings.TrimSpace(text)
	if priority != nil {
		n := len(strings.Fields(text))
		if (typ == "SRV" && n == 3) || (typ == "URI" && n == 2) {
			text = strconv.Itoa(*priority) + " " + text
		}
	}
	f, err := platform.RecordFields(typ, text)
	if err != nil {
		return nil, nil, err
	}
	num := func(i int) int { n, _ := strconv.Atoi(f[i]); return n }
	switch typ {
	case "SRV":
		return map[string]any{"priority": num(0), "weight": num(1), "port": num(2), "target": f[3]}, nil, nil
	case "CAA":
		return map[string]any{"flags": num(0), "tag": f[1], "value": f[2]}, nil, nil
	case "TLSA", "SMIMEA":
		return map[string]any{"usage": num(0), "selector": num(1), "matching_type": num(2), "certificate": f[3]}, nil, nil
	case "SSHFP":
		return map[string]any{"algorithm": num(0), "type": num(1), "fingerprint": f[2]}, nil, nil
	case "DS":
		return map[string]any{"key_tag": num(0), "algorithm": num(1), "digest_type": num(2), "digest": f[3]}, nil, nil
	case "DNSKEY":
		return map[string]any{"flags": num(0), "protocol": num(1), "algorithm": num(2), "public_key": f[3]}, nil, nil
	case "CERT":
		return map[string]any{"type": num(0), "key_tag": num(1), "algorithm": num(2), "certificate": f[3]}, nil, nil
	case "URI":
		p := num(0)
		return map[string]any{"weight": num(1), "target": f[2]}, &p, nil
	case "NAPTR":
		return map[string]any{"order": num(0), "preference": num(1), "flags": f[2], "service": f[3], "regex": f[4], "replacement": f[5]}, nil, nil
	case "HTTPS", "SVCB":
		// value holds the parameters as zone-file text (alpn="h3,h2").
		v, err := platform.CheckRecord(platform.RecordCheck{Type: typ, Value: text})
		if err != nil {
			return nil, nil, err
		}
		params := ""
		if parts := strings.SplitN(v.Value, " ", 3); len(parts) == 3 {
			params = parts[2]
		}
		return map[string]any{"priority": num(0), "target": f[1], "value": params}, nil, nil
	case "LOC":
		fl := func(i int) float64 {
			x, _ := strconv.ParseFloat(strings.TrimSuffix(f[i], "m"), 64)
			return x
		}
		return map[string]any{
			"lat_degrees": num(0), "lat_minutes": num(1), "lat_seconds": fl(2), "lat_direction": f[3],
			"long_degrees": num(4), "long_minutes": num(5), "long_seconds": fl(6), "long_direction": f[7],
			"altitude": fl(8), "size": fl(9), "precision_horz": fl(10), "precision_vert": fl(11),
		}, nil, nil
	}
	return nil, nil, fmt.Errorf("%w: %s values are not written as components", platform.ErrInvalidInput, typ)
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
