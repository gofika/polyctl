package gcp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/api/googleapi"
)

// Aggregated lists read every scope (zone, region, global) of a project in
// one call. A scope the API cannot reach is reported in two ways, and both
// are read:
//
//   - with returnPartialSuccess=true (which the API reference recommends
//     for every aggregatedList), the call succeeds and names the scope in
//     the top-level unreachables field;
//   - the scope's entry in items carries warning.code UNREACHABLE and no
//     resources.
//
// The generated Go client does not expose returnPartialSuccess, so it is
// sent as a query parameter.

// partialSuccess asks an aggregated list to answer the scopes it can read.
var partialSuccess = googleapi.QueryParameter("returnPartialSuccess", "true")

// aggregatedCall is the generated call of an aggregated list.
type aggregatedCall[C any, R any] interface {
	Context(context.Context) C
	PageToken(string) C
	Do(...googleapi.CallOption) (R, error)
}

// aggregatedPage reads one page of an aggregated list: it returns the next
// page token and the scopes of that page that could not be reached.
type aggregatedPage[R any] func(R) (next string, unreachable []string)

// aggregatedPages runs an aggregated list with partial success over every
// page and returns the unreachable scopes, sorted and without repeats (a
// scope named by both signals counts once).
func aggregatedPages[C aggregatedCall[C, R], R any](ctx context.Context, call C, page aggregatedPage[R]) ([]string, error) {
	call = call.Context(ctx)
	var scopes []string
	for {
		resp, err := call.Do(partialSuccess)
		if err != nil {
			return nil, err
		}
		next, u := page(resp)
		scopes = append(scopes, u...)
		if next == "" {
			break
		}
		call = call.PageToken(next)
	}
	return uniqueScopes(scopes), nil
}

// warnedUnreachable returns scope when its warning code says it could not
// be reached.
func warnedUnreachable(scope, code string) []string {
	if code == "UNREACHABLE" {
		return []string{scope}
	}
	return nil
}

// uniqueScopes sorts scopes and drops repeats; "zones/x" and a URL ending
// in "/zones/x" are the same scope.
func uniqueScopes(scopes []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range scopes {
		k := scopeKey(s)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scopeKey is the "zones/x", "regions/x" or "global" form of a scope.
func scopeKey(s string) string {
	s = strings.TrimSuffix(s, "/")
	for _, kind := range []string{"zones/", "regions/"} {
		if i := strings.LastIndex(s, kind); i >= 0 {
			return s[i:]
		}
	}
	if s == "global" || strings.HasSuffix(s, "/global") {
		return "global"
	}
	return s
}

// unreachableListErr is the error of a list that must be complete (a
// lookup that would otherwise miss a resource) when scopes were
// unreachable.
func unreachableListErr(what string, scopes []string) error {
	if len(scopes) == 0 {
		return nil
	}
	return fmt.Errorf("list %s: scopes could not be reached: %s", what, strings.Join(scopes, ", "))
}
