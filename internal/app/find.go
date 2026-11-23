package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// FindTypes are the resource types `polyctl find` looks through, in the
// order they are synced.
var FindTypes = []platform.ResourceType{platform.ResInstance, platform.ResLoadBalancer, platform.ResEIP, platform.ResDBInstance}

// FindRequest is what `polyctl find` asks for.
type FindRequest struct {
	Query platform.FindQuery
	// Platforms restricts the accounts searched; empty means every platform.
	Platforms map[platform.ID]bool
	// Refresh syncs the find resource types of the selected accounts first.
	Refresh bool
	// Detail looks up the network details of matched instances live.
	Detail bool
}

// FindError is the failure of one account (or one region of it, or the
// detail lookup of one match) during find. The matches found elsewhere are
// still reported.
type FindError struct {
	Platform platform.ID           `json:"platform" yaml:"platform"`
	Profile  string                `json:"profile" yaml:"profile"`
	Type     platform.ResourceType `json:"type,omitempty" yaml:"type,omitempty"`
	Region   string                `json:"region,omitempty" yaml:"region,omitempty"`
	Resource string                `json:"resource,omitempty" yaml:"resource,omitempty"`
	Error    string                `json:"error" yaml:"error"`
	// Err is the error behind Error.
	Err error `json:"-" yaml:"-"`
}

// FindResult is the outcome of a find.
type FindResult struct {
	Query string            `json:"query" yaml:"query"`
	Kind  platform.FindKind `json:"kind" yaml:"kind"`
	// Cached is true when the inventory was read as it was (no --refresh).
	Cached bool `json:"cached" yaml:"cached"`
	// SyncedAt is the oldest sync time of the sets searched; nil when none
	// was ever synced.
	SyncedAt *time.Time           `json:"synced_at" yaml:"synced_at"`
	Matches  []platform.FindMatch `json:"matches" yaml:"matches"`
	Errors   []FindError          `json:"errors" yaml:"errors"`
	Hint     string               `json:"hint,omitempty" yaml:"hint,omitempty"`

	// Accounts is how many accounts were searched.
	Accounts int `json:"-" yaml:"-"`
	// NeverSynced is true when no set searched was ever synced.
	NeverSynced bool `json:"-" yaml:"-"`
	// Stale is true when a set searched is older than its TTL.
	Stale bool `json:"-" yaml:"-"`
	// AllFailed is true when --refresh could sync no account at all.
	AllFailed bool `json:"-" yaml:"-"`
}

// Hints of a find result without matches.
const (
	FindHintRefresh     = "rerun with --refresh to sync the local inventory"
	FindHintNeverSynced = "the inventory has never been synced; run: polyctl sync"
)

// findAccount is an account find searches.
type findAccount struct {
	ref   config.AccountRef
	types []platform.ResourceType
}

// findAccounts returns the selected accounts whose platform carries
// addresses in its inventory rows, with the find types each syncs.
func (rt *Runtime) findAccounts(only map[platform.ID]bool) ([]findAccount, error) {
	refs, err := rt.Accounts()
	if err != nil {
		return nil, err
	}
	var out []findAccount
	for _, ref := range refs {
		if len(only) > 0 && !only[ref.Platform] {
			continue
		}
		prov, err := platform.Get(ref.Platform)
		if err != nil {
			continue
		}
		src, ok := prov.(platform.IPSource)
		if !ok {
			continue
		}
		var types []platform.ResourceType
		for _, t := range FindTypes {
			for _, s := range src.FindTypes() {
				if s == t && platform.Supports(prov, t) {
					types = append(types, t)
				}
			}
		}
		if len(types) > 0 {
			out = append(out, findAccount{ref: ref, types: types})
		}
	}
	return out, nil
}

// Find looks the query up in the IP index of the inventory. It uses the
// network only with req.Refresh (to sync first) and req.Detail (to look up
// the subnets of matched instances). The error is for failures of the
// command itself (configuration, database); what failed per account is in
// FindResult.Errors.
func (rt *Runtime) Find(ctx context.Context, req FindRequest) (*FindResult, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	accounts, err := rt.findAccounts(req.Platforms)
	if err != nil {
		return nil, err
	}
	res := &FindResult{Query: req.Query.Value, Kind: req.Query.Kind, Cached: !req.Refresh, Accounts: len(accounts),
		Matches: []platform.FindMatch{}, Errors: []FindError{}}
	if req.Refresh && len(accounts) > 0 {
		rt.findSync(ctx, cfg, accounts, res)
	}
	if err := rt.findFreshness(ctx, db, accounts, res); err != nil {
		return nil, err
	}
	if err := rt.findLookup(ctx, cfg, db, req.Query, accounts, res); err != nil {
		return nil, err
	}
	if req.Detail && len(res.Matches) > 0 {
		rt.findDetail(ctx, cfg, res)
	}
	if len(res.Matches) == 0 {
		res.Hint = FindHintRefresh
		if res.NeverSynced {
			res.Hint = FindHintNeverSynced
		}
	}
	return res, nil
}

// findSync syncs the find types of the accounts, at most
// find.concurrency at a time. Accounts are opened one after the other
// (opening may update the configuration); the syncs run in parallel. A
// failure is recorded in res.Errors and warned about on stderr, and never
// stops the other accounts.
func (rt *Runtime) findSync(ctx context.Context, cfg *config.Config, accounts []findAccount, res *FindResult) {
	type job struct {
		acct   findAccount
		client platform.Client
		prof   platform.Profile
	}
	var jobs []job
	var mu sync.Mutex
	ok := 0
	fail := func(e FindError) {
		mu.Lock()
		defer mu.Unlock()
		res.Errors = append(res.Errors, e)
		msg := fmt.Sprintf("warning: %s/%s", e.Platform, e.Profile)
		if e.Type != "" {
			msg += " " + string(e.Type)
		}
		if e.Region != "" {
			msg += " in " + e.Region
		}
		msg += ": " + e.Error
		if errors.Is(e.Err, platform.ErrUnauthorized) || errors.Is(e.Err, platform.ErrForbidden) {
			msg += " (see `polyctl auth status`)"
		}
		rt.Infof("%s", msg)
	}
	rt.Infof("syncing %d account(s) for find...", len(accounts))
	for _, a := range accounts {
		c, p, err := rt.Open(ctx, a.ref.Profile, a.ref.Platform)
		if err != nil {
			fail(FindError{Platform: a.ref.Platform, Profile: a.ref.Profile, Error: err.Error(), Err: err})
			continue
		}
		jobs = append(jobs, job{acct: a, client: c, prof: p})
	}
	sem := make(chan struct{}, cfg.FindConcurrency())
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			reports, err := rt.SyncClient(ctx, j.prof, j.client, j.acct.types)
			synced := false
			for _, r := range reports {
				if r.Err == nil {
					synced = true
					continue
				}
				if rse := platform.AsRegionSyncError(r.Err); rse != nil {
					synced = true
					for _, f := range rse.Failures {
						fail(FindError{Platform: r.Platform, Profile: r.Profile, Type: r.Type, Region: f.Region, Error: f.Err.Error(), Err: f.Err})
					}
					continue
				}
				if err != nil && r.Err == err {
					continue // reported below
				}
				fail(FindError{Platform: r.Platform, Profile: r.Profile, Type: r.Type, Error: r.Err.Error(), Err: r.Err})
			}
			if err != nil {
				fail(FindError{Platform: j.acct.ref.Platform, Profile: j.acct.ref.Profile, Error: err.Error(), Err: err})
			}
			if synced {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	res.AllFailed = ok == 0
}

// findFreshness records the oldest sync time of the sets searched and
// whether any of them is stale or none was ever synced.
func (rt *Runtime) findFreshness(ctx context.Context, db *inventory.DB, accounts []findAccount, res *FindResult) error {
	now := time.Now()
	var oldest time.Time
	for _, a := range accounts {
		for _, t := range a.types {
			st, err := db.GetState(ctx, inventory.Set{Platform: a.ref.Platform, Profile: a.ref.Profile, Type: t})
			if err != nil {
				return err
			}
			if st == nil {
				continue
			}
			if oldest.IsZero() || st.SyncedAt.Before(oldest) {
				oldest = st.SyncedAt
			}
			if !st.Fresh(now) {
				res.Stale = true
			}
		}
	}
	if oldest.IsZero() {
		res.NeverSynced = true
		return nil
	}
	t := oldest.UTC()
	res.SyncedAt = &t
	return nil
}

type matchKey struct {
	platform platform.ID
	profile  string
	typ      platform.ResourceType
	id       string
}

// findLookup reads the index and turns the hits into matches.
func (rt *Runtime) findLookup(ctx context.Context, cfg *config.Config, db *inventory.DB, q platform.FindQuery, accounts []findAccount, res *FindResult) error {
	var hits []inventory.IPHit
	var err error
	if q.Kind == platform.FindIP {
		hits, err = db.LookupIP(ctx, q.Addr)
	} else {
		hits, err = db.LookupDNS(ctx, q.Value)
	}
	if err != nil {
		return err
	}
	selected := map[config.AccountRef]bool{}
	for _, a := range accounts {
		selected[a.ref] = true
	}
	seen := map[matchKey]bool{}
	var reserved []*platform.FindMatch
	for _, h := range hits {
		if !selected[config.AccountRef{Profile: h.Profile, Platform: h.Platform}] {
			continue
		}
		k := matchKey{h.Platform, h.Profile, h.Type, h.ResourceID}
		if seen[k] {
			continue
		}
		seen[k] = true
		r, err := db.Get(ctx, inventory.Set{Platform: h.Platform, Profile: h.Profile}, h.Type, h.ResourceID)
		if errors.Is(err, platform.ErrNotFound) {
			continue // an index row without its resource is never reported
		}
		if err != nil {
			return err
		}
		m := platform.FindMatch{Platform: h.Platform, Profile: h.Profile, Type: h.Type, ID: r.ID, Name: r.Name,
			MatchedField: platform.MatchedField(h.Kind, h.Type), Data: r.Data}
		rt.describeMatch(cfg, &m)
		if h.Kind == platform.IPReserved {
			reserved = append(reserved, &m)
			continue
		}
		res.Matches = append(res.Matches, m)
	}
	// A static address reserved for a resource that holds the address
	// annotates that resource; it is a match of its own only when nothing
	// else of the account holds the address.
	for _, r := range reserved {
		attached := false
		for i := range res.Matches {
			m := &res.Matches[i]
			if m.Platform == r.Platform && m.Profile == r.Profile && m.Type != platform.ResEIP {
				m.Addresses = append(m.Addresses, r.Name)
				attached = true
			}
		}
		if !attached {
			res.Matches = append(res.Matches, *r)
		}
	}
	sort.SliceStable(res.Matches, func(i, j int) bool {
		a, b := res.Matches[i], res.Matches[j]
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	return nil
}

// describeMatch fills a match from its stored data through its provider,
// offline, and adds the console link.
func (rt *Runtime) describeMatch(cfg *config.Config, m *platform.FindMatch) {
	var meta map[string]string
	if a, err := cfg.Account(m.Profile, m.Platform); err == nil {
		meta = a.Metadata
	}
	if prov, err := platform.Get(m.Platform); err == nil {
		if d, ok := prov.(platform.MatchDescriber); ok {
			if err := d.DescribeMatch(meta, m); err != nil {
				rt.Verbosef("describe %s/%s %s %s: %v", m.Platform, m.Profile, m.Type, m.ID, err)
			}
		}
		if l, ok := prov.(platform.ConsoleLinker); ok {
			m.URL = l.ConsoleURL(meta, m)
		}
	}
	if m.InternalIPs == nil {
		m.InternalIPs = []string{}
	}
	if m.ExternalIPs == nil {
		m.ExternalIPs = []string{}
	}
}

// findDetail looks up the network details of the matched instances, each
// within find.detail_timeout. A failure leaves the match without detail and
// is recorded in res.Errors.
func (rt *Runtime) findDetail(ctx context.Context, cfg *config.Config, res *FindResult) {
	type acct struct {
		platform platform.ID
		profile  string
	}
	clients := map[acct]platform.DetailProvider{}
	failed := map[acct]bool{}
	var mu sync.Mutex
	record := func(m *platform.FindMatch, err error) {
		mu.Lock()
		defer mu.Unlock()
		res.Errors = append(res.Errors, FindError{Platform: m.Platform, Profile: m.Profile, Type: m.Type, Resource: m.ID, Error: "detail: " + err.Error(), Err: err})
		rt.Infof("warning: %s/%s %s %s: detail: %v", m.Platform, m.Profile, m.Type, m.ID, err)
	}
	var todo []int
	for i := range res.Matches {
		m := &res.Matches[i]
		if m.Type != platform.ResInstance {
			continue
		}
		k := acct{m.Platform, m.Profile}
		if failed[k] {
			continue
		}
		if _, ok := clients[k]; !ok {
			c, _, err := rt.Open(ctx, m.Profile, m.Platform)
			if err != nil {
				failed[k] = true
				record(m, err)
				continue
			}
			dp, ok := c.(platform.DetailProvider)
			if !ok {
				failed[k] = true
				continue
			}
			clients[k] = dp
		}
		todo = append(todo, i)
	}
	timeout := cfg.FindDetailTimeout()
	sem := make(chan struct{}, cfg.FindConcurrency())
	var wg sync.WaitGroup
	for _, i := range todo {
		m := &res.Matches[i]
		dp := clients[acct{m.Platform, m.Profile}]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			dctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			d, err := dp.NetworkDetail(dctx, m)
			switch {
			case errors.Is(err, platform.ErrNotSupported):
			case err != nil:
				record(m, err)
			default:
				m.Detail = d
			}
		}()
	}
	wg.Wait()
}

// Ago renders the age of a sync time for messages: "4m ago", "6h ago",
// "3d ago".
func Ago(t time.Time, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d/time.Hour))
	}
	return fmt.Sprintf("%dd ago", int(d/(24*time.Hour)))
}
