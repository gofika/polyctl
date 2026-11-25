package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"

	"github.com/gofika/polyctl/internal/platform"
)

// A GCP account works on every project its credentials see: all of them
// are enabled unless the user disabled them, the ones created later
// included. Only the disabled ones are stored, as the metadata
// "disabled_projects" (comma-separated), next to the default project,
// "project", which is always enabled. The enabled projects are what the
// credentials list now, minus the disabled ones (enabledProjects).

// metaProject and metaDisabledProjects are the metadata keys of the
// default project and of the disabled projects. legacyProjects is the key
// that held the selected projects before every visible project was
// enabled: it is not read any more and is dropped when the metadata of
// the account is written.
const (
	metaProject          = "project"
	metaDisabledProjects = "disabled_projects"
	legacyProjects       = "projects"
)

// splitProjects splits a comma-separated list of project ids, dropping
// blanks and repeats.
func splitProjects(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// disabledProjects returns the disabled projects of an account from its
// metadata. The default project is never one of them, whatever a
// config.yaml edited by hand says.
func disabledProjects(meta map[string]string) []string {
	def := strings.TrimSpace(meta[metaProject])
	var out []string
	for _, p := range splitProjects(meta[metaDisabledProjects]) {
		if p != def {
			out = append(out, p)
		}
	}
	return out
}

// setProjects writes the default project and the disabled projects into
// meta: the list sorted and without the default, the key absent when
// nothing is disabled. The key of the former selection is dropped.
func setProjects(meta map[string]string, def string, disabled []string) {
	meta[metaProject] = def
	delete(meta, legacyProjects)
	list := disabledProjects(map[string]string{metaProject: def, metaDisabledProjects: strings.Join(disabled, ",")})
	if len(list) == 0 {
		delete(meta, metaDisabledProjects)
		return
	}
	sort.Strings(list)
	meta[metaDisabledProjects] = strings.Join(list, ",")
}

// checkProjectID refuses what cannot be a project id where one is given
// (--project, the project commands, --set project).
func checkProjectID(id string) error {
	if id == "" || strings.ContainsAny(id, "/|, \t\r\n") {
		return fmt.Errorf("%q is not a project id", id)
	}
	return nil
}

// inProject returns the client bound to another project: a shallow copy
// sharing the API services and what is known of the account (cov).
func (c *client) inProject(project string) *client {
	if project == "" || project == c.project {
		return c
	}
	cp := *c
	cp.project = project
	return &cp
}

// pin returns the client of --project: bound to that project, its lists
// reading that project alone.
func (c *client) pin(project string) *client {
	cp := *c
	cp.project = project
	cp.pinned = true
	return &cp
}

// visibleProjects lists the active projects the credentials see, once per
// opened account. canList is false for credentials that may not list
// projects (a 403: no permission, or the Resource Manager API is not
// enabled for the caller): such an account works on its default project
// alone. Any other failure is returned and asked again by the next call.
func (c *client) visibleProjects(ctx context.Context) (projects []*cloudresourcemanager.Project, canList bool, err error) {
	cov := c.cov
	if cov == nil {
		return nil, false, nil
	}
	cov.listMu.Lock()
	defer cov.listMu.Unlock()
	if cov.listed {
		return cov.visible, cov.canList, nil
	}
	if c.crm == nil {
		return nil, false, nil
	}
	projects, err = listProjects(ctx, c.crm)
	var ge *googleapi.Error
	switch {
	case err == nil:
		cov.visible, cov.canList = projects, true
	case errors.As(err, &ge) && ge.Code == http.StatusForbidden && !isCapacity(googleReason(err)) && !isCapacityMessage(ge.Message):
		cov.cannotList = err
	default:
		return nil, false, fmt.Errorf("list the projects of %s: %w", c.accountLabel(), err)
	}
	cov.listed = true
	return cov.visible, cov.canList, nil
}

// enabledProjects are the projects of the account that syncs, lists and
// lookups cover, the default project first and the others sorted by id:
// every active project the credentials see but the disabled ones. With
// credentials that cannot list projects, or see none, it is the default
// project alone. It asks the network once per opened account, hence the
// error.
func (c *client) enabledProjects(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.cov == nil {
		return []string{c.project}, nil
	}
	def := c.cov.def
	if def == "" {
		def = c.project
	}
	visible, _, err := c.visibleProjects(ctx)
	if err != nil {
		return nil, err
	}
	out := []string{def}
	for _, p := range visible {
		if p.ProjectId != def && !slices.Contains(c.cov.disabled, p.ProjectId) {
			out = append(out, p.ProjectId)
		}
	}
	return out, nil
}

// sweep are the projects a list or lookup of the client reads: the
// pinned project alone for the client of --project, the enabled projects
// otherwise.
func (c *client) sweep(ctx context.Context) ([]string, error) {
	if c.pinned {
		return []string{c.project}, nil
	}
	return c.enabledProjects(ctx)
}

// covers reports whether project is one of the enabled projects, that
// is, one the syncs of the account read.
func (c *client) covers(ctx context.Context, project string) (bool, error) {
	projects, err := c.enabledProjects(ctx)
	if err != nil {
		return false, err
	}
	return slices.Contains(projects, project), nil
}

// cacheable reports whether what was read of the client's project may be
// written to the inventory: only a project the syncs cover, since the
// next sync would not refresh the rows of another. A disabled project is
// not covered, and the default project and one the inventory holds rows
// of (markHeld) are, without asking; when it cannot be told of another,
// nothing is written.
func (c *client) cacheable(ctx context.Context) bool {
	if c.cov != nil {
		switch {
		case slices.Contains(c.cov.disabled, c.project):
			return false
		case c.project == c.cov.def, c.isHeld():
			return true
		}
	}
	ok, err := c.covers(ctx, c.project)
	return err == nil && ok
}

// markHeld records that the inventory holds a row of the client's
// project, which only a sync that covers the project stored: what is read
// of it may be cached without asking the account for its projects.
func (c *client) markHeld() {
	if c.cov == nil {
		return
	}
	c.cov.mu.Lock()
	defer c.cov.mu.Unlock()
	if c.cov.held == nil {
		c.cov.held = map[string]bool{}
	}
	c.cov.held[c.project] = true
}

func (c *client) isHeld() bool {
	c.cov.mu.Lock()
	defer c.cov.mu.Unlock()
	return c.cov.held[c.project]
}

// projectOr returns p, or the client's project for the rows stored before
// they carried their project.
func (c *client) projectOr(p string) string {
	if p == "" {
		return c.project
	}
	return p
}

// parentOf is the inventory parent of a row: its project for a global
// row, "<project>/<zone or region>" otherwise. A sync that fails for a
// whole project keeps the rows of that tree.
func parentOf(project, location string) string {
	if location == "" {
		return project
	}
	return project + "/" + location
}

// locationOf is the zone or region of an inventory parent ("" for a
// global row), and its project.
func locationOf(parent string) (project, location string) {
	if i := strings.Index(parent, "/"); i >= 0 {
		return parent[:i], parent[i+1:]
	}
	return parent, ""
}

// isAPIDisabled reports the answer of a project that cannot hold anything
// of the API asked: the API is not enabled in it, or its billing is off
// (403 accessNotConfigured / SERVICE_DISABLED / billingNotEnabled /
// BILLING_DISABLED, or one of the messages those answers carry). A quota
// or capacity answer is never one, whatever else it says: that project
// may hold resources.
func isAPIDisabled(err error) bool {
	var ge *googleapi.Error
	if !errors.As(err, &ge) || ge.Code != http.StatusForbidden {
		return false
	}
	reasons := append([]string{googleReason(err)}, detailReasons(ge)...)
	for _, r := range reasons {
		if isCapacity(r) {
			return false
		}
	}
	if isCapacityMessage(ge.Message) {
		return false
	}
	for _, r := range reasons {
		switch r {
		case "accessNotConfigured", "SERVICE_DISABLED", "billingNotEnabled", "BILLING_DISABLED":
			return true
		}
	}
	return containsAny(strings.ToLower(ge.Message), "has not been used", "is disabled", "requires billing to be enabled", "billing is disabled")
}

// detailReasons returns the reasons of the google.rpc.ErrorInfo details
// of an API error ("SERVICE_DISABLED", "BILLING_DISABLED", ...): the
// newer APIs name the cause there and not in Errors[0].Reason.
func detailReasons(ge *googleapi.Error) []string {
	var out []string
	for _, d := range ge.Details {
		m, ok := d.(map[string]any)
		if !ok {
			continue
		}
		if r, ok := m["reason"].(string); ok && r != "" {
			out = append(out, r)
		}
	}
	return out
}

// projectConcurrency bounds the projects read at the same time.
const projectConcurrency = 4

// eachProject runs fn for every enabled project and returns the rows of
// all of them, for the inventory. api is the API fn asks (apiDNS,
// apiCompute).
//
//   - a project in which the API is not enabled, or whose billing is off,
//     holds nothing of the type: it contributes no rows and no failure,
//     also when it is the only project. The later types of the same run
//     do not ask it again, and the user is told once (noteOff);
//   - with one project enabled any other answer is fn's result as it is;
//   - with several, a project that fails is a failure of its whole tree
//     (platform.RegionError.Tree): the rows stored for it are kept and the
//     rows of the other projects replace theirs;
//   - an unreachable zone or region of a project (a *RegionSyncError of
//     fn) keeps the rows of that scope only;
//   - when every project fails the result is a plain error wrapping the
//     first one, so that nothing is replaced and the exit code is kept.
func (c *client) eachProject(ctx context.Context, api string, fn func(ctx context.Context, pc *client) ([]platform.Resource, error)) ([]platform.Resource, error) {
	projects, err := c.enabledProjects(ctx)
	if err != nil {
		return nil, err
	}
	defer c.flushOff()
	one := func(ctx context.Context, pc *client) ([]platform.Resource, error) {
		if c.isOff(pc.project, api) {
			return nil, nil
		}
		res, err := fn(ctx, pc)
		if isAPIDisabled(err) {
			c.markOff(pc.project, api)
			c.noteOff(pc.project, err)
			return nil, nil
		}
		return res, err
	}
	if len(projects) == 1 {
		return one(ctx, c.inProject(projects[0]))
	}
	results := runProjects(ctx, c, projects, one)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []platform.Resource
	var failures []platform.RegionError
	failed := 0
	var first error
	for _, r := range results {
		switch rse := platform.AsRegionSyncError(r.err); {
		case r.err == nil:
			out = append(out, r.res...)
		case rse != nil:
			out = append(out, r.res...)
			failures = append(failures, rse.Failures...)
		default:
			failed++
			if first == nil {
				first = r.err
			}
			failures = append(failures, platform.RegionError{Region: r.project, Tree: true,
				Err: fmt.Errorf("%w (if the project is not to be used any more: polyctl gcp project disable %s)", r.err, r.project)})
		}
	}
	if len(failures) == 0 {
		return out, nil
	}
	sort.SliceStable(failures, func(i, j int) bool { return failures[i].Region < failures[j].Region })
	e := &platform.RegionSyncError{Failures: failures, Noun: "project or zone"}
	if failed == len(projects) {
		return nil, fmt.Errorf("every enabled project failed (%s): %w", e.Error(), first)
	}
	return out, e
}

// projectResult is what one project answered in a walk over projects.
type projectResult[T any] struct {
	project string
	res     []T
	err     error
}

// runProjects runs fn with the client of each project, projectConcurrency
// of them at a time, and returns their answers in the order of projects.
// One project is asked on the caller's goroutine.
func runProjects[T any](ctx context.Context, c *client, projects []string, fn func(ctx context.Context, pc *client) ([]T, error)) []projectResult[T] {
	results := make([]projectResult[T], len(projects))
	if len(projects) == 1 {
		res, err := fn(ctx, c.inProject(projects[0]))
		results[0] = projectResult[T]{project: projects[0], res: res, err: err}
		return results
	}
	sem := make(chan struct{}, projectConcurrency)
	var wg sync.WaitGroup
	for i, p := range projects {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := ctx.Err(); err != nil {
				results[i] = projectResult[T]{project: p, err: err}
				return
			}
			res, err := fn(ctx, c.inProject(p))
			results[i] = projectResult[T]{project: p, res: res, err: err}
		}()
	}
	wg.Wait()
	return results
}

// sweepProjects is a list read live: it runs fn with the client of every
// project the lists of c cover (sweep), several at a time, and returns
// their rows in the order of the projects. fn runs on several goroutines:
// it returns what it found and leaves printing to its caller.
//
// A project whose API is not enabled is skipped (noteOff), unless it is
// the project of --project. Any other failure fails the sweep with the
// error of the first such project, named after it when there are several.
func sweepProjects[T any](ctx context.Context, c *client, fn func(ctx context.Context, pc *client) ([]T, error)) ([]T, error) {
	projects, err := c.sweep(ctx)
	if err != nil {
		return nil, err
	}
	defer c.flushOff()
	results := runProjects(ctx, c, projects, fn)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []T
	for _, r := range results {
		switch {
		case r.err == nil:
			out = append(out, r.res...)
		case !c.pinned && isAPIDisabled(r.err):
			c.noteOff(r.project, r.err)
		case len(projects) == 1:
			return nil, r.err
		default:
			return nil, fmt.Errorf("project %s: %w", r.project, r.err)
		}
	}
	return out, nil
}

// maxProjectsNamed is how many projects a message names before it counts
// them instead.
const maxProjectsNamed = 3

// projectNames abbreviates a list of projects for a message: "p1, p2,
// p3", or "7 projects" beyond three.
func projectNames(projects []string) string {
	if len(projects) > maxProjectsNamed {
		return fmt.Sprintf("%d projects", len(projects))
	}
	return strings.Join(projects, ", ")
}

// projectsLabel names the projects the lists of the client cover:
// "project p1", "projects p1, p2", or "7 projects" beyond three.
func (c *client) projectsLabel(ctx context.Context) string {
	projects, err := c.sweep(ctx)
	switch {
	case err != nil:
		return "project " + c.project
	case len(projects) == 1:
		return "project " + projects[0]
	case len(projects) > maxProjectsNamed:
		return projectNames(projects)
	}
	return "projects " + projectNames(projects)
}
