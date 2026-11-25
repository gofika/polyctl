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

	"google.golang.org/api/googleapi"

	"github.com/gofika/polyctl/internal/platform"
)

// A GCP account works on several projects: the selection, stored as the
// metadata "projects" (comma-separated), with the default project, stored
// as "project", among them. An account without "projects" (every login
// before the selection existed) has exactly its one project selected.

// metaProject and metaProjects are the metadata keys of the default
// project and of the selection.
const (
	metaProject  = "project"
	metaProjects = "projects"
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

// selectedProjects returns the selection of an account from its metadata:
// the default project first, then the others in stored order. It always
// holds the default project, and is empty only without one.
func selectedProjects(meta map[string]string) []string {
	def := strings.TrimSpace(meta[metaProject])
	var out []string
	if def != "" {
		out = append(out, def)
	}
	for _, p := range splitProjects(meta[metaProjects]) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// setSelection writes the default project and the selection into meta. A
// selection of the default project alone is stored without "projects", as
// a login before the selection existed stored it.
func setSelection(meta map[string]string, def string, selected []string) {
	meta[metaProject] = def
	sel := selectedProjects(map[string]string{metaProject: def, metaProjects: strings.Join(selected, ",")})
	if len(sel) <= 1 {
		delete(meta, metaProjects)
		return
	}
	meta[metaProjects] = strings.Join(sel, ",")
}

// checkProjectID refuses what cannot be a project id where one is given
// (--project, project use/add/remove, --set projects).
func checkProjectID(id string) error {
	if id == "" || strings.ContainsAny(id, "/|, \t\r\n") {
		return fmt.Errorf("%q is not a project id", id)
	}
	return nil
}

// inProject returns the client bound to another project: a shallow copy
// sharing the API services, the selection unchanged.
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

// selected reports whether the client's project is one of the selection,
// that is, one the inventory holds.
func (c *client) selected() bool { return slices.Contains(c.projects, c.project) }

// listProjects are the projects a list of the client covers: the
// selection, or the pinned project alone.
func (c *client) listProjects() []string {
	if c.pinned || len(c.projects) == 0 {
		return []string{c.project}
	}
	return c.projects
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

// eachProject runs fn for every selected project and returns the rows of
// all of them, for the inventory.
//
// With one project selected it is fn's result as it is. With several:
//
//   - a project that fails is a failure of its whole tree
//     (platform.RegionError.Tree): the rows stored for it are kept and the
//     rows of the other projects replace theirs;
//   - an unreachable zone or region of a project (a *RegionSyncError of
//     fn) keeps the rows of that scope only;
//   - a project in which the API of the type is not enabled holds nothing
//     of the type: a DNS-only project does not fail every instance sync;
//   - when every project fails the result is a plain error wrapping the
//     first one, so that nothing is replaced and the exit code is kept.
func (c *client) eachProject(ctx context.Context, fn func(ctx context.Context, pc *client) ([]platform.Resource, error)) ([]platform.Resource, error) {
	projects := c.projects
	if len(projects) == 0 {
		projects = []string{c.project}
	}
	if len(projects) == 1 {
		return fn(ctx, c.inProject(projects[0]))
	}
	type result struct {
		res []platform.Resource
		err error
	}
	results := make([]result, len(projects))
	sem := make(chan struct{}, projectConcurrency)
	var wg sync.WaitGroup
	for i, p := range projects {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := ctx.Err(); err != nil {
				results[i] = result{err: err}
				return
			}
			res, err := fn(ctx, c.inProject(p))
			results[i] = result{res: res, err: err}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []platform.Resource
	var failures []platform.RegionError
	failed := 0
	var first error
	for i, r := range results {
		switch rse := platform.AsRegionSyncError(r.err); {
		case r.err == nil:
			out = append(out, r.res...)
		case rse != nil:
			out = append(out, r.res...)
			failures = append(failures, rse.Failures...)
		case isAPIDisabled(r.err):
		default:
			failed++
			if first == nil {
				first = r.err
			}
			failures = append(failures, platform.RegionError{Region: projects[i], Tree: true,
				Err: fmt.Errorf("%w (if the project is not to be used any more: polyctl gcp project remove %s)", r.err, projects[i])})
		}
	}
	if len(failures) == 0 {
		return out, nil
	}
	sort.SliceStable(failures, func(i, j int) bool { return failures[i].Region < failures[j].Region })
	e := &platform.RegionSyncError{Failures: failures, Noun: "project or zone"}
	if failed == len(projects) {
		return nil, fmt.Errorf("every selected project failed (%s): %w", e.Error(), first)
	}
	return out, e
}

// forProjects runs fn with the client of every project the lists of the
// client cover (listProjects). A project whose API is not enabled is
// skipped when there are several; any other failure ends the walk, named
// after its project.
func (c *client) forProjects(ctx context.Context, fn func(pc *client) error) error {
	projects := c.listProjects()
	for _, p := range projects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(c.inProject(p)); err != nil {
			if len(projects) == 1 {
				return err
			}
			if isAPIDisabled(err) {
				continue
			}
			return fmt.Errorf("project %s: %w", p, err)
		}
	}
	return nil
}

// projectsLabel names the projects the lists of the client cover:
// "project p1", or "projects p1, p2".
func (c *client) projectsLabel() string {
	projects := c.listProjects()
	if len(projects) == 1 {
		return "project " + projects[0]
	}
	return "projects " + strings.Join(projects, ", ")
}
