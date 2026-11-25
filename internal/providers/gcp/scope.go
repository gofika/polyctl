package gcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// A GCP command works on the selected projects of its account, or on the
// one project --project pins. A scope is one account and one project of
// it; lookups that search several accounts search their scopes.

// projectFlag is the value of --project: a project id, checked as it is
// set.
type projectFlag struct{ v *string }

func (f projectFlag) String() string {
	if f.v == nil {
		return ""
	}
	return *f.v
}
func (f projectFlag) Type() string { return "string" }
func (f projectFlag) Set(s string) error {
	s = strings.TrimSpace(s)
	if err := checkProjectID(s); err != nil {
		return err
	}
	*f.v = s
	return nil
}

// projectFlagHelp is the usage text of --project.
const projectFlagHelp = "Google Cloud project of this call (default: every selected project for lookups and lists, the default project for creates); a project outside the selection is read live and not cached"

// addProjectFlag adds --project to a command and everything below it.
func addProjectFlag(rt *app.Runtime, cmd *cobra.Command) {
	rt.Flags.Project = ""
	cmd.PersistentFlags().Var(projectFlag{&rt.Flags.Project}, "project", projectFlagHelp)
}

// pinnedProject is the project of --project, "" when the flag was not
// given.
func pinnedProject(rt *app.Runtime) string { return strings.TrimSpace(rt.Flags.Project) }

// accountProjects returns the default project and the selection of a
// profile's gcp account, from the config.
func accountProjects(rt *app.Runtime, profile string) (def string, selected []string, err error) {
	cfg, err := rt.Config()
	if err != nil {
		return "", nil, err
	}
	a, err := cfg.Account(profile, platform.GCP)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	return a.Metadata[metaProject], selectedProjects(a.Metadata), nil
}

// pinUnselected reports whether --project names a project outside the
// selection of the profile: one the inventory does not hold, read live.
func pinUnselected(rt *app.Runtime, profile string) bool {
	pin := pinnedProject(rt)
	if pin == "" {
		return false
	}
	_, selected, err := accountProjects(rt, profile)
	return err == nil && !slices.Contains(selected, pin)
}

// keepProject reports whether a cached row of project (empty: the default
// project of the account, for rows stored before they carried it) is in
// the scope of the call: the pinned project with --project, any selected
// project without it.
//
// A row of a project that is no longer selected is out of scope: the
// selection may have changed (a new login, an edited config.yaml) while
// the set that holds the row is still fresh, and a command must not find,
// let alone change, a resource of a project the account was taken off.
func keepProject(rt *app.Runtime, profile, project string) bool {
	def, selected, err := accountProjects(rt, profile)
	if project == "" {
		project = def
	}
	if pin := pinnedProject(rt); pin != "" {
		return project == pin
	}
	return err != nil || slices.Contains(selected, project)
}

// scope is one account and one of its projects. c, when set, is the
// opened client of the account: the scopes of one account share it, so
// that the account is opened, and its projects are asked, once.
type scope struct {
	profile string
	project string
	c       *client
}

func (s scope) String() string { return "gcp/" + s.profile + " project " + s.project }

// gcpScopes returns the scopes of the call: every selected project of
// every GCP account selected by --profile, or, with --project, that
// project in each of them.
func gcpScopes(ctx context.Context, rt *app.Runtime) ([]scope, error) {
	accounts, err := gcpAccounts(rt)
	if err != nil {
		return nil, err
	}
	return scopesOf(ctx, rt, accounts)
}

// scopesOf opens each account once and returns one scope for every
// project its lists read (sweep).
func scopesOf(ctx context.Context, rt *app.Runtime, accounts []config.AccountRef) ([]scope, error) {
	var out []scope
	for _, a := range accounts {
		c, err := openProfile(ctx, rt, a.Profile)
		if err != nil {
			return nil, err
		}
		projects, err := c.sweep(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range projects {
			out = append(out, scope{profile: a.Profile, project: p, c: c})
		}
	}
	return out, nil
}

// openScope returns the client of a scope: the client of its account
// moved to its project, opened here when the scope does not carry it.
func openScope(ctx context.Context, rt *app.Runtime, s scope) (*client, error) {
	c := s.c
	if c == nil {
		var err error
		if c, err = openProfile(ctx, rt, s.profile); err != nil {
			return nil, err
		}
	}
	return c.inProject(s.project), nil
}

// flushScopes tells, once per account, the projects a walk over scopes
// skipped because an API is not enabled in them (noteOff).
func flushScopes(scopes []scope) {
	for _, s := range scopes {
		flushOffNotes(string(platform.GCP) + "/" + s.profile)
	}
}

// scopeLabels names scopes for a message: "gcp/a project p1, gcp/a
// project p2".
func scopeLabels(scopes []scope) string {
	names := make([]string, 0, len(scopes))
	for _, s := range scopes {
		names = append(names, s.String())
	}
	return strings.Join(names, ", ")
}

// regionFlags are the flags that choose among the scopes of a regional or
// global resource.
const regionFlags = "--region <r> or --global"

// cand is one candidate of an ambiguous lookup: where it is and what tells
// it from the others.
type cand struct {
	profile string
	project string
	// where is the zone or region of the candidate, "global" for a global
	// one, "" when the kind has no location.
	where string
	// id and detail tell the candidates apart beyond their place: the
	// numeric id, the status, the DNS name.
	id, detail string
}

func (c cand) String() string {
	s := "gcp/" + c.profile + " project " + c.project
	if c.where != "" {
		s += " " + c.where
	}
	var extra []string
	for _, v := range []string{c.id, c.detail} {
		if v != "" {
			extra = append(extra, v)
		}
	}
	if len(extra) > 0 {
		s += " (" + strings.Join(extra, ", ") + ")"
	}
	return s
}

// ambiguous is the error of a lookup that found ref in several places:
// every candidate, and the flags that choose one. Only the flags whose
// value differs among the candidates are named: --profile, --project and
// locFlag (the flag of the location: "--zone <zone>", "--region <r> or
// --global"); alt is another way to name one ("the instance id").
//
// The interactive flow turns it into a pick (disambiguate); the
// non-interactive flow returns it (exit code 5).
func ambiguous(what, ref string, cands []cand, locFlag, alt string) *app.AmbiguousError {
	distinct := func(get func(cand) string) bool {
		for _, c := range cands[1:] {
			if get(c) != get(cands[0]) {
				return true
			}
		}
		return false
	}
	var flags []string
	if distinct(func(c cand) string { return c.profile }) {
		flags = append(flags, "--profile <name>")
	}
	if distinct(func(c cand) string { return c.project }) {
		flags = append(flags, "--project <id>")
	}
	if locFlag != "" && distinct(func(c cand) string { return c.where }) {
		flags = append(flags, locFlag)
	}
	hint := "pass " + strings.Join(flags, " or ")
	switch {
	case len(flags) == 0 && alt != "":
		hint = "pass " + alt
	case len(flags) == 0:
		hint = "name it by what tells the candidates apart"
	case alt != "":
		hint += ", or " + alt + ","
	}
	names := make([]string, 0, len(cands))
	for _, c := range cands {
		names = append(names, c.String())
	}
	return &app.AmbiguousError{What: fmt.Sprintf("%s %q", what, ref), Candidates: names, Hint: hint + " to choose"}
}

// locateProject finds the project of a resource that a command names
// without its project (a firewall rule, a network, a certificate): c is
// the client of the account, exists tells whether a project holds it.
//
// With one project to look in (one selected, or --project) nothing is
// asked of the API: the client of that project is returned and the command
// reports a missing resource as it always did. With several, every one is
// asked: one holder is used, several are ambiguous (a pick in the
// interactive flow, exit code 5 otherwise, naming --project), none is not
// found, naming the projects searched. exists runs for several projects at
// the same time.
func locateProject(ctx context.Context, rt *app.Runtime, c *client, profile, what, name string, exists func(ctx context.Context, pc *client) (bool, error)) (*client, error) {
	projects, err := c.sweep(ctx)
	if err != nil {
		return nil, err
	}
	if len(projects) == 1 {
		return c.inProject(projects[0]), nil
	}
	found, err := sweepProjects(ctx, c, func(ctx context.Context, pc *client) ([]*client, error) {
		if ok, err := exists(ctx, pc); err != nil || !ok {
			return nil, err
		}
		return []*client{pc}, nil
	})
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: %s %q in the selected projects of gcp/%s (%s)", platform.ErrNotFound, what, name, profile, projectNames(projects))
	case 1:
		return found[0], nil
	}
	sort.Slice(found, func(i, j int) bool { return found[i].project < found[j].project })
	cands := make([]cand, 0, len(found))
	for _, f := range found {
		cands = append(cands, cand{profile: profile, project: f.project})
	}
	return disambiguate(rt, ambiguous(what, name, cands, "", ""), found, func(f *client) string {
		return prompt.Cells(name, "project "+f.project, "gcp/"+profile)
	})
}

// notFoundIs turns a "not found" of get into "does not exist" for
// locateProject: (false, nil).
func notFoundIs(err error) (bool, error) {
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, platform.ErrNotFound):
		return false, nil
	}
	return false, err
}

// chooseListProject asks, in the interactive flow, which project a pick
// without a name lists from, when several are selected (the default
// project proposed). With one project, with --project and in the
// non-interactive flow nothing is asked: the client's project is used.
func chooseListProject(ctx context.Context, rt *app.Runtime, c *client, profile string) (*client, error) {
	projects, err := c.sweep(ctx)
	if err != nil {
		return nil, err
	}
	if len(projects) < 2 || !rt.Interactive() {
		return c.inProject(projects[0]), nil
	}
	opts := make([]prompt.Option, 0, len(projects))
	for i, p := range projects {
		mark := ""
		if i == 0 {
			mark = "default"
		}
		opts = append(opts, prompt.Option{Label: prompt.Cells(p, mark), Value: p})
	}
	p, err := rt.Choose(app.Choice{Title: "Project", Options: opts, Default: projects[0], Arg: "--project", What: "selected project of gcp/" + profile})
	if err != nil {
		return nil, err
	}
	return c.inProject(p), nil
}
