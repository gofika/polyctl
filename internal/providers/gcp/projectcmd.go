package gcp

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// ---------------------------------------------------------------- project

func newProjectCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Google Cloud projects of the account: the selected ones and the default",
		Long: `A gcp account works on the projects selected for it: the inventory, name
lookups, domain routing and certificate deployment cover all of them. One of
them is the default project, where new resources are created. The login
selects them; use, add and remove change the selection without a new login.

A project that is not selected can still be named with --project on the gcp
dns and gcp compute commands: it is read live and nothing of it is cached.`,
	}
	cmd.AddCommand(newProjectListCmd(rt), newProjectCurrentCmd(rt), newProjectUseCmd(rt), newProjectAddCmd(rt), newProjectRemoveCmd(rt))
	return cmd
}

type projectRow struct {
	ProjectID string `json:"project_id" yaml:"project_id"`
	Name      string `json:"name" yaml:"name"`
	Number    int64  `json:"project_number" yaml:"project_number"`
	State     string `json:"state" yaml:"state"`
	Selected  bool   `json:"selected" yaml:"selected"`
	Default   bool   `json:"default" yaml:"default"`
}

// projectRows lists the active projects visible to the credentials, with
// the selection marked. A selected project the list does not show (no
// permission to list it) is appended without name and state.
func projectRows(ctx context.Context, c *client) ([]projectRow, error) {
	projects, err := c.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	def := c.projects[0]
	rows := make([]projectRow, 0, len(projects))
	seen := map[string]bool{}
	for _, p := range projects {
		seen[p.ProjectId] = true
		rows = append(rows, projectRow{ProjectID: p.ProjectId, Name: p.Name, Number: p.ProjectNumber, State: p.LifecycleState,
			Selected: slices.Contains(c.projects, p.ProjectId), Default: p.ProjectId == def})
	}
	for _, p := range c.projects {
		if !seen[p] {
			rows = append(rows, projectRow{ProjectID: p, Selected: true, Default: p == def})
		}
	}
	return rows, nil
}

func newProjectListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the active projects visible to the credentials, with the selected and the default ones marked",
		Long: `List the active projects visible to the profile's credentials. SELECTED marks
the projects the account works on, and * the default one; a selected project
the credentials may not list is shown without name and state.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			rows, err := projectRows(cmd.Context(), c)
			if err != nil {
				return err
			}
			rt.Infof("%d project(s) via gcp/%s, %d selected", len(rows), prof.Name, len(c.projects))
			return rt.Render(rows, func() output.Grid { return projectGrid(rows) })
		},
	}
}

// projectGrid is the table of project list: * marks the default project.
func projectGrid(rows []projectRow) output.Grid {
	g := output.Grid{Headers: []string{"PROJECT_ID", "NAME", "NUMBER", "STATE", "SELECTED"}, Empty: "no projects"}
	for _, r := range rows {
		marker, sel, number := "", "", ""
		if r.Default {
			marker = " *"
		}
		if r.Selected {
			sel = "yes"
		}
		if r.Number != 0 {
			number = fmt.Sprint(r.Number)
		}
		g.Rows = append(g.Rows, []string{r.ProjectID + marker, r.Name, number, r.State, sel})
	}
	return g
}

type currentProject struct {
	Profile string `json:"profile" yaml:"profile"`
	// Project is the default project; Projects the selection, the default
	// first.
	Project  string   `json:"project" yaml:"project"`
	Projects []string `json:"projects" yaml:"projects"`
	Method   string   `json:"method" yaml:"method"`
	Account  string   `json:"account,omitempty" yaml:"account,omitempty"`
}

// currentOf reads the projects of a profile's gcp account from the config.
func currentOf(rt *app.Runtime, profile string) (currentProject, error) {
	cfg, err := rt.Config()
	if err != nil {
		return currentProject{}, err
	}
	p, err := cfg.Account(profile, platform.GCP)
	if err != nil {
		return currentProject{}, err
	}
	account := p.Metadata["email"]
	if account == "" {
		account = p.Metadata["client_email"]
	}
	return currentProject{Profile: profile, Project: p.Metadata[metaProject], Projects: selectedProjects(p.Metadata), Method: p.Metadata["method"], Account: account}, nil
}

func renderCurrent(rt *app.Runtime, cur currentProject) error {
	return rt.Render(cur, func() output.Grid {
		return output.KV("profile", cur.Profile, "project", cur.Project, "projects", strings.Join(cur.Projects, ", "), "method", cur.Method, "account", cur.Account)
	})
}

func newProjectCurrentCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the default project and the selected projects of the gcp account",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			cur, err := currentOf(rt, name)
			if err != nil {
				return err
			}
			return renderCurrent(rt, cur)
		},
	}
}

// projectArgs checks the project ids given to use, add or remove.
func projectArgs(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		a = strings.TrimSpace(a)
		if err := checkProjectID(a); err != nil {
			return nil, app.UsageErrf("%v", err)
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, nil
}

// saveSelection stores a new default project and selection for the
// profile's gcp account, drops what is cached for the projects that left
// the selection (instance secrets stay) and makes every cached set of the
// account due, so that the next read syncs the new selection.
func saveSelection(ctx context.Context, rt *app.Runtime, profile, def string, selected []string) error {
	cfg, err := rt.ReloadConfig()
	if err != nil {
		return err
	}
	a, err := cfg.Account(profile, platform.GCP)
	if err != nil {
		return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	before := selectedProjects(a.Metadata)
	if a.Metadata == nil {
		a.Metadata = map[string]string{}
	}
	setSelection(a.Metadata, def, selected)
	if err := cfg.Save(); err != nil {
		return err
	}
	if _, err := rt.ReloadConfig(); err != nil {
		return err
	}
	db, err := rt.DB()
	if err != nil {
		return err
	}
	after := selectedProjects(a.Metadata)
	for _, p := range before {
		if !slices.Contains(after, p) {
			if err := db.PurgeTree(ctx, platform.GCP, profile, p); err != nil {
				return err
			}
		}
	}
	return db.Expire(ctx, platform.GCP, profile)
}

// checkProjects verifies that the credentials reach the projects before
// they are selected. Offline nothing can be checked, which is said.
func checkProjects(ctx context.Context, rt *app.Runtime, profile string, projects []string) error {
	if rt.Flags.Offline {
		rt.Infof("note: --offline: access to %s was not checked", strings.Join(projects, ", "))
		return nil
	}
	c, err := openAccount(ctx, rt, profile)
	if err != nil {
		return err
	}
	for _, p := range projects {
		if err := c.inProject(p).checkAccess(ctx); err != nil {
			return err
		}
	}
	return nil
}

// visibleProjectOptions are the projects the credentials list, as options
// labelled with what the selection says about them. keep filters them.
func visibleProjectOptions(ctx context.Context, rt *app.Runtime, profile string, keep func(projectRow) bool) ([]prompt.Option, error) {
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	c, err := openAccount(ctx, rt, profile)
	if err != nil {
		return nil, err
	}
	rows, err := projectRows(ctx, c)
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, r := range rows {
		if keep != nil && !keep(r) {
			continue
		}
		mark := ""
		switch {
		case r.Default:
			mark = "default"
		case r.Selected:
			mark = "selected"
		}
		opts = append(opts, prompt.Option{Label: prompt.Cells(r.ProjectID, r.Name, mark), Value: r.ProjectID})
	}
	return opts, nil
}

func newProjectUseCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use <project-id>",
		Short: "Make a project the default project of the gcp account",
		Long: `Make <project-id> the default project of the profile's gcp account: the one
new resources are created in and commands work on when nothing else names a
project. A project that is not selected yet is added to the selection. The
credentials must reach it (not checked with --offline). On a terminal,
without <project-id> the visible projects are offered.

Only the local configuration changes; the cached inventory of the account is
synced again on its next use.`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			ids, err := projectArgs(args)
			if err != nil {
				return err
			}
			cur, err := currentOf(rt, profile)
			if err != nil {
				return err
			}
			var id string
			if len(ids) > 0 {
				id = ids[0]
			} else {
				opts, err := visibleProjectOptions(ctx, rt, profile, nil)
				if err != nil {
					return err
				}
				if id, err = rt.Choose(app.Choice{Title: "Default project", Options: opts, Default: cur.Project, Arg: "<project-id>", What: "project visible to gcp/" + profile}); err != nil {
					return err
				}
			}
			if id == cur.Project {
				rt.Infof("project %s is already the default project of gcp/%s", id, profile)
				return renderCurrent(rt, cur)
			}
			if !slices.Contains(cur.Projects, id) {
				if err := checkProjects(ctx, rt, profile, []string{id}); err != nil {
					return err
				}
			}
			if err := saveSelection(ctx, rt, profile, id, append([]string{id}, cur.Projects...)); err != nil {
				return err
			}
			rt.Infof("project %s is now the default project of gcp/%s", id, profile)
			if cur, err = currentOf(rt, profile); err != nil {
				return err
			}
			return renderCurrent(rt, cur)
		},
	}
	app.MarkNoDryRun(cmd)
	return cmd
}

func newProjectAddCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <project-id>...",
		Short: "Add projects to the selection of the gcp account",
		Long: `Add projects to the selection of the profile's gcp account, without a new
login: the inventory, name lookups, domain routing and certificate deployment
cover them from then on. The default project stays. The credentials must
reach each project (not checked with --offline). A project that is selected
already is left as it is. On a terminal, without <project-id> the visible
projects that are not selected are offered (tick several).

Only the local configuration changes; the cached inventory of the account is
synced again on its next use.`,
		Args: app.RangeArgsOrInteractive(rt, 1, 100, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			ids, err := projectArgs(args)
			if err != nil {
				return err
			}
			cur, err := currentOf(rt, profile)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				opts, err := visibleProjectOptions(ctx, rt, profile, func(r projectRow) bool { return !r.Selected })
				if err != nil {
					return err
				}
				if ids, err = rt.ChooseMany(app.Choice{Title: "Projects to add", Options: opts, Arg: "<project-id>", What: "visible project that is not selected yet"}); err != nil {
					return err
				}
			}
			var add []string
			for _, id := range ids {
				if !slices.Contains(cur.Projects, id) {
					add = append(add, id)
				}
			}
			if len(add) == 0 {
				return app.NothingToDof("%s: already selected for gcp/%s", strings.Join(ids, ", "), profile)
			}
			if err := checkProjects(ctx, rt, profile, add); err != nil {
				return err
			}
			if err := saveSelection(ctx, rt, profile, cur.Project, append(cur.Projects, add...)); err != nil {
				return err
			}
			rt.Infof("added %s to the projects of gcp/%s", strings.Join(add, ", "), profile)
			if cur, err = currentOf(rt, profile); err != nil {
				return err
			}
			return renderCurrent(rt, cur)
		},
	}
	app.MarkNoDryRun(cmd)
	return cmd
}

func newProjectRemoveCmd(rt *app.Runtime) *cobra.Command {
	var newDefault string
	cmd := &cobra.Command{
		Use:   "remove <project-id>...",
		Short: "Take projects out of the selection of the gcp account",
		Long: `Take projects out of the selection of the profile's gcp account. Nothing in
Google Cloud changes: the projects are no longer synced or searched, and what
the inventory cached of them is dropped (stored instance passwords stay). A
project that is not selected is not found (exit code 4).

The default project can be removed only together with --default <id>, which
names the selected project that becomes the default (on a terminal it is
asked); without it this is a usage error (exit code 2), as is removing every
project (log the account out with "polyctl auth logout gcp" instead). On a
terminal, without <project-id> the selected projects are offered.

No confirmation is asked: only the local configuration and a cache that the
next sync rebuilds change. Works with --offline.`,
		Args: app.RangeArgsOrInteractive(rt, 1, 100, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			profile, err := rt.ProfileFor(platform.GCP)
			if err != nil {
				return err
			}
			ids, err := projectArgs(args)
			if err != nil {
				return err
			}
			cur, err := currentOf(rt, profile)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				var opts []prompt.Option
				for _, p := range cur.Projects {
					mark := ""
					if p == cur.Project {
						mark = "default"
					}
					opts = append(opts, prompt.Option{Label: prompt.Cells(p, mark), Value: p})
				}
				if ids, err = rt.ChooseMany(app.Choice{Title: "Projects to remove", Options: opts, Arg: "<project-id>", What: "selected project"}); err != nil {
					return err
				}
			}
			var missing []string
			for _, id := range ids {
				if !slices.Contains(cur.Projects, id) {
					missing = append(missing, id)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				return fmt.Errorf("%w: %s is not selected for gcp/%s (selected: %s)", platform.ErrNotFound, strings.Join(missing, ", "), profile, strings.Join(cur.Projects, ", "))
			}
			var rest []string
			for _, p := range cur.Projects {
				if !slices.Contains(ids, p) {
					rest = append(rest, p)
				}
			}
			if len(rest) == 0 {
				return app.UsageErrf("this would remove every project of gcp/%s; an account needs one (to drop the account: polyctl auth logout gcp --profile %s)", profile, profile)
			}
			def := cur.Project
			newDefault = strings.TrimSpace(newDefault)
			switch {
			case newDefault != "":
				if !slices.Contains(rest, newDefault) {
					return app.UsageErrf("--default %s: not one of the projects that stay selected (%s)", newDefault, strings.Join(rest, ", "))
				}
				def = newDefault
			case !slices.Contains(rest, def):
				if len(rest) == 1 && rt.Interactive() {
					def = rest[0]
					break
				}
				var opts []prompt.Option
				for _, p := range rest {
					opts = append(opts, prompt.Option{Label: p, Value: p})
				}
				if def, err = rt.Choose(app.Choice{Title: "New default project", Options: opts, Arg: "--default", Missing: func() error {
					return app.UsageErrf("%s is the default project of gcp/%s: pass --default <id> to name the one that replaces it (one of: %s)", cur.Project, profile, strings.Join(rest, ", "))
				}}); err != nil {
					return err
				}
			}
			if err := saveSelection(ctx, rt, profile, def, rest); err != nil {
				return err
			}
			rt.Infof("removed %s from the projects of gcp/%s", strings.Join(ids, ", "), profile)
			if def != cur.Project {
				rt.Infof("project %s is now the default project of gcp/%s", def, profile)
			}
			if cur, err = currentOf(rt, profile); err != nil {
				return err
			}
			return renderCurrent(rt, cur)
		},
	}
	cmd.Flags().StringVar(&newDefault, "default", "", "the selected project that becomes the default, when the default project is removed")
	app.MarkNoDryRun(cmd)
	return cmd
}
