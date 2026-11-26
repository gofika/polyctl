package gcp

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/api/cloudresourcemanager/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// ---------------------------------------------------------------- project

func newProjectCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Google Cloud projects of the account: the default one, and the ones kept out of every sync",
		Long: `A gcp account works on every project its credentials see: the inventory,
name lookups, domain routing and certificate deployment cover all of them, the
ones created later included. One of them is the default project, where new
resources are created and which a command works on when nothing names a
project: use sets it.

enable manages which projects are enabled: on a terminal, without arguments,
it lists every project the credentials see with the enabled ones ticked, and
what is ticked at the end is enabled and the rest disabled. A disabled project
is kept out of every sync, list and lookup: disable the ones that are
certainly not used. "enable <project-id>..." and "disable <project-id>..." are
the shortcuts that change the projects named, for scripts. A project in which
the Compute Engine or Cloud DNS API is not enabled holds nothing and is
skipped with a note; disabling it stops asking it.

A disabled project can still be named with --project on the gcp dns and gcp
compute commands: it is read live and nothing of it is cached.`,
	}
	cmd.AddCommand(newProjectListCmd(rt), newProjectCurrentCmd(rt), newProjectUseCmd(rt),
		newProjectEnableCmd(rt, "enable", false), newProjectDisableCmd(rt, "disable", false),
		// The names these two had while the account held a selection.
		newProjectEnableCmd(rt, "add", true), newProjectDisableCmd(rt, "remove", true))
	return cmd
}

type projectRow struct {
	ProjectID string `json:"project_id" yaml:"project_id"`
	Name      string `json:"name" yaml:"name"`
	Number    int64  `json:"project_number" yaml:"project_number"`
	State     string `json:"state" yaml:"state"`
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	// Selected is Enabled under the name it had in polyctl 0.4.0.
	// Deprecated: read Enabled.
	Selected bool `json:"selected" yaml:"selected"`
	Default  bool `json:"default" yaml:"default"`
	// hidden marks a project the credentials do not list.
	hidden bool
}

// projectRows lists the active projects visible to the credentials, each
// enabled unless it is disabled. The default project and the disabled
// projects the list does not show (no permission to list them, or deleted
// since) are appended without name and state. Credentials that cannot
// list projects are an error: the account works on its default project
// alone.
func projectRows(ctx context.Context, c *client) ([]projectRow, error) {
	projects, canList, err := c.visibleProjects(ctx)
	if err != nil {
		return nil, err
	}
	def, disabled := c.cov.def, c.cov.disabled
	if !canList {
		return nil, fmt.Errorf("%w: the credentials of %s cannot list projects (%v); the account works on its default project %s alone",
			platform.ErrUnauthorized, c.accountLabel(), c.cov.cannotList, def)
	}
	rows := make([]projectRow, 0, len(projects))
	seen := map[string]bool{}
	add := func(r projectRow) {
		r.Default = r.ProjectID == def
		r.Enabled = r.Default || !slices.Contains(disabled, r.ProjectID)
		r.Selected = r.Enabled
		seen[r.ProjectID] = true
		rows = append(rows, r)
	}
	for _, p := range projects {
		add(projectRow{ProjectID: p.ProjectId, Name: p.Name, Number: p.ProjectNumber, State: p.LifecycleState})
	}
	rest := append([]string{def}, disabled...)
	sort.Strings(rest[1:])
	for _, p := range rest {
		if !seen[p] {
			add(projectRow{ProjectID: p, hidden: true})
		}
	}
	return rows, nil
}

func newProjectListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the active projects visible to the credentials, with the default and the disabled ones marked",
		Long: `List the active projects visible to the profile's credentials. Every one is
enabled (synced, listed and searched) unless it was disabled: ENABLED says
which, and * marks the default project. The default project and the disabled
projects the credentials do not list are shown without name and state.

In JSON and YAML "enabled" says the same; "selected" is a deprecated copy of
it, kept for scripts written for polyctl 0.4.0.`,
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
			enabled := 0
			for _, r := range rows {
				if r.Enabled {
					enabled++
				} else if r.hidden {
					rt.Infof("note: disabled project %s is not visible to the credentials (to forget it: polyctl gcp project enable %s)", r.ProjectID, r.ProjectID)
				}
			}
			rt.Infof("%d project(s) via gcp/%s, %d enabled, %d disabled", len(rows), prof.Name, enabled, len(rows)-enabled)
			return rt.Render(rows, func() output.Grid { return projectGrid(rows) })
		},
	}
}

// projectGrid is the table of project list: * marks the default project.
func projectGrid(rows []projectRow) output.Grid {
	g := output.Grid{Headers: []string{"PROJECT_ID", "NAME", "NUMBER", "STATE", "ENABLED"}, Empty: "no projects"}
	for _, r := range rows {
		marker, enabled, number := "", "no", ""
		if r.Default {
			marker = " *"
		}
		if r.Enabled {
			enabled = "yes"
		}
		if r.Number != 0 {
			number = fmt.Sprint(r.Number)
		}
		g.Rows = append(g.Rows, []string{r.ProjectID + marker, r.Name, number, r.State, enabled})
	}
	return g
}

type currentProject struct {
	Profile string `json:"profile" yaml:"profile"`
	// Project is the default project; Disabled the projects kept out of
	// every sync. The enabled projects are not stored: project list reads
	// them.
	Project  string   `json:"project" yaml:"project"`
	Disabled []string `json:"disabled_projects" yaml:"disabled_projects"`
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
	disabled := disabledProjects(p.Metadata)
	sort.Strings(disabled)
	if disabled == nil {
		disabled = []string{}
	}
	return currentProject{Profile: profile, Project: strings.TrimSpace(p.Metadata[metaProject]), Disabled: disabled, Method: p.Metadata["method"], Account: account}, nil
}

func renderCurrent(rt *app.Runtime, cur currentProject) error {
	return rt.Render(cur, func() output.Grid {
		return output.KV("profile", cur.Profile, "project", cur.Project, "disabled", strings.Join(cur.Disabled, ", "), "method", cur.Method, "account", cur.Account)
	})
}

func newProjectCurrentCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the default project and the disabled projects of the gcp account",
		Long: `Show the default project and the disabled projects of the profile's gcp
account, from the local configuration (nothing is asked of Google Cloud; works
with --offline). The enabled projects are every other project the credentials
see: "polyctl gcp project list" reads them.`,
		Args: cobra.NoArgs,
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

// projectArgs checks the project ids given to use, enable or disable.
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

// saveProjects stores a new default project and new disabled projects for
// the profile's gcp account. What the inventory cached of the projects
// that are disabled now is dropped (instance secrets stay). The cached
// sets of the account are made due when a project was enabled again or
// the default changed, so that the next read syncs what was added; a
// project that was only disabled leaves them as they are, its rows being
// gone.
func saveProjects(ctx context.Context, rt *app.Runtime, profile, def string, disabled []string) error {
	cfg, err := rt.ReloadConfig()
	if err != nil {
		return err
	}
	a, err := cfg.Account(profile, platform.GCP)
	if err != nil {
		return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	if a.Metadata == nil {
		a.Metadata = map[string]string{}
	}
	beforeDef, before := strings.TrimSpace(a.Metadata[metaProject]), disabledProjects(a.Metadata)
	setProjects(a.Metadata, def, disabled)
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
	after := disabledProjects(a.Metadata)
	for _, p := range after {
		if !slices.Contains(before, p) {
			if err := db.PurgeTree(ctx, platform.GCP, profile, p); err != nil {
				return err
			}
		}
	}
	due := beforeDef != def
	for _, p := range before {
		due = due || !slices.Contains(after, p)
	}
	if !due {
		return nil
	}
	return db.Expire(ctx, platform.GCP, profile)
}

// projectDiff tells the projects that def and disabled disable (off) and
// enable again (on) against cur, each sorted.
func projectDiff(cur currentProject, def string, disabled []string) (off, on []string) {
	for _, p := range disabled {
		if p != def && !slices.Contains(cur.Disabled, p) && !slices.Contains(off, p) {
			off = append(off, p)
		}
	}
	for _, p := range cur.Disabled {
		if p == def || !slices.Contains(disabled, p) {
			on = append(on, p)
		}
	}
	sort.Strings(off)
	sort.Strings(on)
	return off, on
}

// finishProjects is the common end of enable and disable: nothing to do
// when def and disabled are what cur holds, the change report with
// --dry-run (nothing is saved, purged or made due), and applyProjects
// otherwise.
func finishProjects(ctx context.Context, rt *app.Runtime, profile string, cur currentProject, def string, disabled []string) error {
	off, on := projectDiff(cur, def, disabled)
	if len(off)+len(on) == 0 && def == cur.Project {
		return app.NothingToDof("the enabled projects and the default project of gcp/%s are unchanged", profile)
	}
	var changes []platform.Change
	for _, p := range off {
		changes = append(changes, app.ResourceChange("project", p, platform.Updated, "disabled"))
	}
	for _, p := range on {
		changes = append(changes, app.ResourceChange("project", p, platform.Updated, "enabled"))
	}
	if def != cur.Project {
		changes = append(changes, app.ResourceChange("project", def, platform.Updated, "default"))
	}
	if done, err := rt.WouldWrite(platform.Target{Platform: platform.GCP, Profile: profile}, changes...); done || err != nil {
		return err
	}
	return applyProjects(ctx, rt, profile, cur, def, disabled)
}

// newDefaultProject tells the default project of an account whose
// disabled projects become disabled: the one it has, unless that is among
// them or --default (newDefault) names another. rest are the projects
// that stay enabled, as far as the credentials tell. A default that is
// disabled is replaced by --default, by the only project left or by the
// answer on a terminal, and is a usage error otherwise, as is disabling
// every project.
func newDefaultProject(rt *app.Runtime, profile string, cur currentProject, disabled, rest []string, newDefault string) (string, error) {
	def := cur.Project
	newDefault = strings.TrimSpace(newDefault)
	gone := slices.Contains(disabled, def)
	needDefault := func() error {
		if len(rest) == 0 {
			return app.UsageErrf("%s is the default project of gcp/%s: pass --default <id> to name the one that replaces it", cur.Project, profile)
		}
		return app.UsageErrf("%s is the default project of gcp/%s: pass --default <id> to name the one that replaces it (one of: %s)", cur.Project, profile, strings.Join(rest, ", "))
	}
	switch {
	case gone && !rt.Flags.Offline && len(rest) == 0:
		// Also the answer for credentials that cannot list projects:
		// their account works on its default alone.
		return "", app.UsageErrf("this would disable every project of gcp/%s; an account needs one (to drop the account: polyctl auth logout gcp --profile %s)", profile, profile)
	case newDefault != "":
		if err := checkProjectID(newDefault); err != nil {
			return "", app.UsageErrf("--default: %v", err)
		}
		// With --offline the enabled projects are not known: any project
		// that is not disabled is taken.
		if slices.Contains(disabled, newDefault) || (!rt.Flags.Offline && !slices.Contains(rest, newDefault)) {
			return "", app.UsageErrf("--default %s: not one of the projects that stay enabled (%s)", newDefault, strings.Join(rest, ", "))
		}
		return newDefault, nil
	case gone && len(rest) == 0:
		return "", needDefault()
	case gone && len(rest) == 1 && rt.Interactive():
		return rest[0], nil
	case gone:
		var opts []prompt.Option
		for _, p := range rest {
			opts = append(opts, prompt.Option{Label: p, Value: p})
		}
		return rt.Choose(app.Choice{Title: "New default project", Options: opts, Arg: "--default", Missing: needDefault})
	}
	return def, nil
}

// pickProjects is enable without arguments on a terminal: one
// list of every project the credentials see, and of the disabled ones
// they do not, in which the enabled ones are ticked. What is ticked at
// the end is enabled and the rest disabled; a default project that was
// unticked is replaced as newDefaultProject says.
func pickProjects(ctx context.Context, rt *app.Runtime, profile string, cur currentProject, newDefault string) error {
	rows, err := visibleRows(ctx, rt, profile)
	if err != nil {
		return err
	}
	var opts []prompt.Option
	var ticked []string
	for _, r := range rows {
		mark := ""
		switch {
		case r.Default:
			mark = "default"
		case r.hidden:
			mark = "not visible"
		}
		opts = append(opts, prompt.Option{Label: prompt.Cells(r.ProjectID, r.Name, mark), Value: r.ProjectID})
		if r.Enabled {
			ticked = append(ticked, r.ProjectID)
		}
	}
	keep, err := rt.ChooseMany(app.Choice{Title: fmt.Sprintf("Enabled projects of gcp/%s (ticked: synced and searched)", profile),
		Options: opts, Selected: ticked, Arg: "<project-id>", What: "project visible to gcp/" + profile})
	if err != nil {
		return err
	}
	// A project the credentials do not list cannot become the default
	// here: ticking it only forgets that it was disabled.
	var disabled, rest []string
	for _, r := range rows {
		switch {
		case !slices.Contains(keep, r.ProjectID):
			disabled = append(disabled, r.ProjectID)
		case !r.hidden || r.Default:
			rest = append(rest, r.ProjectID)
		}
	}
	sort.Strings(rest)
	def, err := newDefaultProject(rt, profile, cur, disabled, rest, newDefault)
	if err != nil {
		return err
	}
	return finishProjects(ctx, rt, profile, cur, def, disabled)
}

// applyProjects stores the default project and the disabled projects a
// command arrived at, says what changed against cur and prints the
// account as project current does.
func applyProjects(ctx context.Context, rt *app.Runtime, profile string, cur currentProject, def string, disabled []string) error {
	off, on := projectDiff(cur, def, disabled)
	if err := saveProjects(ctx, rt, profile, def, disabled); err != nil {
		return err
	}
	if len(off) > 0 {
		rt.Infof("disabled %s for gcp/%s", strings.Join(off, ", "), profile)
	}
	if len(on) > 0 {
		rt.Infof("enabled %s for gcp/%s", strings.Join(on, ", "), profile)
	}
	if def != cur.Project {
		rt.Infof("project %s is now the default project of gcp/%s", def, profile)
	}
	cur, err := currentOf(rt, profile)
	if err != nil {
		return err
	}
	return renderCurrent(rt, cur)
}

// visibleRows reads the project rows of the profile's account for a
// command that needs the live list (a pick, a check of the ids given).
func visibleRows(ctx context.Context, rt *app.Runtime, profile string) ([]projectRow, error) {
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	c, err := openAccount(ctx, rt, profile)
	if err != nil {
		return nil, err
	}
	return projectRows(ctx, c)
}

// projectOptions are project rows as the options of a pick, labelled with
// the id, the name and what the account says about the project.
func projectOptions(rows []projectRow) []prompt.Option {
	var opts []prompt.Option
	for _, r := range rows {
		mark := ""
		switch {
		case r.Default:
			mark = "default"
		case !r.Enabled:
			mark = "disabled"
		}
		opts = append(opts, prompt.Option{Label: prompt.Cells(r.ProjectID, r.Name, mark), Value: r.ProjectID})
	}
	return opts
}

func newProjectUseCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use <project-id>",
		Short: "Make a project the default project of the gcp account",
		Long: `Make <project-id> the default project of the profile's gcp account: the one
new resources are created in and commands work on when nothing else names a
project. A disabled project that becomes the default is enabled again. The
credentials must reach the project (not checked with --offline). On a
terminal, without <project-id> the visible projects are offered.

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
				rows, err := visibleRows(ctx, rt, profile)
				if err != nil {
					return err
				}
				if id, err = rt.Choose(app.Choice{Title: "Default project", Options: projectOptions(rows), Default: cur.Project, Arg: "<project-id>", What: "project visible to gcp/" + profile}); err != nil {
					return err
				}
			}
			if id == cur.Project {
				rt.Infof("project %s is already the default project of gcp/%s", id, profile)
				return renderCurrent(rt, cur)
			}
			if rt.Flags.Offline {
				rt.Infof("note: --offline: access to %s was not checked", id)
			} else {
				c, err := openAccount(ctx, rt, profile)
				if err != nil {
					return err
				}
				if err := c.inProject(id).checkAccess(ctx); err != nil {
					return err
				}
			}
			var disabled []string
			for _, p := range cur.Disabled {
				if p != id {
					disabled = append(disabled, p)
				}
			}
			if len(disabled) != len(cur.Disabled) {
				rt.Infof("project %s was disabled and is enabled again", id)
			}
			return applyProjects(ctx, rt, profile, currentProject{Profile: profile, Project: cur.Project, Disabled: disabled}, id, disabled)
		},
	}
	app.MarkNoDryRun(cmd)
	return cmd
}

// formerName says, in the help of a hidden command, which command it is
// the former name of.
func formerName(cmd *cobra.Command, now string) {
	if cmd.Hidden {
		cmd.Long = fmt.Sprintf("The name \"polyctl gcp project %s\" had in polyctl 0.4.0; it does the same.\n\n", now) + cmd.Long
	}
}

// newProjectEnableCmd builds enable, and add, the name it had in polyctl
// 0.4.0, kept hidden for the scripts written then.
func newProjectEnableCmd(rt *app.Runtime, name string, hidden bool) *cobra.Command {
	var newDefault string
	cmd := &cobra.Command{
		Use:    name + " <project-id>...",
		Hidden: hidden,
		Short:  "Choose which projects of the gcp account are enabled, or enable the ones named",
		Long: `Manage which projects of the profile's gcp account are enabled. An enabled
project is covered by the inventory, name lookups, domain routing and
certificate deployment; a disabled one is kept out of every sync, list and
lookup. Every project the credentials see is enabled unless it was disabled,
the ones created later included.

On a terminal, without <project-id> every project the credentials see is
listed with the enabled ones ticked: what is ticked at the end is enabled, the
rest is disabled. A default project that was unticked is replaced by --default
<id>, or by the answer to a question when it is left out. The list needs
Google Cloud (not with --offline). Off a terminal the project ids are required
(exit code 2).

With <project-id>... the projects named are enabled again, and the others are
left as they are; "polyctl gcp project disable <project-id>..." is the
opposite shortcut.

A project that is enabled already is left as it is (exit code 0, nothing is
written). One that is neither disabled nor visible to the credentials is not
found (exit code 4): name it with --project, or make it the default project
with "polyctl gcp project use". A disabled project that is no longer visible
is forgotten.

Only the local configuration changes; the cached inventory of the account is
synced again on its next use. --dry-run reports what would change and writes
nothing. Works with --offline for projects that are disabled.`,
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
				return pickProjects(ctx, rt, profile, cur, newDefault)
			}
			var on, unknown []string
			for _, id := range ids {
				switch {
				case slices.Contains(cur.Disabled, id):
					on = append(on, id)
				case id != cur.Project:
					unknown = append(unknown, id)
				}
			}
			// Only an id that is not disabled needs the list: is it enabled
			// already, or not a project of the account at all?
			if len(unknown) > 0 {
				if rt.Flags.Offline {
					rt.Infof("note: --offline: whether the credentials see %s was not checked", strings.Join(unknown, ", "))
				} else {
					c, err := openAccount(ctx, rt, profile)
					if err != nil {
						return err
					}
					visible, _, err := c.visibleProjects(ctx)
					if err != nil {
						return err
					}
					for _, id := range unknown {
						if !slices.ContainsFunc(visible, func(p *cloudresourcemanager.Project) bool { return p.ProjectId == id }) {
							return fmt.Errorf("%w: project %s is not visible to the credentials of gcp/%s: nothing to enable (name it with --project, or make it the default: polyctl gcp project use %s)", platform.ErrNotFound, id, profile, id)
						}
					}
				}
			}
			if len(on) == 0 {
				return app.NothingToDof("%s: already enabled for gcp/%s", strings.Join(ids, ", "), profile)
			}
			var disabled []string
			for _, p := range cur.Disabled {
				if !slices.Contains(on, p) {
					disabled = append(disabled, p)
				}
			}
			return finishProjects(ctx, rt, profile, cur, cur.Project, disabled)
		},
	}
	cmd.Flags().StringVar(&newDefault, "default", "", "the enabled project that becomes the default, when the default project is unticked in the list (enabling the projects named never needs it)")
	formerName(cmd, "enable")
	return cmd
}

// disableArgs are the arguments of disable: one project at least, on a
// terminal too, since the list in which the enabled projects are ticked
// belongs to enable. remove, the hidden name disable had in polyctl 0.4.0,
// asked which projects to remove when none was named on a terminal: it
// still asks, with the list of enable.
func disableArgs(rt *app.Runtime, name string) cobra.PositionalArgs {
	missing := func(*cobra.Command, []string) error {
		return app.UsageErrf(`name the projects to disable, or choose from the list with "polyctl gcp project enable"`)
	}
	if name == "remove" {
		return app.RangeArgsOrInteractive(rt, 1, 100, missing)
	}
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return missing(cmd, args)
		}
		return cobra.RangeArgs(1, 100)(cmd, args)
	}
}

// newProjectDisableCmd builds disable, and remove, the name it had in
// polyctl 0.4.0, kept hidden for the scripts written then.
func newProjectDisableCmd(rt *app.Runtime, name string, hidden bool) *cobra.Command {
	var newDefault string
	cmd := &cobra.Command{
		Use:    name + " <project-id>...",
		Hidden: hidden,
		Short:  "Disable the projects named: keep them out of every sync, list and lookup",
		Long: `Disable the projects named of the profile's gcp account: the ones that are
certainly not used. Nothing in Google Cloud changes: the projects are no longer synced,
listed or searched, and what the inventory cached of them is dropped (stored
instance passwords stay). "polyctl gcp project enable" takes them back, and
--project still names one for a single call.

A project that is disabled already is left as it is (exit code 0, nothing is
written). One the credentials do not see is not found (exit code 4).

The default project can be disabled only together with --default <id>, which
names the enabled project that becomes the default (on a terminal it is
asked); without it this is a usage error (exit code 2), as is disabling every
project (log the account out with "polyctl auth logout gcp" instead).

At least one <project-id> is required (exit code 2 without one, on a terminal
too): to choose from a list of the projects, with the enabled ones ticked, run
"polyctl gcp project enable" without arguments.

No confirmation is asked: only the local configuration and a cache that the
next sync rebuilds change. --dry-run reports what would change and writes
nothing. With --offline the projects are not checked against what the
credentials see.`,
		Args: disableArgs(rt, name),
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
			// Only remove gets here without a project (see disableArgs).
			if len(ids) == 0 {
				return pickProjects(ctx, rt, profile, cur, newDefault)
			}
			// enabled are the projects that are enabled now, when the
			// credentials can tell (listed): the candidates of a new
			// default.
			var enabled []string
			listed := false
			switch {
			case rt.Flags.Offline:
				rt.Infof("note: --offline: whether the credentials see %s was not checked", strings.Join(ids, ", "))
			default:
				c, err := openAccount(ctx, rt, profile)
				if err != nil {
					return err
				}
				var visible []*cloudresourcemanager.Project
				if visible, listed, err = c.visibleProjects(ctx); err != nil {
					return err
				}
				if enabled, err = c.enabledProjects(ctx); err != nil {
					return err
				}
				if !listed {
					rt.Infof("note: the credentials of gcp/%s cannot list projects: whether they see %s was not checked", profile, strings.Join(ids, ", "))
				}
				for _, id := range ids {
					known := id == cur.Project || slices.Contains(cur.Disabled, id) ||
						slices.ContainsFunc(visible, func(p *cloudresourcemanager.Project) bool { return p.ProjectId == id })
					if listed && !known {
						return fmt.Errorf("%w: project %s is not visible to the credentials of gcp/%s", platform.ErrNotFound, id, profile)
					}
				}
			}
			disabled := append([]string(nil), cur.Disabled...)
			var off []string
			for _, id := range ids {
				if !slices.Contains(disabled, id) {
					off = append(off, id)
					disabled = append(disabled, id)
				}
			}
			if len(off) == 0 {
				return app.NothingToDof("%s: already disabled for gcp/%s", strings.Join(ids, ", "), profile)
			}
			// rest are the projects that stay enabled, as far as the
			// credentials tell.
			var rest []string
			for _, p := range enabled {
				if !slices.Contains(disabled, p) {
					rest = append(rest, p)
				}
			}
			sort.Strings(rest)
			def, err := newDefaultProject(rt, profile, cur, disabled, rest, newDefault)
			if err != nil {
				return err
			}
			return finishProjects(ctx, rt, profile, cur, def, disabled)
		},
	}
	cmd.Flags().StringVar(&newDefault, "default", "", "the enabled project that becomes the default, when the default project is disabled")
	formerName(cmd, "disable")
	if cmd.Hidden {
		cmd.Long += `

On a terminal, without <project-id>, this former name still opens the list of
"polyctl gcp project enable".`
	}
	return cmd
}
