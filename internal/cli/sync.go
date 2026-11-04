package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func newSyncCmd(rt *app.Runtime) *cobra.Command {
	var platforms, types []string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Fetch resources from the platforms into the local inventory",
		Long: `Fetch resources of every profile (or those selected with --platform /
--profile) and replace them in the local inventory. Resource types default to
everything the platform supports; narrow with --type.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			want := map[platform.ID]bool{}
			for _, p := range platforms {
				id, err := platform.Parse(p)
				if err != nil {
					return usageErr("%v", err)
				}
				want[id] = true
			}
			var rts []platform.ResourceType
			for _, t := range types {
				rt, err := platform.ParseResourceType(t)
				if err != nil {
					return usageErr("%v", err)
				}
				rts = append(rts, rt)
			}
			names := cfg.ProfileNames()
			if rt.Flags.Profile != "" {
				if _, err := cfg.Profile(rt.Flags.Profile); err != nil {
					return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
				}
				names = []string{rt.Flags.Profile}
			}
			var reports []app.SyncReport
			var firstErr error
			for _, n := range names {
				if len(want) > 0 && !want[cfg.Profiles[n].Platform] {
					continue
				}
				reps, err := rt.SyncProfile(cmd.Context(), n, rts)
				reports = append(reports, reps...)
				if err != nil {
					rt.Infof("warning: %s: %v", n, err)
					if firstErr == nil {
						firstErr = err
					}
				}
			}
			if len(reports) == 0 && firstErr == nil {
				return fmt.Errorf("nothing to sync (no matching profiles)")
			}
			return renderSyncReports(rt, reports, firstErr)
		},
	}
	cmd.Flags().StringSliceVar(&platforms, "platform", nil, "only sync these platforms (comma-separated)")
	cmd.Flags().StringSliceVar(&types, "type", nil, "only sync these resource types: domain, zone, dns_record, instance")
	_ = cmd.RegisterFlagCompletionFunc("platform", completePlatforms)
	_ = cmd.RegisterFlagCompletionFunc("type", cobra.FixedCompletions([]string{"domain", "zone", "dns_record", "instance"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

// renderSyncReports prints the reports and returns firstErr, or an error
// when any report failed, so a partially failed sync never exits 0.
func renderSyncReports(rt *app.Runtime, reports []app.SyncReport, firstErr error) error {
	err := rt.Render(reports, func() output.Grid {
		g := output.Grid{Headers: []string{"PLATFORM", "PROFILE", "TYPE", "COUNT", "STATUS"}}
		for _, r := range reports {
			st := "ok"
			if r.Error != "" {
				st = "FAILED: " + r.Error
			} else if r.Duration > 0 {
				st = "ok (" + r.Duration.Round(10e6).String() + ")"
			}
			g.Rows = append(g.Rows, []string{string(r.Platform), r.Profile, string(r.Type), fmt.Sprint(r.Count), st})
		}
		return g
	})
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range reports {
		if r.Error != "" {
			failed++
		}
	}
	if firstErr == nil && failed > 0 {
		firstErr = fmt.Errorf("%d resource set(s) failed to sync", failed)
	}
	return firstErr
}

func newInventoryCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Inspect the local resource inventory",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "stats",
		Short: "Show counts and freshness per profile and resource type",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := rt.DB()
			if err != nil {
				return err
			}
			stats, err := db.Stats(cmd.Context())
			if err != nil {
				return err
			}
			return rt.Render(stats, func() output.Grid {
				g := output.Grid{Headers: []string{"PLATFORM", "PROFILE", "TYPE", "COUNT", "SYNCED", "EXPIRES"}, Empty: "inventory is empty; run `polyctl sync`"}
				for _, s := range stats {
					g.Rows = append(g.Rows, []string{string(s.Platform), s.Profile, string(s.Type), fmt.Sprint(s.Count), s.SyncedAt.Format("2006-01-02 15:04"), s.ExpiresAt.Format("2006-01-02 15:04")})
				}
				return g
			})
		},
	})
	var typ, plat, name string
	list := &cobra.Command{
		Use:   "list",
		Short: "List cached resources",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := rt.DB()
			if err != nil {
				return err
			}
			q := inventory.Query{Profile: rt.Flags.Profile, Name: name}
			if typ != "" {
				t, err := platform.ParseResourceType(typ)
				if err != nil {
					return usageErr("%v", err)
				}
				q.Type = t
			}
			if plat != "" {
				id, err := platform.Parse(plat)
				if err != nil {
					return usageErr("%v", err)
				}
				q.Platform = id
			}
			rows, err := db.List(cmd.Context(), q)
			if err != nil {
				return err
			}
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"PLATFORM", "PROFILE", "TYPE", "NAME", "ID", "UPDATED"}, Empty: "no cached resources"}
				for _, r := range rows {
					g.Rows = append(g.Rows, []string{string(r.Platform), r.Profile, string(r.Type), r.Name, r.ID, r.UpdatedAt.Format("2006-01-02 15:04")})
				}
				return g
			})
		},
	}
	list.Flags().StringVar(&typ, "type", "", "resource type filter")
	list.Flags().StringVar(&plat, "platform", "", "platform filter")
	list.Flags().StringVar(&name, "name", "", "exact name filter")
	cmd.AddCommand(list)
	cmd.AddCommand(&cobra.Command{
		Use:   "path",
		Short: "Print the inventory database path",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := rt.InventoryPath()
			if err != nil {
				return err
			}
			fmt.Fprintln(rt.Stdout, path)
			return nil
		},
	})
	return cmd
}
