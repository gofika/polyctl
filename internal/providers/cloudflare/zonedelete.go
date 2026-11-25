package cloudflare

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func newZoneDeleteCmd(rt *app.Runtime) *cobra.Command {
	var downgrade bool
	cmd := &cobra.Command{
		Use:   "delete <zone>",
		Short: "Delete a zone and all of its DNS records",
		Long: `Delete the zone <zone> (a name or a zone id) with all of its DNS records.
The zone is found among the selected accounts of the Cloudflare logins
(narrowed by --profile and --account; a name several accounts hold a zone of
is ambiguous, exit code 5: --account, --profile or the zone id choose) and
read live first. The interactive flow shows it with its plan, status and number of
DNS records and asks for a confirmation (default no); the non-interactive
flow needs --yes (exit code 2 without it, before anything is read).

An Enterprise zone has to be moved to the Free plan before it can be
deleted. polyctl does that only with --downgrade-enterprise, which changes
the billing of the zone; without it the command stops (exit code 1) and asks
you to downgrade the zone in the dashboard. A token without billing
permission cannot downgrade (exit code 3, nothing is deleted). When the
downgrade succeeds but the deletion fails, the zone stays on the Free plan:
run the command again.

A zone that no longer exists is not found (exit code 4) and is removed from
the local inventory.`,
		Example: "  polyctl cloudflare zone delete example.com\n  polyctl cloudflare zone delete example.com --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if !rt.DryRun() && len(args) > 0 {
				if err := rt.CanConfirm("delete zone " + args[0]); err != nil {
					return err
				}
			}
			s, err := resolveLiveZone(ctx, rt, app.Arg(args, 0))
			if err != nil {
				return err
			}
			name, id, plan := s.name(), s.z.ID, s.plan()
			records, err := s.c.api.countRecords(ctx, id)
			if err != nil {
				return s.gone(ctx, rt, err)
			}
			count := fmt.Sprint(records)
			if records < 0 {
				count = "unknown"
			}
			enterprise := plan == planEnterprise
			if enterprise && !downgrade {
				return fmt.Errorf("zone %s is on the enterprise plan, which has to be moved to Free before the zone can be deleted: downgrade it to Free in the dashboard and run 'zone delete' again, or pass --downgrade-enterprise to let polyctl do it (this changes the zone's billing)", name)
			}
			res := "zone/" + name
			var changes []platform.Change
			if enterprise {
				changes = append(changes, platform.Change{Resource: res + "/subscription", Action: platform.Updated, Detail: "enterprise -> free"})
			}
			changes = append(changes, platform.Change{Resource: res, Action: platform.Deleted, ID: id, Detail: fmt.Sprintf("plan=%s records=%s", plan, count)})
			if done, err := rt.WouldWrite(s.target(), changes...); done || err != nil {
				return err
			}
			rt.Infof("zone %s (id=%s, plan=%s, status=%s, %s DNS records) via cloudflare/%s", name, id, plan, s.z.Status, count, s.profile)
			rt.Infof("This cannot be undone! The zone and all of its DNS records will be deleted.")
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete zone %s (id=%s, plan=%s, status=%s, %s DNS records)?", name, id, plan, s.z.Status, count), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; zone %s was not deleted", platform.ErrNothingToDo, name)
			}
			var done []platform.Change
			if enterprise {
				if err := s.c.api.downgradeToFree(ctx, id); err != nil {
					if errors.Is(err, platform.ErrUnauthorized) {
						return fmt.Errorf("zone %s is on the enterprise plan; this token has no billing permission to downgrade it. Downgrade the zone to Free in the dashboard, then rerun 'zone delete': %w", name, err)
					}
					return s.gone(ctx, rt, err)
				}
				done = append(done, platform.Change{Resource: res + "/subscription", Action: platform.Updated, Detail: "enterprise -> free"})
			}
			if err := s.c.api.deleteZone(ctx, id); err != nil {
				if zoneGone(err) {
					dropZone(ctx, rt, s.profile, id)
					return fmt.Errorf("%w: zone %s (id %s) is already deleted (removed from the local inventory)", platform.ErrNotFound, name, id)
				}
				if enterprise {
					return fmt.Errorf("zone %s was downgraded to Free but could not be deleted; run 'zone delete' again: %w", name, err)
				}
				return err
			}
			dropZone(ctx, rt, s.profile, id)
			done = append(done, platform.Change{Resource: res, Action: platform.Deleted, ID: id, Detail: "id=" + id})
			rt.Infof("zone %s deleted via cloudflare/%s", name, s.profile)
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: done})
		},
	}
	cmd.Flags().BoolVar(&downgrade, "downgrade-enterprise", false, "move an Enterprise zone to the Free plan before deleting it (changes its billing)")
	return cmd
}
