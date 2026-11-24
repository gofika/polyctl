package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func newFindCmd(rt *app.Runtime) *cobra.Command {
	var platforms []string
	var detail bool
	cmd := &cobra.Command{
		Use:   "find <ip|dns-name>",
		Short: "Find the resources that hold an IP address or DNS name, in the local inventory",
		Long: `Find the instances, load balancers, elastic / static IP addresses and database
endpoints that hold an IP address (IPv4 or IPv6) or a DNS name, across every
account of every profile (narrow with --profile and --platform).

find reads the local inventory only and never syncs on its own, even when it is
stale or finds nothing: --refresh syncs the instance, load_balancer, eip and
db_instance sets of the selected accounts first. --detail looks up the subnet
of each matched instance live. Several matches are not an error: the same
private address commonly exists in several networks, and all of them are
listed with their network.`,
		Example: `  polyctl find 203.0.113.10
  polyctl find 10.0.1.100 --platform gcp,aws --detail
  polyctl find mydb.abc123.ap-east-1.rds.amazonaws.com -o json
  polyctl find 203.0.113.10 --refresh`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline && detail {
				return usageErr("--detail and --offline are mutually exclusive: --detail looks the subnets up on the platforms")
			}
			if len(args) == 0 {
				// An address or a name cannot be listed: asked, and checked
				// as it is typed.
				v, err := rt.AskInput("<ip|dns-name>", "IP address or DNS name to find", "", func(s string) error {
					_, err := platform.ParseFindQuery(strings.TrimSpace(s))
					if err != nil {
						return errors.New(strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": "))
					}
					return nil
				})
				if err != nil {
					return err
				}
				args = []string{v}
			}
			q, err := platform.ParseFindQuery(args[0])
			if err != nil {
				return usageErr("%v", strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": "))
			}
			want := map[platform.ID]bool{}
			for _, p := range platforms {
				id, err := platform.Parse(p)
				if err != nil {
					return usageErr("%v", err)
				}
				want[id] = true
			}
			res, err := rt.Find(cmd.Context(), app.FindRequest{Query: q, Platforms: want, Refresh: rt.Flags.Refresh, Detail: detail})
			if err != nil {
				return err
			}
			wide := detail || rt.Flags.Verbose
			if err := rt.Render(res, func() output.Grid { return findGrid(res, detail, wide) }); err != nil {
				return err
			}
			return findOutcome(rt, res)
		},
	}
	cmd.Flags().StringSliceVar(&platforms, "platform", nil, "only search these platforms (comma-separated)")
	cmd.Flags().BoolVar(&detail, "detail", false, "look up the subnet of each matched instance on its platform (uses the network)")
	_ = cmd.RegisterFlagCompletionFunc("platform", completePlatformList)
	return cmd
}

// findGrid is the table of find: one row per match, with the console link
// (and the subnet details of --detail) when wide.
func findGrid(res *app.FindResult, detail, wide bool) output.Grid {
	g := output.Grid{Headers: []string{"PLATFORM", "PROFILE", "TYPE", "NAME", "REGION/ZONE", "INTERNAL", "EXTERNAL", "STATE", "NETWORK"}}
	if detail {
		g.Headers = append(g.Headers, "SUBNET", "CIDR", "GATEWAY")
	}
	if wide {
		g.Headers = append(g.Headers, "URL")
	}
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	for _, m := range res.Matches {
		where := m.Zone
		if where == "" {
			where = m.Region
		}
		name := m.Name
		if name == "" {
			name = m.ID
		}
		row := []string{string(m.Platform), m.Profile, string(m.Type), name, dash(where),
			dash(strings.Join(m.InternalIPs, ",")), dash(strings.Join(m.ExternalIPs, ",")), dash(m.State), dash(m.Network)}
		if detail {
			var subnet, cidr, gw string
			if d := m.Detail; d != nil {
				subnet, cidr, gw = d.Subnet, d.SubnetCIDR, d.SubnetGateway
			}
			row = append(row, dash(subnet), dash(cidr), dash(gw))
		}
		if wide {
			row = append(row, dash(m.URL))
		}
		g.Rows = append(g.Rows, row)
	}
	return g
}

// findSyncTypes is the --type list of the sync that find suggests.
func findSyncTypes() string {
	names := make([]string, 0, len(app.FindTypes))
	for _, t := range app.FindTypes {
		names = append(names, string(t))
	}
	return strings.Join(names, ",")
}

// findOutcome writes the status line of a find to stderr and returns its
// exit status: nil with matches, not found without (or a general failure
// when --refresh could sync no account).
func findOutcome(rt *app.Runtime, res *app.FindResult) error {
	now := time.Now()
	synced := "never synced"
	if res.SyncedAt != nil {
		synced = "synced " + app.Ago(*res.SyncedAt, now)
	}
	if len(res.Matches) > 0 {
		src := "local inventory, "
		if !res.Cached {
			src = "after --refresh, "
		}
		rt.Infof("matched %d resource(s) (%s%s)", len(res.Matches), src, synced)
		if res.Stale && res.Cached {
			rt.Infof("the local inventory may be stale (%s); rerun with --refresh to sync it first", synced)
		}
		return nil
	}
	accounts := fmt.Sprintf("%d account(s)", res.Accounts)
	switch {
	case res.Accounts == 0:
		return fmt.Errorf("%w: no selected account holds resources find can search (see `polyctl auth list`)", platform.ErrNotFound)
	case res.AllFailed:
		return fmt.Errorf("no resource found for %s: every selected account failed to sync (%d error(s) above)", res.Query, len(res.Errors))
	case res.NeverSynced:
		return fmt.Errorf("%w: no resource found for %s: the inventory has never been synced (%s); run: polyctl sync (or: polyctl find %s --refresh)",
			inventory.ErrNeverSynced, res.Query, accounts, res.Query)
	case !res.Cached:
		return fmt.Errorf("%w: no resource found for %s (%s, %s)", platform.ErrNotFound, res.Query, accounts, synced)
	}
	return fmt.Errorf("%w", &findNotFound{query: res.Query, accounts: accounts, synced: synced})
}

// findNotFound is the message of a find without matches in the inventory,
// with the commands that sync it.
type findNotFound struct{ query, accounts, synced string }

func (e *findNotFound) Error() string {
	return fmt.Sprintf("no resource found for %s in the local inventory (%s, last %s).\n"+
		"The inventory may be stale. To re-sync from the platforms and search again:\n"+
		"  polyctl find %s --refresh\n"+
		"  polyctl sync --type %s      # sync only, no search",
		e.query, e.accounts, e.synced, e.query, findSyncTypes())
}

func (e *findNotFound) Is(target error) bool { return errors.Is(platform.ErrNotFound, target) }
