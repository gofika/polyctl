package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// defaultFoundationTimeout bounds the wait for the nameservers of a zone to
// follow a Foundation DNS switch.
const defaultFoundationTimeout = time.Minute

// foundationPollInterval is the pause between two reads of the nameservers.
var foundationPollInterval = 5 * time.Second

// settingRow is the json / yaml shape of one setting.
type settingRow struct {
	ID         string `json:"id" yaml:"id"`
	Value      any    `json:"value" yaml:"value"`
	Editable   bool   `json:"editable" yaml:"editable"`
	ModifiedOn string `json:"modified_on" yaml:"modified_on"`
	Zone       string `json:"zone" yaml:"zone"`
}

func settingRows(zone string, settings []zoneSetting) []settingRow {
	out := make([]settingRow, 0, len(settings))
	for _, s := range settings {
		out = append(out, settingRow{ID: s.ID, Value: s.Value, Editable: s.Editable, ModifiedOn: s.ModifiedOn, Zone: zone})
	}
	return out
}

func settingGrid(rows []settingRow) output.Grid {
	g := output.Grid{Headers: []string{"SETTING", "VALUE", "EDITABLE", "MODIFIED_ON"}, Empty: "no settings"}
	for _, r := range rows {
		mod := r.ModifiedOn
		if mod == "" {
			mod = "-"
		}
		g.Rows = append(g.Rows, []string{r.ID, settingText(r.Value), fmt.Sprint(r.Editable), mod})
	}
	return g
}

// settingName normalizes a <setting> argument.
func settingName(arg string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(arg))
	if name == "" || strings.ContainsAny(name, "/?# ") {
		return "", app.UsageErrf("%q is not a zone setting name (such as ssl, always_use_https, 0rtt)", arg)
	}
	return name, nil
}

func newZoneSettingCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setting",
		Short: "Read and write zone settings (ssl, always_use_https, 0rtt, argo_smart_routing, foundation_dns, ...)",
		Long: `Read and write the settings of a zone by their Cloudflare id (ssl,
always_use_https, 0rtt, min_tls_version, http3, ...). Two names address
endpoints of their own: argo_smart_routing (Argo Smart Routing, on/off) and
foundation_dns (Foundation DNS, true/false). Setting names are not checked
by polyctl: an unknown one is not found (exit code 4).`,
	}
	cmd.AddCommand(newZoneSettingGetCmd(rt), newZoneSettingSetCmd(rt), newZoneSettingListCmd(rt))
	return cmd
}

func newZoneSettingListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:               "list <zone>",
		Short:             "List the settings of a zone (rum, Argo and Foundation DNS are read with `setting get`)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := resolveLiveZone(ctx, rt, args[0])
			if err != nil {
				return err
			}
			settings, err := s.c.api.listSettings(ctx, s.z.ID)
			if err != nil {
				return s.gone(ctx, rt, err)
			}
			sort.SliceStable(settings, func(i, j int) bool { return settings[i].ID < settings[j].ID })
			rows := settingRows(s.name(), settings)
			return rt.Render(rows, func() output.Grid { return settingGrid(rows) })
		},
	}
}

func newZoneSettingGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:               "get <zone> <setting>",
		Short:             "Show one setting of a zone",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name, err := settingName(args[1])
			if err != nil {
				return err
			}
			s, err := resolveLiveZone(ctx, rt, args[0])
			if err != nil {
				return err
			}
			cur, err := s.c.api.readSetting(ctx, s.z.ID, name)
			if err != nil {
				return s.gone(ctx, rt, err)
			}
			row := settingRows(s.name(), []zoneSetting{*cur})[0]
			return rt.Render(row, func() output.Grid { return settingGrid([]settingRow{row}) })
		},
	}
}

func newZoneSettingSetCmd(rt *app.Runtime) *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "set <zone> <setting> <value>",
		Short: "Set one setting of a zone (unchanged when it already has the value)",
		Long: `Set the setting <setting> of <zone> to <value>. The setting is read first:
when it already has the value nothing is written and it is reported as
unchanged. Boolean settings take on or off (true and false are accepted and
written as on / off); argo_smart_routing takes on or off, foundation_dns
true or false (on / off are accepted). Other values are passed to the API
as given (a number or a JSON object when the setting holds one), and the
API judges them: an invalid value fails (exit code 1), a setting the plan
cannot change is not supported (exit code 7).

Switching foundation_dns changes the nameservers of the zone: the command
waits (up to --timeout) until the zone reports the new ones and prints them;
set them at the registrar (polyctl domain ns set).`,
		Example: `  polyctl cloudflare zone setting set example.com always_use_https on
  polyctl cloudflare zone setting set example.com argo_smart_routing on`,
		Args:              cobra.ExactArgs(3),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name, err := settingName(args[1])
			if err != nil {
				return err
			}
			if timeout <= 0 {
				return app.UsageErrf("--timeout must be a positive duration, got %s", timeout)
			}
			// The value of the special settings is checked before
			// anything is read.
			if name == settingArgo || name == settingFoundationDNS {
				if _, err := settingValue(name, args[2], nil); err != nil {
					return app.UsageErrf("%v", err)
				}
			}
			s, err := resolveLiveZone(ctx, rt, args[0])
			if err != nil {
				return err
			}
			cur, err := s.c.api.readSetting(ctx, s.z.ID, name)
			if foundationUnsupported(err) && name == settingFoundationDNS {
				return fmt.Errorf("%w: the account of zone %s cannot use Foundation DNS: %v", platform.ErrNotSupported, s.name(), err)
			}
			if err != nil {
				return s.gone(ctx, rt, err)
			}
			value, err := settingValue(name, args[2], cur.Value)
			if errors.Is(err, errBadSettingValue) {
				return app.UsageErrf("%v", err)
			}
			from, to := settingText(cur.Value), settingText(value)
			res := "zone/" + s.name() + "/setting/" + name
			if from == to {
				return rt.RenderReport(platform.Report{Target: s.target(), DryRun: rt.DryRun(),
					Changes: []platform.Change{{Resource: res, Action: platform.Unchanged, Detail: to}}})
			}
			change := platform.Change{Resource: res, Action: platform.Updated, Detail: from + " -> " + to, Attrs: map[string]string{"from": from, "to": to}}
			if done, err := rt.WouldWrite(s.target(), change); done || err != nil {
				return err
			}
			out, err := s.c.api.writeSetting(ctx, s.z.ID, name, value, s.plan())
			if foundationUnsupported(err) && name == settingFoundationDNS {
				return fmt.Errorf("%w: the account of zone %s cannot use Foundation DNS: %v", platform.ErrNotSupported, s.name(), err)
			}
			if err != nil {
				return s.gone(ctx, rt, err)
			}
			if got := settingText(out.Value); got != "" && got != to {
				change.Detail = from + " -> " + got
				change.Attrs["to"] = got
			}
			rt.Infof("%s of zone %s set to %s via cloudflare/%s", name, s.name(), to, s.profile)
			if name == settingFoundationDNS {
				on, _ := value.(bool)
				if err := waitFoundationNS(ctx, rt, s, on, timeout); err != nil {
					return err
				}
			}
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", defaultFoundationTimeout, "foundation_dns: upper bound of the wait for the new nameservers (a Go duration such as 90s)")
	return cmd
}

// waitFoundationNS waits until the nameservers of the zone follow the
// Foundation DNS switch (on: *.foundationdns.*; off: the default ones),
// then stores the zone and prints the nameservers to set at the registrar.
func waitFoundationNS(ctx context.Context, rt *app.Runtime, s *zoneScope, on bool, timeout time.Duration) error {
	want := "Foundation DNS nameservers"
	if !on {
		want = "default nameservers"
	}
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "zone/" + s.name(), Want: "served by " + want, Timeout: timeout, Interval: foundationPollInterval},
		func(ctx context.Context) (platform.WaitState, string, error) {
			z, err := s.c.api.getZone(ctx, s.z.ID)
			if err != nil {
				return platform.KeepWaiting, "", err
			}
			s.z = z
			if usesFoundationDNS(z.NameServers) == on {
				return platform.WaitDone, strings.Join(z.NameServers, ","), nil
			}
			return platform.KeepWaiting, strings.Join(z.NameServers, ","), nil
		})
	if err != nil {
		return err
	}
	storeZone(ctx, rt, s.profile, *s.z)
	rt.Infof("nameservers of zone %s are now %s; set them at the registrar: polyctl domain ns set %s %s",
		s.name(), strings.Join(s.z.NameServers, ", "), s.name(), strings.Join(s.z.NameServers, " "))
	return nil
}
