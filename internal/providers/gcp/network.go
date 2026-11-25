package gcp

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// VPC networks and subnetworks are read live: they are few, change often
// and are not kept in the inventory. A resource belongs to a network when
// the last segment of its network URL equals the network name exactly
// ("net-a" never matches "net-a-2").

// proxyOnlyPurposes are the purposes of proxy-only subnetworks: the
// current regional one, the global one, and the older name of the
// regional one that older projects still have.
var proxyOnlyPurposes = []string{"REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER"}

// isProxyOnly reports whether a subnetwork is a proxy-only subnetwork.
func isProxyOnly(s *compute.Subnetwork) bool {
	for _, p := range proxyOnlyPurposes {
		if strings.EqualFold(s.Purpose, p) {
			return true
		}
	}
	return false
}

// defaultMTU is the MTU of a network that never set one: the API then
// reads back 0.
const defaultMTU = 1460

// networkMode tells how a network creates its subnetworks: "legacy" for a
// network with a single IPv4 range (no subnetworks), "auto" for one that
// creates a subnetwork in every region, "custom" otherwise.
func networkMode(n *compute.Network) string {
	switch {
	case n.IPv4Range != "":
		return "legacy"
	case n.AutoCreateSubnetworks:
		return "auto"
	}
	return "custom"
}

// networkView is the output shape of a VPC network.
type networkView struct {
	Name string `json:"name" yaml:"name"`
	// Project is the project of the network.
	Project     string `json:"project,omitempty" yaml:"project,omitempty"`
	Mode        string `json:"mode" yaml:"mode"`
	RoutingMode string `json:"routing_mode" yaml:"routing_mode"`
	// MTU is 0 when the network never set one (it then uses 1460).
	MTU               int64        `json:"mtu" yaml:"mtu"`
	IPv4Range         string       `json:"ipv4_range,omitempty" yaml:"ipv4_range,omitempty"`
	Subnetworks       []string     `json:"subnetworks" yaml:"subnetworks"`
	Description       string       `json:"description,omitempty" yaml:"description,omitempty"`
	CreationTimestamp string       `json:"creation_timestamp,omitempty" yaml:"creation_timestamp,omitempty"`
	Subnets           []subnetView `json:"subnets,omitempty" yaml:"subnets,omitempty"`
}

func networkFromAPI(n *compute.Network) networkView {
	v := networkView{Name: n.Name, Mode: networkMode(n), MTU: n.Mtu, IPv4Range: n.IPv4Range, Subnetworks: []string{},
		Description: n.Description, CreationTimestamp: n.CreationTimestamp}
	if n.RoutingConfig != nil {
		v.RoutingMode = n.RoutingConfig.RoutingMode
	}
	for _, u := range n.Subnetworks {
		v.Subnetworks = append(v.Subnetworks, subnetPath(u))
	}
	sort.Strings(v.Subnetworks)
	return v
}

// subnetPath turns a subnetwork URL into "<region>/<name>".
func subnetPath(u string) string {
	parts := strings.Split(strings.TrimRight(u, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "regions" && parts[i+2] == "subnetworks" && i+3 < len(parts) {
			return parts[i+1] + "/" + parts[i+3]
		}
	}
	return lastSegment(u)
}

func mtuLabel(mtu int64) string {
	if mtu == 0 {
		return fmt.Sprintf("%d(default)", defaultMTU)
	}
	return strconv.FormatInt(mtu, 10)
}

// secondaryRange is a secondary range of a subnetwork.
type secondaryRange struct {
	Name  string `json:"range_name" yaml:"range_name"`
	Range string `json:"ip_cidr_range" yaml:"ip_cidr_range"`
}

// subnetView is the output shape of a subnetwork.
type subnetView struct {
	Name string `json:"name" yaml:"name"`
	// Project is the project of the subnetwork (set by subnet list).
	Project         string           `json:"project,omitempty" yaml:"project,omitempty"`
	Region          string           `json:"region" yaml:"region"`
	Network         string           `json:"network" yaml:"network"`
	Range           string           `json:"ip_cidr_range" yaml:"ip_cidr_range"`
	SecondaryRanges []secondaryRange `json:"secondary_ranges" yaml:"secondary_ranges"`
	Purpose         string           `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	Role            string           `json:"role,omitempty" yaml:"role,omitempty"`
}

func subnetFromAPI(s *compute.Subnetwork) subnetView {
	v := subnetView{Name: s.Name, Region: lastSegment(s.Region), Network: lastSegment(s.Network), Range: s.IpCidrRange,
		SecondaryRanges: []secondaryRange{}, Purpose: s.Purpose, Role: s.Role}
	if v.Region == "" {
		v.Region = regionFromURL(s.SelfLink)
	}
	for _, r := range s.SecondaryIpRanges {
		v.SecondaryRanges = append(v.SecondaryRanges, secondaryRange{Name: r.RangeName, Range: r.IpCidrRange})
	}
	return v
}

// regionFromURL returns the region segment of a regional resource URL.
func regionFromURL(u string) string {
	parts := strings.Split(u, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "regions" {
			return parts[i+1]
		}
	}
	return ""
}

func sortSubnets(list []subnetView) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Region != list[j].Region {
			return list[i].Region < list[j].Region
		}
		return list[i].Name < list[j].Name
	})
}

func subnetGrid(list []subnetView) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "PROJECT", "REGION", "NETWORK", "RANGE", "SECONDARY-RANGES", "PURPOSE", "ROLE"}, Empty: "no subnetworks"}
	for _, s := range list {
		var sec []string
		for _, r := range s.SecondaryRanges {
			sec = append(sec, r.Name+"="+r.Range)
		}
		g.Rows = append(g.Rows, []string{s.Name, s.Project, s.Region, s.Network, s.Range, strings.Join(sec, ","), s.Purpose, s.Role})
	}
	return g
}

// listNetworks lists the VPC networks of the project.
func (c *client) listNetworks(ctx context.Context) ([]*compute.Network, error) {
	var out []*compute.Network
	err := c.compute.Networks.List(c.project).Pages(ctx, func(l *compute.NetworkList) error {
		out = append(out, l.Items...)
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// listSubnets lists the subnetworks of a region, or of every region when
// region is empty, keeping those of network (every network when empty).
func (c *client) listSubnets(ctx context.Context, region, network string) ([]*compute.Subnetwork, error) {
	if region != "" {
		if network != "" {
			return c.subnetworksOf(ctx, region, network)
		}
		var out []*compute.Subnetwork
		err := c.compute.Subnetworks.List(c.project, region).Pages(ctx, func(l *compute.SubnetworkList) error {
			out = append(out, l.Items...)
			return nil
		})
		if err != nil {
			return nil, computeErr(err)
		}
		return out, nil
	}
	var out []*compute.Subnetwork
	unreachable, err := aggregatedPages(ctx, c.compute.Subnetworks.AggregatedList(c.project), func(l *compute.SubnetworkAggregatedList) (string, []string) {
		u := l.Unreachables
		for scope, sl := range l.Items {
			if sl.Warning != nil {
				u = append(u, warnedUnreachable(scope, sl.Warning.Code)...)
			}
			for _, s := range sl.Subnetworks {
				if network != "" && lastSegment(s.Network) != network {
					continue
				}
				if s.Region == "" {
					s.Region = strings.TrimPrefix(scope, "regions/")
				}
				out = append(out, s)
			}
		}
		return l.NextPageToken, u
	})
	if err != nil {
		return nil, computeErr(err)
	}
	if err := unreachableListErr("subnetworks", unreachable); err != nil {
		return nil, err
	}
	return out, nil
}

// vpcRanges returns the primary and secondary ranges of subnetworks.
func vpcRanges(subnets []*compute.Subnetwork) []string {
	var out []string
	for _, s := range subnets {
		if s.IpCidrRange != "" {
			out = append(out, s.IpCidrRange)
		}
		for _, r := range s.SecondaryIpRanges {
			if r.IpCidrRange != "" {
				out = append(out, r.IpCidrRange)
			}
		}
	}
	return out
}

// proxyOnlySubnets returns the primary ranges of the proxy-only
// subnetworks among subnets.
func proxyOnlySubnets(subnets []*compute.Subnetwork) []string {
	var out []string
	for _, s := range subnets {
		if isProxyOnly(s) && s.IpCidrRange != "" {
			out = append(out, s.IpCidrRange)
		}
	}
	return out
}

// ------------------------------------------------------------ commands

func newNetworkCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "network", Short: "VPC networks (read-only)"}
	cmd.AddCommand(networkListCmd(rt), networkGetCmd(rt))
	return cmd
}

func newSubnetCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "subnet", Short: "VPC subnetworks (read-only)"}
	cmd.AddCommand(subnetListCmd(rt))
	return cmd
}

// gcpProfile returns the gcp profile of a command that works on one
// project (--profile, else the default one). A --profile that exists but
// holds no gcp account is "not supported" (exit code 7).
func gcpProfile(rt *app.Runtime) (string, error) {
	profile, err := rt.ProfileFor(platform.GCP)
	if err == nil || rt.Flags.Profile == "" {
		return profile, err
	}
	cfg, cerr := rt.Config()
	if cerr != nil {
		return "", err
	}
	if _, perr := cfg.Profile(rt.Flags.Profile); perr != nil {
		return "", err
	}
	if _, aerr := cfg.Account(rt.Flags.Profile, platform.GCP); aerr != nil {
		return "", fmt.Errorf("%w: profile %s has no gcp account (log in with `polyctl auth login gcp --profile %s`)", platform.ErrNotSupported, rt.Flags.Profile, rt.Flags.Profile)
	}
	return "", err
}

// openGCP opens the client of the gcp profile of a single-project command.
func openGCP(ctx context.Context, rt *app.Runtime) (*client, string, error) {
	if rt.Flags.Offline {
		return nil, "", app.ErrOffline
	}
	profile, err := gcpProfile(rt)
	if err != nil {
		return nil, "", err
	}
	c, err := openProfile(ctx, rt, profile)
	if err != nil {
		return nil, profile, err
	}
	return c, profile, nil
}

func networkListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the VPC networks of the selected projects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, profile, err := openGCP(cmd.Context(), rt)
			if err != nil {
				return err
			}
			rows := []networkView{}
			err = c.forProjects(cmd.Context(), func(pc *client) error {
				nets, err := pc.listNetworks(cmd.Context())
				if err != nil {
					return err
				}
				for _, n := range nets {
					v := networkFromAPI(n)
					v.Project = pc.project
					rows = append(rows, v)
				}
				return nil
			})
			if err != nil {
				return err
			}
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].Project != rows[j].Project {
					return rows[i].Project < rows[j].Project
				}
				return rows[i].Name < rows[j].Name
			})
			if len(rows) == 0 {
				rt.Infof("note: no VPC networks in %s (gcp/%s)", c.projectsLabel(cmd.Context()), profile)
			} else {
				rt.Infof("%d network(s) in %s via gcp/%s", len(rows), c.projectsLabel(cmd.Context()), profile)
			}
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"NAME", "PROJECT", "MODE", "ROUTING", "MTU", "SUBNETS"}, Empty: "no networks"}
				for _, n := range rows {
					g.Rows = append(g.Rows, []string{n.Name, n.Project, n.Mode, n.RoutingMode, mtuLabel(n.MTU), strconv.Itoa(len(n.Subnetworks))})
				}
				return g
			})
		},
	}
}

func networkGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <name>",
		Short: "Show a VPC network with its subnetworks in every region",
		Long:  "Show a VPC network with its subnetworks in every region. On a terminal,\nwithout <name> the networks of one project are offered (which one is asked\nfirst when several are selected).",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			name := app.Arg(args, 0)
			if name != "" {
				c, err = locateProject(ctx, rt, c, profile, "VPC network", name, func(ctx context.Context, pc *client) (bool, error) {
					_, err := pc.network(ctx, name)
					return notFoundIs(err)
				})
			} else {
				c, err = chooseListProject(ctx, rt, c, profile)
			}
			if err != nil {
				return err
			}
			if name == "" {
				nets, err := c.listNetworks(ctx)
				if err != nil {
					return err
				}
				sort.Slice(nets, func(i, j int) bool { return nets[i].Name < nets[j].Name })
				var opts []prompt.Option
				for _, n := range nets {
					opts = append(opts, prompt.Option{Label: networkLabel(n), Value: n.Name})
				}
				if name, err = rt.Choose(app.Choice{Title: "VPC network", Options: opts, Arg: "<name>", What: "VPC network in gcp/" + profile}); err != nil {
					return err
				}
			}
			n, err := c.network(ctx, name)
			if err != nil {
				return fmt.Errorf("%w (gcp/%s)", err, profile)
			}
			v := networkFromAPI(n)
			v.Project = c.project
			subnets, err := c.listSubnets(ctx, "", n.Name)
			if err != nil {
				return err
			}
			for _, s := range subnets {
				v.Subnets = append(v.Subnets, subnetFromAPI(s))
			}
			sortSubnets(v.Subnets)
			rt.Infof("network %s in project %s via gcp/%s", v.Name, c.project, profile)
			return rt.Render(v, func() output.Grid {
				g := output.KV("name", v.Name, "project", v.Project, "mode", v.Mode, "routing", v.RoutingMode, "mtu", mtuLabel(v.MTU),
					"description", v.Description, "created", v.CreationTimestamp)
				if v.IPv4Range != "" {
					g.Rows = append(g.Rows, []string{"ipv4 range", v.IPv4Range})
				}
				for _, s := range v.Subnets {
					val := s.Range
					for _, r := range s.SecondaryRanges {
						val += ", " + r.Name + "=" + r.Range
					}
					if s.Purpose != "" && s.Purpose != "PRIVATE" {
						val += " (" + strings.TrimSpace(s.Purpose+" "+s.Role) + ")"
					}
					g.Rows = append(g.Rows, []string{"subnet " + s.Region + "/" + s.Name, val})
				}
				return g
			})
		},
	}
}

func subnetListCmd(rt *app.Runtime) *cobra.Command {
	var network, region string
	var proxyOnly bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List subnetworks, of every region or of --region, optionally of one --network",
		Long: `List the subnetworks of the selected projects with their primary and secondary ranges,
purpose and role. --region lists one region, otherwise every region is
listed. --network keeps the subnetworks of that network (its name must
match exactly). --proxy-only keeps the proxy-only subnetworks (purpose
REGIONAL_MANAGED_PROXY, GLOBAL_MANAGED_PROXY or INTERNAL_HTTPS_LOAD_BALANCER).`,
		Example: "  polyctl gcp compute subnet list --network default --region us-central1 --proxy-only",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			rows := []subnetView{}
			err = c.forProjects(ctx, func(pc *client) error {
				subnets, err := pc.listSubnets(ctx, region, lastSegment(network))
				if err != nil {
					return err
				}
				var own []subnetView
				for _, s := range subnets {
					if proxyOnly && !isProxyOnly(s) {
						continue
					}
					v := subnetFromAPI(s)
					v.Project = pc.project
					own = append(own, v)
				}
				sortSubnets(own)
				rows = append(rows, own...)
				return nil
			})
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				rt.Infof("note: no matching subnetworks in %s (gcp/%s)", c.projectsLabel(ctx), profile)
			} else {
				rt.Infof("%d subnetwork(s) in %s via gcp/%s", len(rows), c.projectsLabel(ctx), profile)
			}
			return rt.Render(rows, func() output.Grid { return subnetGrid(rows) })
		},
	}
	cmd.Flags().StringVar(&network, "network", "", "only the subnetworks of this VPC network (exact name)")
	cmd.Flags().StringVar(&region, "region", "", "only this region (default: every region)")
	cmd.Flags().BoolVar(&proxyOnly, "proxy-only", false, "only proxy-only subnetworks")
	return cmd
}
