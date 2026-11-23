package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// keyPairCmd is `aws ec2 key-pair`: list, import and ensure. There is no
// delete on purpose: a key pair may still be bound to running instances.
func keyPairCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key-pair",
		Short: "EC2 SSH key pairs (regional)",
		Long: `EC2 SSH key pairs. A key pair belongs to one region: --region picks it (the
profile's region by default). AWS imports RSA and ED25519 public keys only.
A key pair is never replaced or deleted by polyctl.`,
	}
	cmd.AddCommand(keyPairListCmd(rt), keyPairImportCmd(rt), keyPairEnsureCmd(rt))
	return cmd
}

func keyPairGrid(kps []keyPairInfo) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "FINGERPRINT", "CREATED"}, Empty: "no key pairs"}
	for _, k := range kps {
		g.Rows = append(g.Rows, []string{k.Name, k.Type, k.displayFingerprint(), k.Created})
	}
	return g
}

func keyPairListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the key pairs of a region (the profile's region is cached locally)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			kps := []keyPairInfo{}
			where := region
			if region != "" {
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				if kps, err = c.listKeyPairs(cmd.Context(), region); err != nil {
					return err
				}
			} else {
				set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResKeyPair}
				rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
					c, _, err := openClient(ctx, rt)
					if err != nil {
						return nil, err
					}
					where = c.region
					return c.keyPairResources(ctx, c.region)
				})
				if err != nil {
					return err
				}
				for _, r := range rows {
					var k keyPairInfo
					if err := r.Decode(&k); err != nil {
						return fmt.Errorf("decode cached key pair %s: %w", r.ID, err)
					}
					if where == "" {
						where = k.Region
					}
					kps = append(kps, k)
				}
				sortKeyPairs(kps)
				if cached {
					rt.Infof("%d key pair(s) via aws/%s (local inventory)", len(kps), profName)
				}
			}
			if len(kps) == 0 {
				if where != "" {
					rt.Infof("no key pairs in %s via aws/%s", where, profName)
				} else {
					rt.Infof("no key pairs via aws/%s", profName)
				}
			}
			return rt.Render(kps, func() output.Grid { return keyPairGrid(kps) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "list another region (bypasses the local inventory)")
	return cmd
}

func sortKeyPairs(kps []keyPairInfo) {
	sort.Slice(kps, func(i, j int) bool { return kps[i].Name < kps[j].Name })
}

// storeKeyPair records a new key pair in the inventory, when it belongs to
// the region the inventory holds (the profile's region).
func storeKeyPair(ctx context.Context, rt *app.Runtime, c *client, profName string, k keyPairInfo) {
	if k.Region != c.region || k.KeyPairID == "" {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResKeyPair}, k.resource(), cfg.TTLFor(platform.ResKeyPair))
}

// keyPairTags are the tags of a new key pair: defaults.aws.tags.
func keyPairTags(rt *app.Runtime, profName string) (map[string]string, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	tags, err := cfg.DefaultMap(profName, platform.AWS, "tags")
	if err != nil {
		return nil, app.UsageErrf("config.yaml: %v", err)
	}
	return tags, nil
}

// checkKeyPairName refuses a name AWS would refuse: empty, longer than 255
// characters, or not ASCII.
func checkKeyPairName(name string) error {
	if strings.TrimSpace(name) == "" {
		return app.UsageErrf("the key pair name is empty")
	}
	if len(name) > 255 {
		return app.UsageErrf("key pair name %q is longer than 255 characters", name)
	}
	for _, r := range name {
		if r < 0x20 || r > 0x7e {
			return app.UsageErrf("key pair name %q holds a character AWS does not accept (printable ASCII only)", name)
		}
	}
	return nil
}

func keyPairImportCmd(rt *app.Runtime) *cobra.Command {
	var keys app.KeyFlags
	var region string
	cmd := &cobra.Command{
		Use:   "import <name>",
		Short: "Import an SSH public key as a new key pair",
		Long: `Import the public key of --ssh-key (the key itself) or --ssh-key-file (a .pub
file) as the key pair <name>. A name that is taken is a usage error (exit
code 2), whatever key it holds: the existing key pair is never replaced. Use
key-pair ensure to reuse the key pair that already holds the key.`,
		Example: "  polyctl aws ec2 key-pair import ops --ssh-key-file ~/.ssh/id_ed25519.pub",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := checkKeyPairName(name); err != nil {
				return err
			}
			key, err := keys.PublicKey()
			if err != nil {
				return err
			}
			if key == nil {
				return app.UsageErrf("a public key is required: pass --ssh-key-file <path> or --ssh-key <public key>")
			}
			if err := key.CheckType(platform.AWSKeyTypes); err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if region == "" {
				region = c.region
			}
			target := platform.Target{Platform: platform.AWS, Profile: prof.Name, Region: region}
			change := platform.Change{Resource: "key-pair/" + name, Action: platform.Created, Detail: "import from " + key.Source + " (" + key.Summary() + ")"}
			// The dry run sends no request: the key was checked locally.
			if done, err := rt.WouldWrite(target, change); done || err != nil {
				return err
			}
			tags, err := keyPairTags(rt, prof.Name)
			if err != nil {
				return err
			}
			info, err := c.importKeyPair(cmd.Context(), region, name, key, tags)
			if err != nil {
				return err
			}
			storeKeyPair(cmd.Context(), rt, c, prof.Name, info)
			change.ID = info.KeyPairID
			rt.Infof("imported key pair %s (%s) in %s via aws/%s", name, info.KeyPairID, region, prof.Name)
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	app.AddPublicKeyFlags(cmd, &keys)
	cmd.Flags().StringVar(&region, "region", "", "region of the key pair (default: the profile's region)")
	return cmd
}

func keyPairEnsureCmd(rt *app.Runtime) *cobra.Command {
	var keys app.KeyFlags
	var region string
	cmd := &cobra.Command{
		Use:   "ensure [<name>]",
		Short: "Make sure a key pair holding the public key exists (existing first)",
		Long: `Make sure a key pair exists, reusing an existing one first:

- With a public key (--ssh-key or --ssh-key-file): the key pairs of the
  region are compared with it by their public key. A key pair that holds
  it is used as it is (unchanged), under its own name. When several do,
  <name> picks one of them; otherwise a terminal asks, and the
  non-interactive flow is ambiguous (exit code 5). When none does, the key
  is imported as <name>; without <name> a terminal asks for the name and
  the non-interactive flow is a usage error (exit code 2): no name is ever
  chosen for you.
- With <name> only: an existing key pair is used; a missing one needs a
  public key (asked for on a terminal, a usage error otherwise).

A key pair <name> that holds another key is never replaced: exit code 2.`,
		Example: `  polyctl aws ec2 key-pair ensure ops --ssh-key-file ~/.ssh/id_ed25519.pub
  polyctl aws ec2 key-pair ensure --ssh-key-file ~/.ssh/id_ed25519.pub --dry-run`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				keys.KeyPair = args[0]
				if err := checkKeyPairName(keys.KeyPair); err != nil {
					return err
				}
			}
			base := keyInputBase()
			base.NameFlag = "<name>"
			in, err := rt.KeyInput(&keys, base)
			if err != nil {
				return err
			}
			if in.Key != nil {
				if err := in.Key.CheckType(platform.AWSKeyTypes); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if region == "" {
				region = c.region
			}
			target := platform.Target{Platform: platform.AWS, Profile: prof.Name, Region: region}
			lister := &keyPairLister{c: c, region: region}
			if in.Key != nil && in.Name != "" {
				// The key pair named on the command line must hold the key
				// when it exists: ensure never settles for another name
				// while the one asked for holds a different key.
				pairs, err := lister.ListKeyPairs(cmd.Context())
				if err != nil {
					return err
				}
				for _, kp := range pairs {
					if kp.Name == in.Name && !in.Match.Match(in.Key, kp) {
						return fmt.Errorf("%w: key pair %q already exists in %s with a different public key; choose another name (an existing key pair is never replaced)", platform.ErrInvalidInput, in.Name, region)
					}
				}
			}
			kp, err := platform.ResolveKeyPair(cmd.Context(), lister, in)
			if err != nil {
				return err
			}
			if kp.Create {
				if err := checkKeyPairName(kp.Name); err != nil {
					return err
				}
			}
			for _, n := range kp.Notes {
				rt.Infof("%s", n)
			}
			var tags map[string]string
			if kp.Create && !rt.DryRun() {
				if tags, err = keyPairTags(rt, prof.Name); err != nil {
					return err
				}
			}
			var plan platform.Plan
			plan.Add(kp.Step(func(ctx context.Context, name string, key *platform.PublicKey) (string, error) {
				info, err := c.importKeyPair(ctx, region, name, key, tags)
				if err != nil {
					return "", err
				}
				storeKeyPair(ctx, rt, c, prof.Name, info)
				return info.KeyPairID, nil
			}))
			return rt.Ensure(cmd.Context(), "aws.ec2.key-pair.ensure", target, &plan)
		},
	}
	app.AddPublicKeyFlags(cmd, &keys)
	cmd.Flags().StringVar(&region, "region", "", "region of the key pair (default: the profile's region)")
	return cmd
}
