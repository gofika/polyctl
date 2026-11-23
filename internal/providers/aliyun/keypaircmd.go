package aliyun

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// keyPairNameMax is the longest key pair name ECS accepts; the shortest is
// 2 characters (InvalidKeyPairName.Malformed below that).
const (
	keyPairNameMin = 2
	keyPairNameMax = 128
)

// newKeyPairCmd is `aliyun ecs key-pair`: list, import and ensure. There is
// no delete on purpose: a key pair may still be bound to instances.
func newKeyPairCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key-pair",
		Short: "ECS SSH key pairs (regional)",
		Long: `ECS SSH key pairs. A key pair belongs to one region: --region picks it (the
profile's region by default); a key used in several regions is imported in
each. ECS imports RSA, ECDSA and ED25519 public keys and never returns them:
key pairs are compared by fingerprint (the MD5 of the key). A key pair is
never replaced or deleted by polyctl.`,
	}
	cmd.AddCommand(keyPairListCmd(rt), keyPairImportCmd(rt), keyPairEnsureCmd(rt))
	return cmd
}

// checkKeyPairName refuses a name ECS would refuse or read as a pattern.
func checkKeyPairName(name string) error {
	switch n := len([]rune(name)); {
	case strings.TrimSpace(name) == "":
		return app.UsageErrf("the key pair name is empty")
	case strings.Contains(name, "*"):
		return app.UsageErrf("key pair name %q holds *, which Alibaba Cloud reads as a wildcard", name)
	case n < keyPairNameMin:
		return app.UsageErrf("key pair name %q is too short (at least %d characters)", name, keyPairNameMin)
	case n > keyPairNameMax:
		return app.UsageErrf("key pair name %q is longer than %d characters", name, keyPairNameMax)
	}
	return nil
}

// keyPairImportErr maps the errors of ImportKeyPair: a taken name is a
// failure that ensure resolves, a malformed name a usage error.
func keyPairImportErr(name, region string, err error) error {
	switch {
	case platform.HasErrorCode(err, errKeyPairExists):
		return fmt.Errorf("key pair %q already exists in %s (it is never replaced): use `polyctl aliyun ecs key-pair ensure` to reuse the key pair that holds the key: %w", name, region, err)
	case platform.HasErrorCode(err, errKeyPairMalformed):
		return fmt.Errorf("%w: key pair name %q is not accepted by Alibaba Cloud: %v", platform.ErrInvalidInput, name, err)
	}
	return err
}

func keyPairGrid(kps []keyPairInfo) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "FINGERPRINT", "CREATED"}, Empty: "no key pairs"}
	for _, k := range kps {
		g.Rows = append(g.Rows, []string{k.Name, k.Fingerprint, k.Created})
	}
	return g
}

// storeKeyPair records a key pair in the inventory.
func storeKeyPair(ctx context.Context, rt *app.Runtime, profile string, k keyPairInfo) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: profile, Type: platform.ResKeyPair}, k.resource(), cfg.TTLFor(platform.ResKeyPair))
}

func keyPairListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the key pairs of a region (cached locally)",
		Long: `List the key pairs of the profile's region, or of --region, with their
fingerprint (MD5 of the key, lower-case hexadecimal) and creation time. The
list is cached in the local inventory per region.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			region, err := resolveRegion(rt, prof, region)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResKeyPair, Scope: region}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				return c.keyPairResources(ctx, region)
			})
			if err != nil {
				return err
			}
			kps := []keyPairInfo{}
			for _, r := range rows {
				var k keyPairInfo
				if err := r.Decode(&k); err != nil {
					return fmt.Errorf("decode cached key pair %s: %w", r.ID, err)
				}
				kps = append(kps, k)
			}
			if len(kps) == 0 {
				rt.Infof("no key pairs in %s via aliyun/%s%s", region, prof, cacheNote(cached))
			} else {
				rt.Infof("%d key pair(s) in %s via aliyun/%s%s", len(kps), region, prof, cacheNote(cached))
			}
			return rt.Render(kps, func() output.Grid { return keyPairGrid(kps) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func keyPairImportCmd(rt *app.Runtime) *cobra.Command {
	var keys app.KeyFlags
	var region string
	cmd := &cobra.Command{
		Use:   "import <name>",
		Short: "Import an SSH public key as a new key pair",
		Long: `Import the public key of --ssh-key (the key itself) or --ssh-key-file (a .pub
file) as the key pair <name>. The key is checked locally (Alibaba Cloud
accepts almost any text): a malformed key or a private key is a usage error
(exit code 2). A name that is taken is an error (exit code 1), whatever key
it holds: the existing key pair is never replaced; key-pair ensure reuses
the key pair that already holds the key.`,
		Example: "  polyctl aliyun ecs key-pair import ops --ssh-key-file ~/.ssh/id_ed25519.pub",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
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
			if err := key.CheckType(platform.AliyunKeyTypes); err != nil {
				return err
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			existing, err := s.c.listKeyPairs(ctx, s.region, name, "")
			if err != nil {
				return err
			}
			if len(existing) > 0 {
				return fmt.Errorf("key pair %q already exists in %s (fingerprint %s; it is never replaced): use `polyctl aliyun ecs key-pair ensure` to reuse the key pair that holds the key", name, s.where(), existing[0].Fingerprint)
			}
			change := platform.Change{Resource: "key-pair/" + name, Action: platform.Created, Detail: "import from " + key.Source + " (" + key.Summary() + ")"}
			if done, err := rt.WouldWrite(s.target(), change); done || err != nil {
				return err
			}
			info, err := s.c.importKeyPair(ctx, s.region, name, key)
			if err != nil {
				return keyPairImportErr(name, s.region, err)
			}
			storeKeyPair(ctx, rt, s.profile, info)
			change.ID = info.Name
			change.Attrs = map[string]string{"fingerprint": info.Fingerprint}
			rt.Infof("imported key pair %s (fingerprint %s) in %s", info.Name, info.Fingerprint, s.where())
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: []platform.Change{change}})
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
  region are compared with it by fingerprint (MD5 of the key). A key pair
  that holds it is used as it is (unchanged, "matched by fingerprint"),
  under its own name. When several do, <name> picks one of them; otherwise
  a terminal asks, and the non-interactive flow is ambiguous (exit code 5).
  When none does, the key is imported as <name>; without <name> a terminal
  asks for the name and the non-interactive flow is a usage error (exit
  code 2): no name is ever chosen for you.
- With <name> only: an existing key pair is used; a missing one needs a
  public key (asked for on a terminal, a usage error otherwise).

A key pair <name> that holds another key is never replaced: exit code 2.`,
		Example: `  polyctl aliyun ecs key-pair ensure ops --ssh-key-file ~/.ssh/id_ed25519.pub
  polyctl aliyun ecs key-pair ensure --ssh-key-file ~/.ssh/id_ed25519.pub --dry-run`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) == 1 {
				keys.KeyPair = args[0]
				if err := checkKeyPairName(keys.KeyPair); err != nil {
					return err
				}
			}
			in, err := rt.KeyInput(&keys, platform.KeyInput{NameFlag: "<name>", Match: platform.MatchByFingerprintMD5,
				AllowedTypes: platform.AliyunKeyTypes, MinNameLength: keyPairNameMin})
			if err != nil {
				return err
			}
			if in.Key != nil {
				if err := in.Key.CheckType(platform.AliyunKeyTypes); err != nil {
					return err
				}
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			_, step, err := resolveKeyPairStep(ctx, rt, s, in)
			if err != nil {
				return err
			}
			var plan platform.Plan
			plan.Add(step)
			return rt.Ensure(ctx, "aliyun.ecs.key-pair.ensure", s.target(), &plan)
		},
	}
	app.AddPublicKeyFlags(cmd, &keys)
	cmd.Flags().StringVar(&region, "region", "", "region of the key pair (default: the profile's region)")
	return cmd
}

// resolveKeyPairStep decides which key pair of the scope's region a
// command binds, existing first (platform.ResolveKeyPair), and returns the
// plan step that reports it or imports the key. A key pair named on the
// command line that holds another key is a usage error: it is never
// replaced, and the command never settles for another name meanwhile.
func resolveKeyPairStep(ctx context.Context, rt *app.Runtime, s *ecsScope, in platform.KeyInput) (platform.KeyPairPlan, platform.Step, error) {
	if in.Key != nil {
		if err := in.Key.CheckType(platform.AliyunKeyTypes); err != nil {
			return platform.KeyPairPlan{}, platform.Step{}, err
		}
	}
	if in.Key != nil && in.Name != "" {
		named, err := s.c.listKeyPairs(ctx, s.region, in.Name, "")
		if err != nil {
			return platform.KeyPairPlan{}, platform.Step{}, err
		}
		for _, kp := range named {
			if !in.Match.Match(in.Key, platform.KeyPair{Name: kp.Name, Fingerprint: kp.Fingerprint}) {
				return platform.KeyPairPlan{}, platform.Step{}, fmt.Errorf("%w: key pair %q already exists in %s with a different public key (fingerprint %s, the key's is %s); choose another name (an existing key pair is never replaced)",
					platform.ErrInvalidInput, in.Name, s.where(), kp.Fingerprint, in.Key.FingerprintMD5Hex())
			}
		}
	}
	kp, err := platform.ResolveKeyPair(ctx, &keyPairLister{c: s.c, region: s.region, key: in.Key, name: in.Name}, in)
	if err != nil {
		return platform.KeyPairPlan{}, platform.Step{}, err
	}
	if kp.Create {
		if err := checkKeyPairName(kp.Name); err != nil {
			return platform.KeyPairPlan{}, platform.Step{}, err
		}
	}
	for _, n := range kp.Notes {
		rt.Infof("%s", n)
	}
	step := kp.Step(func(ctx context.Context, name string, key *platform.PublicKey) (string, error) {
		info, err := s.c.importKeyPair(ctx, s.region, name, key)
		if platform.HasErrorCode(err, errKeyPairExists) {
			// Imported meanwhile by someone else: fine when it holds the key.
			named, lerr := s.c.listKeyPairs(ctx, s.region, name, "")
			if lerr == nil && len(named) == 1 && named[0].Fingerprint == key.FingerprintMD5Hex() {
				storeKeyPair(ctx, rt, s.profile, named[0])
				return name, nil
			}
			return "", fmt.Errorf("%w: key pair %q was created meanwhile with a different public key: %v", platform.ErrInvalidInput, name, err)
		}
		if err != nil {
			return "", keyPairImportErr(name, s.region, err)
		}
		storeKeyPair(ctx, rt, s.profile, info)
		return info.Name, nil
	})
	return kp, step, nil
}
