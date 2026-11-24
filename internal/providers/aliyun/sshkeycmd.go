package aliyun

import (
	"context"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// `aliyun ecs instance ssh-key list|add|remove` manage the keys of a Linux
// instance over SSH (an instance binds one key pair, to the login user set
// at creation): the shared commands of package app, with the login user
// the instance was created with.

// The login users of an ECS Linux instance: root, unless the instance was
// created to log in as ecs-user (RunInstances ImageOptions.LoginAsNonRoot,
// which DescribeInstances returns in ImageOptions.LoginAsNonRoot). See
// https://www.alibabacloud.com/help/en/ecs/user-guide/instance-logon-credential-management
const (
	rootUser    = "root"
	nonRootUser = "ecs-user"
)

// windowsInstance reports an instance that runs Windows (OSType windows,
// or an OS name of Windows for a row that has no OSType).
func windowsInstance(in Instance) bool {
	return strings.EqualFold(in.OSType, "windows") || strings.HasPrefix(strings.ToLower(in.OS), "windows")
}

// ecsLoginUsers are the users to log in to a Linux instance as, in order,
// and what they come from. An instance created to log in as ecs-user
// disables root logins: ecs-user only. Otherwise root, then ecs-user: a
// false LoginAsNonRoot is also what a response without ImageOptions
// decodes to, so the note does not claim the instance was created for
// root.
func ecsLoginUsers(in *Instance) (users []string, from string) {
	label := nameOr(in.Name, in.ID)
	if in.Name != "" && in.Name != in.ID {
		label += " (" + in.ID + ")"
	}
	if in.LoginAsNonRoot {
		return []string{nonRootUser}, "instance " + label + ", created to log in as " + nonRootUser
	}
	return []string{rootUser, nonRootUser}, "instance " + label + ", not created to log in as " + nonRootUser
}

func ecsSSHKeyCmd(rt *app.Runtime) *cobra.Command {
	var region string
	return app.SSHKeyCommands(rt, app.SSHKeyCommand{
		Platform: platform.Aliyun,
		Tree:     ecsInstanceTree,
		Detail: `Alibaba Cloud ECS: the login user is the one the instance was created
with (DescribeInstances ImageOptions.LoginAsNonRoot): ecs-user for an
instance created to log in as ecs-user, which cannot log in as root;
otherwise root, then ecs-user. Pass --login-user for a user added by hand.
The key pair is the one bound to the instance (ecs:DescribeKeyPairs,
matched by public key); it stays as it is: these commands only edit
authorized_keys, which needs no restart.`,
		Flags: func(cmd *cobra.Command) {
			cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
		},
		Resolve: func(ctx context.Context, arg string) (*app.SSHKeyInstance, error) {
			if arg == "" {
				args, err := instanceArg(ctx, rt, nil, region, "running Linux instance", func(in Instance) bool {
					return in.Status == instRunning && !windowsInstance(in)
				})
				if err != nil {
					return nil, err
				}
				arg = args[0]
			}
			s, in, err := resolveECSInstance(ctx, rt, arg, region)
			if err != nil {
				return nil, err
			}
			inst := &app.SSHKeyInstance{Name: in.Name, ID: in.ID, Target: s.target(),
				Windows: windowsInstance(*in), Running: in.Status == instRunning, State: in.Status,
				PublicIP: in.PublicIP, PrivateIP: in.PrivateIP}
			if inst.Windows || !inst.Running {
				return inst, nil
			}
			inst.LoginUsers, inst.LoginUsersFrom = ecsLoginUsers(in)
			inst.KeyPairName = in.KeyPair
			inst.KeyPairMatch = platform.MatchAliyun
			if in.KeyPair != "" {
				inst.KeyPair, inst.KeyPairError = s.c.boundKeyPair(ctx, s.region, in.KeyPair)
			}
			return inst, nil
		},
	})
}
