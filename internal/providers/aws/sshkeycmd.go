package aws

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2instanceconnect"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// `aws ec2 instance ssh-key list|add|remove` manage the keys of a Linux
// instance over SSH (an instance binds one key pair at launch): the shared
// commands of package app, with the login users derived from the
// instance's image and the key pair the instance was launched with. When
// this machine has no private key of that key pair, the temporary ways in
// are Systems Manager Run Command (runcommand.go), first, then EC2 Instance
// Connect: Run Command needs no network path to port 22 nor the
// ec2-instance-connect package, and puts no key on the instance, so it is
// tried first on an instance whose SSM Agent is online; Instance Connect
// covers the instances Systems Manager does not manage. A key pushed with
// Instance Connect proves nothing until the login works (the push succeeds
// on images without the package), which the shared code checks.

// ec2icAPI is the part of the EC2 Instance Connect API polyctl uses.
type ec2icAPI interface {
	SendSSHPublicKey(ctx context.Context, in *ec2instanceconnect.SendSSHPublicKeyInput, optFns ...func(*ec2instanceconnect.Options)) (*ec2instanceconnect.SendSSHPublicKeyOutput, error)
}

// newEC2IC creates the EC2 Instance Connect client of a region; tests
// replace it with a fake.
var newEC2IC = func(cfg awssdk.Config) ec2icAPI { return ec2instanceconnect.NewFromConfig(cfg) }

// unknownImageUsers are the users tried, in order, for an image whose
// family polyctl does not recognize: the defaults AWS documents for its
// Linux AMIs, most common first, root last (RHEL and SUSE).
var unknownImageUsers = []string{"ec2-user", "ubuntu", "admin", "centos", "rocky", "fedora", "bitnami", "root"}

// imageFamily is what polyctl knows of an image's system.
type imageFamily struct {
	// Name is the family ("Amazon Linux", "Ubuntu"); "" for unknown.
	Name string
	// Users are its default login users, in the order to try.
	Users []string
	// InstanceConnect says EC2 Instance Connect comes preinstalled.
	InstanceConnect bool
}

var (
	amzn2DateRe   = regexp.MustCompile(`amzn2-ami-.*?2\.0\.(\d{8})`)
	ubuntuVerRe   = regexp.MustCompile(`(?:^|[^0-9.])(\d{2})\.(04|10)(?:[^0-9]|$)`)
	oracleLinuxRe = regexp.MustCompile(`^ol\d`)
)

// familyOf recognizes the system of an image from its name and
// description (both free text set by the publisher; AWS documents no field
// that names the default user), and from the PlatformDetails billing
// label, which tells Red Hat, SUSE and Ubuntu Pro apart. The users are
// those of https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/managing-users.html
// (and the connection prerequisites page for Rocky Linux).
func familyOf(name, description, platformDetails string) imageFamily {
	n := strings.ToLower(name)
	text := n + " " + strings.ToLower(description)
	pd := strings.ToLower(platformDetails)
	has := func(s string) bool { return strings.Contains(text, s) }
	switch {
	case has("bitnami"):
		// Bitnami images name the system they are built on, so they come
		// first.
		return imageFamily{Name: "Bitnami", Users: []string{"bitnami"}}
	case has("macos"):
		return imageFamily{Name: "macOS", Users: []string{"ec2-user"}}
	case strings.HasPrefix(n, "al2023-ami-"):
		// The standard image ships EC2 Instance Connect; minimal and
		// ECS-optimized ones do not.
		return imageFamily{Name: "Amazon Linux 2023", Users: []string{"ec2-user"},
			InstanceConnect: !strings.Contains(n, "minimal") && !strings.Contains(n, "-ecs-")}
	case strings.HasPrefix(n, "amzn2-ami-"):
		ic := false
		if m := amzn2DateRe.FindStringSubmatch(n); m != nil {
			ic = m[1] >= "20190618" && !strings.Contains(n, "minimal") && !strings.Contains(n, "-ecs-")
		}
		return imageFamily{Name: "Amazon Linux 2", Users: []string{"ec2-user"}, InstanceConnect: ic}
	case strings.HasPrefix(n, "amzn-ami-"), strings.HasPrefix(n, "amazon-eks"), has("amazon linux"):
		return imageFamily{Name: "Amazon Linux", Users: []string{"ec2-user"}}
	case has("ubuntu"), strings.Contains(pd, "ubuntu"):
		ic := false
		if m := ubuntuVerRe.FindStringSubmatch(text); m != nil {
			v, _ := strconv.Atoi(m[1])
			ic = v >= 20
		}
		return imageFamily{Name: "Ubuntu", Users: []string{"ubuntu"}, InstanceConnect: ic}
	case has("debian"):
		return imageFamily{Name: "Debian", Users: []string{"admin"}}
	case has("centos"):
		return imageFamily{Name: "CentOS", Users: []string{"centos", "ec2-user"}}
	case has("fedora"):
		return imageFamily{Name: "Fedora", Users: []string{"fedora", "ec2-user"}}
	case has("rocky"):
		return imageFamily{Name: "Rocky Linux", Users: []string{"rocky"}}
	case strings.HasPrefix(n, "rhel-"), has("red hat"), strings.Contains(pd, "red hat"):
		return imageFamily{Name: "Red Hat Enterprise Linux", Users: []string{"ec2-user", "root"}}
	case has("suse"), has("sles"), strings.Contains(pd, "suse"):
		return imageFamily{Name: "SUSE Linux", Users: []string{"ec2-user", "root"}}
	case oracleLinuxRe.MatchString(n), has("oracle linux"):
		return imageFamily{Name: "Oracle Linux", Users: []string{"ec2-user"}}
	case has("freebsd"):
		return imageFamily{Name: "FreeBSD", Users: []string{"ec2-user"}}
	}
	return imageFamily{}
}

// instanceLoginUsers derives the login users of a Linux instance from its
// image (ec2:DescribeImages); an image that cannot be read (deregistered,
// private to another account, no permission) falls back to the instance's
// PlatformDetails. It returns the users, what they were derived from, a
// note for an image of no known family, and whether EC2 Instance Connect
// comes with the image.
func instanceLoginUsers(ctx context.Context, l *locatedInstance) (users []string, from, note string, ic bool) {
	id := awssdk.ToString(l.inst.ImageId)
	pd := awssdk.ToString(l.inst.PlatformDetails)
	var im *ec2types.Image
	var readErr error
	if id != "" {
		out, err := l.c.ec2For(l.region).DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{id}})
		if err != nil {
			readErr = ec2Err("DescribeImages", l.region, err)
		} else {
			for i := range out.Images {
				if awssdk.ToString(out.Images[i].ImageId) == id {
					im = &out.Images[i]
				}
			}
		}
	}
	var fam imageFamily
	if im != nil {
		name := awssdk.ToString(im.Name)
		fam = familyOf(name, awssdk.ToString(im.Description), awssdk.ToString(im.PlatformDetails))
		from = "image " + id
		if name != "" {
			from += " (" + name + ")"
		}
	} else {
		fam = familyOf("", "", pd)
		from = "instance " + instanceLabel(l.inst)
		if pd != "" {
			from = "the platform details " + strconv.Quote(pd) + " of the instance"
		}
		switch {
		case id == "":
			note = fmt.Sprintf("note: instance %s names no image", instanceLabel(l.inst))
		case readErr != nil:
			note = fmt.Sprintf("note: cannot read image %s of instance %s: %v", id, instanceLabel(l.inst), readErr)
		default:
			note = fmt.Sprintf("note: cannot read image %s of instance %s: it is not visible to this account (deregistered or private)", id, instanceLabel(l.inst))
		}
	}
	if fam.Name == "" {
		u := "note: polyctl does not know the default user of " + from + "; trying " + strings.Join(unknownImageUsers, ", ") + " (pass --login-user to name it)"
		if note != "" {
			note += "\n" + u
		} else {
			note = u
		}
		return unknownImageUsers, from, note, false
	}
	from += ", " + fam.Name
	return fam.Users, from, note, fam.InstanceConnect
}

// sendSSHPublicKey makes key a valid login of user on the instance for 60
// seconds (ec2-instance-connect:SendSSHPublicKey).
func (c *client) sendSSHPublicKey(ctx context.Context, region, id, az, user string, key ssh.PublicKey) error {
	in := &ec2instanceconnect.SendSSHPublicKeyInput{InstanceId: awssdk.String(id), InstanceOSUser: awssdk.String(user),
		SSHPublicKey: awssdk.String(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))}
	if az != "" {
		in.AvailabilityZone = awssdk.String(az)
	}
	if _, err := c.icFor(region).SendSSHPublicKey(ctx, in); err != nil {
		m := mapErr(err)
		// AuthException (HTTP 400) is how EC2 Instance Connect says the
		// credentials may not push a key to this instance or for this OS
		// user (an ec2:osuser condition, say): an authorization failure.
		if apiErrorCode(err) == "AuthException" && !errors.Is(m, platform.ErrUnauthorized) {
			m = fmt.Errorf("%w: %w", platform.ErrUnauthorized, err)
		}
		if errors.Is(m, platform.ErrUnauthorized) {
			return fmt.Errorf("ec2-instance-connect:SendSSHPublicKey in %s (the credentials need the IAM action ec2-instance-connect:SendSSHPublicKey on the instance): %w", region, m)
		}
		return fmt.Errorf("ec2-instance-connect:SendSSHPublicKey in %s: %w", region, m)
	}
	return nil
}

// instanceKeyPair reads the key pair an instance was launched with
// (ec2:DescribeKeyPairs with its public key): nil and why, when it cannot
// be read. KeyName stays on the instance after the key pair is deleted.
func instanceKeyPair(ctx context.Context, l *locatedInstance) (*platform.KeyPair, string) {
	name := awssdk.ToString(l.inst.KeyName)
	if name == "" {
		return nil, ""
	}
	recs, err := l.c.describeKeyPairs(ctx, l.region, true)
	if err != nil {
		return nil, err.Error()
	}
	for _, r := range recs {
		if r.info.Name == name {
			return &platform.KeyPair{Name: name, ID: r.info.KeyPairID, Fingerprint: r.info.Fingerprint, PublicKey: r.publicKey}, ""
		}
	}
	return nil, "no key pair of that name in " + l.region + " (deleted?)"
}

func ec2SSHKeyCmd(rt *app.Runtime) *cobra.Command {
	var region string
	return app.SSHKeyCommands(rt, app.SSHKeyCommand{
		Platform: platform.AWS,
		Tree:     ec2InstanceTree,
		Detail: `AWS EC2: the login users come from the instance's image (ec2:DescribeImages):
ec2-user for Amazon Linux, Oracle Linux, FreeBSD and macOS, ubuntu for
Ubuntu, admin for Debian, centos then ec2-user for CentOS, fedora then
ec2-user for Fedora, ec2-user then root for Red Hat and SUSE, rocky for
Rocky Linux, bitnami for Bitnami. An image of another family, or one that
cannot be read, gets ec2-user, ubuntu, admin, centos, rocky, fedora,
bitnami and root tried in turn (pass --login-user to name the user).
The key pair is the instance's KeyName (ec2:DescribeKeyPairs, matched by
public key). Without a local private key of it, no other local key is
tried; the keys are reached through Systems Manager Run Command
(ssm:SendCommand of AWS-RunShellScript, run as root, the key script as the
target user) when the instance's SSM Agent is online
(ssm:DescribeInstanceInformation), else through EC2 Instance Connect: a key
generated in memory for this run is pushed (ec2-instance-connect:
SendSSHPublicKey, valid 60 seconds) for each login user in turn. Instance
Connect works on images with it installed (standard Amazon Linux 2023,
Amazon Linux 2 since 2019-06-18 and Ubuntu 20.04 or later ship it).`,
		Flags: func(cmd *cobra.Command) {
			cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
		},
		Resolve: func(ctx context.Context, arg string) (*app.SSHKeyInstance, error) {
			if arg == "" {
				ref, err := pickInstanceRef(ctx, rt, "<name|id>", "", region, "running Linux instance", false, func(in instanceInfo) bool {
					return in.State == stateRunning && in.Platform != string(ec2types.PlatformValuesWindows)
				})
				if err != nil {
					return nil, err
				}
				arg = ref
			}
			l, err := resolveInstance(ctx, rt, arg, region, false)
			if err != nil {
				return nil, err
			}
			inst := &app.SSHKeyInstance{Name: instanceName(l.inst), ID: l.id(), Target: l.target(),
				Windows: l.inst.Platform == ec2types.PlatformValuesWindows,
				Running: instanceState(l.inst) == stateRunning, State: instanceState(l.inst),
				PublicIP: awssdk.ToString(l.inst.PublicIpAddress), PrivateIP: awssdk.ToString(l.inst.PrivateIpAddress)}
			if inst.Windows || !inst.Running {
				return inst, nil
			}
			inst.LoginUsers, inst.LoginUsersFrom, inst.LoginUsersNote, _ = instanceLoginUsers(ctx, l)
			inst.KeyPairName = awssdk.ToString(l.inst.KeyName)
			inst.KeyPair, inst.KeyPairError = instanceKeyPair(ctx, l)
			inst.KeyPairMatch = platform.MatchAWS
			az := ""
			if l.inst.Placement != nil {
				az = awssdk.ToString(l.inst.Placement.AvailabilityZone)
			}
			inst.TempAccess = []app.SSHKeyAccess{
				{Name: "SSM Run Command",
					Check: func(ctx context.Context) error { return l.c.ssmManagedLinux(ctx, l.region, l.id()) },
					RunCommand: func(ctx context.Context, cmd string) ([]byte, []byte, int, error) {
						return l.c.runShellCommand(ctx, l.region, l.id(), cmd)
					}},
				{Name: "EC2 Instance Connect", PushKey: func(ctx context.Context, user string, key ssh.PublicKey) error {
					return l.c.sendSSHPublicKey(ctx, l.region, l.id(), az, user, key)
				}},
			}
			return inst, nil
		},
	})
}
