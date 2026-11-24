package aliyun

import (
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
)

// newImageCmd is `aliyun ecs image`: latest.
func newImageCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "image", Short: "ECS system images"}
	cmd.AddCommand(imageLatestCmd(rt))
	return cmd
}

func imageLatestCmd(rt *app.Runtime) *cobra.Command {
	var osName, arch, region string
	cmd := &cobra.Command{
		Use:   "latest",
		Short: "Print the id of the newest public image of an OS in a region",
		Long: `Print the id of the newest public (system) image of --os for --arch in the
profile's region (or --region). The available public images of the OS
type and architecture are listed (every page) and filtered by the pattern
of their image family, whose number is the OS version; the highest version
wins, then the newest creation time. No family name or image id is
written into polyctl, so a new version is picked as soon as it is
published.

- alibaba-cloud-linux (default): the standard LTS images,
  acs:alibaba_cloud_linux_<version>[_<release>]_lts_x64 (or _lts_arm64),
  such as acs:alibaba_cloud_linux_4_lts_x64 or
  acs:alibaba_cloud_linux_3_2104_lts_x64; the pro, container optimized,
  agentic, GPU and compliance variants are never picked.
- windows: Windows Server Datacenter, Chinese edition,
  acs:win_<version>_datacenter_x64_zh (x86_64 only); the English, Core,
  UEFI and container editions are never picked.

Other systems (Ubuntu, Debian, ...) are not picked: pass their image id
with --image to create and ensure. No matching image is exit code 4. The
table output is the image id alone, for $(...); -o json adds its name, OS
name, architecture, creation time and region. Image ids are regional. It
writes nothing, and --dry-run changes nothing in it.`,
		Example: `  polyctl aliyun ecs image latest
  polyctl aliyun ecs image latest --arch arm64 --region cn-hongkong -o json
  polyctl aliyun ecs image latest --os windows`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkImageOS(osName, arch); err != nil {
				return err
			}
			ctx := cmd.Context()
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			im, err := s.c.latestImage(ctx, s.region, osName, arch)
			if err != nil {
				return err
			}
			rt.Infof("%s (%s, created %s) in %s", im.ImageID, im.OSName, im.CreationTime, s.where())
			return rt.Render(im, func() output.Grid { return output.Grid{Rows: [][]string{{im.ImageID}}} })
		},
	}
	cmd.Flags().StringVar(&osName, "os", osAlibabaCloudLinux, "operating system: "+supportedOSes)
	cmd.Flags().StringVar(&arch, "arch", archX86, "architecture: "+archX86+" or "+archARM)
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}
