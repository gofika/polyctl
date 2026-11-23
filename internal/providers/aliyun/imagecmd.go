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
		Short: "Print the id of the newest system image of an OS in a region",
		Long: `Print the id of the newest plain Alibaba Cloud Linux system image of the
profile's region (or --region) for --arch: the newest image of the family of
version 4, else 3, else 2 (acs:alibaba_cloud_linux_<version>_lts_<arch>);
variants such as pro, container optimized or agentic images are never
picked. When none of these families answers, the available system images
are listed and the plain image of the highest version (then the newest)
is picked. The table output is the image id alone, for $(...); -o json
adds its name, OS name, architecture, creation time and region. Image ids
are regional. Only --os alibaba-cloud-linux is supported. It writes
nothing, and --dry-run changes nothing in it.`,
		Example: `  polyctl aliyun ecs image latest
  polyctl aliyun ecs image latest --arch arm64 --region cn-hongkong -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if osName != osAlibabaCloudLinux {
				return app.UsageErrf("unsupported os %q: --os takes %s", osName, osAlibabaCloudLinux)
			}
			if arch != archX86 && arch != archARM {
				return app.UsageErrf("unsupported architecture %q: --arch takes %s or %s", arch, archX86, archARM)
			}
			ctx := cmd.Context()
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			im, err := s.c.latestAlinuxImage(ctx, s.region, arch)
			if err != nil {
				return err
			}
			rt.Infof("%s (%s, created %s) in %s", im.ImageID, im.OSName, im.CreationTime, s.where())
			return rt.Render(im, func() output.Grid { return output.Grid{Rows: [][]string{{im.ImageID}}} })
		},
	}
	cmd.Flags().StringVar(&osName, "os", osAlibabaCloudLinux, "operating system: "+osAlibabaCloudLinux)
	cmd.Flags().StringVar(&arch, "arch", archX86, "architecture: "+archX86+" or "+archARM)
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}
