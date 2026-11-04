package cli

import (
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/providers/aliyun"
	"github.com/gofika/polyctl/internal/providers/aws"
	"github.com/gofika/polyctl/internal/providers/cloudflare"
	"github.com/gofika/polyctl/internal/providers/gcp"
	"github.com/gofika/polyctl/internal/providers/godaddy"
	"github.com/gofika/polyctl/internal/providers/namecom"
)

// platformCommands mounts each platform's native command tree.
func platformCommands(rt *app.Runtime) []*cobra.Command {
	cmds := []*cobra.Command{
		cloudflare.Command(rt),
		namecom.Command(rt),
		godaddy.Command(rt),
		aws.Command(rt),
		gcp.Command(rt),
		aliyun.Command(rt),
	}
	for _, c := range cmds {
		c.GroupID = "platforms"
	}
	return cmds
}
