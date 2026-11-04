package cloudflare

import (
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
)

// Command returns the `polyctl cf` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "cf",
		Short: "Cloudflare native commands",
	}
}
