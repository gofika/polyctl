package namecom

import (
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
)

// Command returns the `polyctl namecom` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "namecom",
		Short: "name.com native commands",
	}
}
