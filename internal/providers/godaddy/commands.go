package godaddy

import (
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
)

// Command returns the `polyctl godaddy` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "godaddy",
		Short: "GoDaddy native commands",
	}
}
