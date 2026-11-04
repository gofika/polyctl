package aws

import (
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
)

// Command returns the `polyctl aws` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "aws",
		Short: "Amazon Web Services native commands",
	}
}
