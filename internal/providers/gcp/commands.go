package gcp

import (
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
)

// Command returns the `polyctl gcp` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "gcp",
		Short: "Google Cloud native commands",
	}
}
