// Command polyctl is a multi-platform CLI for cloud, CDN/DNS and registrar accounts.
package main

import (
	"os"

	"github.com/gofika/polyctl/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
