// Package cloudflare implements the Cloudflare provider.
package cloudflare

import (
	"context"

	"github.com/gofika/polyctl/internal/platform"
)

func init() { platform.Register(&provider{}) }

type provider struct{}

func (*provider) ID() platform.ID                        { return platform.Cloudflare }
func (*provider) DisplayName() string                    { return "Cloudflare" }
func (*provider) LoginHelp() string                      { return "not implemented yet" }
func (*provider) ResourceTypes() []platform.ResourceType { return nil }

func (*provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	return nil, platform.ErrNotSupported
}

func (*provider) Open(ctx context.Context, p platform.Profile) (platform.Client, error) {
	return nil, platform.ErrNotSupported
}
