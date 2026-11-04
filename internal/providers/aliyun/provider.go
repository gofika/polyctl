// Package aliyun implements the Alibaba Cloud provider.
package aliyun

import (
	"context"

	"github.com/gofika/polyctl/internal/platform"
)

func init() { platform.Register(&provider{}) }

type provider struct{}

func (*provider) ID() platform.ID                        { return platform.Aliyun }
func (*provider) DisplayName() string                    { return "Alibaba Cloud" }
func (*provider) LoginHelp() string                      { return "not implemented yet" }
func (*provider) ResourceTypes() []platform.ResourceType { return nil }

func (*provider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	return nil, platform.ErrNotSupported
}

func (*provider) Open(ctx context.Context, p platform.Profile) (platform.Client, error) {
	return nil, platform.ErrNotSupported
}
