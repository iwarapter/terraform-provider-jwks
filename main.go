package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5/tf5server"
	"github.com/hashicorp/terraform-plugin-mux/tf5muxserver"
	"github.com/iwarapter/terraform-provider-jwks/internal/sdkv2provider"
)

//go:generate terraform fmt -recursive ./examples/

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs

func main() {
	ctx := context.Background()
	providers := []func() tfprotov5.ProviderServer{
		sdkv2provider.Provider().GRPCProvider,
	}
	muxServer, err := tf5muxserver.NewMuxServer(ctx, providers...)
	if err != nil {
		panic(err)
	}
	err = tf5server.Serve("registry.terraform.io/iwarapter/jwks", muxServer.ProviderServer)
	if err != nil {
		panic(err)
	}
}
