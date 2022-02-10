package sdkv2provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-mux/tf5muxserver"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var testAccProvider *schema.Provider
var testAccProviders map[string]func() (tfprotov5.ProviderServer, error)

func init() {
	testAccProvider = Provider()
	testAccProviders = map[string]func() (tfprotov5.ProviderServer, error){
		"jwks": func() (tfprotov5.ProviderServer, error) {
			ctx := context.Background()
			sdkv2 := testAccProvider.GRPCProvider
			factory, err := tf5muxserver.NewMuxServer(ctx, sdkv2)
			if err != nil {
				return nil, err
			}
			return factory.ProviderServer(), nil
		},
	}
}

func testAccPreCheck(t *testing.T) {
}
