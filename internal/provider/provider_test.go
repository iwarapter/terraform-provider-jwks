package provider_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/iwarapter/terraform-provider-jwks/internal/provider"
)

var testAccProviders map[string]func() (tfprotov6.ProviderServer, error)

func init() {
	testAccProviders = map[string]func() (tfprotov6.ProviderServer, error){
		"jwks": providerserver.NewProtocol6WithError(provider.New()),
	}
}

func testAccPreCheck(t *testing.T) {
}
