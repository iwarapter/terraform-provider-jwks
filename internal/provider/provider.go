package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func New() provider.Provider {
	return NewWithVersion("dev")
}

func NewWithVersion(version string) provider.Provider {
	return &jwksProvider{version: version}
}

func NewFunc(version string) func() provider.Provider {
	return func() provider.Provider {
		return NewWithVersion(version)
	}
}

type jwksProvider struct {
	version string
}

func (p *jwksProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "jwks"
	resp.Version = p.version
}

func (p *jwksProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{}
}

func (p *jwksProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *jwksProvider) Resources(_ context.Context) []func() resource.Resource {
	return nil
}

func (p *jwksProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newJwksFromKeyDataSource,
		newJwksFromCertificateDataSource,
	}
}
