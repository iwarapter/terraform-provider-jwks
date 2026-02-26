package provider

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/crypto/ssh"
)

type jwksFromKeyDataSource struct{}

type jwksFromKeyModel struct {
	Key  types.String `tfsdk:"key"`
	Kid  types.String `tfsdk:"kid"`
	Use  types.String `tfsdk:"use"`
	Alg  types.String `tfsdk:"alg"`
	Jwks types.String `tfsdk:"jwks"`
}

func newJwksFromKeyDataSource() datasource.DataSource {
	return &jwksFromKeyDataSource{}
}

func (d *jwksFromKeyDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_from_key"
}

func (d *jwksFromKeyDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Calculates a JSON Web Key Set from a given public or private key.",
		Attributes: map[string]schema.Attribute{
			"key": schema.StringAttribute{
				Required:    true,
				Description: "Requires either a pem encoded or base64 der encoded public or private key.",
			},
			"kid": schema.StringAttribute{
				Optional:    true,
				Description: "Used to populate the kid field of the JWK.",
			},
			"use": schema.StringAttribute{
				Optional:    true,
				Description: "Used to populate the use field of the JWK.",
			},
			"alg": schema.StringAttribute{
				Optional:    true,
				Description: "Used to populate the alg field of the JWK.",
			},
			"jwks": schema.StringAttribute{
				Computed:    true,
				Description: "The calculated JSON Web Key Sets.",
			},
		},
	}
}

func (d *jwksFromKeyDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state jwksFromKeyModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyData, err := parseRawKey(state.Key.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse key", err.Error())
		return
	}

	key, err := jwk.Import(keyData)
	if err != nil {
		resp.Diagnostics.AddError("Unable to import key", err.Error())
		return
	}

	if !state.Kid.IsNull() && !state.Kid.IsUnknown() {
		if err = key.Set(jwk.KeyIDKey, state.Kid.ValueString()); err != nil {
			resp.Diagnostics.AddError("Unable to set kid", err.Error())
			return
		}
	}

	if !state.Use.IsNull() && !state.Use.IsUnknown() {
		if err = key.Set(jwk.KeyUsageKey, state.Use.ValueString()); err != nil {
			resp.Diagnostics.AddError("Unable to set use", err.Error())
			return
		}
	}

	if !state.Alg.IsNull() && !state.Alg.IsUnknown() {
		if err = key.Set(jwk.AlgorithmKey, state.Alg.ValueString()); err != nil {
			resp.Diagnostics.AddError("Unable to set alg", err.Error())
			return
		}
	}

	b, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Unable to serialize key", err.Error())
		return
	}

	state.Jwks = types.StringValue(string(b))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func parseRawKey(data string) (any, error) {
	dataBytes := []byte(data)
	b64data, err := base64.StdEncoding.DecodeString(data)
	if err == nil {
		dataBytes = b64data
	}

	block, _ := pem.Decode(dataBytes)
	if block != nil {
		keyData, privateErr := ssh.ParseRawPrivateKey(dataBytes)
		if privateErr == nil {
			return keyData, nil
		}

		keyData, publicErr := x509.ParsePKIXPublicKey(block.Bytes)
		if publicErr == nil {
			return keyData, nil
		}

		return nil, errors.Join(privateErr, publicErr)
	}

	var parseErrors []error

	if keyData, parseErr := x509.ParsePKCS8PrivateKey(dataBytes); parseErr == nil {
		return keyData, nil
	} else {
		parseErrors = append(parseErrors, parseErr)
	}

	if keyData, parseErr := x509.ParsePKCS1PrivateKey(dataBytes); parseErr == nil {
		return keyData, nil
	} else {
		parseErrors = append(parseErrors, parseErr)
	}

	if keyData, parseErr := x509.ParseECPrivateKey(dataBytes); parseErr == nil {
		return keyData, nil
	} else {
		parseErrors = append(parseErrors, parseErr)
	}

	if keyData, parseErr := x509.ParsePKIXPublicKey(dataBytes); parseErr == nil {
		return keyData, nil
	} else {
		parseErrors = append(parseErrors, parseErr)
	}

	return nil, errors.Join(parseErrors...)
}
