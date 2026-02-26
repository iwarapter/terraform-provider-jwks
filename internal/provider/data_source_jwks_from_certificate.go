package provider

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type jwksFromCertificateDataSource struct{}

type jwksFromCertificateModel struct {
	Pem  types.String `tfsdk:"pem"`
	Kid  types.String `tfsdk:"kid"`
	Use  types.String `tfsdk:"use"`
	Alg  types.String `tfsdk:"alg"`
	Jwks types.String `tfsdk:"jwks"`
}

func newJwksFromCertificateDataSource() datasource.DataSource {
	return &jwksFromCertificateDataSource{}
}

func (d *jwksFromCertificateDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_from_certificate"
}

func (d *jwksFromCertificateDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Calculates a JSON Web Key Set from a given certificate.",
		Attributes: map[string]schema.Attribute{
			"pem": schema.StringAttribute{
				Required: true,
				Description: "Requires a PEM-encoded single certificate or correctly ordered certificate chain that starts with an end-entity certificate. " +
					"Each certificate in the chain is the certificate of the CA that issued the previous certificate.",
			},
			"kid": schema.StringAttribute{
				Optional:    true,
				Description: "Used to override the kid field of the JWK",
			},
			"use": schema.StringAttribute{
				Optional:    true,
				Description: "Used to populate the use field of the JWK",
			},
			"alg": schema.StringAttribute{
				Optional:    true,
				Description: "Used to populate the alg field of the JWK",
			},
			"jwks": schema.StringAttribute{
				Computed:    true,
				Description: "The calculated JWKS",
			},
		},
	}
}

func (d *jwksFromCertificateDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state jwksFromCertificateModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	certs, err := decodePem(state.Pem.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse pem", err.Error())
		return
	}

	certificates, err := parseChain(certs)
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse certificate chain", err.Error())
		return
	}

	leaf := certificates[0]

	kid := calculateCertificateThumbprint(leaf)
	if !state.Kid.IsNull() && !state.Kid.IsUnknown() {
		kid = state.Kid.ValueString()
	}

	use := ""
	if !state.Use.IsNull() && !state.Use.IsUnknown() {
		use = state.Use.ValueString()
	}

	alg := ""
	if !state.Alg.IsNull() && !state.Alg.IsUnknown() {
		alg = state.Alg.ValueString()
	}

	key, err := calculateKey(leaf, certificates, kid, use, alg)
	if err != nil {
		resp.Diagnostics.AddError("Unable to build JWK", err.Error())
		return
	}

	jsonResult, err := json.Marshal(key)
	if err != nil {
		resp.Diagnostics.AddError("Unable to serialize JWK", err.Error())
		return
	}

	state.Jwks = types.StringValue(string(jsonResult))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func parseChain(chain [][]byte) ([]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("certificate chain is empty")
	}

	var parsedCertificates []*x509.Certificate
	var prevCert *x509.Certificate
	var certPool = x509.NewCertPool()

	for _, crt := range chain {
		x509Cert, err := x509.ParseCertificate(crt)
		if err != nil {
			return nil, err
		}

		if prevCert != nil {
			if err := prevCert.CheckSignatureFrom(x509Cert); err != nil {
				return nil, errors.New("unable to validate the certificate signature chain")
			}
		}

		parsedCertificates = append(parsedCertificates, x509Cert)
		certPool.AddCert(x509Cert)
		prevCert = x509Cert
	}

	if _, err := prevCert.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
		return nil, err
	}

	return parsedCertificates, nil
}

func calculateCertificateThumbprint(x509Cert *x509.Certificate) string {
	sum := sha256.Sum256(x509Cert.Raw)
	return base64.URLEncoding.EncodeToString(sum[:])
}

func calculateKey(x509Cert *x509.Certificate, chain []*x509.Certificate, kid, use, alg string) (jwk.Key, error) {
	key, err := jwk.Import(x509Cert.PublicKey)
	if err != nil {
		return nil, err
	}

	x5c, err := processX5c(chain)
	if err != nil {
		return nil, err
	}

	if err = key.Set(jwk.X509CertChainKey, x5c); err != nil {
		return nil, err
	}

	if err = key.Set(jwk.X509CertThumbprintS256Key, calculateCertificateThumbprint(x509Cert)); err != nil {
		return nil, err
	}

	if err = key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}

	if use != "" {
		if err = key.Set(jwk.KeyUsageKey, use); err != nil {
			return nil, err
		}
	}

	if alg != "" {
		if err = key.Set(jwk.AlgorithmKey, alg); err != nil {
			return nil, err
		}
	}

	return key, nil
}

func processX5c(chain []*x509.Certificate) (*cert.Chain, error) {
	x5cs := &cert.Chain{}
	for _, x509Cert := range chain {
		err := x5cs.AddString(base64.StdEncoding.EncodeToString(x509Cert.Raw))
		if err != nil {
			return nil, err
		}
	}

	return x5cs, nil
}

func decodePem(certInput string) ([][]byte, error) {
	var certificates [][]byte
	pemData := []byte(strings.TrimSpace(certInput))

	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("unable to parse pem")
		}

		if block.Type == "CERTIFICATE" {
			certificates = append(certificates, block.Bytes)
		} else {
			return nil, fmt.Errorf("parsed pem is not of correct type, expected: CERTIFICATE, got: %s", block.Type)
		}
	}

	return certificates, nil
}
