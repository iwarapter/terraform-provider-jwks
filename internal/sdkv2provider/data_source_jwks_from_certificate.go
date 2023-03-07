package sdkv2provider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lestrrat-go/jwx/jwk"
)

func dataSourceJwksFromCertificate() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceJwksFromCertificateRead,
		Schema:      dataSourceJwksFromCertificateSchema(),
		Description: `Calculates a JSON Web Key Set from a given certificate.`,
	}
}

func dataSourceJwksFromCertificateSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"pem": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `Requires a pem encoded single certificate or correctly ordered certificate chain`,
		},
		"kid": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Used to override the kid field of the JWK.`,
		},
		"jwks": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: `The calculated JWKS`,
		},
	}
}

func dataSourceJwksFromCertificateRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	pemString := d.Get("pem").(string)

	chain := decodePem(pemString)

	certificates, err := parseChain(chain.Certificate)

	if err != nil {
		return diag.FromErr(err)
	}

	leaf := certificates[0]

	var kid string
	if k, ok := d.GetOk("kid"); ok {
		kid = k.(string)
	} else {
		kid = calculateCertificateThumbprint(leaf)
	}

	key, err := calculateKey(leaf, certificates, kid)

	if err != nil {
		return diag.FromErr(err)
	}

	jsonResult, err := json.Marshal(key)

	if err != nil {
		return diag.FromErr(err)
	}

	tb, err := key.Thumbprint(crypto.SHA256)

	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(hex.EncodeToString(tb))
	return diag.FromErr(d.Set("jwks", string(jsonResult)))
}

func parseChain(chain [][]byte) ([]*x509.Certificate, error) {
	var parsedCertificates []*x509.Certificate
	var prevCert *x509.Certificate
	var certPool = x509.NewCertPool()

	for _, cert := range chain {
		x509Cert, err := x509.ParseCertificate(cert)

		if err != nil {
			return nil, err
		}

		if prevCert != nil {
			if err := prevCert.CheckSignatureFrom(x509Cert); err != nil {
				return nil, err
			}
		}
		parsedCertificates = append(parsedCertificates, x509Cert)
		certPool.AddCert(x509Cert)
		prevCert = x509Cert
	}

	if _, err := prevCert.Verify(x509.VerifyOptions{
		Roots: certPool,
	}); err != nil {
		return nil, err
	}

	return parsedCertificates, nil
}

func calculateCertificateThumbprint(x509Cert *x509.Certificate) string {
	hash := sha256.New()
	hash.Write(x509Cert.Raw)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func calculateKey(x509Cert *x509.Certificate, chain []*x509.Certificate, kid string) (jwk.Key, error) {

	key, err := jwk.New(x509Cert.PublicKey.(*rsa.PublicKey))

	if err != nil {
		return nil, err
	}

	if err := key.Set(jwk.X509CertChainKey, processX5c(chain)); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.X509CertThumbprintS256Key, calculateCertificateThumbprint(x509Cert)); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}

	return key, nil
}

func processX5c(chain []*x509.Certificate) (x5cs []string) {
	for _, x509Cert := range chain {
		x5cs = append(x5cs, base64.StdEncoding.EncodeToString(x509Cert.Raw))
	}

	return x5cs
}

func decodePem(certInput string) tls.Certificate {
	var cert tls.Certificate
	certPEMBlock := []byte(certInput)

	var certDERBlock *pem.Block
	for {

		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)

		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}