package sdkv2provider

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lestrrat-go/jwx/jwk"
)

type Keys struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Kty     *string  `json:"kty"`
	X5C     []string `json:"x5c"`
	N       *string  `json:"n"`
	E       *string  `json:"e"`
	Kid     *string  `json:"kid"`
	X5TS256 *string  `json:"x5t#S256"`
}

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
			Description: `Requires a pem encoded certificate.`,
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

	var keys []Key

	certificates := parseChain(chain.Certificate)

	leaf := certificates[0]

	var kid string
	if k, ok := d.GetOk("kid"); ok {
		kid = k.(string)
	} else {
		kid = calculateCertificateThumbprint(leaf)
	}

	keys = processCertificate(leaf, keys, certificates, kid)

	jsonResult, err := json.Marshal(Keys{Keys: keys})

	if err != nil {
		diag.FromErr(err)
	}

	d.SetId(hex.EncodeToString(jsonResult))
	return diag.FromErr(d.Set("jwks", string(jsonResult)))
}

func parseChain(chain [][]byte) []*x509.Certificate {
	var parsedCertificates []*x509.Certificate

	for _, cert := range chain {
		x509Cert, err := x509.ParseCertificate(cert)
		parsedCertificates = append(parsedCertificates, x509Cert)
		if err != nil {
			diag.FromErr(err)
		}
	}
	return parsedCertificates
}

func calculateCertificateThumbprint(x509Cert *x509.Certificate) string {
	hash := sha256.New()
	hash.Write(x509Cert.Raw)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func processCertificate(x509Cert *x509.Certificate, keys []Key, chain []*x509.Certificate, kid string) []Key {

	publicKey := jwk.NewRSAPublicKey()
	if err := publicKey.FromRaw(x509Cert.PublicKey.(*rsa.PublicKey)); err != nil {
		diag.FromErr(err)
	}

	kty := x509Cert.PublicKeyAlgorithm.String()

	e := base64.StdEncoding.EncodeToString(publicKey.E())
	n := base64.StdEncoding.EncodeToString(publicKey.N())

	x5cs := processX5c(chain)
	x5ts256 := calculateCertificateThumbprint(x509Cert)

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(x509Cert.RawSubject, &subject); err != nil {
		diag.FromErr(err)
	}

	keys = append(keys, Key{
		Kty:     &kty,
		X5C:     x5cs,
		N:       &n,
		E:       &e,
		Kid:     &kid,
		X5TS256: &x5ts256,
	})
	return keys
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
