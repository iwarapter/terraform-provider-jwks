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
	"math/big"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type Keys struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Kty    *string  `json:"kty"`
	X5C    []string `json:"x5c"`
	N      *string  `json:"n"`
	E      *string  `json:"e"`
	Kid    *string  `json:"kid"`
	X5T256 *string  `json:"x5t#256"`
	X5Dn   *string  `json:"x5dn"`
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
		"treat_independently": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: `Determines whether to generate JWK for only leaf certificate in a chain and put other certificates into x5c (default) or generate JWKs for each certificate in a chain`,
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
	treatIndependently := d.Get("treat_independently").(bool)

	chain := decodePem(pemString)

	var keys []Key

	certificates := parseChain(chain.Certificate)

	if treatIndependently {
		for _, x509Cert := range certificates {
			keys = processCertificate(x509Cert, keys, []*x509.Certificate{x509Cert})
		}
	} else {
		leaf := certificates[0]
		keys = processCertificate(leaf, keys, certificates)
	}

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

func processCertificate(x509Cert *x509.Certificate, keys []Key, chain []*x509.Certificate) []Key {
	hash := sha256.New()
	hash.Write(x509Cert.Raw)
	kid := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	kty := x509Cert.PublicKeyAlgorithm.String()
	pulbicKey := x509Cert.PublicKey.(*rsa.PublicKey)

	e := strings.ReplaceAll(base64.StdEncoding.EncodeToString(big.NewInt(int64(pulbicKey.E)).Bytes()), "=", "")
	n := strings.ReplaceAll(base64.StdEncoding.EncodeToString(pulbicKey.N.Bytes()), "=", "")

	x5cs := processX5c(chain)

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(x509Cert.RawSubject, &subject); err != nil {
		diag.FromErr(err)
	}
	x5dn := subject.String()

	keys = append(keys, Key{
		Kty:    &kty,
		X5C:    x5cs,
		N:      &n,
		E:      &e,
		Kid:    &kid,
		X5T256: &kid,
		X5Dn:   &x5dn,
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
