package sdkv2provider

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"filippo.io/mldsa"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

// ML-DSA OIDs from NIST FIPS 204 / draft-ietf-lamps-dilithium-certificates.
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

func dataSourceJwksFromKey() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceJwksFromKeyRead,
		Schema:      dataSourceJwksFromKeySchema(),
		Description: `Calculates a JSON Web Key Set from a given public or private key.`,
	}
}

func dataSourceJwksFromKeySchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"key": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `Requires a PEM-encoded or base64 DER-encoded public or private key. ML-DSA public keys may be provided in PKIX PEM format (BEGIN PUBLIC KEY) or as raw base64-encoded bytes. ML-DSA private seeds may be provided in PKCS#8 PEM format (BEGIN PRIVATE KEY) or as a raw base64-encoded 32-byte seed (requires alg).`,
		},
		"kid": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Used to populate the kid field of the JWK.`,
		},
		"use": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Used to populate the use field of the JWK.`,
		},
		"alg": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Used to populate the alg field of the JWK. Required when providing a raw 32-byte ML-DSA private seed to identify the parameter set (ML-DSA-44, ML-DSA-65, or ML-DSA-87). Not required for PKCS#8 PEM, which is self-describing.`,
		},
		"jwks": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: `The calculated JSON Web Key Sets.`,
		},
	}
}

func dataSourceJwksFromKeyRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var keyData interface{}
	var err error
	data := d.Get("key").(string)
	dataBytes := []byte(data)
	b64data, err := base64.StdEncoding.DecodeString(data)
	if err == nil {
		dataBytes = b64data
	}
	block, _ := pem.Decode(dataBytes)
	if block != nil {
		keyData, err = ssh.ParseRawPrivateKey(dataBytes)
		if err != nil {
			keyData, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				keyData, err = parsePKIXMLDSAPublicKey(block.Bytes)
				if err != nil {
					keyData, err = parsePKCS8MLDSAPrivateKey(block.Bytes)
					if err != nil {
						keyData, err = parseMLDSAKey(d, block.Bytes)
						if err != nil {
							return diag.Errorf("unable to parse private or public key pem")
						}
					}
				}
			}
		}
	} else {
		keyData, err = x509.ParsePKCS8PrivateKey(dataBytes)
		if err != nil {
			keyData, err = x509.ParsePKCS1PrivateKey(dataBytes)
			if err != nil {
				keyData, err = x509.ParseECPrivateKey(dataBytes)
				if err != nil {
					keyData, err = x509.ParsePKIXPublicKey(dataBytes)
					if err != nil {
						keyData, err = parsePKIXMLDSAPublicKey(dataBytes)
						if err != nil {
							keyData, err = parsePKCS8MLDSAPrivateKey(dataBytes)
							if err != nil {
								keyData, err = parseMLDSAKey(d, dataBytes)
								if err != nil {
									return diag.FromErr(err)
								}
							}
						}
					}
				}
			}
		}
	}

	key, err := jwk.Import[jwk.Key](keyData)
	if err != nil {
		return diag.FromErr(err)
	}
	kid, ok := d.GetOk("kid")
	if ok {
		err = key.Set(jwk.KeyIDKey, kid.(string))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	use, ok := d.GetOk("use")
	if ok {
		err = key.Set(jwk.KeyUsageKey, use.(string))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	alg, ok := d.GetOk("alg")
	if ok {
		err = key.Set(jwk.AlgorithmKey, alg.(string))
		if err != nil {
			return diag.FromErr(err)
		}
	}
	b, err := json.Marshal(key)
	if err != nil {
		return diag.FromErr(err)
	}
	tb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return diag.Errorf("unable to generate fingerprint: %s", err)
	}
	d.SetId(hex.EncodeToString(tb))
	return diag.FromErr(d.Set("jwks", string(b)))
}

func mldsaParamsFromOID(oid asn1.ObjectIdentifier) (*mldsa.Parameters, error) {
	switch {
	case oid.Equal(oidMLDSA44):
		return mldsa.MLDSA44(), nil
	case oid.Equal(oidMLDSA65):
		return mldsa.MLDSA65(), nil
	case oid.Equal(oidMLDSA87):
		return mldsa.MLDSA87(), nil
	default:
		return nil, fmt.Errorf("not an ML-DSA OID: %s", oid)
	}
}

// parsePKIXMLDSAPublicKey parses a SubjectPublicKeyInfo DER block whose OID is
// one of the ML-DSA OIDs (draft-ietf-lamps-dilithium-certificates). The BIT
// STRING contains the raw public key bytes as produced by Go 1.27+ crypto/x509.
func parsePKIXMLDSAPublicKey(der []byte) (interface{}, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &spki); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("not a valid PKIX structure")
	}
	params, err := mldsaParamsFromOID(spki.Algorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	return mldsa.NewPublicKey(params, spki.PublicKey.Bytes)
}

// parsePKCS8MLDSAPrivateKey parses a PKCS#8 / OneAsymmetricKey DER block whose
// OID is one of the ML-DSA OIDs. Go 1.27+ encodes the 32-byte seed inside the
// privateKey OCTET STRING as a context-specific [0] primitive tag.
func parsePKCS8MLDSAPrivateKey(der []byte) (interface{}, error) {
	var key struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &key); err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("not a valid PKCS#8 structure")
	}
	params, err := mldsaParamsFromOID(key.Algorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	// Go 1.27 encodes the seed as [0] context-specific primitive inside the
	// privateKey OCTET STRING content.
	var rawSeed asn1.RawValue
	if _, err := asn1.Unmarshal(key.PrivateKey, &rawSeed); err != nil {
		return nil, fmt.Errorf("invalid ML-DSA private key encoding: %w", err)
	}
	if rawSeed.Class != asn1.ClassContextSpecific || rawSeed.Tag != 0 {
		return nil, fmt.Errorf("unexpected ML-DSA private key tag (class=%d tag=%d)", rawSeed.Class, rawSeed.Tag)
	}
	return mldsa.NewPrivateKey(params, rawSeed.Bytes)
}

// parseMLDSAKey detects ML-DSA keys by raw byte length. Public keys are
// unambiguous (1312/1952/2592 bytes). A 32-byte input is treated as a
// private-key seed and requires the alg field to identify the parameter set.
func parseMLDSAKey(d *schema.ResourceData, b []byte) (interface{}, error) {
	switch len(b) {
	case mldsa.MLDSA44().PublicKeySize():
		return mldsa.NewPublicKey(mldsa.MLDSA44(), b)
	case mldsa.MLDSA65().PublicKeySize():
		return mldsa.NewPublicKey(mldsa.MLDSA65(), b)
	case mldsa.MLDSA87().PublicKeySize():
		return mldsa.NewPublicKey(mldsa.MLDSA87(), b)
	case 32:
		algVal, ok := d.GetOk("alg")
		if !ok {
			return nil, fmt.Errorf("32-byte input requires alg set to ML-DSA-44, ML-DSA-65, or ML-DSA-87")
		}
		var params *mldsa.Parameters
		switch algVal.(string) {
		case "ML-DSA-44":
			params = mldsa.MLDSA44()
		case "ML-DSA-65":
			params = mldsa.MLDSA65()
		case "ML-DSA-87":
			params = mldsa.MLDSA87()
		default:
			return nil, fmt.Errorf("unrecognised ML-DSA alg %q: must be ML-DSA-44, ML-DSA-65, or ML-DSA-87", algVal.(string))
		}
		return mldsa.NewPrivateKey(params, b)
	default:
		return nil, fmt.Errorf("unable to parse key: not a recognised DER, SSH, or ML-DSA format")
	}
}
