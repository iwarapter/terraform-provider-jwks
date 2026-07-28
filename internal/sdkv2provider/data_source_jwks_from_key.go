package sdkv2provider

import (
	"context"
	"crypto"
	"crypto/x509"
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
			Description: `Requires either a pem encoded or base64 der encoded public or private key.`,
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
			Description: `Used to populate the alg field of the JWK.`,
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
		//handle pem encoded
		keyData, err = ssh.ParseRawPrivateKey(dataBytes)
		if err != nil {
			keyData, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return diag.Errorf("unable to parse private or public key pem")
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
						keyData, err = parseMLDSAKey(d, dataBytes)
						if err != nil {
							return diag.FromErr(err)
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
		return nil, fmt.Errorf("unable to parse private or public key pem")
	}
}
