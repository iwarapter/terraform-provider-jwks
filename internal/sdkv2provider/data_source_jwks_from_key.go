package sdkv2provider

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

func dataSourceJwksFromKey() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceJwksFromKeyRead,
		Schema:      dataSourceJwksFromKeySchema(),
		Description: `Calculates a JSON Web Key Set from a given public or private key. RSA and EC keys are emitted as RFC 7517 JWKs; ML-DSA (FIPS 204) public keys are emitted as RFC 9964 AKP JWKs.`,
	}
}

func dataSourceJwksFromKeySchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"key": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `Requires either a pem encoded or base64 der encoded public or private key. RSA, EC and ML-DSA (ML-DSA-44, ML-DSA-65, ML-DSA-87) keys are supported.`,
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

	// ML-DSA SPKI is not handled by crypto/x509 or jwx, so detect it and emit the
	// RFC 9964 AKP JWK before the RSA/EC handling below.
	mldsaDER := dataBytes
	if block != nil {
		mldsaDER = block.Bytes
	}
	if alg, pub, ok := mldsaFromSPKI(mldsaDER); ok {
		jwks, id, mErr := mldsaJWK(alg, pub, d.Get("kid").(string), d.Get("use").(string), d.Get("alg").(string))
		if mErr != nil {
			return diag.FromErr(mErr)
		}
		d.SetId(id)
		return diag.FromErr(d.Set("jwks", jwks))
	}

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
						return diag.Errorf("unable to parse private or public key pem")
					}
				}
			}
		}
	}

	key, err := jwk.New(keyData)
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
