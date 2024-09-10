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

	"github.com/lestrrat-go/jwx/jwk"

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
		"generate_kid": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: `Used to populate the kid field of the JWK with the a key ID non-reversibly from the public key (only with public keys in PEM format). See https://github.com/kubernetes/kubernetes/blob/0f140bf1eeaf63c155f5eba1db8db9b5d52d5467/pkg/serviceaccount/jwt.go#L98`,
			Default:     false,
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
	} else {
		generateKid := d.Get("generate_kid").(bool)
		if generateKid {
			newKid, err := keyIDFromPublicKey(keyData)
			if err != nil {
				return diag.FromErr(err)
			} else {
				err = key.Set(jwk.KeyIDKey, newKid)
				if err != nil {
					return diag.FromErr(err)
				}
			}
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

func keyIDFromPublicKey(publicKey interface{}) (string, error) {

	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)

	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}
