package sdkv2provider

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lestrrat-go/jwx/jwk"
	"golang.org/x/crypto/ssh"
)

func dataSourceJwksFromPem() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceJwksFromPemRead,
		Schema:      dataSourceJwksFromPemSchema(),
		Description: `Calculates a JSON Web Key Set from a given public or private key.`,
	}
}

func dataSourceJwksFromPemSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"pem": {
			Type:        schema.TypeString,
			Required:    true,
			Description: `Required pem encoded public or private key.`,
		},
		"jwks": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: `The calculated JSON Web Key Sets.`,
		},
	}
}

func dataSourceJwksFromPemRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	data := d.Get("pem").(string)
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return diag.Errorf("unable to decode key pem")
	}
	keyData, err := ssh.ParseRawPrivateKey([]byte(data))
	if err != nil {
		keyData, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return diag.Errorf("unable to parse private or public key pem")
		}
	}
	key, err := jwk.New(keyData)
	if err != nil {
		return diag.FromErr(err)
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
