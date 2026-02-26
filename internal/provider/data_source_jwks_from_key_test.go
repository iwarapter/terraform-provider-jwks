package provider_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/iwarapter/terraform-provider-jwks/internal/provider"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func TestAccJwksFromKeyDataSource(t *testing.T) {
	resourceName := "data.jwks_from_key.test"

	rsaPrivatePEM, rsaPublicPEM := testRSAPEMFixtures(t)
	ecPrivatePEM, ecPublicPEM := testECP384PEMFixtures(t)

	rsaPrivateDER := testDERBase64FromPEM(t, rsaPrivatePEM)
	rsaPublicDER := testDERBase64FromPEM(t, rsaPublicPEM)
	ecPrivateDER := testDERBase64FromPEM(t, ecPrivatePEM)
	ecPublicDER := testDERBase64FromPEM(t, ecPublicPEM)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", rsaPrivatePEM, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, rsaPrivatePEM, "", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", rsaPublicPEM, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, rsaPublicPEM, "", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", ecPrivatePEM, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, ecPrivatePEM, "", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", ecPublicPEM, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, ecPublicPEM, "", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", rsaPrivateDER, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, rsaPrivateDER, "", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", rsaPublicDER, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, rsaPublicDER, "", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", ecPrivateDER, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, ecPrivateDER, "", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", ecPublicDER, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, ecPublicDER, "", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", ecPrivateDER, "123", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, ecPrivateDER, "123", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", ecPublicDER, "123", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, ecPublicDER, "123", "", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", rsaPublicPEM, "", "sig", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, rsaPublicPEM, "", "sig", "")),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_key", "key", rsaPublicPEM, "", "", "RS256"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedJWKSFromKey(t, rsaPublicPEM, "", "", "RS256")),
				),
			},
		},
	})
}

func expectedJWKSFromKey(t *testing.T, keyInput, kid, use, alg string) string {
	t.Helper()

	keyData, err := provider.ParseRawKey(keyInput)
	if err != nil {
		t.Fatalf("failed to parse expected key fixture: %v", err)
	}

	key, err := jwk.Import(keyData)
	if err != nil {
		t.Fatalf("failed to import expected key fixture: %v", err)
	}

	if kid != "" {
		if err = key.Set(jwk.KeyIDKey, kid); err != nil {
			t.Fatalf("failed to set expected kid: %v", err)
		}
	}

	if use != "" {
		if err = key.Set(jwk.KeyUsageKey, use); err != nil {
			t.Fatalf("failed to set expected use: %v", err)
		}
	}

	if alg != "" {
		if err = key.Set(jwk.AlgorithmKey, alg); err != nil {
			t.Fatalf("failed to set expected alg: %v", err)
		}
	}

	b, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("failed to marshal expected key fixture: %v", err)
	}

	return string(b)
}

func testRSAPEMFixtures(t *testing.T) (string, string) {
	t.Helper()

	_, privatePEM, err := acctest.RandSSHKeyPair("terraform-provider-jwks")
	if err != nil {
		t.Fatalf("failed to generate RSA fixture with acctest: %v", err)
	}

	block, _ := pem.Decode([]byte(privatePEM))
	if block == nil {
		t.Fatalf("failed to decode RSA private fixture PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse RSA private fixture key: %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public fixture key: %v", err)
	}

	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	return privatePEM, publicPEM
}

func testECP384PEMFixtures(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC private fixture key: %v", err)
	}

	privateDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal EC private fixture key: %v", err)
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal EC public fixture key: %v", err)
	}

	privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}))
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	return privatePEM, publicPEM
}

func testDERBase64FromPEM(t *testing.T, pemData string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		t.Fatalf("failed to decode PEM fixture into DER")
	}

	return base64.StdEncoding.EncodeToString(block.Bytes)
}
