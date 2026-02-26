package provider_test

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/iwarapter/terraform-provider-jwks/internal/provider"
)

func TestAccJwksFromCertificateDataSource(t *testing.T) {
	resourceName := "data.jwks_from_certificate.test"

	certificatePEM, _, err := acctest.RandTLSCert("terraform-provider-jwks")
	if err != nil {
		t.Fatalf("failed to generate certificate fixture: %v", err)
	}

	wrongOrderCert1, _, err := acctest.RandTLSCert("terraform-provider-jwks-a")
	if err != nil {
		t.Fatalf("failed to generate wrong-order certificate fixture #1: %v", err)
	}

	wrongOrderCert2, _, err := acctest.RandTLSCert("terraform-provider-jwks-b")
	if err != nil {
		t.Fatalf("failed to generate wrong-order certificate fixture #2: %v", err)
	}

	_, nonCertPEM, err := acctest.RandSSHKeyPair("terraform-provider-jwks-invalid")
	if err != nil {
		t.Fatalf("failed to generate non-certificate fixture: %v", err)
	}

	wrongOrderCertificatePEM := wrongOrderCert2 + "\n" + wrongOrderCert1

	expectedDefault := expectedJWKSFromCertificate(t, certificatePEM, "", "", "")
	expectedWithKid := expectedJWKSFromCertificate(t, certificatePEM, "123", "", "")
	expectedWithUse := expectedJWKSFromCertificate(t, certificatePEM, "", "sig", "")
	expectedWithAlg := expectedJWKSFromCertificate(t, certificatePEM, "", "", "RS256")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceConfig("jwks_from_certificate", "pem", certificatePEM, "", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedDefault),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_certificate", "pem", certificatePEM, "123", "", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedWithKid),
				),
			},
			{
				Config:      testAccDataSourceConfig("jwks_from_certificate", "pem", nonCertPEM, "", "", ""),
				ExpectError: regexp.MustCompile("parsed pem is not of correct type, expected: CERTIFICATE, got: RSA"),
			},
			{
				Config:      testAccDataSourceConfig("jwks_from_certificate", "pem", wrongOrderCertificatePEM, "", "", ""),
				ExpectError: regexp.MustCompile("unable to validate the certificate signature chain"),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_certificate", "pem", certificatePEM, "", "sig", ""),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedWithUse),
				),
			},
			{
				Config: testAccDataSourceConfig("jwks_from_certificate", "pem", certificatePEM, "", "", "RS256"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", expectedWithAlg),
				),
			},
		},
	})
}

func expectedJWKSFromCertificate(t *testing.T, pemData, kid, use, alg string) string {
	t.Helper()

	chainRaw, err := provider.DecodePem(pemData)
	if err != nil {
		t.Fatalf("failed to deco	de pem fixture: %v", err)
	}

	chain, err := provider.ParseChain(chainRaw)
	if err != nil {
		t.Fatalf("failed to parse certificate fixture chain: %v", err)
	}

	leaf := chain[0]
	resolvedKid := kid
	if resolvedKid == "" {
		resolvedKid = provider.CalculateCertificateThumbprint(leaf)
	}

	key, err := provider.CalculateKey(leaf, chain, resolvedKid, use, alg)
	if err != nil {
		t.Fatalf("failed to calculate expected jwk fixture: %v", err)
	}

	jsonResult, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("failed to marshal expected jwk fixture: %v", err)
	}

	return string(jsonResult)
}
