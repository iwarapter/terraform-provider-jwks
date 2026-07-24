# terraform-provider-jwks

A Terraform provider for generating [JSON Web Key Sets (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517) from keys and certificates.

## Data Sources

### `jwks_from_key`

Generates a JWKS from a PEM-encoded or base64 DER-encoded public or private key.

```hcl
data "jwks_from_key" "example" {
  key = file("${path.module}/public.pem")
  kid = "my-key-id"
  use = "sig"
  alg = "RS256"
}

output "jwks" {
  value = data.jwks_from_key.example.jwks
}
```

Accepts keys from AWS KMS, local PEM files, or any base64 DER source:

```hcl
data "jwks_from_key" "kms" {
  key = data.aws_kms_public_key.example.public_key
}
```

### `jwks_from_certificate`

Generates a JWKS from a PEM-encoded certificate or certificate chain. The chain must be ordered with the end-entity certificate first.

```hcl
data "jwks_from_certificate" "example" {
  pem = file("${path.module}/certificate.pem")
  kid = "my-cert-id"
  use = "sig"
  alg = "RS256"
}
```

## Development

```sh
make test    # run tests
make checks  # fmt, vet, staticcheck, gosec
```
