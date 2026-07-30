data "jwks_from_key" "pem_example" {
  key = <<EOF
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgUElV5mwqkloIrM8ZNZ7
2gSCcnSJt7+/Usa5G+D15YQUAdf9c1zEekTfHgDP+04nw/uFNFaE5v1RbHaPxhZY
Vg5ZErNCa/hzn+x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL/c3H/B+2G
le3hTxjlWFb3F5qLgR+4Mf4ruhER1v6eHQa/nchi03MBpT4UeJ7MrL92hTJYLdpS
yCqmr8yjxkKJDVC2uRrr+sTSxfh7r6v24u/vp/QTmBIAlNPgadVAZw17iNNb7vjV
7Gwl/5gHXonCUKURaV++dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV+
7QIDAQAB
-----END PUBLIC KEY-----
EOF
}

data "jwks_from_key" "base64_der_example" {
  key = data.aws_kms_public_key.example.public_key
}

data "jwks_from_key" "base64_der_with_metadata" {
  key = data.aws_kms_public_key.example.public_key
  kid = "123"
  use = "sig"
  alg = "RS256"
}

# ML-DSA-44 public key in PKIX/SubjectPublicKeyInfo PEM format (BEGIN PUBLIC KEY).
# The OID (2.16.840.1.101.3.4.3.17) identifies ML-DSA-44; no alg attribute needed.
# Generate with: go1.27+ crypto/x509.MarshalPKIXPublicKey or openssl pkey (1.x+).
data "jwks_from_key" "mldsa44_public" {
  key = file("${path.module}/mldsa44_public.pem")
  kid = "my-mldsa44-key"
  use = "sig"
}

# ML-DSA-65 public key in PKIX format (OID 2.16.840.1.101.3.4.3.18).
data "jwks_from_key" "mldsa65_public" {
  key = file("${path.module}/mldsa65_public.pem")
  kid = "my-mldsa65-key"
  use = "sig"
}

# ML-DSA-87 public key in PKIX format (OID 2.16.840.1.101.3.4.3.19).
data "jwks_from_key" "mldsa87_public" {
  key = file("${path.module}/mldsa87_public.pem")
  kid = "my-mldsa87-key"
  use = "sig"
}

# ML-DSA-44 private key in PKCS#8/OneAsymmetricKey PEM format (BEGIN PRIVATE KEY).
# The OID identifies the parameter set; no alg attribute is required.
# The private key encodes the 32-byte seed as specified in draft-ietf-lamps-dilithium-certificates.
# Generate with: go1.27+ crypto/x509.MarshalPKCS8PrivateKey.
data "jwks_from_key" "mldsa44_private" {
  key = file("${path.module}/mldsa44_private.pem")
  kid = "my-mldsa44-signing-key"
  use = "sig"
}

# ML-DSA-44 private seed as raw base64 (32 bytes). The alg field is required
# because a raw 32-byte seed is ambiguous across parameter sets.
data "jwks_from_key" "mldsa44_seed_raw" {
  key = data.aws_secretsmanager_secret_version.mldsa_seed.secret_string
  alg = "ML-DSA-44"
  kid = "my-mldsa44-raw-seed"
  use = "sig"
}
