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

# ML-DSA-44 public key (1312 raw bytes, base64-encoded).
# Provide the raw public key bytes — not PEM, not DER.
# filebase64() reads the file and base64-encodes it automatically.
data "jwks_from_key" "mldsa44_public" {
  key = filebase64("${path.module}/mldsa44_public.key")
  kid = "my-mldsa44-key"
  use = "sig"
}

# ML-DSA-65 public key (1952 raw bytes, base64-encoded).
data "jwks_from_key" "mldsa65_public" {
  key = filebase64("${path.module}/mldsa65_public.key")
  kid = "my-mldsa65-key"
  use = "sig"
}

# ML-DSA-87 public key (2592 raw bytes, base64-encoded).
data "jwks_from_key" "mldsa87_public" {
  key = filebase64("${path.module}/mldsa87_public.key")
  kid = "my-mldsa87-key"
  use = "sig"
}

# ML-DSA private seed (32 raw bytes, base64-encoded).
# The alg field is required to identify the parameter set because all
# ML-DSA parameter sets use a 32-byte seed and the size alone is ambiguous.
data "jwks_from_key" "mldsa44_seed" {
  key = data.aws_secretsmanager_secret_version.mldsa_seed.secret_string
  alg = "ML-DSA-44"
  kid = "my-mldsa44-signing-key"
  use = "sig"
}
