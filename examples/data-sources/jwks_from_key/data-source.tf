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

data "jwks_from_key" "base64_der_example" {
  key = data.aws_kms_public_key.example.public_key
  kid = "123"
  use = "sig"
}
