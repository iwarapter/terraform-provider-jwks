data "jwks_from_certificate" "pem_example" {
  pem = file("${path.module}/certificate.pem")
}

data "jwks_from_certificate" "pem_example_2" {
  pem = file("${path.module}/certificate.pem")
  kid = "123"
  use = "sig"
  alg = "RS256"
}
