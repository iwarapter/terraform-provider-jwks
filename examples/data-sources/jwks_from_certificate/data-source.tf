
data "jwks_from_certificate" "pem_example" {
  key = file("${path.module}/certificate.pem")
}

data "jwks_from_certificate" "pem_example_2" {
  key                 = file("${path.module}/certificate.pem")
  kid = "123"
}
