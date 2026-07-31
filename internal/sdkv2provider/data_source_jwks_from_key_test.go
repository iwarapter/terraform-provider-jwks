package sdkv2provider

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"filippo.io/mldsa"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const (
	PrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAgUElV5mwqkloIrM8ZNZ72gSCcnSJt7+/Usa5G+D15YQUAdf9
c1zEekTfHgDP+04nw/uFNFaE5v1RbHaPxhZYVg5ZErNCa/hzn+x10xzcepeS3KPV
Xcxae4MR0BEegvqZqJzN9loXsNL/c3H/B+2Gle3hTxjlWFb3F5qLgR+4Mf4ruhER
1v6eHQa/nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr+sTSxfh7
r6v24u/vp/QTmBIAlNPgadVAZw17iNNb7vjV7Gwl/5gHXonCUKURaV++dBNLrHIZ
pqcAM8wHRph8mD1EfL9hsz77pHewxolBATV+7QIDAQABAoIBAC1rK+kFW3vrAYm3
+8/fQnQQw5nec4o6+crng6JVQXLeH32qXShNf8kLLG/Jj0vaYcTPPDZw9JCKkTMQ
0mKj9XR/5DLbBMsV6eNXXuvJJ3x4iKW5eD9WkLD4FKlNarBRyO7j8sfPTqXW7uat
NxWdFH7YsSRvNh/9pyQHLWA5OituidMrYbc3EUx8B1GPNyJ9W8Q8znNYLfwYOjU4
Wv1SLE6qGQQH9Q0WzA2WUf8jklCYyMYTIywAjGb8kbAJlKhmj2t2Igjmqtwt1PYc
pGlqbtQBDUiWXt5S4YX/1maIQ/49yeNUajjpbJiH3DbhJbHwFTzP3pZ9P9GHOzlG
kYR+wSECgYEAw/Xida8kSv8n86V3qSY/I+fYQ5V+jDtXIE+JhRnS8xzbOzz3v0WS
Oo5H+o4nJx5eL3Ghb3Gcm0Jn46dHrxinHbm+3RjXv/X6tlbxIYjRSQfHOTSMCTvd
qcliF5vC6RCLXuc7R+IWR1Ky6eDEZGtrvt3DyeYABsp9fRUFR/6NluUCgYEAqNsw
1aSl7WJa27F0DoJdlU9LWerpXcazlJcIdOz/S9QDmSK3RDQTdqfTxRmrxiYI9LEs
mkOkvzlnnOBMpnZ3ZOU5qIRfprecRIi37KDAOHWGnlC0EWGgl46YLb7/jXiWf0AG
Y+DfJJNd9i6TbIDWu8254/erAS6bKMhW/3q7f2kCgYAZ7Id/BiKJAWRpqTRBXlvw
BhXoKvjI2HjYP21z/EyZ+PFPzur/lNaZhIUlMnUfibbwE9pFggQzzf8scM7c7Sf+
mLoVSdoQ/Rujz7CqvQzi2nKSsM7t0curUIb3lJWee5/UeEaxZcmIufoNUrzohAWH
BJOIPDM4ssUTLRq7wYM9uQKBgHCBau5OP8gE6mjKuXsZXWUoahpFLKwwwmJUp2vQ
pOFPJ/6WZOlqkTVT6QPAcPUbTohKrF80hsZqZyDdSfT3peFx4ZLocBrS56m6NmHR
UYHMvJ8rQm76T1fryHVidz85g3zRmfBeWg8yqT5oFg4LYgfLsPm1gRjOhs8LfPvI
OLlRAoGBAIZ5Uv4Z3s8O7WKXXUe/lq6j7vfiVkR1NW/Z/WLKXZpnmvJ7FgxN4e56
RXT7GwNQHIY8eDjDnsHxzrxd+raOxOZeKcMHj3XyjCX3NHfTscnsBPAGYpY/Wxzh
T8UYnFu6RzkixElTf2rseEav7rkdKkI3LAeIZy7B0HulKKsmqVQ7
-----END RSA PRIVATE KEY-----
`

	PublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgUElV5mwqkloIrM8ZNZ7
2gSCcnSJt7+/Usa5G+D15YQUAdf9c1zEekTfHgDP+04nw/uFNFaE5v1RbHaPxhZY
Vg5ZErNCa/hzn+x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL/c3H/B+2G
le3hTxjlWFb3F5qLgR+4Mf4ruhER1v6eHQa/nchi03MBpT4UeJ7MrL92hTJYLdpS
yCqmr8yjxkKJDVC2uRrr+sTSxfh7r6v24u/vp/QTmBIAlNPgadVAZw17iNNb7vjV
7Gwl/5gHXonCUKURaV++dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV+
7QIDAQAB
-----END PUBLIC KEY-----
`

	RSAPublicKeyDER = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgUElV5mwqkloIrM8ZNZ72gSCcnSJt7+/Usa5G+D15YQUAdf9c1zEekTfHgDP+04nw/uFNFaE5v1RbHaPxhZYVg5ZErNCa/hzn+x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL/c3H/B+2Gle3hTxjlWFb3F5qLgR+4Mf4ruhER1v6eHQa/nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr+sTSxfh7r6v24u/vp/QTmBIAlNPgadVAZw17iNNb7vjV7Gwl/5gHXonCUKURaV++dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV+7QIDAQAB"

	ECPrivateKey = `
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBYv+Kxcvmf1THbJ3amFFEwf9o8JnBV+CFQSERT0XQvQQqiLswPShGK
uWypa5iw3B2gBwYFK4EEACKhZANiAARCdKoVsoZ0SLP+DQKhkVcEC+wwxswGqqdn
eMn/OsvG4FKENOauxGhTswI4Atu3Th8WhEjwfTppLVarVewBsyIwtSqmXmOg5Z5Q
KHHI9vS/7sHzogT3b31QcGlsB9ye2F0=
-----END EC PRIVATE KEY-----`

	ECPublicKey = `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQnSqFbKGdEiz/g0CoZFXBAvsMMbMBqqn
Z3jJ/zrLxuBShDTmrsRoU7MCOALbt04fFoRI8H06aS1Wq1XsAbMiMLUqpl5joOWe
UChxyPb0v+7B86IE9299UHBpbAfcnthd
-----END PUBLIC KEY-----`

	ECPublicKeyDER = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQnSqFbKGdEiz/g0CoZFXBAvsMMbMBqqnZ3jJ/zrLxuBShDTmrsRoU7MCOALbt04fFoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v+7B86IE9299UHBpbAfcnthd"

	MLDSAPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhALpx+fZOEbrrWPqcb7tuFOYfGGQ9q0lbR1Oa
kWbKAZgTHET4JrvVbjTlXbXl4tczSF456iYPxgAMXqS6gNNFXN5TtG80SCrt/VRQ
/C4bpPJdFfnBRCQvs5u1IocYkDDFBJjhcXt8dYsZCmdI6pqj96yq8sfLUm7XF8n3
muuEIU+lzY3tkqDD+hVYgQ8SxwUKNncI0ZbNJOWvl0kErtjkzohy6GlrC3vKUORS
zX0w6ppK2sAxHWcsa96EliQLB0MUY3CIlc2br8MWMtc5dkk4j9r8v30wWj3ppJXs
p0M6j4O6DwslxBPG45yW631pGzTTfON/HurRzyF+Je807s8/fGD4S47f3ehAXU+D
JXbGHvmOCi8o2hh3AJU5JPaGuUYUcFvPU9M/7dQ0jt3b3yi1Bl4fIHdQQ+hc+TH4
KReTY6Gn50BKg47AAIawl2OG/mN8mCRHV+P3ad3URnRxv61nD5oF+CRu5Qp7Hq+H
/EBpw64qogMyWBF3kvC81J4IP9G8dJar/ynMlOSGiyEhTtMWUlOZphD73UqA58gH
FfKVeOKoS7QL3dvZ9HoRtufaEYobZY01norvVetGtTdrW2VZeZhKkivuv8WbzWAN
UwnczXLb8Hh9uLp1e1N8Hq/VwPUOpLyVg1SeKCmkLCjKwkjJbXgSTEcVmxiu3XVK
uhexnUMPt49jPqnSb1SpvVD42Pa3NZT4KJdufqCcU7u58RpWyVB/uJuaXrwDejcm
epX4W41kypcZKxCmb0F7P2H+nKVxMKSP2SXq4qtVAtVxyKUZA8HTmPTB92p+EXQ5
dq/bxpfyMJSjzXYf+Whd4y4J+zwordRTSQMAvHyJ3AF4AJYHFyKUV3XyZOGwYjvP
RhnHEsg4dhIF2HaRt17zYBlsu56bkqDUxO1iMm5QJNd1ELjuLHQmzCLq4gncnxO9
5r8I9ecYG9O0WUULRRpRU5pxXCHWfdMw61lw2wDZ7b+ygisDb6E7r+uG2Nx4hm4/
jUPlPXjMpVlab6+Ia13BEvHPStz6h1gA2QtIiDr5cxb+FQaHP8FX5XDqy/0iKGjR
QjQQGWavtr+ZQIKSU6lTraifx1a2qEn3CsuYOOafqlC7p14+icKttX6G0IirmwSi
jmcHCRciQ+xeAAilzq8/hyL0hzAllv/XVa0bgqScNLNGlRW0aqKQzYbuOOp6m+Px
A2EDNbUxzKMz3f4ysUUQ9LB++V/GaE6MRUqSwQ27XVnHp8Y/swX+iBln2Z5mnrYy
hAWCVgu0A0MdQPdaSVSQhIIngpKCH06pHkLnj6SMruPINhRtz9c40RfpLpoVE30o
6OaktGImUMtBNQTLOjNdRL7sV0bBwpSx6MuZy2CNko+M41Y2MsUh8j0TxhqPYcAd
+Mlsc2DbTzxoql0v3TQqYv80WcEWOJQhq0PoWExFiCtQ5uTpbbbwuP3okNXb+tzY
hpC0SeZCQN2yAjdH8wg2PjAap3dXFp/GFQYo1ZILWqGrHIy/RMsA4CXXh51ytHnj
r1MRx4VyVZDanIm5/DuEUHaVVOtE0gProruu+crSI3ARwupE7/APKZpI/+KMqT3f
hfdmCCQu+NbMJGEKHiB4/KxPk4XDFJBeyqguVTkW2U0afB7GUqoIiXCD2qLrsXdf
vEca4nd315BOqfG5K8rD2KMVhCYIe2RbEQjw1l/sk3icBTdDyhT9Y9BemLZS3yuc
L/nOBfGUBwP/snP4Dg4nMuyplg2YG0z9O3u4BFs8ODBUa53Y2w0=
-----END PUBLIC KEY-----
`

	MLDSAPublicKeyDER = "MIIFMjALBglghkgBZQMEAxEDggUhALpx+fZOEbrrWPqcb7tuFOYfGGQ9q0lbR1OakWbKAZgTHET4JrvVbjTlXbXl4tczSF456iYPxgAMXqS6gNNFXN5TtG80SCrt/VRQ/C4bpPJdFfnBRCQvs5u1IocYkDDFBJjhcXt8dYsZCmdI6pqj96yq8sfLUm7XF8n3muuEIU+lzY3tkqDD+hVYgQ8SxwUKNncI0ZbNJOWvl0kErtjkzohy6GlrC3vKUORSzX0w6ppK2sAxHWcsa96EliQLB0MUY3CIlc2br8MWMtc5dkk4j9r8v30wWj3ppJXsp0M6j4O6DwslxBPG45yW631pGzTTfON/HurRzyF+Je807s8/fGD4S47f3ehAXU+DJXbGHvmOCi8o2hh3AJU5JPaGuUYUcFvPU9M/7dQ0jt3b3yi1Bl4fIHdQQ+hc+TH4KReTY6Gn50BKg47AAIawl2OG/mN8mCRHV+P3ad3URnRxv61nD5oF+CRu5Qp7Hq+H/EBpw64qogMyWBF3kvC81J4IP9G8dJar/ynMlOSGiyEhTtMWUlOZphD73UqA58gHFfKVeOKoS7QL3dvZ9HoRtufaEYobZY01norvVetGtTdrW2VZeZhKkivuv8WbzWANUwnczXLb8Hh9uLp1e1N8Hq/VwPUOpLyVg1SeKCmkLCjKwkjJbXgSTEcVmxiu3XVKuhexnUMPt49jPqnSb1SpvVD42Pa3NZT4KJdufqCcU7u58RpWyVB/uJuaXrwDejcmepX4W41kypcZKxCmb0F7P2H+nKVxMKSP2SXq4qtVAtVxyKUZA8HTmPTB92p+EXQ5dq/bxpfyMJSjzXYf+Whd4y4J+zwordRTSQMAvHyJ3AF4AJYHFyKUV3XyZOGwYjvPRhnHEsg4dhIF2HaRt17zYBlsu56bkqDUxO1iMm5QJNd1ELjuLHQmzCLq4gncnxO95r8I9ecYG9O0WUULRRpRU5pxXCHWfdMw61lw2wDZ7b+ygisDb6E7r+uG2Nx4hm4/jUPlPXjMpVlab6+Ia13BEvHPStz6h1gA2QtIiDr5cxb+FQaHP8FX5XDqy/0iKGjRQjQQGWavtr+ZQIKSU6lTraifx1a2qEn3CsuYOOafqlC7p14+icKttX6G0IirmwSijmcHCRciQ+xeAAilzq8/hyL0hzAllv/XVa0bgqScNLNGlRW0aqKQzYbuOOp6m+PxA2EDNbUxzKMz3f4ysUUQ9LB++V/GaE6MRUqSwQ27XVnHp8Y/swX+iBln2Z5mnrYyhAWCVgu0A0MdQPdaSVSQhIIngpKCH06pHkLnj6SMruPINhRtz9c40RfpLpoVE30o6OaktGImUMtBNQTLOjNdRL7sV0bBwpSx6MuZy2CNko+M41Y2MsUh8j0TxhqPYcAd+Mlsc2DbTzxoql0v3TQqYv80WcEWOJQhq0PoWExFiCtQ5uTpbbbwuP3okNXb+tzYhpC0SeZCQN2yAjdH8wg2PjAap3dXFp/GFQYo1ZILWqGrHIy/RMsA4CXXh51ytHnjr1MRx4VyVZDanIm5/DuEUHaVVOtE0gProruu+crSI3ARwupE7/APKZpI/+KMqT3fhfdmCCQu+NbMJGEKHiB4/KxPk4XDFJBeyqguVTkW2U0afB7GUqoIiXCD2qLrsXdfvEca4nd315BOqfG5K8rD2KMVhCYIe2RbEQjw1l/sk3icBTdDyhT9Y9BemLZS3yucL/nOBfGUBwP/snP4Dg4nMuyplg2YG0z9O3u4BFs8ODBUa53Y2w0="
)

func TestAccJwksFromKeyDataSource(t *testing.T) {
	resourceName := "data.jwks_from_key.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProviders,
		CheckDestroy:             testAccCheckJwksFromKeyDataSourceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJwksFromKeyDataSourceConfig(PrivateKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"d":"LWsr6QVbe-sBibf7z99CdBDDmd5zijr5yueDolVBct4ffapdKE1_yQssb8mPS9phxM88NnD0kIqRMxDSYqP1dH_kMtsEyxXp41de68knfHiIpbl4P1aQsPgUqU1qsFHI7uPyx89Opdbu5q03FZ0UftixJG82H_2nJActYDk6K26J0ythtzcRTHwHUY83In1bxDzOc1gt_Bg6NTha_VIsTqoZBAf1DRbMDZZR_yOSUJjIxhMjLACMZvyRsAmUqGaPa3YiCOaq3C3U9hykaWpu1AENSJZe3lLhhf_WZohD_j3J41RqOOlsmIfcNuElsfAVPM_eln0_0Yc7OUaRhH7BIQ","dp":"GeyHfwYiiQFkaak0QV5b8AYV6Cr4yNh42D9tc_xMmfjxT87q_5TWmYSFJTJ1H4m28BPaRYIEM83_LHDO3O0n_pi6FUnaEP0bo8-wqr0M4tpykrDO7dHLq1CG95SVnnuf1HhGsWXJiLn6DVK86IQFhwSTiDwzOLLFEy0au8GDPbk","dq":"cIFq7k4_yATqaMq5exldZShqGkUsrDDCYlSna9Ck4U8n_pZk6WqRNVPpA8Bw9RtOiEqsXzSGxmpnIN1J9Pel4XHhkuhwGtLnqbo2YdFRgcy8nytCbvpPV-vIdWJ3PzmDfNGZ8F5aDzKpPmgWDgtiB8uw-bWBGM6Gzwt8-8g4uVE","e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q","p":"w_Xida8kSv8n86V3qSY_I-fYQ5V-jDtXIE-JhRnS8xzbOzz3v0WSOo5H-o4nJx5eL3Ghb3Gcm0Jn46dHrxinHbm-3RjXv_X6tlbxIYjRSQfHOTSMCTvdqcliF5vC6RCLXuc7R-IWR1Ky6eDEZGtrvt3DyeYABsp9fRUFR_6NluU","q":"qNsw1aSl7WJa27F0DoJdlU9LWerpXcazlJcIdOz_S9QDmSK3RDQTdqfTxRmrxiYI9LEsmkOkvzlnnOBMpnZ3ZOU5qIRfprecRIi37KDAOHWGnlC0EWGgl46YLb7_jXiWf0AGY-DfJJNd9i6TbIDWu8254_erAS6bKMhW_3q7f2k","qi":"hnlS_hnezw7tYpddR7-WrqPu9-JWRHU1b9n9Yspdmmea8nsWDE3h7npFdPsbA1Achjx4OMOewfHOvF36to7E5l4pwwePdfKMJfc0d9OxyewE8AZilj9bHOFPxRicW7pHOSLESVN_aux4Rq_uuR0qQjcsB4hnLsHQe6UoqyapVDs"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(PublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(RSAPublicKeyDER),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ECPrivateKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"crv":"P-384","d":"WL_isXL5n9Ux2yd2phRRMH_aPCZwVfghUEhEU9F0L0EKoi7MD0oRirlsqWuYsNwd","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ECPublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"crv":"P-384","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ECPublicKeyDER),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"crv":"P-384","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(MLDSAPublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"alg":"ML-DSA-44","kty":"AKP","pub":"unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(MLDSAPublicKeyDER),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"alg":"ML-DSA-44","kty":"AKP","pub":"unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(privateKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"d":"LWsr6QVbe-sBibf7z99CdBDDmd5zijr5yueDolVBct4ffapdKE1_yQssb8mPS9phxM88NnD0kIqRMxDSYqP1dH_kMtsEyxXp41de68knfHiIpbl4P1aQsPgUqU1qsFHI7uPyx89Opdbu5q03FZ0UftixJG82H_2nJActYDk6K26J0ythtzcRTHwHUY83In1bxDzOc1gt_Bg6NTha_VIsTqoZBAf1DRbMDZZR_yOSUJjIxhMjLACMZvyRsAmUqGaPa3YiCOaq3C3U9hykaWpu1AENSJZe3lLhhf_WZohD_j3J41RqOOlsmIfcNuElsfAVPM_eln0_0Yc7OUaRhH7BIQ","dp":"GeyHfwYiiQFkaak0QV5b8AYV6Cr4yNh42D9tc_xMmfjxT87q_5TWmYSFJTJ1H4m28BPaRYIEM83_LHDO3O0n_pi6FUnaEP0bo8-wqr0M4tpykrDO7dHLq1CG95SVnnuf1HhGsWXJiLn6DVK86IQFhwSTiDwzOLLFEy0au8GDPbk","dq":"cIFq7k4_yATqaMq5exldZShqGkUsrDDCYlSna9Ck4U8n_pZk6WqRNVPpA8Bw9RtOiEqsXzSGxmpnIN1J9Pel4XHhkuhwGtLnqbo2YdFRgcy8nytCbvpPV-vIdWJ3PzmDfNGZ8F5aDzKpPmgWDgtiB8uw-bWBGM6Gzwt8-8g4uVE","e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q","p":"w_Xida8kSv8n86V3qSY_I-fYQ5V-jDtXIE-JhRnS8xzbOzz3v0WSOo5H-o4nJx5eL3Ghb3Gcm0Jn46dHrxinHbm-3RjXv_X6tlbxIYjRSQfHOTSMCTvdqcliF5vC6RCLXuc7R-IWR1Ky6eDEZGtrvt3DyeYABsp9fRUFR_6NluU","q":"qNsw1aSl7WJa27F0DoJdlU9LWerpXcazlJcIdOz_S9QDmSK3RDQTdqfTxRmrxiYI9LEsmkOkvzlnnOBMpnZ3ZOU5qIRfprecRIi37KDAOHWGnlC0EWGgl46YLb7_jXiWf0AGY-DfJJNd9i6TbIDWu8254_erAS6bKMhW_3q7f2k","qi":"hnlS_hnezw7tYpddR7-WrqPu9-JWRHU1b9n9Yspdmmea8nsWDE3h7npFdPsbA1Achjx4OMOewfHOvF36to7E5l4pwwePdfKMJfc0d9OxyewE8AZilj9bHOFPxRicW7pHOSLESVN_aux4Rq_uuR0qQjcsB4hnLsHQe6UoqyapVDs"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(publicKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ecPrivateKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"crv":"P-384","d":"WL_isXL5n9Ux2yd2phRRMH_aPCZwVfghUEhEU9F0L0EKoi7MD0oRirlsqWuYsNwd","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ecPublicKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"crv":"P-384","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyWithKidDataSourceConfig(ecPrivateKeyDer(), "123"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"crv":"P-384","d":"WL_isXL5n9Ux2yd2phRRMH_aPCZwVfghUEhEU9F0L0EKoi7MD0oRirlsqWuYsNwd","kid":"123","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyWithKidDataSourceConfig(ecPublicKeyDer(), "123"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"crv":"P-384","kid":"123","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyWithUseDataSourceConfig(PublicKey, "sig"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q","use":"sig"}`),
				),
			},
			{
				Config: testAccJwksFromKeyWithAlgDataSourceConfig(PublicKey, "RS256"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"alg":"RS256","e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
		},
	})
}

func TestAccJwksFromKeyMLDSADataSource(t *testing.T) {
	resourceName := "data.jwks_from_key.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProviders,
		CheckDestroy:             testAccCheckJwksFromKeyDataSourceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJwksFromKeyMLDSAPublicConfig(mlDSAKeyBase64(mldsa.MLDSA44())),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-44", false),
			},
			{
				Config: testAccJwksFromKeyMLDSAPublicConfig(mlDSAKeyBase64(mldsa.MLDSA65())),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-65", false),
			},
			{
				Config: testAccJwksFromKeyMLDSAPublicConfig(mlDSAKeyBase64(mldsa.MLDSA87())),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-87", false),
			},
			{
				Config: testAccJwksFromKeyMLDSAPrivateConfig(mlDSASeedBase64(), "ML-DSA-44"),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-44", true),
			},
			{
				Config: testAccJwksFromKeyMLDSAPrivateConfig(mlDSASeedBase64(), "ML-DSA-65"),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-65", true),
			},
			{
				Config: testAccJwksFromKeyMLDSAPrivateConfig(mlDSASeedBase64(), "ML-DSA-87"),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-87", true),
			},
		},
	})
}

func testAccCheckJwksFromKeyDataSourceDestroy(s *terraform.State) error {
	return nil
}

func testAccJwksFromKeyDataSourceConfig(data string) string {
	return fmt.Sprintf(`
data "jwks_from_key" "test" {
  key = <<EOF
%s
EOF
}
	`, data)
}

func testAccJwksFromKeyWithKidDataSourceConfig(data, kid string) string {
	return fmt.Sprintf(`
	data "jwks_from_key" "test" {
		key = <<EOF
%s
EOF
		kid = %s
	}
	`, data, kid)
}

func testAccJwksFromKeyWithUseDataSourceConfig(data, use string) string {
	return fmt.Sprintf(`
	data "jwks_from_key" "test" {
		key = <<EOF
%s
EOF
		use = "%s"
	}
	`, data, use)
}

func testAccJwksFromKeyWithAlgDataSourceConfig(data, alg string) string {
	return fmt.Sprintf(`
	data "jwks_from_key" "test" {
		key = <<EOF
%s
EOF
		alg = "%s"
	}
	`, data, alg)
}

func privateKeyDer() string {
	block, _ := pem.Decode([]byte(PrivateKey))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func publicKeyDer() string {
	block, _ := pem.Decode([]byte(PublicKey))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func ecPrivateKeyDer() string {
	block, _ := pem.Decode([]byte(ECPrivateKey))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func ecPublicKeyDer() string {
	block, _ := pem.Decode([]byte(ECPublicKey))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

// mlDSAKeyBase64 returns a base64 std-encoded ML-DSA public key for the given
// parameter set, derived from a fixed all-zeros seed for test determinism.
func mlDSAKeyBase64(params *mldsa.Parameters) string {
	seed := make([]byte, 32)
	sk, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes())
}

// mlDSASeedBase64 returns the base64 std-encoding of a fixed all-zeros 32-byte
// seed, usable as ML-DSA private key input.
func mlDSASeedBase64() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

// checkMLDSAJWK returns a TestCheckFunc that parses the jwks attribute as JSON
// and asserts kty=="AKP", alg==wantAlg, pub is non-empty, and (if wantPriv)
// priv is non-empty.
func checkMLDSAJWK(resourceName, wantAlg string, wantPriv bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found", resourceName)
		}
		raw := rs.Primary.Attributes["jwks"]
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return fmt.Errorf("jwks is not valid JSON: %w", err)
		}
		if m["kty"] != "AKP" {
			return fmt.Errorf("expected kty=AKP, got %v", m["kty"])
		}
		if m["alg"] != wantAlg {
			return fmt.Errorf("expected alg=%s, got %v", wantAlg, m["alg"])
		}
		if _, ok := m["pub"]; !ok {
			return fmt.Errorf("expected pub field to be present")
		}
		if wantPriv {
			if _, ok := m["priv"]; !ok {
				return fmt.Errorf("expected priv field to be present")
			}
		} else {
			if _, ok := m["priv"]; ok {
				return fmt.Errorf("expected priv field to be absent for public key JWK")
			}
		}
		return nil
	}
}

func testAccJwksFromKeyMLDSAPublicConfig(keyBase64 string) string {
	return fmt.Sprintf(`
data "jwks_from_key" "test" {
  key = "%s"
}
`, keyBase64)
}

func testAccJwksFromKeyMLDSAPrivateConfig(seedBase64, alg string) string {
	return fmt.Sprintf(`
data "jwks_from_key" "test" {
  key = "%s"
  alg = "%s"
}
`, seedBase64, alg)
}
