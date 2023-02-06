package sdkv2provider

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"

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
			{
				Config: testAccJwksFromKeyWithGenerateKidDataSourceConfig(ecPublicKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwks", `{"crv":"P-384","kid":"ZgtsBVoa8fdL4gQGYjFJdZVMbQV2LQ3LVnbfZWrT_Nw","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
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

func testAccJwksFromKeyWithGenerateKidDataSourceConfig(data string) string {
	return fmt.Sprintf(`
	data "jwks_from_key" "test" {
		key = <<EOF
%s
EOF
		generate_kid = true
	}
	`, data)
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
