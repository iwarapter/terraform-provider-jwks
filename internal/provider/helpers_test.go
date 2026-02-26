package provider_test

import "fmt"

func testAccDataSourceConfig(dataSourceName, inputField, inputValue, kid, use, alg string) string {
	return fmt.Sprintf(`
data "%s" "test" {
  %s = <<EOF
%s
EOF%s%s%s
}
`, dataSourceName, inputField, inputValue, testAccOptionalStringAttribute("kid", kid), testAccOptionalStringAttribute("use", use), testAccOptionalStringAttribute("alg", alg))
}

func testAccOptionalStringAttribute(name, value string) string {
	if value == "" {
		return ""
	}

	return fmt.Sprintf("\n  %s = %q", name, value)
}
