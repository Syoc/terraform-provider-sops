package provider_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccSOPSConfigDataSource_Defaults verifies the default output when
// path_regexes is not specified — a single catch-all rule with no path_regex.
func TestAccSOPSConfigDataSource_Defaults(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}
	vaultAddr := requireEnv(t, "VAULT_ADDR")
	vaultToken := requireEnv(t, "VAULT_TOKEN")
	keyName := envOrDefault("SOPS_VAULT_KEY", "sops-test")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSOPSConfigDefault(vaultAddr, vaultToken, keyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.sops_config.test", "content"),
					resource.TestCheckResourceAttrSet("data.sops_config.test", "id"),
					resource.TestCheckResourceAttrWith("data.sops_config.test", "content",
						func(v string) error {
							for _, want := range []string{"creation_rules:", "hc_vault_transit_uri:", keyName} {
								if !strings.Contains(v, want) {
									return fmt.Errorf("content missing %q:\n%s", want, v)
								}
							}
							if strings.Contains(v, "path_regex:") {
								return fmt.Errorf("content must not contain path_regex when path_regexes is unset:\n%s", v)
							}
							return nil
						}),
				),
			},
		},
	})
}

// TestAccSOPSConfigDataSource_CustomRegexes verifies that user-supplied
// path_regexes appear in the output.
func TestAccSOPSConfigDataSource_CustomRegexes(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}
	vaultAddr := requireEnv(t, "VAULT_ADDR")
	vaultToken := requireEnv(t, "VAULT_TOKEN")
	keyName := envOrDefault("SOPS_VAULT_KEY", "sops-test")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccSOPSConfigCustom(vaultAddr, vaultToken, keyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.sops_config.test", "path_regexes.#", "1"),
					resource.TestCheckResourceAttrWith("data.sops_config.test", "content",
						func(v string) error {
							for _, want := range []string{"path_regex:", "secrets/", "hc_vault_transit_uri:"} {
								if !strings.Contains(v, want) {
									return fmt.Errorf("content missing %q; got:\n%s", want, v)
								}
							}
							return nil
						}),
				),
			},
		},
	})
}

func testAccSOPSConfigDefault(vaultAddr, vaultToken, keyName string) string {
	return fmt.Sprintf(`
provider "sops" {
  vault_address = %q
  vault_token   = %q
}

data "sops_config" "test" {
  vault_key_name = %q
}
`, vaultAddr, vaultToken, keyName)
}

func testAccSOPSConfigCustom(vaultAddr, vaultToken, keyName string) string {
	return fmt.Sprintf(`
provider "sops" {
  vault_address = %q
  vault_token   = %q
}

data "sops_config" "test" {
  vault_key_name = %q
  path_regexes   = ["^secrets/.*\\.yaml$"]
}
`, vaultAddr, vaultToken, keyName)
}
