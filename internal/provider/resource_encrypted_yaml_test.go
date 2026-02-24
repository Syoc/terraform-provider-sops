package provider_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccEncryptedYAMLResource(t *testing.T) {
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
				Config: testAccEncryptedYAMLConfig(vaultAddr, vaultToken, keyName,
					`{"database":{"host":"db.example.com","password":"secret"}}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("sops_encrypted_yaml.test", "ciphertext"),
					// YAML ciphertext must not be a JSON object.
					resource.TestCheckResourceAttrWith("sops_encrypted_yaml.test", "ciphertext",
						func(v string) error {
							if strings.HasPrefix(strings.TrimSpace(v), "{") {
								return fmt.Errorf("ciphertext looks like JSON, expected YAML")
							}
							if !strings.Contains(v, "sops:") {
								return fmt.Errorf("ciphertext missing YAML sops block")
							}
							return nil
						}),
				),
			},
		},
	})
}

func TestAccEncryptedYAMLResource_CiphertextIsStable(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("set TF_ACC=1 to run acceptance tests")
	}
	vaultAddr := requireEnv(t, "VAULT_ADDR")
	vaultToken := requireEnv(t, "VAULT_TOKEN")
	keyName := envOrDefault("SOPS_VAULT_KEY", "sops-test")
	content := `{"key":"stable-value"}`

	var first string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccEncryptedYAMLConfig(vaultAddr, vaultToken, keyName, content),
				Check: resource.TestCheckResourceAttrWith("sops_encrypted_yaml.test", "ciphertext",
					func(v string) error { first = v; return nil }),
			},
			{
				Config: testAccEncryptedYAMLConfig(vaultAddr, vaultToken, keyName, content),
				Check: resource.TestCheckResourceAttrWith("sops_encrypted_yaml.test", "ciphertext",
					func(v string) error {
						if v != first {
							return fmt.Errorf("ciphertext changed between plans without input change")
						}
						return nil
					}),
			},
		},
	})
}

func testAccEncryptedYAMLConfig(vaultAddr, vaultToken, keyName, content string) string {
	return fmt.Sprintf(`
provider "sops" {
  vault_address = %q
  vault_token   = %q
}

resource "sops_encrypted_yaml" "test" {
  content        = %q
  vault_key_name = %q
}
`, vaultAddr, vaultToken, content, keyName)
}
