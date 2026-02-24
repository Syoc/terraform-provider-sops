package provider_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccEncryptedJSONResource exercises the full Terraform lifecycle against
// a real Vault instance.
//
// Required environment variables:
//
//	VAULT_ADDR  – e.g. http://127.0.0.1:8200
//	VAULT_TOKEN – a token with transit encrypt/decrypt access
//
// Optional:
//
//	SOPS_VAULT_KEY – transit key name (default: sops-test)
func TestAccEncryptedJSONResource(t *testing.T) {
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
				Config: testAccEncryptedJSONConfig(vaultAddr, vaultToken, keyName,
					`{"database":{"host":"db.example.com","password":"secret"},"api_key":"mykey"}`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("sops_encrypted_json.test", "ciphertext"),
					resource.TestCheckResourceAttrWith("sops_encrypted_json.test", "ciphertext",
						notEqualsPlaintext("secret")),
				),
			},
		},
	})
}

func TestAccEncryptedJSONResource_CiphertextIsStable(t *testing.T) {
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
				Config: testAccEncryptedJSONConfig(vaultAddr, vaultToken, keyName, content),
				Check: resource.TestCheckResourceAttrWith("sops_encrypted_json.test", "ciphertext",
					func(v string) error { first = v; return nil }),
			},
			{
				Config: testAccEncryptedJSONConfig(vaultAddr, vaultToken, keyName, content),
				Check: resource.TestCheckResourceAttrWith("sops_encrypted_json.test", "ciphertext",
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

func TestAccEncryptedJSONResource_Pretty(t *testing.T) {
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
				Config: testAccEncryptedJSONPrettyConfig(vaultAddr, vaultToken, keyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("sops_encrypted_json.test", "ciphertext"),
					resource.TestCheckResourceAttr("sops_encrypted_json.test", "pretty", "true"),
				),
			},
		},
	})
}

func TestAccEncryptedJSONResource_EncryptedRegex(t *testing.T) {
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
				Config: testAccEncryptedJSONScopeConfig(vaultAddr, vaultToken, keyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("sops_encrypted_json.test", "ciphertext"),
					resource.TestCheckResourceAttr("sops_encrypted_json.test", "encrypted_regex", "^password$"),
				),
			},
		},
	})
}

func testAccEncryptedJSONConfig(vaultAddr, vaultToken, keyName, content string) string {
	return fmt.Sprintf(`
provider "sops" {
  vault_address = %q
  vault_token   = %q
}

resource "sops_encrypted_json" "test" {
  content        = %q
  vault_key_name = %q
}
`, vaultAddr, vaultToken, content, keyName)
}

func testAccEncryptedJSONPrettyConfig(vaultAddr, vaultToken, keyName string) string {
	return fmt.Sprintf(`
provider "sops" {
  vault_address = %q
  vault_token   = %q
}

resource "sops_encrypted_json" "test" {
  content        = jsonencode({ key = "value" })
  vault_key_name = %q
  pretty         = true
}
`, vaultAddr, vaultToken, keyName)
}

func testAccEncryptedJSONScopeConfig(vaultAddr, vaultToken, keyName string) string {
	return fmt.Sprintf(`
provider "sops" {
  vault_address = %q
  vault_token   = %q
}

resource "sops_encrypted_json" "test" {
  content          = jsonencode({ password = "secret", host = "db.example.com" })
  vault_key_name   = %q
  encrypted_regex  = "^password$"
}
`, vaultAddr, vaultToken, keyName)
}

func notEqualsPlaintext(plain string) func(string) error {
	return func(v string) error {
		if v == plain {
			return fmt.Errorf("ciphertext equals plaintext %q", plain)
		}
		return nil
	}
}
