terraform {
  required_providers {
    sops = { source = "registry.opentofu.org/syoc/sops" }
  }
}

# vault_address and vault_token fall back to VAULT_ADDR / VAULT_TOKEN env vars.
provider "sops" {}

locals {
  # Define the document structure once; reference it in the resource.
  app_secrets = jsonencode({
    database = {
      host     = "db.example.com"
      password = var.db_password
    }
    api_key = var.api_key
  })
}

# Encrypt everything — ciphertext is stable across plans.
resource "sops_encrypted_json" "secrets" {
  content        = local.app_secrets
  vault_key_name = "app-secrets"
  pretty         = true
}

# Encrypt only keys matching the regex; host remains in plaintext.
resource "sops_encrypted_json" "partial" {
  content         = local.app_secrets
  vault_key_name  = "app-secrets"
  encrypted_regex = "^(password|api_key)$"
}

output "encrypted_secrets" {
  value     = sops_encrypted_json.secrets.ciphertext
  sensitive = true
}

variable "db_password" { type = string; sensitive = true }
variable "api_key"     { type = string; sensitive = true }
