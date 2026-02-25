terraform {
  required_providers {
    sops = {
      source  = "registry.opentofu.org/syoc/sops"
      version = "~> 0.1"
    }
  }
}

# vault_address and vault_token fall back to VAULT_ADDR / VAULT_TOKEN.
provider "sops" {}
