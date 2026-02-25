---
page_title: "Provider: SOPS"
description: |-
  The SOPS provider encrypts structured secrets using Mozilla SOPS with
  HashiCorp Vault Transit as the key backend.
---

# SOPS Provider

The SOPS provider encrypts structured documents using [Mozilla SOPS](https://github.com/getsops/sops)
(Secrets OPerationS) with [HashiCorp Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit)
as the key backend. The resulting ciphertext is a standard SOPS document that
can be committed to version control and decrypted with `sops -d` given Vault
access.

Vault credentials are injected directly into the Vault API client and are
never written to the process environment.

## Example Usage

```terraform
terraform {
  required_providers {
    sops = {
      source  = "registry.opentofu.org/syoc/sops"
      version = "~> 0.1"
    }
  }
}

# Token auth — vault_address and vault_token fall back to
# VAULT_ADDR and VAULT_TOKEN environment variables.
provider "sops" {
  vault_address = "https://vault.example.com"
  vault_token   = var.vault_token
}

# AppRole auth
provider "sops" {
  vault_address   = "https://vault.example.com"
  vault_role_id   = var.role_id
  vault_secret_id = var.secret_id
}
```

## Argument Reference

* `vault_address` - (Optional) Vault server URL. Falls back to the `VAULT_ADDR` environment variable.
* `vault_token` - (Optional, Sensitive) Vault token. Falls back to `VAULT_TOKEN`. Mutually exclusive with `vault_role_id` and `vault_secret_id`.
* `vault_transit_engine` - (Optional) Mount path for the Vault Transit secrets engine. Defaults to `transit`.
* `vault_role_id` - (Optional) AppRole role ID. Falls back to `VAULT_ROLE_ID`. Must be paired with `vault_secret_id`. Mutually exclusive with `vault_token`.
* `vault_secret_id` - (Optional, Sensitive) AppRole secret ID. Falls back to `VAULT_SECRET_ID`. Must be paired with `vault_role_id`. Mutually exclusive with `vault_token`.
* `vault_approle_path` - (Optional) Auth mount path for AppRole. Defaults to `approle`.
