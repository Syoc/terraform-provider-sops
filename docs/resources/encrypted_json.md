---
page_title: "sops_encrypted_json (Resource)"
description: |-
  Encrypts a JSON document using SOPS with Vault Transit and stores the
  ciphertext in state.
---

# sops_encrypted_json

Encrypts a structured document using SOPS (AES-256-GCM) with a Vault Transit
key and stores the resulting SOPS-encrypted JSON ciphertext in state.

Define the document with `jsonencode()` in a `locals` block. The ciphertext is
stable across plans until any input changes, at which point the resource is
replaced and re-encrypted.

The ciphertext is a standard SOPS document and can be decrypted with:

```shell
sops -d --input-type json secrets.json
```

## Example Usage

```terraform
locals {
  secrets = jsonencode({
    database = {
      host     = "db.example.com"
      password = var.db_password
    }
    api_key = var.api_key
  })
}

# Encrypt every value in the document.
resource "sops_encrypted_json" "secrets" {
  content        = local.secrets
  vault_key_name = "app-secrets"
  pretty         = true
}

# Encrypt only the keys matching the regex; host remains in plaintext.
resource "sops_encrypted_json" "partial" {
  content         = local.secrets
  vault_key_name  = "app-secrets"
  encrypted_regex = "^(password|api_key)$"
}

output "encrypted_secrets" {
  value     = sops_encrypted_json.secrets.ciphertext
  sensitive = true
}
```

## Argument Reference

* `content` - (Required, Sensitive) JSON-encoded document to encrypt. Use `jsonencode()` to produce this value.
* `vault_key_name` - (Required) Name of the Vault Transit key used to wrap the data key.
* `encrypted_regex` - (Optional) Only values whose key name matches this regex are encrypted. Mutually exclusive with other scope options.
* `encrypted_suffix` - (Optional) Only values whose key name ends with this suffix are encrypted. Mutually exclusive with other scope options.
* `unencrypted_regex` - (Optional) Values whose key name matches this regex are left in plaintext; all others are encrypted. Mutually exclusive with other scope options.
* `unencrypted_suffix` - (Optional) Values whose key name ends with this suffix are left in plaintext; all others are encrypted. Mutually exclusive with other scope options.
* `pretty` - (Optional) Indent the SOPS JSON output with two spaces. Defaults to `false`.

At most one scope option (`encrypted_regex`, `encrypted_suffix`,
`unencrypted_regex`, `unencrypted_suffix`) may be set. When none are set,
every value in the document is encrypted.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The Vault key name.
* `ciphertext` - (Sensitive) The SOPS-encrypted JSON document.
