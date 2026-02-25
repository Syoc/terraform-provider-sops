---
page_title: "sops_encrypted_yaml (Resource)"
description: |-
  Encrypts a document using SOPS with Vault Transit and stores the
  YAML 1.2 ciphertext in state.
---

# sops_encrypted_yaml

Encrypts a structured document using SOPS (AES-256-GCM) with a Vault Transit
key and stores the resulting SOPS-encrypted YAML 1.2 ciphertext in state.

Define the document with `jsonencode()` in a `locals` block — the resource
converts it to YAML internally. The ciphertext is stable across plans until
any input changes, at which point the resource is replaced and re-encrypted.

The ciphertext is a standard SOPS document and can be decrypted with:

```shell
sops -d --input-type yaml secrets.yaml
```

## Example Usage

```terraform
locals {
  # Use jsonencode() to build the document; the resource handles the
  # JSON-to-YAML conversion before encryption.
  helm_values = jsonencode({
    image = {
      repository = "myapp"
      tag        = var.image_tag
    }
    database = {
      host     = "db.example.com"
      password = var.db_password
    }
  })
}

resource "sops_encrypted_yaml" "helm_secrets" {
  content        = local.helm_values
  vault_key_name = "helm-secrets"
}

# Store the encrypted YAML in a Kubernetes secret, an S3 object, etc.
output "encrypted_helm_values" {
  value     = sops_encrypted_yaml.helm_secrets.ciphertext
  sensitive = true
}
```

## Argument Reference

* `content` - (Required, Sensitive) JSON-encoded document to encrypt. Use `jsonencode()` to produce this value. The output is YAML regardless of the JSON input format.
* `vault_key_name` - (Required) Name of the Vault Transit key used to wrap the data key.
* `encrypted_regex` - (Optional) Only values whose key name matches this regex are encrypted. Mutually exclusive with other scope options.
* `encrypted_suffix` - (Optional) Only values whose key name ends with this suffix are encrypted. Mutually exclusive with other scope options.
* `unencrypted_regex` - (Optional) Values whose key name matches this regex are left in plaintext; all others are encrypted. Mutually exclusive with other scope options.
* `unencrypted_suffix` - (Optional) Values whose key name ends with this suffix are left in plaintext; all others are encrypted. Mutually exclusive with other scope options.

At most one scope option (`encrypted_regex`, `encrypted_suffix`,
`unencrypted_regex`, `unencrypted_suffix`) may be set. When none are set,
every value in the document is encrypted.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The Vault key name.
* `ciphertext` - (Sensitive) The SOPS-encrypted YAML 1.2 document.
