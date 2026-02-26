---
page_title: "sops_config (Data Source)"
description: |-
  Renders the content of a .sops.yaml configuration file for the
  HashiCorp Vault Transit backend.
---

# sops_config

Renders the content of a `.sops.yaml` configuration file that instructs the
SOPS CLI to use a Vault Transit key. This is a purely computational data
source — no Vault API calls are made.

Use the `local_file` resource to write the rendered content to disk so that
the SOPS CLI can pick it up automatically:

```terraform
resource "local_file" "sops_yaml" {
  content  = data.sops_config.main.content
  filename = "${path.module}/.sops.yaml"
}
```

## Example Usage

```terraform
# Catch-all rule — the generated .sops.yaml has no path_regex,
# so it applies to every file SOPS operates on.
data "sops_config" "main" {
  vault_key_name = "app-secrets"
}

# Scoped rules — one creation_rule per regex entry.
data "sops_config" "scoped" {
  vault_key_name = "app-secrets"
  path_regexes   = ["^secrets/.*\\.yaml$", "^config/.*\\.json$"]
}

resource "local_file" "sops_yaml" {
  content  = data.sops_config.main.content
  filename = "${path.module}/.sops.yaml"
}
```

The catch-all example produces a `.sops.yaml` similar to:

```yaml
creation_rules:
  - hc_vault_transit_uri: https://vault.example.com/v1/transit/keys/app-secrets
```

The scoped example produces:

```yaml
creation_rules:
  - path_regex: ^secrets/.*\.yaml$
    hc_vault_transit_uri: https://vault.example.com/v1/transit/keys/app-secrets
  - path_regex: ^config/.*\.json$
    hc_vault_transit_uri: https://vault.example.com/v1/transit/keys/app-secrets
```

## Argument Reference

* `vault_key_name` - (Required) Name of the Vault Transit key referenced in every creation rule.
* `vault_transit_engine` - (Optional) Vault Transit mount path for this data source. Overrides the provider-level `vault_transit_engine`. Defaults to `transit`.
* `path_regexes` - (Optional) List of path regexes. Each entry becomes one `creation_rule` with a `path_regex` field. When omitted, a single catch-all creation rule with no `path_regex` is emitted, which matches all files.

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - SHA-256 hash of the rendered content.
* `content` - The rendered `.sops.yaml` YAML content.
