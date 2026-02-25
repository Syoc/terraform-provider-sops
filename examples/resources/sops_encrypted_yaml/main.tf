terraform {
  required_providers {
    sops = { source = "registry.opentofu.org/syoc/sops" }
  }
}

provider "sops" {}

locals {
  # jsonencode() in a local is the idiomatic way to build the document.
  # The resource converts it to YAML internally.
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

variable "image_tag"    { type = string }
variable "db_password"  { type = string; sensitive = true }
