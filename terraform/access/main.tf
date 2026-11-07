terraform {
  # client_key_wo (write-only, kept out of state) needs Terraform 1.11+.
  required_version = ">= 1.11"

  cloud {
    organization = "rgorme-org"

    workspaces {
      name = "terraform-proxmox-access"
    }
  }

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.111.1"
    }
  }
}

provider "proxmox" {
  endpoint  = var.proxmox_api_url
  api_token = "${var.proxmox_api_token_id}=${var.proxmox_api_token_secret}"
  insecure  = true
}

# Login through Authentik. Users are created on first login as
# <preferred_username>@authentik and have no permissions until they are a
# member of one of the groups below.
resource "proxmox_realm_openid" "authentik" {
  realm      = "authentik"
  comment    = "Authentik SSO. Managed by Terraform."
  issuer_url = var.authentik_issuer_url
  client_id  = var.authentik_client_id

  client_key_wo         = var.authentik_client_secret
  client_key_wo_version = var.authentik_client_secret_version

  scopes         = "openid profile email"
  username_claim = "username"
  autocreate     = true

  # Proxmox maps a claim group <name> to the existing PVE group
  # <name>-authentik. Overwrite on each login, so removing someone from the
  # Authentik group also removes their Proxmox access.
  groups_claim      = "groups"
  groups_autocreate = false
  groups_overwrite  = true
}

locals {
  # Authentik group name => Proxmox role granted on /.
  authentik_groups = {
    "proxmox-admins"   = "Administrator"
    "proxmox-auditors" = "PVEAuditor"
  }
}

resource "proxmox_virtual_environment_group" "authentik" {
  for_each = local.authentik_groups

  group_id = "${each.key}-${proxmox_realm_openid.authentik.realm}"
  comment  = "Members of Authentik group ${each.key}. Managed by Terraform."
}

resource "proxmox_acl" "authentik" {
  for_each = local.authentik_groups

  path      = "/"
  group_id  = proxmox_virtual_environment_group.authentik[each.key].group_id
  role_id   = each.value
  propagate = true
}
