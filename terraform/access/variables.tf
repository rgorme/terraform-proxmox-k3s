variable "proxmox_api_url" {
  description = "Proxmox API URL"
  type        = string
}

variable "proxmox_api_token_id" {
  description = "Proxmox API token ID in user@realm!token-name form"
  type        = string
}

variable "proxmox_api_token_secret" {
  description = "Proxmox API token secret"
  type        = string
  sensitive   = true
}

variable "authentik_issuer_url" {
  description = "OIDC issuer URL of the Authentik application for Proxmox"
  type        = string
  default     = "https://authentik.gormsboel.dk/application/o/proxmox/"
}

variable "authentik_client_id" {
  description = "Client ID of the Authentik OAuth2/OpenID provider for Proxmox"
  type        = string
}

variable "authentik_client_secret" {
  description = "Client secret of the Authentik OAuth2/OpenID provider for Proxmox"
  type        = string
  sensitive   = true
  ephemeral   = true
}

variable "authentik_client_secret_version" {
  description = "Increase to push a rotated authentik_client_secret to Proxmox"
  type        = number
  default     = 1
}
