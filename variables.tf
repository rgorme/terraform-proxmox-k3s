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

variable "template_vm_id" {
  description = "ID of the Ubuntu 24.04 cloud-init template used to create K3s VMs"
  type        = number
  default     = 9001
}

variable "ssh_public_key" {
  description = "SSH public key configured by Proxmox cloud-init"
  type        = string
}

variable "network_gateway" {
  description = "IPv4 default gateway for K3s VMs"
  type        = string
}

variable "k3s_vms" {
  description = "K3s VM definitions keyed by stable Terraform resource name."
  type = map(object({
    vm_id      = number
    name       = string
    node_name  = string
    datastore  = string
    disk_size  = number
    ip_address = string
    memory_mib = number
  }))
}
