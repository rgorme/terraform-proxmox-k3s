terraform {
  cloud {
    organization = "rgorme-org"

    workspaces {
      name = "terraform-proxmox-lxc"
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

resource "proxmox_virtual_environment_container" "powerdns01" {
  node_name = "prox02"
  vm_id     = 201

  description = "PowerDNS01"

  cpu {
    cores = 1
  }

  memory {
    dedicated = 1024
  }

  disk {
    datastore_id = "zvmdata"
    size         = 8
  }

  initialization {
    hostname = "powerdns01"

    user_account {
      keys = [var.ssh_public_key]
    }

    ip_config {
      ipv4 {
        address = "192.168.1.61/24"
        gateway = "192.168.1.1"
      }
    }

    dns {
      servers = ["192.168.1.1"]
    }
  }

  network_interface {
    name   = "eth0"
    bridge = "vmbr0"
  }

  operating_system {
    template_file_id = "local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst"
    type             = "debian"
  }

  start_on_boot = true
}

resource "proxmox_virtual_environment_container" "powerdns02" {
  node_name = "prox01"
  vm_id     = 202

  description = "PowerDNS02"

  cpu {
    cores = 1
  }

  memory {
    dedicated = 1024
  }

  disk {
    datastore_id = "zvmdata"
    size         = 8
  }

  initialization {
    hostname = "powerdns02"

    user_account {
      keys = [var.ssh_public_key]
    }

    ip_config {
      ipv4 {
        address = "192.168.1.62/24"
        gateway = "192.168.1.1"
      }
    }

    dns {
      servers = ["192.168.1.1"]
    }
  }

  network_interface {
    name   = "eth0"
    bridge = "vmbr0"
  }

  operating_system {
    template_file_id = "local:vztmpl/debian-12-standard_12.12-1_amd64.tar.zst"
    type             = "debian"
  }

  start_on_boot = true
}
