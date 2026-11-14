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

# PostgreSQL HA: Patroni on pg01/pg02 (one per Proxmox host) and an etcd-only
# witness on prox01, so etcd keeps quorum when either PostgreSQL host is down.
# Clients use the keepalived VIP 192.168.1.60, which follows the Patroni leader.
locals {
  postgresql_ha_containers = {
    pg01 = {
      node_name = "prox02"
      vm_id     = 203
      address   = "192.168.1.57/24"
      cores     = 2
      memory    = 2048
      disk_size = 32
    }
    pg02 = {
      node_name = "prox03"
      vm_id     = 204
      address   = "192.168.1.58/24"
      cores     = 2
      memory    = 2048
      disk_size = 32
    }
    pg-witness = {
      node_name = "prox01"
      vm_id     = 205
      address   = "192.168.1.59/24"
      cores     = 1
      memory    = 512
      disk_size = 4
    }
  }
}

resource "proxmox_virtual_environment_container" "postgresql_ha" {
  for_each = local.postgresql_ha_containers

  node_name = each.value.node_name
  vm_id     = each.value.vm_id

  description = "PostgreSQL HA (${each.key})"
  tags        = ["postgresql"]

  cpu {
    cores = each.value.cores
  }

  memory {
    dedicated = each.value.memory
  }

  disk {
    datastore_id = "zvmdata"
    size         = each.value.disk_size
  }

  initialization {
    hostname = each.key

    user_account {
      keys = [var.ssh_public_key]
    }

    ip_config {
      ipv4 {
        address = each.value.address
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
