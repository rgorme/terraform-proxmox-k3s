terraform {
  cloud {
    organization = "rgorme-org"

    workspaces {
      name = "terraform-proxmox-k3s"
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

# Resource pool for our cluster
resource "proxmox_virtual_environment_pool" "k3s_pool" {
  pool_id = "k3s"
}

locals {
  k3s_vms = {
    master_0 = {
      vm_id      = 102
      name       = "k3s-master-0"
      node_name  = "prox01"
      datastore  = "local-lvm"
      disk_size  = 20
      ip_address = "192.168.1.17/24"
      memory_mib = 4096
    }
    master_1 = {
      vm_id      = 101
      name       = "k3s-master-1"
      node_name  = "prox02"
      datastore  = "local-lvm"
      disk_size  = 20
      ip_address = "192.168.1.18/24"
      memory_mib = 4096
    }
    worker_0 = {
      vm_id      = 104
      name       = "k3s-worker-0"
      node_name  = "prox01"
      datastore  = "zvmdata"
      disk_size  = 30
      ip_address = "192.168.1.32/24"
      memory_mib = 4096
    }
    worker_1 = {
      vm_id      = 103
      name       = "k3s-worker-1"
      node_name  = "prox02"
      datastore  = "zvmdata"
      disk_size  = 30
      ip_address = "192.168.1.33/24"
      memory_mib = 4096
    }
  }
}

resource "proxmox_virtual_environment_vm" "k3s" {
  for_each = local.k3s_vms

  name        = each.value.name
  description = "Managed by Terraform."
  node_name   = each.value.node_name
  pool_id     = proxmox_virtual_environment_pool.k3s_pool.pool_id
  vm_id       = each.value.vm_id

  agent {
    enabled = true
  }

  clone {
    vm_id = var.template_vm_id
    full  = true
  }

  cpu {
    cores   = 2
    sockets = 1
    type    = "host"
  }

  memory {
    dedicated = each.value.memory_mib
    floating  = 0
  }

  disk {
    datastore_id = each.value.datastore
    size         = each.value.disk_size
    interface    = "scsi0"
    file_format  = "raw"
    replicate    = false
  }

  initialization {
    datastore_id = each.value.datastore

    ip_config {
      ipv4 {
        address = each.value.ip_address
        gateway = var.network_gateway
      }
    }

    user_account {
      keys     = [var.ssh_public_key]
      username = "k3s"
    }
  }

  network_device {
    bridge = "vmbr0"
    model  = "virtio"
  }

  on_boot       = true
  protection    = false
  scsi_hardware = "virtio-scsi-pci"
  started       = true
  tablet_device = true

  lifecycle {
    prevent_destroy = true

    # Clone metadata is not retained by imports. Preserve existing cloud-init
    # passwords and the obsolete USB device until it is removed deliberately.
    ignore_changes = [
      clone,
      initialization[0].user_account[0].password,
      usb,
      operating_system,
    ]
  }
}