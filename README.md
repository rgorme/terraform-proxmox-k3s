# Terraform Proxmox K3s

This repository adopts and manages an existing K3s cluster on Proxmox VE.

Terraform owns the four K3s VMs. Ansible manages their OS prerequisites and
K3s installation. The `k3s-support` VM remains external: it
hosts MariaDB and Nginx, which load-balances the Kubernetes API to both K3s
servers.

## Managed Infrastructure

All VMs belong to pool `k3s`, were cloned from template `9001`
(`ubuntu-2404-CI`), use the `k3s` login user, and have a common default gateway
of `192.168.1.1`.

## Terraform Adoption

`main.tf` has `prevent_destroy = true` on every K3s VM. Terraform cannot
destroy or replace an adopted VM unless that protection is deliberately removed.
It also ignores clone metadata, cloud-init passwords, and the obsolete USB
device on `k3s-worker-1` during initial adoption.

Create an ignored local variables file from the example:

```sh
cp terraform.tfvars.example terraform.tfvars
```

Set `ssh_public_key` to the public key already configured by cloud-init and set
the Proxmox token secret. The token ID is:

```hcl
proxmox_api_token_id = "terraform-prov@pve!terraform-token-new"
```

Initialize and import the existing pool and VMs. Imports only write Terraform
state; they do not change the Proxmox resources.

```sh
terraform init
terraform import proxmox_virtual_environment_pool.k3s_pool k3s
terraform import 'proxmox_virtual_environment_vm.k3s["master_0"]' prox01/102
terraform import 'proxmox_virtual_environment_vm.k3s["master_1"]' prox02/101
terraform import 'proxmox_virtual_environment_vm.k3s["worker_0"]' prox01/104
terraform import 'proxmox_virtual_environment_vm.k3s["worker_1"]' prox02/103
terraform plan
```

Do not run `terraform apply` while the plan includes a destroy, replacement,
network-device removal, disk move, or unexpected cloud-init change. Resolve
each difference in configuration first. Back up the resulting local
`terraform.tfstate` until a remote backend is configured.

## K3s Management

K3s settings are managed in `/etc/rancher/k3s/config.yaml`, not in custom
systemd `ExecStart` definitions. The official K3s installer owns the service
units, making normal installer-based upgrades possible.

The shared API endpoint is on the support vm Nginx on the external
support VM forwards TCP traffic to both servers. Server configuration retains:

- the shared K3s token;
- the external MariaDB datastore endpoint;
- Traefik disabled; and
- the `CriticalAddonsOnly=true:NoExecute` server taint.

The playbook pins every node to `v1.36.2+k3s1`. This first brings the workers
from `v1.32.5+k3s1` into supported version skew with the servers. Workers run
serially and the playbook waits for each one to become `Ready` before moving to
the next.

Create local Ansible configuration and encrypted secrets:

```sh
cd ansible
cp ansible.cfg.example ansible.cfg
cp secrets.yml.example secrets.yml
ansible-vault encrypt secrets.yml
```

Set the private-key path in `ansible.cfg`. Replace the placeholders in
`secrets.yml` with the existing K3s token and MariaDB connection string before
encrypting it. Do not reset either secret during migration.

Review the playbook before the first live run, then execute it with an
interactive Vault password prompt:

```sh
ansible-playbook setup-k3s.yml --ask-vault-pass
```

Validate the result from either server:

```sh
sudo k3s kubectl get nodes -o wide
sudo k3s kubectl get pods -A
```

## Deliberate Follow-up Work

- Remove the obsolete USB passthrough from VM `103` in its own reviewed change.
- Move Terraform state to a remote backend with locking and encrypted backups.
- Add backup and restore automation for the external single-instance MariaDB
  datastore and Nginx configuration on `k3s-support`.
- Upgrade K3s only one minor version at a time, with a cluster health check
  between each version.