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

The Terraform configuration is in `k3s/`. Its `main.tf` has `prevent_destroy = true` on every K3s VM. Terraform cannot
destroy or replace an adopted VM unless that protection is deliberately removed.
It also ignores clone metadata, cloud-init passwords, and the obsolete USB
device on `k3s-worker-1` during initial adoption.

Create an ignored local variables file from the example:

```sh
cd k3s
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
cd k3s
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

## PostgreSQL HA

Terraform in `terraform/lxc/` also creates the PostgreSQL HA containers:
`pg01` (`192.168.1.57`, `prox02`), `pg02` (`192.168.1.58`, `prox03`) and the
etcd-only `pg-witness` (`192.168.1.59`, `prox01`). Patroni runs PostgreSQL on
`pg01`/`pg02` with etcd on all three, and keepalived holds the client VIP
`192.168.1.60` on the current leader.

```sh
cd ansible
ansible-playbook setup-postgresql.yml --ask-vault-pass
```

Migration from the old single container (LXC 200) and failover tests are in
`docs/runbooks/postgresql-ha.md`.

## PowerDNS Management

Terraform in `terraform/lxc/` creates two Debian 12 PowerDNS containers:
`powerdns01` (`192.168.1.61`, `prox02`) and `powerdns02`
(`192.168.1.62`, `prox01`). They share the existing PostgreSQL database at
`192.168.1.60` and run PowerDNS Authoritative, PowerDNS Recursor, and dnsdist.

dnsdist accepts DNS traffic on port 53. It sends `gormsboel.dk` requests to
the local Authoritative server and sends other requests from the LAN to the
local Recursor, which forwards them to the ISP router at `192.168.1.1`.
Recursive DNS is restricted to `192.168.1.0/24`; Authoritative DNS remains
available for the configured zone.

Create the empty PostgreSQL database and ensure the `powerdns` user can create
tables in it. PostgreSQL must permit connections from both PowerDNS container
addresses. Then add these values to the ignored `ansible/secrets.yml` file:

```yaml
powerdns_postgresql_password: REPLACE_WITH_POWERDNS_POSTGRESQL_PASSWORD
powerdns_api_key: REPLACE_WITH_A_RANDOM_32_CHARACTER_OR_LONGER_API_KEY
```

Deploy the containers and configure PowerDNS:

```sh
cd terraform/lxc
terraform apply

cd ../../ansible
ansible-playbook setup-powerdns.yml
```

The playbook initializes the schema and creates the `gormsboel.dk` zone with
`ns1.gormsboel.dk` and `ns2.gormsboel.dk` NS records. Manage host records
through the PowerDNS API on port `8081` or PowerDNS-Admin. The API is limited
to `192.168.1.0/24`.

For LAN HA, configure clients to use both `192.168.1.61` and `192.168.1.62` as
their DNS servers. Public delegation additionally requires public reachability
for TCP and UDP port 53 to each nameserver and glue records at the registrar.
Do not expose recursive DNS to the Internet.

## Proxmox Login with Authentik

Terraform in `terraform/access/` adds the OpenID Connect realm `authentik` to
Proxmox, plus two groups that grant access on `/`:

| Authentik group | Proxmox group | Role |
| --- | --- | --- |
| `proxmox-admins` | `proxmox-admins-authentik` | `Administrator` |
| `proxmox-auditors` | `proxmox-auditors-authentik` | `PVEAuditor` |

Users are created on first login as `<username>@authentik`. Their groups are
replaced from the `groups` claim on every login, so removing a user from the
Authentik group removes their Proxmox access at the next login. A user in
neither group can log in but sees nothing. Proxmox ignores group names that
contain spaces, so keep the Authentik group names exactly as above.

One-time setup in Authentik:

1. Create an OAuth2/OpenID provider with client type *Confidential*, signing key
   set, scopes `openid profile email`, and these redirect URIs (strict):
   `https://192.168.1.2:8006` and `https://192.168.1.3:8006`. Add any DNS
   names you use for the web UI as well; Proxmox redirects back to the address
   in the browser.
2. Create an application with slug `proxmox` that uses the provider.
3. Create the groups `proxmox-admins` and `proxmox-auditors` and add users.

The Terraform token needs `Realm.Allocate`, `Group.Allocate` and
`Permissions.Modify` on `/` (the `Administrator` role covers all three). Then
apply:

```sh
cd terraform/access
cp terraform.tfvars.example terraform.tfvars   # set client ID and secret
terraform init
terraform apply
```

The client secret is a write-only argument and is never stored in Terraform
state. To rotate it, change the secret and increase
`authentik_client_secret_version`. Keep `root@pam` as a break-glass login.

## Deliberate Follow-up Work

- Remove the obsolete USB passthrough from VM `103` in its own reviewed change.
- Move Terraform state to a remote backend with locking and encrypted backups.
- Add backup and restore automation for the external single-instance MariaDB
  datastore and Nginx configuration on `k3s-support`.
- Upgrade K3s only one minor version at a time, with a cluster health check
  between each version.