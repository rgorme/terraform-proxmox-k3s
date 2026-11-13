# Runbook: PostgreSQL HA (Patroni) erstatter LXC 200

Mål: PostgreSQL spredt på to Proxmox-hosts med automatisk failover. Klienterne
bruger fortsat `192.168.1.60`, som bliver en VIP, der følger Patroni-lederen.

| Container  | VMID | Node   | IP             | Rolle                          |
|------------|------|--------|----------------|--------------------------------|
| pg01       | 203  | prox02 | 192.168.1.57   | PostgreSQL + Patroni + etcd    |
| pg02       | 204  | prox03 | 192.168.1.58   | PostgreSQL + Patroni + etcd    |
| pg-witness | 205  | prox01 | 192.168.1.59   | Kun etcd (tredje quorum-stemme) |
| VIP        | –    | –      | 192.168.1.60   | keepalived på Patroni-lederen  |

- etcd har tre medlemmer, så quorum overlever, at én host går ned. Ingen split-brain:
  en Patroni-node uden etcd-quorum degraderer sig selv.
- `synchronous_mode: true` (ikke strict): commits venter på standby'en, når den kører.
  Er standby'en nede, fortsætter primary'en asynkront. Ved failover vælges kun en
  synkron standby, så bekræftede commits går ikke tabt.
- keepalived tjekker Patronis `/primary`-endpoint. Kun lederen holder VIP'en.
- Ingen watchdog (LXC har ikke `/dev/watchdog`).

Klienter: Authentik, PowerDNS (powerdns01/02) og PowerDNS-Admin. De peger alle på
`192.168.1.60` og skal ikke ændres.

---

## 0. Forberedelse

Afklaret ved oprettelsen (13. nov. 2026):
- `.57`–`.59` ligger under DHCP-poolen (starter ved `.64`)
- VMID 203–205 er ledige
- LXC 200 kører PostgreSQL 15.14. Dump/restore i trin 3 er samtidig opgraderingen til 17
- Ingen extensions ud over `plpgsql`

- [ ] Backup af LXC 200: `vzdump 200 --mode snapshot --storage <backup-storage>`
- [ ] Tilføj til `ansible/secrets.yml` (`ansible-vault edit secrets.yml`):
      `postgresql_ha_superuser_password`, `postgresql_ha_replication_password`,
      `postgresql_ha_restapi_password` (mindst 16 tegn hver)

## 1. Opret containerne (Terraform)

- [ ] `cd terraform/lxc && terraform plan`. Planen må kun **oprette** de tre
      `proxmox_virtual_environment_container.postgresql_ha[...]`, ingen ændringer i powerdns01/02
- [ ] `terraform apply`
- [ ] SSH virker til `root@192.168.1.57`, `.58` og `.59`. Tjek host keys mod `pct exec <vmid> -- ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`

## 2. Byg clusteret (VIP slået fra)

`postgresql_ha_vip_enabled` står på `false`, så keepalived ikke tager `.60` fra LXC 200.

- [ ] `cd ansible && ansible-playbook setup-postgresql.yml --ask-vault-pass`
- [ ] På pg01: `etcdctl --endpoints=http://127.0.0.1:2379 member list` viser tre medlemmer
- [ ] På pg01: `patronictl -c /etc/patroni/config.yml list` viser én `Leader` og én
      `Sync Standby` med `streaming`, lag 0

## 3. Flyt data (kort nedetid)

Nedetid: Authentik-login, RADIUS-login på HP 2915 og PowerDNS Authoritative
(`gormsboel.dk`). Rekursiv DNS kører videre. Hold vinduet kort.

- [ ] Stop skrivende klienter:
  - `kubectl -n authentik scale deploy authentik-server authentik-worker --replicas=0`
  - `kubectl -n powerdns-admin scale deploy powerdns-admin --replicas=0`
  - På powerdns01 og powerdns02: `systemctl stop pdns`
  - ArgoCD self-heal skalerer op igen: pause auto-sync for `authentik` og `powerdns-admin` først
- [ ] På prox02: dump alt, men udelad `postgres`-rollen (Patroni ejer dens password):
      `pct exec 200 -- su - postgres -c pg_dumpall | grep -vE '^(CREATE|ALTER) ROLE postgres( |;)' > /root/pg200.sql`
- [ ] Kopiér til lederen (pg01, hvis `patronictl list` stadig siger det):
      `scp /root/pg200.sql root@192.168.1.57:/tmp/`
- [ ] På lederen: `su - postgres -c 'psql -v ON_ERROR_STOP=0 -f /tmp/pg200.sql' 2>&1 | grep -i error`.
      Kun "already exists" for `template1`/`postgres` er OK
- [ ] Sammenlign: `\l` og rækkeantal i et par tabeller pr. database på LXC 200 og pg01
- [ ] Stop LXC 200 og slå autostart fra (den beholdes som fallback):
      `pct stop 200 && pct set 200 --onboot 0`

## 4. Slå VIP'en til

- [ ] Sæt `postgresql_ha_vip_enabled: true` i `ansible/group_vars/postgresql_ha.yml`
- [ ] `ansible-playbook setup-postgresql.yml --ask-vault-pass --tags keepalived`
- [ ] `ip -br addr show eth0` på lederen viser `192.168.1.60`, på standby'en ikke
- [ ] Fra en anden maskine: `psql -h 192.168.1.60 -U powerdns -d powerdns -c 'select pg_is_in_recovery()'` giver `f`

## 5. Start klienterne igen

- [ ] På powerdns01 og powerdns02: `systemctl start pdns`, og `dig @192.168.1.61 gormsboel.dk SOA`
- [ ] Genaktivér ArgoCD auto-sync for `authentik` og `powerdns-admin` (skalerer op igen)
- [ ] Log ind i Authentik, og log ind på HP 2915 via RADIUS (`ssh hp2915`)
- [ ] PowerDNS-Admin viser zonen

## 6. Test failover

- [ ] Planlagt: `patronictl -c /etc/patroni/config.yml switchover --candidate pg02 --force`.
      VIP'en flytter til pg02 inden for få sekunder. Authentik virker stadig
- [ ] Uplanlagt: `pct stop 204` på prox03 (mens pg02 er leder). pg01 bliver leder efter
      ca. `ttl` (30 s), og VIP'en flytter. `pct start 204`, og pg02 kommer tilbage som
      `Sync Standby` (via `pg_rewind`)
- [ ] Skift tilbage: `switchover --candidate pg01 --force`

## 7. Efterarbejde

- [ ] Efter en uges drift: slet LXC 200 (`pct destroy 200`). vzdump-backuppen fra trin 0 bliver liggende
- [ ] Backup: HA er ikke backup. Opsæt fx pgBackRest eller et natligt `pg_dumpall` fra lederen
- [ ] Grafana/alarmer: alarm på `patroni_primary` = 0 i hele clusteret og på replikerings-lag
- [ ] Opdatér idétavlen

## Rollback (før trin 6)

1. `systemctl disable --now keepalived` på pg01 og pg02 (frigiver `.60`)
2. `pct set 200 --onboot 1 && pct start 200` på prox02
3. Genstart klienterne som i trin 5. Skrivninger lavet efter trin 3 findes kun i Patroni-clusteret
