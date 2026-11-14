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

- [x] Backup af LXC 200: `vzdump 200 --mode snapshot --storage <backup-storage>`
- [x] Tilføj til `ansible/secrets.yml` (`ansible-vault edit secrets.yml`):
      `postgresql_ha_superuser_password`, `postgresql_ha_replication_password`,
      `postgresql_ha_restapi_password` (mindst 16 tegn hver)
- [x] Debian 12-templaten findes på alle tre noder (prox03 havde den ikke):
      `pveam update && pveam download local debian-12-standard_12.12-1_amd64.tar.zst`

## 1. Opret containerne (Terraform)

- [x] `cd terraform/lxc && terraform plan`. Planen må kun **oprette** de tre
      `proxmox_virtual_environment_container.postgresql_ha[...]`, ingen ændringer i powerdns01/02
- [x] `terraform apply` (alle tre oprettet 14. nov.; efterfølgende plan: `No changes`)
- [x] SSH virker til `root@192.168.1.57`, `.58` og `.59`. Tjek host keys mod `pct exec <vmid> -- ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`

## 2. Byg clusteret (VIP slået fra)

`postgresql_ha_vip_enabled` står på `false`, så keepalived ikke tager `.60` fra LXC 200.

- [x] `cd ansible && ansible-playbook setup-postgresql.yml --ask-vault-pass`
- [x] På pg01: `etcdctl --endpoints=http://127.0.0.1:2379 member list` viser tre medlemmer
- [x] På pg01: `patronictl -c /etc/patroni/config.yml list` viser én `Leader` og én
      `Sync Standby` med `streaming`, lag 0

## 3. Flyt data (kort nedetid)

Udført 14.–15. nov. 2026. Nedetid 23:39–00:00 (ca. 21 min) for Authentik-login,
RADIUS-login på HP 2915 og PowerDNS Authoritative (`gormsboel.dk`).

- [x] Tjek klienter på LXC 200 (`pg_stat_activity`): kun Authentik, PowerDNS og PowerDNS-Admin.
      `netbox` og `planka` findes som databaser, men intet bruger dem. De følger med i dumpet
- [x] Merge rgorme/gitops#98 (pauser auto-sync for `authentik` og `powerdns-admin`)
- [x] Stop skrivende klienter: scale `authentik-server`, `authentik-worker` og `powerdns-admin`
      til 0 (alle stod på 2), og `systemctl stop pdns` på powerdns01/02
- [x] På prox02: `pct exec 200 -- su - postgres -c pg_dumpall > /root/pg200-full.sql`, og
      `grep -vE '^(CREATE|ALTER) ROLE postgres( |;)'` til `/root/pg200.sql` (Patroni ejer `postgres`)
- [x] Kopiér til lederen som `/var/lib/postgresql/pg200.sql`. Ikke `/tmp`: `protected_regular`
      forhindrer root i at skrive en postgres-ejet fil der
- [x] `authentik`, `netbox` og `planka` bruger locale `da_DK.UTF-8`. Generér den på begge noder
      (nu i Patroni-rollen) og kør `patronictl restart`, ellers fejler `CREATE DATABASE`
- [x] Restore på lederen: `su postgres -c 'psql -X -v ON_ERROR_STOP=0 -f pg200.sql'`.
      Kun "role ... already exists" er OK
- [x] Sammenlign præcist rækkeantal i alle tabeller, roller og extensions: identisk
      (488 tabeller, 402.765 rækker)
- [x] `pct shutdown 200 && pct set 200 --onboot 0` (beholdes som fallback)

## 4. Slå VIP'en til

- [x] Sæt `postgresql_ha_vip_enabled: true` i `ansible/group_vars/postgresql_ha.yml`
- [x] `ansible-playbook setup-postgresql.yml --ask-vault-pass --tags keepalived`
- [x] `.60` ligger kun på lederen (pg01), og ARP for `.60` peger på pg01's MAC

## 5. Start klienterne igen

kubectl logger ind via Authentik-OIDC og virker ikke, mens Authentik er nede. Brug
break-glass: `ssh k3s@192.168.1.17 sudo k3s kubectl ...`.

- [x] `systemctl start pdns` på powerdns01/02, og `dig gormsboel.dk SOA` svarer fra begge
- [x] Scale `authentik-server`, `authentik-worker` og `powerdns-admin` til 2 (via break-glass)
- [x] `pg_stat_activity` på pg01 viser alle tre klienter. Authentik `/-/health/ready/` giver 200
- [ ] Revert rgorme/gitops#98, så ArgoCD genaktiverer auto-sync
- [ ] Log ind i Authentik, og log ind på HP 2915 via RADIUS (`ssh hp2915`)
- [ ] PowerDNS-Admin viser zonen

## 6. Test failover

Udført 15. nov. 2026 med en markør-tabel og en monitor, der hvert sekund tjekkede
`.60:5432` og Authentiks `/-/health/ready/`.

- [x] Login i Authentik, RADIUS på HP 2915 og PowerDNS-Admin virker (testet af ejeren)
- [x] Planlagt: `patronictl switchover pg-homelab --leader pg01 --candidate pg02 --force`.
      `.60` var væk i ca. 1 s, og Authentik var ikke klar i ca. 5 s
- [x] Uplanlagt: hård stop af pg02 som leder (`pvesh create /nodes/prox03/lxc/204/status/stop`).
      `.60` var væk i ca. 33 s (Patroni `ttl` 30), og Authentik var ikke klar i ca. 65 s,
      fordi den genopretter sine forbindelser. pg01 blev leder på timeline 3
- [x] Ingen datatab: alle markør-rækker fandtes efter begge tests
- [x] Start pg02: den kom tilbage via `pg_rewind` som `Sync Standby`, lag 0

Fundet under testen: efter genstart startede Patroni ikke, fordi `/run/postgresql`
manglede. `systemd-tmpfiles-setup` fejler ved boot i containerne ("Failed to set up
credentials", samme årsag som PowerDNS-overrides). Patroni-rollen har nu et drop-in
med `RuntimeDirectory=postgresql`, som er lagt ind på begge noder.

## 7. Efterarbejde

- [ ] Efter en uges drift: slet LXC 200 (`pct destroy 200`). vzdump-backuppen fra trin 0 bliver liggende
- [ ] Backup: HA er ikke backup. Opsæt fx pgBackRest eller et natligt `pg_dumpall` fra lederen
- [ ] Grafana/alarmer: alarm på `patroni_primary` = 0 i hele clusteret og på replikerings-lag
- [ ] Opdatér idétavlen

## Rollback (før trin 6)

1. `systemctl disable --now keepalived` på pg01 og pg02 (frigiver `.60`)
2. `pct set 200 --onboot 1 && pct start 200` på prox02
3. Genstart klienterne som i trin 5. Skrivninger lavet efter trin 3 findes kun i Patroni-clusteret
