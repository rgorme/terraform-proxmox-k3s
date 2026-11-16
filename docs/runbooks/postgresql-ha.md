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
- etcd kræver login: Patroni bruger brugeren `patroni`, der kun må læse og skrive under
  `/service/`. `root` (medlemskab, brugere) ligger i `secrets.yml`. Se "Slå etcd-login til".

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
- [ ] Backup: HA er ikke backup. pgBackRest er sat op i Ansible, se trin 8
- [ ] Grafana/alarmer: alarm på `patroni_primary` = 0 i hele clusteret og på replikerings-lag
- [ ] etcd: klient-TLS, så Patronis login ikke går over ren HTTP (se "Slå etcd-login til")
- [ ] Opdatér idétavlen

## 8. Backup med pgBackRest

Point-in-time recovery (PITR) for hele clusteret, uafhængigt af hvem der er leder.

| Del             | Hvor        | Hvad                                                                  |
|-----------------|-------------|-----------------------------------------------------------------------|
| Repository      | pg-witness  | `/var/lib/pgbackrest`, ejet af brugeren `pgbackrest`                  |
| WAL-arkivering  | pg01, pg02  | `archive_command` skubber WAL til pg-witness over SSH (async, spool i `/var/spool/pgbackrest`) |
| Backups         | pg-witness  | systemd-timere: full søndag 01:30, diff man–lør 01:30                 |
| Retention       | –           | 14 dage (`repo1-retention-full-type=time`). PITR når altid mindst 14 dage tilbage |

- Backuppen kører på pg-witness, og pgBackRest finder selv primary'en blandt
  `pg1-host` (pg01) og `pg2-host` (pg02). Efter en failover rammer næste backup den nye leder.
  Er der ingen primary, fejler kørslen, og `pgbackrest-backup@full.service` står som failed.
- Kun lederen arkiverer (`archive_mode=on` i Patroni-DCS). `always` ville også lade standby'en
  arkivere, men pgBackRests `backup` og `check` afviser det (`[067] archive_mode=always not
  supported`). Prisen: dør lederen med WAL i sin async-spool, eller har standby'en streamet
  segmenter, som lederen ikke nåede at arkivere, kommer de aldrig i repoet. PITR til
  minutterne lige før en failover kan derfor have et hul. Alt efter failoveren er dækket,
  og tidslinjeskiftet håndteres af pgBackRest. Tag en full-backup efter en failover.
- Patroni-parametre, der ændres i Ansible (`patroni_postgresql_parameters` og pgBackRests
  `archive_*`), PATCHes ind i den dynamiske config via REST API'et på den første node i
  `postgresql`, der er med i kørslen. `bootstrap.dcs` gælder kun ved første bootstrap.
  Kør playbooken uden `--limit`: pgbackrest-rollen stopper, hvis en af de tre hosts mangler
- SSH: `postgres` på pg01/pg02 → `pgbackrest@.59` (arkivering, restore) og
  `pgbackrest` på pg-witness → `postgres@.57/.58` (backup). Nøglerne er genereret af
  rollen og begrænset med `from=`.
- Retention er tidsbaseret: full-backups ældre end 14 dage slettes, men pgBackRest beholder
  den nyeste full, der er ældre end 14 dage. Lige efter søndagens full ligger der derfor tre
  fulls (ca. 15–21 dage), så PITR aldrig dækker under 14 dage. Diffs og WAL slettes sammen
  med den full, de hører til
- Er pg-witness nede, hober WAL sig op i `pg_wal` på lederen. Over 4 GiB
  (`archive-push-queue-max`) smider pgBackRest WAL'en væk for at redde lederens disk.
  Så er PITR brudt indtil næste full-backup.
- pg-witness bærer nu både etcd-stemmen og backupperne. prox01 er stadig en anden host
  end pg01/pg02, men der er ingen offsite-kopi.

### Pladsforbrug og nye databaser

- Nye databaser kommer automatisk med: pgBackRest tager backup af hele clusteret
  (alle databaser og WAL), så der er intet at sætte op pr. database
- Følg repoets vækst på pg-witness:
  - `runuser -u pgbackrest -- pgbackrest --stanza=pg-homelab info` viser størrelse pr. backup
    (`database size`/`backup size`, og `repo1: backup set size` komprimeret)
  - `du -sh /var/lib/pgbackrest/backup /var/lib/pgbackrest/archive` og `df -h /var/lib/pgbackrest`
- Estimat (15. nov. 2026): databaserne fylder ca. 210 MB, og lederen skriver ca. 0,4 GB WAL i
  døgnet (målt over 5 min. midt på dagen). Repoet rummer op til 21 dages data: 3 fulls,
  op til 18 diffs og 21 døgns WAL. Med zst-komprimering bliver det ca. 3–5 GB, og ca. 10 GB
  i værste fald uden nævneværdig komprimering
- Tommelfingerregel: repo ≈ 3 × databasestørrelse + 21 × WAL pr. døgn (begge komprimeret,
  plus diffs). Disken er 32 GB, så det bliver trangt, når `df` passerer ca. 75 % (ca. 24 GB),
  eller når den komprimerede WAL nærmer sig 1 GB i døgnet (se `archive/` vokse over en uge).
  Udvid så disken i Terraform (kun opad, ellers erstattes containeren) eller skru retention ned

### 8.1 Opsætning

- [x] Udvid pg-witness' disk fra 4 til 32 GB: `cd terraform/lxc && terraform plan`. Planen må kun
      vise `~ size = 4 -> 32` på `postgresql_ha["pg-witness"]` som *update in-place*. Står der
      *must be replaced*, så stop. Derefter `terraform apply`, og tjek `df -h /` på pg-witness
- [x] Slå `nesting` til på alle tre containere (2026-11-17). Uden den kan systemd ikke lave
      mount-namespaces i de privilegerede containere: `systemd-logind` starter aldrig, hvert
      SSH-login venter 25 s i `pam_systemd`, og pgBackRests `check`/`backup` rammer
      60-sekunders WAL-timeouten. Terraform-tokenet må ikke ændre features på en privilegeret
      container (kun `root@pam`), så det gøres på hosten og spejles i `main.tf`:
      `pct set <vmid> --features nesting=1`, derefter genstart én ad gangen: pg-witness,
      standby'en, `patronictl switchover --leader <leder> --candidate <standby>`, den gamle leder.
      Tjek bagefter `systemctl is-active systemd-logind` og at `ssh postgres@<node> true`
      fra pg-witness tager under et sekund
- [x] `cd ansible && ansible-playbook setup-postgresql.yml --ask-vault-pass --tags pgbackrest`.
      Rollen installerer pgBackRest fra PGDG på alle tre, udveksler SSH-nøgler, kører
      `stanza-create` på pg-witness, slår timerne til og PATCHer Patronis dynamiske config
      med `archive_mode: on` og `archive_command` (samme som `patronictl edit-config`;
      `bootstrap.dcs` gælder kun ved første bootstrap)
- [x] `patronictl -c /etc/patroni/config.yml show-config` viser `archive_mode` og `archive_command`
- [x] `patronictl -c /etc/patroni/config.yml list` viser `Pending restart` på begge noder.
      `archive_mode` kræver genstart: `patronictl -c /etc/patroni/config.yml restart pg-homelab --pending`.
      Genstart af lederen giver et par sekunders afbrydelse (Authentik genforbinder)
- [x] På begge noder: `su postgres -c "psql -Atc 'show archive_mode'"` giver `on`
- [x] På pg-witness: `runuser -u pgbackrest -- pgbackrest --stanza=pg-homelab check`
      (tvinger et WAL-skift og venter på, at det er arkiveret)
- [x] Første full-backup med det samme: `systemctl start pgbackrest-backup@full.service`,
      derefter `journalctl -u pgbackrest-backup@full.service` uden fejl
- [x] `systemctl list-timers 'pgbackrest-*'` viser begge timere med næste kørsel

Køres playbooken igen, sker der intet, når DCS-værdierne allerede er sat. Er clusteret
blevet genskabt (fx efter `patronictl remove`, se 8.4), sætter playbooken dem igen.

### 8.2 Tjek at backuppen virker

Alt på pg-witness som `pgbackrest` (`runuser -u pgbackrest -- ...`):

- `pgbackrest --stanza=pg-homelab info`: status `ok`, seneste backup fra i nat, og
  `wal archive min/max` hvor max er få minutter gammel
- `pgbackrest --stanza=pg-homelab check`: arkiveringen virker lige nu
- `pgbackrest --stanza=pg-homelab verify`: læser hele repoet og tjekker checksummer
  (backups og WAL). Tager lidt tid, men kører fint midt på dagen
- `systemctl --failed` er tom, og `journalctl -u 'pgbackrest-backup@*' --since -2d` viser
  de seneste kørsler
- `df -h /` på pg-witness: repoet skal kunne rumme op til 3 ugers backups og WAL (se nedenfor)
- På lederen: `su postgres -c "psql -Atc 'select archived_count, failed_count, last_failed_time from pg_stat_archiver'"`.
  `failed_count` må gerne være > 0 fra fortiden, men `last_failed_time` skal være gammel

### 8.3 Restore-test (PITR til en sidevogn)

Restorer til en midlertidig mappe på **standby'en** og starter en ekstra PostgreSQL på
port 5433. Patroni, clusteret og VIP'en røres ikke. Kør den efter opsætningen og derefter
fx hvert kvartal.

1. På lederen: lav en markør og notér tiden:
   ```sh
   su postgres -c "psql -Atc \"create table public.restore_marker(t timestamptz default now()); insert into public.restore_marker default values; select now();\""
   ```
   Vent et par sekunder, notér tiden igen (`T`), og slet så markøren (det er "uheldet"):
   ```sh
   su postgres -c "psql -Atc 'select now()'"     # = T, fx 2026-11-16 12:34:56.789+01
   su postgres -c "psql -Atc 'drop table public.restore_marker; select pg_switch_wal()'"
   ```
2. På pg-witness: `runuser -u pgbackrest -- pgbackrest --stanza=pg-homelab check` (WAL'en er arkiveret)
3. På standby'en (`patronictl list` viser hvem):
   ```sh
   install -d -o postgres -g postgres -m 0700 /var/lib/postgresql/restore-test
   su postgres -c "pgbackrest --stanza=pg-homelab --pg1-path=/var/lib/postgresql/restore-test \
     --type=time --target='T' --target-action=promote restore"
   ```
4. Start den som en løs instans. `archive_mode=off` er vigtigt: ellers skubber test-instansen
   sin nye tidslinje ind i det rigtige repo. `synchronous_standby_names` nulstilles, så
   skrivninger ikke hænger:
   ```sh
   su postgres -c "/usr/lib/postgresql/17/bin/pg_ctl -D /var/lib/postgresql/restore-test \
     -l /var/lib/postgresql/restore-test.log -w -t 600 start \
     -o \"-c port=5433 -c listen_addresses=127.0.0.1 -c archive_mode=off \
         -c synchronous_standby_names='' -c shared_buffers=128MB -c cluster_name=restore-test \
         -c hba_file=/var/lib/postgresql/restore-test/pg_hba.conf \
         -c ident_file=/var/lib/postgresql/restore-test/pg_ident.conf\""
   ```
   `hba_file`/`ident_file` skal med: Patronis `postgresql.conf` peger på filerne i
   `/var/lib/postgresql/17/patroni`, altså den kørende standbys.
5. Tjek:
   - `su postgres -c "psql -p 5433 -Atc 'select * from public.restore_marker'"` giver
     markør-rækken (den er slettet i det rigtige cluster)
   - `su postgres -c "psql -p 5433 -Atc 'select pg_is_in_recovery()'"` giver `f`
   - `psql -p 5433 -l` viser `authentik`, `powerdns`, `powerdnsadmin`, `netbox`, `planka`,
     og fx `select count(*) from authentik_core_user` i `authentik` svarer til lederen
   - `grep -E 'recovery stopping|selected new timeline' /var/lib/postgresql/restore-test.log`
6. Ryd op:
   ```sh
   su postgres -c "/usr/lib/postgresql/17/bin/pg_ctl -D /var/lib/postgresql/restore-test -m fast stop"
   rm -rf /var/lib/postgresql/restore-test /var/lib/postgresql/restore-test.log
   ```
   Notér dato og resultat her.

Log over restore-tests:

- [x] 2026-11-17, standby pg01 (leder pg02, TL 4): restore fra full `20261117-013102F` + WAL
      til T = `18:50:06.78+00`, 15 s for 216 MB. Markøren var der, `pg_is_in_recovery()` = `f`
      efter promoveringen (`t` i de første sekunder, mens den promoverer), alle seks databaser,
      7 brugere i `authentik_core_user` som på lederen. Loggen: `recovery stopping before commit
      of transaction 325679` (DROP'et) og `selected new timeline ID: 5`. Repoet fik ingen
      tidslinje 5 (`archive_mode=off` virker). Bestået

### 8.4 Restore af hele clusteret (katastrofe)

Når data i clusteret er ødelagt (fx en slettet tabel) eller begge noder er tabt. Alle
klienter er nede undervejs. Stop dem som i trin 3, og brug break-glass til kubectl.

1. Notér, hvem der er leder (`patronictl list`; nedenfor kaldet "lederen", den anden "standby'en").
   Stop Patroni på begge noder: `systemctl stop patroni` (standby'en først, så lederen).
   keepalived slipper `.60`, når `/primary` svarer nej
2. På lederen: restore oven i data-mappen. `--delta` genbruger uændrede filer:
   ```sh
   su postgres -c "pgbackrest --stanza=pg-homelab --delta \
     --type=time --target='<tidspunkt>' --target-action=promote restore"
   ```
   Uden `--type`/`--target` restorer den til seneste arkiverede WAL
3. Start PostgreSQL løst, så recovery bliver færdig og den promoverer:
   ```sh
   su postgres -c "/usr/lib/postgresql/17/bin/pg_ctl -D /var/lib/postgresql/17/patroni -w -t 600 start \
     -o '-c archive_mode=off -c synchronous_standby_names=\"\"'"
   ```
   Tjek data med `psql`, og stop den igen: `pg_ctl -D ... -m fast stop`
4. Nulstil Patronis cluster-tilstand i etcd (også den dynamiske config):
   `patronictl -c /etc/patroni/config.yml remove pg-homelab` (spørger om navnet og bekræftelse)
5. `systemctl start patroni` på lederen. Den overtager den eksisterende data-mappe som leder
   og skriver `bootstrap.dcs` som ny dynamisk config
6. På standby'en: `rm -rf /var/lib/postgresql/17/patroni` og `systemctl start patroni`. Den
   kloner fra lederen og bliver `Sync Standby`
7. `ansible-playbook setup-postgresql.yml --ask-vault-pass --tags pgbackrest` (sætter
   arkiveringen i DCS igen), og `patronictl restart pg-homelab --pending`
8. På pg-witness: `pgbackrest --stanza=pg-homelab check`, og tag straks en ny full-backup
   (`systemctl start pgbackrest-backup@full.service`). Den gamle tidslinje er stadig i
   repoet, til den udløber
9. Start klienterne som i trin 5

## Rollback (før trin 6)

1. `systemctl disable --now keepalived` på pg01 og pg02 (frigiver `.60`)
2. `pct set 200 --onboot 1 && pct start 200` på prox02
3. Genstart klienterne som i trin 5. Skrivninger lavet efter trin 3 findes kun i Patroni-clusteret

---

## Slå etcd-login til (på det kørende cluster)

Uden login kan alle på `192.168.1.0/24` skrive i Patronis DCS, fx
`postgresql.parameters.archive_command`, som kører som `postgres` på lederen. etcd lytter
stadig på LAN-IP'en (Patroni på den anden node skal kunne nå den), men kræver nu bruger og
adgangskode. `auth enable` gælder for hele clusteret med det samme, så rækkefølgen er:
Patroni skal have sine legitimationsoplysninger **før** login slås til. Ellers mister
Patroni DCS'en og lederen demoterer efter `ttl` (30 s).

Playbooken gør det i den rigtige rækkefølge: etcd-rollen (ingen genstart af etcd, filen
`/etc/default/etcd` er uændret), så Patroni-rollen (ny `config.yml` med `etcd3.username`
og `password`, `reload` af Patroni, én node ad gangen), og til sidst et play med tagget
`etcd_auth`, der opretter brugerne og slår login til. Det play nægter at slå login til, før
`/etc/patroni/config.yml` på begge PostgreSQL-noder har brugernavnet (det læser filen på
begge, også ved `--limit`).

Trafikken er stadig ren HTTP: adgangskoden og Patronis token kan opsnappes af en, der sidder
på vejen (ARP-spoofing på LAN'et). Login lukker for tilfældige skrivninger, ikke for det.
Næste trin er klient-TLS på etcd (`cacert`/`cert`/`key` i Patronis `etcd3`-sektion), se afsnit 7.

- [ ] Tilføj til `ansible/secrets.yml` (`ansible-vault edit secrets.yml`):
      `postgresql_ha_etcd_root_password` og `postgresql_ha_etcd_password` (mindst 16 tegn)
- [ ] Første kørsel uden selve switchen:
      `ansible-playbook setup-postgresql.yml --ask-vault-pass --skip-tags etcd_auth`.
      Forvent `changed` på "Configure Patroni" (begge noder) og "Mark this member as
      bootstrapped" (markøren får indholdet `new`), og ingen genstart af etcd
- [ ] På begge noder: `grep -A1 username: /etc/patroni/config.yml` viser `patroni`, og
      `journalctl -u patroni --since -5m` viser reload uden fejl.
      `patronictl -c /etc/patroni/config.yml list` viser stadig `Leader` og `Sync Standby`
- [ ] Hav en terminal klar på pg01 med fortryd-kommandoen (virker inden for de 30 s):
      `etcdctl --user root:<root-password> auth disable`
- [ ] Slå login til: `ansible-playbook setup-postgresql.yml --ask-vault-pass --tags etcd_auth`.
      Det opretter `root` (rollen `root`), rollen `patroni` (readwrite på `/service/`),
      brugeren `patroni` og kører `auth enable`
- [ ] Inden for 10 s: `journalctl -fu patroni` på begge noder. Patroni får én gang
      `user name is empty`/`permission denied` fra etcd, logger ind igen og fortsætter.
      Bliver fejlene ved, så kør fortryd-kommandoen og find fejlen i `config.yml`
- [ ] `patronictl -c /etc/patroni/config.yml list` (bruger samme login) viser uændret cluster.
      `etcdctl get /service/pg-homelab/leader` fejler uden `--user`; med
      `--user patroni:<password>` virker den, og `--user patroni:... member list` virker også
      (`member add/remove` kræver `root`)
- [ ] Næste fulde kørsel af playbooken er `ok` hele vejen (`auth enable` springes over)

Skift af adgangskode: `etcdctl --user root:... user passwd patroni`, opdatér `secrets.yml`
og kør playbooken straks efter. Patronis token udløber ved skiftet, og lykkes det nye login
ikke inden for 30 s, demoterer lederen (som et planlagt switchover, få sekunder for
klienterne). Gør det i et vedligeholdelsesvindue.

## Erstat en etcd-node

Gælder pg-witness, og pg01/pg02 når en container genopbygges (fx ved skiftet til
unprivileged, se nedenfor). En etcd-node, der genopbygges, er et nyt medlem: det gamle
medlem skal fjernes fra clusteret, og det nye tilføjes, før etcd startes med
`ETCD_INITIAL_CLUSTER_STATE=existing`. Starter den med `new`, nægter clusteret den.

Rollen gør det selv, når markøren `/var/lib/etcd/.cluster-bootstrapped` mangler på hosten:
den spørger de andre medlemmer (`member list`), fjerner en gammel post med hostens navn
eller peer-URL, kører `member add` og skriver `existing` i markøren. Første gang alle tre
bygges, svarer ingen peers, og alle tre starter med `new` som før. De to andre medlemmer skal
være sunde: medlemsskift kræver quorum (2 af 3).

Mangler markøren på et medlem, der faktisk kører i clusteret (slettet i hånden, eller
`/var/lib/etcd` restoret fra en ældre backup), nægter rollen at slette dets datamappe: den
sammenligner cluster-ID fra den lokale etcd med peerens. Genskab markøren
(`echo new > /var/lib/etcd/.cluster-bootstrapped`), eller kør med `-e etcd_force_rejoin=true`,
hvis medlemmet virkelig skal bygges om.

- [ ] Byg containeren igen (Terraform, se "Skift til unprivileged containere") og fjern den
      gamle host key: `ssh-keygen -R 192.168.1.59` (eller `.57`/`.58`)
- [ ] På et af de andre medlemmer: `etcdctl --user root:... endpoint health --cluster` viser
      to sunde og ét fejlende medlem. Fortsæt kun hvis de to er sunde
- [ ] `ansible-playbook setup-postgresql.yml --ask-vault-pass` uden `--limit`: etcd- og
      Patroni-rollerne er no-ops på de sunde noder, og pgbackrest-playet (afsnit 8) kræver alle
      tre hosts for at udveksle SSH-nøgler med den nye. Forvent `changed` på
      "Remove the old entry for this host" og "Add this host to the cluster"
- [ ] `etcdctl --user root:... member list` viser tre startede medlemmer med nye ID for det
      genopbyggede, og `endpoint health --cluster` er sund på alle tre
- [ ] `patronictl -c /etc/patroni/config.yml list` er uændret (Patroni mærker ikke medlemsskiftet)

Manuelt (hvis rollen fejler, fx uden quorum, eller etcd er installeret i hånden). På et sundt
medlem, alle `etcdctl` med `--user root:<root-password>`:

1. `etcdctl member list` og notér ID (hex) for det gamle medlem
2. `etcdctl member remove <id>`
3. `etcdctl member add pg-witness --peer-urls=http://192.168.1.59:2380` (navn og IP som i
   `ansible/hosts`)
4. På den nye node: `systemctl stop etcd && rm -rf /var/lib/etcd/default`, sæt
   `ETCD_INITIAL_CLUSTER_STATE="existing"` i `/etc/default/etcd` (resten som på de andre,
   `ETCD_INITIAL_CLUSTER` med alle tre), `systemctl start etcd`
5. `echo existing > /var/lib/etcd/.cluster-bootstrapped`, så playbooken ikke rører den igen
6. Tjek som ovenfor. Et medlem, der fejler mellem trin 2 og 3, efterlader clusteret med to
   medlemmer; det er stadig sundt (quorum 2 af 2), men tåler ingen fejl, så gør trin 3 færdigt

## Skift til unprivileged containere

De tre containere blev oprettet privilegerede (providerens standard, `unprivileged` var ikke
sat). Skiftet kræver, at containeren genskabes (Terraform: *must be replaced*), så det sker
ved næste genopbygning, én node ad gangen. keepalived (VRRP og VIP'en på `eth0`) og Patroni
kræver intet ekstra i en unprivileged container. `features { nesting = true }`, som systemd i
Debian 12 skal bruge til sine egne mount-namespaces, er allerede sat på alle tre (8.1) og følger
med, når containeren genskabes.

Rækkefølge: standby'en først, lad den klone, switchover, så den anden. pg-witness kan tages
når som helst (etcd tåler, at ét medlem er væk), men ikke samtidig med en PostgreSQL-node.

- [ ] Vælg node og sæt `unprivileged = true` på **kun den** i `terraform/lxc/main.tf`.
      `terraform plan` må kun vise den ene container som *must be replaced*; de to andre
      *No changes*
- [ ] PostgreSQL-node: tjek at den er standby (`patronictl list`), ellers
      `patronictl switchover pg-homelab --leader <den> --candidate <den anden> --force`
- [ ] `terraform apply`. Containeren slettes og genskabes med samme VMID og IP (datamappe,
      etcd-data og host key er væk)
- [ ] `ssh-keygen -R <ip>`, og `ansible-playbook setup-postgresql.yml --ask-vault-pass`
      (uden `--limit`, så Patroni-playet kører med `serial: 1`). etcd joiner som beskrevet i
      "Erstat en etcd-node", og Patroni kloner fra lederen (`pg_basebackup`) og bliver
      `Sync Standby` med lag 0. Login på etcd er allerede slået til og springes over
- [ ] `pct config <vmid> | grep -E 'unprivileged|features'` på Proxmox-noden viser
      `unprivileged: 1` og `nesting=1`. `.60` ligger på lederen, og `systemctl status keepalived`
      på den genopbyggede node er uden fejl
- [ ] Switchover til den genopbyggede node og gentag med den anden. Derefter pg-witness
- [ ] Når alle tre er unprivileged: `terraform plan` viser *No changes*
