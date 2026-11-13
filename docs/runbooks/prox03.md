# Runbook: prox03 erstatter RPi-QDevicen

Mål: tredje Proxmox-node (`prox03`, 32 GB RAM, 128 GB OS-disk + 512 GB NVMe) med
rigtigt corosync-quorum, og RAM-headroom til k3s-workers på 6 GiB.

Slutresultat:

| Node   | VM'er                         | RAM til VM'er |
|--------|-------------------------------|---------------|
| prox01 | k3s-master-0, k3s-worker-0    | 4 + 6 GiB     |
| prox02 | k3s-master-1, k3s-worker-1    | 4 + 6 GiB     |
| prox03 | k3s-worker-2, k3s-worker-3    | 6 + 6 GiB     |

k3s bruger en ekstern MySQL-datastore (`192.168.1.16`), så der er intet etcd-quorum
at tage hensyn til. To masters er nok.

---

## 0. Forberedelse

- [ ] Proxmox installeret på prox03 (OS på 128 GB-disken)
- [ ] prox03 har fast IP `192.168.1.5` (ikke `.4`, som QDevicen har) og kan nå prox01/prox02.
      Skift før join: ret `address` under `vmbr0` i `/etc/network/interfaces` og linjen i
      `/etc/hosts` til `192.168.1.5`, kør `ifreload -a` og tjek med `hostname -i`
- [ ] `.5` ligger uden for DHCP-poolen på HP 2915 (eller er reserveret til prox03's MAC)
- [ ] Hostname er `prox03` og står korrekt i `/etc/hosts` på prox03
- [ ] Samme PVE-version på alle tre noder. Kør på hver: `pveversion`
- [ ] Alle noder opdateret (`apt update && apt full-upgrade`) **før** join
- [ ] prox03 har ingen VM'er/containere
- [ ] Clusteret er sundt: `pvecm status` viser `Quorate: Yes` og 3 stemmer
- [ ] HA-ressourcer? `ha-manager status`. Hvis ja, sæt dem til `ignored` under migreringen
- [ ] Vælg et roligt tidspunkt: i trin 1–2 må prox01/prox02 **ikke** genstarte

## 1. Fjern QDevicen (på prox01)

- [ ] `pvecm qdevice remove`
- [ ] `pvecm status` viser `Expected votes: 2` og `Quorate: Yes`

## 2. Meld prox03 ind (på prox03)

- [ ] `pvecm add 192.168.1.2` (eller GUI: Datacenter → Cluster → Join Information)
- [ ] `pvecm status` viser 3 noder, `Expected votes: 3`, `Quorate: Yes`
- [ ] prox03 er synlig og grøn i GUI'en

## 3. Storage på prox03

- [ ] Se de eksisterende indstillinger (på prox01):
      `zpool get ashift zvmdata && zfs get compression,atime zvmdata`
- [ ] Find NVMe-diskens id (på prox03): `ls -l /dev/disk/by-id/ | grep nvme`
- [ ] Wipe NVMe'en, hvis den har partitioner (GUI: prox03 → Disks → Wipe Disk)
- [ ] Opret poolen med samme navn: `zpool create -o ashift=12 zvmdata /dev/disk/by-id/nvme-XXXX`
      (GUI: Disks → ZFS → Create, **uden** "Add Storage")
- [ ] `zfs set compression=lz4 zvmdata` (eller det, prox01 bruger)
- [ ] Tjek storage-definitionen: `grep -A5 "zfspool: zvmdata" /etc/pve/storage.cfg`
- [ ] Hvis der står en `nodes`-linje: `pvesm set zvmdata --nodes prox01,prox02,prox03`
- [ ] `pvesm status` på prox03 viser `zvmdata` som `active`

## 4. Begræns ZFS ARC (alle tre noder)

Uden loft tager ARC op til 50 % af RAM.

- [ ] Se nuværende værdi: `cat /sys/module/zfs/parameters/zfs_arc_max` (0 = 50 % af RAM)
- [ ] prox03: `echo "options zfs zfs_arc_max=4294967296" > /etc/modprobe.d/zfs.conf && update-initramfs -u -k all`
- [ ] prox03: `echo 4294967296 > /sys/module/zfs/parameters/zfs_arc_max`
- [ ] Samme på prox01 og prox02, hvis de også står på 0

## 5. Pensionér RPi'en

- [ ] Fjern eventuelt `corosync-qdevice` på prox01/prox02: `apt remove corosync-qdevice`
- [ ] Sluk RPi'en (`192.168.1.4`), eller kør `apt remove corosync-qnetd` på den
- [ ] `pvecm status` er stadig `Quorate: Yes` med 3 stemmer

## 6. Flyt k3s-workers og giv dem 6 GiB (Terraform)

`main.tf` har `migrate = true`, så en ændret `node_name` live-migrerer VM'en med
disk i stedet for at genskabe den. Ændringen af `memory_mib` genstarter VM'en.
Tag én worker ad gangen.

For hver worker i rækkefølgen `worker_2`, `worker_3`, `worker_0`, `worker_1`:

- [ ] `kubectl drain k3s-worker-N --ignore-daemonsets --delete-emptydir-data`
- [ ] `terraform plan -target='proxmox_virtual_environment_vm.k3s["worker_N"]'`.
      Bekræft at planen er **update in-place**, ikke destroy/create
- [ ] `terraform apply -target='proxmox_virtual_environment_vm.k3s["worker_N"]'`
- [ ] VM'en kører på den rigtige node med 6 GiB (`qm config <vmid> | grep memory`)
- [ ] `kubectl get node k3s-worker-N` viser `Ready`
- [ ] `kubectl uncordon k3s-worker-N`
- [ ] Longhorn: alle volumes er `Healthy`, før du går videre til næste worker

Kryds af pr. worker:

- [ ] worker_2 (105) → prox03, 6 GiB
- [ ] worker_3 (106) → prox03, 6 GiB
- [ ] worker_0 (104) → 6 GiB
- [ ] worker_1 (103) → 6 GiB
- [ ] Til sidst: fuld `terraform plan` viser `No changes`

## 7. Efterarbejde

- [ ] Zone-labels på k3s-noderne (`topology.kubernetes.io/zone=<proxmox-node>`) med
      `kubectl label node`. Nye noder får dem via `proxmox_node` i `ansible/hosts`
- [ ] Longhorn: `replica-zone-soft-anti-affinity=false`, så to replicas aldrig havner
      på samme Proxmox-host. Gør det **før** worker-3 flyttes til prox03
- [ ] Spred Grafana, Home Assistant og Authentik ud på workers på forskellige noder
- [ ] Grafana/alarmer: tilføj prox03 til Proxmox-monitoreringen
- [ ] Opdatér idétavlen: `proxmox-node-3` → færdig
