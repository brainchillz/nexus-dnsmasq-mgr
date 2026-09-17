# Backlog

Feature ideas not yet scheduled. Roughly ordered by value; items are
independent unless noted.

## 9. Wake-on-LAN from the lease table

The MACs are already there; add a WoL button per lease/static lease.

## 14. Persistent query log

Store parsed queries in the existing SQLite ring buffer with retention, add
search by client and domain, and lift the 200-line journal window on bare
metal (the sudoers pin). Today the live view loses everything older than a
few dozen queries.

## 20. Mirror-aware rollback and restore

Spun out of the 2026-09-17 review (fix.md item 5): rollback and backup
restore must never overwrite a mirror-locked section or revert
`mirror_token_hash` / `mirror_accept` / `mirror_sources`. Listed here as the
feature-shaped half (a "detach then restore" flow and a visible "this node
was reverted, re-push from the source" state); the defect half is in fix.md.

---

## Shipped

- **2026-09-17 — 8, 10, 13, 15, 16, 17, 18 (v0.5.0).** Prometheus
  `/metrics` (read-only token) + public `/api/health` + Docker HEALTHCHECK;
  existing-config importer (paste or scan the host's dnsmasq.conf/dnsmasq.d,
  preview, validated merge/replace, Config page); blocklist allowlist
  (`server=/d/#` + list filtering, Allow button on the Query Log); real-time
  lease events via a rendered `dhcp-script` hook over loopback UDP (instant
  new-device alerts, live lease table, Release lease via `dhcp_release`);
  IEEE OUI vendor lookup (leases, Network Scan, alerts); daily local
  snapshots with retention, download/restore/delete from Settings; filter
  boxes and CSV / hosts-file export on host records, static and live leases.
- **2026-08-05 — 11. Encrypted DNS upstream (opt-in).** dnsmasq →
  supervised dnscrypt-proxy on loopback → encrypted hop, both modes (direct
  DoH/DNSCrypt and anonymized relay) behind one selector; fail-closed by
  default with an explicit fail-open toggle (`strict-order` fallback), forced
  `no-resolv`, `dnscrypt-proxy -check`-gated saves, provider presets,
  `encdns_down` alert, Query Log / Lookup labelling, backup/restore support;
  apt-packaged binary in Docker + installer, distro socket unit disabled
  (`/api/encdns`); v0.4.0.
- **2026-08-05 — 1. Lookup / diagnosis tool with source attribution.**
  Lookup page (`/api/lookup`) attributing every answer to managed record /
  `/etc/hosts` (file+line) / foreign `dnsmasq.d` / DHCP lease / blocklist /
  upstream, with "not managed by me" warnings; `no-hosts` toggle in Settings;
  shadowing audit banner (`/api/lookup/audit`) on the DNS and Lookup pages.
- **2026-08-05 — 2. Live query log viewer.** Query Log page over the
  journal / child ring buffer with per-query resolution and top
  domains/clients/blocked/upstream aggregates (`/api/querylog`).
- **2026-08-05 — 3. Blocklist subscriptions.** Per-list conf files, four
  input formats, scheduled refresh on the stats tick, entry counts,
  enable/disable, `dnsmasq --test`-gated swaps (`/api/blocklists`).
- **2026-08-05 — 7. Full-state backup / restore.** Single-JSON export /
  all-or-nothing validated restore, accounts optional (`/api/backup`).
- **2026-08-05 — 4. Change history with diff and rollback.** Every apply
  recorded with identity, store snapshot and rendered config; diffs and
  validated one-click rollback on the History page (`/api/changelog`).
- **2026-08-05 — 5. Alerts / webhooks.** New-device, pool-utilization,
  service-down/restart and cert-expiry checks on the stats tick;
  generic/ntfy/Slack webhook delivery with cooldowns (`/api/alerts`).
- **2026-08-05 — 6. Network reconnaissance for record hygiene.** Ping/ARP
  sweep over managed ranges/records/leases; unnamed devices, stale records,
  duplicate mappings on the Network Scan page (`/api/recon`).
