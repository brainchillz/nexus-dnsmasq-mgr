# Backlog

Feature ideas not yet scheduled. Roughly ordered by value; items are
independent unless noted.

## 8. Prometheus `/metrics` endpoint

Reuse the stats collector; expose current counters and pool utilization for
Grafana without touching the SQLite history.

## 9. Wake-on-LAN from the lease table

The MACs are already there; add a WoL button per lease/static lease.

## 10. Existing-config importer

Onboarding: parse an existing `dnsmasq.conf` / `dnsmasq.d` into the app's
stores (ranges, static leases, options, host records). Current import only
handles hosts files.

## 12. Full recursion (unbound)

Spun out of item 11, which deliberately rejected it *for the network-path
goal*: recursion removes the third-party resolver but still talks plaintext
port 53 to root/TLD/authoritative servers, so the on-path observer loses
nothing. It remains interesting for the opposite threat model — "don't trust
any resolver operator" — as a third upstream shape beside the encrypted
modes. Oblivious DoH is another candidate selector value there.

---

## Shipped

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
