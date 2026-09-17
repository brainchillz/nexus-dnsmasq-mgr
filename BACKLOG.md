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

## 13. Blocklist allowlist

A per-node list of domains stripped from every rendered blocklist, plus an
"allow this" action on the Query Log blocked column. The most common blocklist
complaint ("it blocked something I need"); a small change in
`render_blocklist` plus a store field, and it composes with item 14's
persistent log.

## 14. Persistent query log

Store parsed queries in the existing SQLite ring buffer with retention, add
search by client and domain, and lift the 200-line journal window on bare
metal (the sudoers pin). Today the live view loses everything older than a
few dozen queries.

## 15. Real-time lease events via `dhcp-script`

A tiny script posting lease add/del/old to a local socket the app owns. Lets
new-device alerts and the lease table update instantly instead of on the
5-minute tick, and enables "release lease" from the UI. Also the natural
feed for an IPAM's lease overlay.

## 16. OUI vendor lookup

Fetch the IEEE OUI list the way blocklists are fetched (scheduled, cached
under DATA_DIR) and show the manufacturer next to MACs in the lease table and
Network Scan. Makes "unnamed devices" identifiable.

## 17. Scheduled local backups + health endpoint

Reuse `backup_export` to write a dated snapshot under DATA_DIR nightly with
retention. Add an unauthenticated `/api/health` (running / not, version) and
a Dockerfile `HEALTHCHECK` on it.

## 18. Table search, filtering and CSV export

Host records, static leases and live leases get a filter box and a CSV
export (hosts-file export for host records). The pages get unwieldy past
about fifty rows.

## 19. Two-factor (TOTP) for admin logins

Server-enforced, per user, optional. Sessions, tokens and SSO are all in
place, so it slots into `api_login`. Worth it the moment the UI is reachable
beyond the LAN.

## 20. Mirror-aware rollback and restore

Spun out of the 2026-09-17 review (fix.md item 5): rollback and backup
restore must never overwrite a mirror-locked section or revert
`mirror_token_hash` / `mirror_accept` / `mirror_sources`. Listed here as the
feature-shaped half (a "detach then restore" flow and a visible "this node
was reverted, re-push from the source" state); the defect half is in fix.md.

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
