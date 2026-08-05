# Backlog

Feature ideas not yet scheduled. Roughly ordered by value; items are
independent unless noted.

## 4. Change history with diff and rollback

Every change already goes render → validate → atomic swap. Keep the last N
versions of the JSON stores, show a timeline of what changed / when / by
which user or token, with rendered-config diffs and one-click revert.

## 5. Alerts / webhooks

Hang notifications off the existing 5-minute stats tick: unknown MAC took a
lease (new device on LAN), DHCP pool >90% utilized, dnsmasq
restarted/respawned, web certificate nearing expiry. One generic webhook
plus ntfy/Slack-compatible payloads covers most targets.

## 6. Network reconnaissance for record hygiene

ARP/ping sweep of configured subnets, cross-referenced against leases and
host records: devices with no DNS name, host records pointing at IPs that no
longer answer (would have flagged the stale record from the 2026-08-05
incident), and duplicate name↔IP mappings.

## 8. Prometheus `/metrics` endpoint

Reuse the stats collector; expose current counters and pool utilization for
Grafana without touching the SQLite history.

## 9. Wake-on-LAN from the lease table

The MACs are already there; add a WoL button per lease/static lease.

## 10. Existing-config importer

Onboarding: parse an existing `dnsmasq.conf` / `dnsmasq.d` into the app's
stores (ranges, static leases, options, host records). Current import only
handles hosts files.

---

## Shipped

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
