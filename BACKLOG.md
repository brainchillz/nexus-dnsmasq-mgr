# Backlog

Feature ideas not yet scheduled. Roughly ordered by value; items are
independent unless noted.

## 11. Encrypted DNS upstream (opt-in)

Stop leaking every query to the ISP in plaintext. dnsmasq has no DoH/DoT of
its own, so the standard shape is a local proxy on loopback that dnsmasq
forwards to (`server=127.0.0.1#5335`) and that speaks encrypted DNS upstream.

**Off by default, opt-in only.** Nothing changes for existing installs until
someone turns it on — which also means the defaults *inside* the feature can
be the safe ones rather than the compatible ones.

### Backend: dnscrypt-proxy

Preferred over the alternatives because it is packaged in Debian/Ubuntu (the
installer stays apt-only — no fetched binaries, no new supply-chain surface),
it is the well-trodden pairing in the Pi-hole world, and it covers DoH,
DNSCrypt **and anonymized relays** in one binary. stubby is DoT-only;
cloudflared and AdGuard's dnsproxy aren't in the repos.

Runs as a **supervised child process in both modes** (Docker and bare metal):
the listener is an unprivileged high port on loopback, so this needs no root
and no sudoers rules, and it sidesteps fighting the distro's own
dnscrypt-proxy unit. Same lifecycle pattern as `ChildController`. Note the
distro package ships a socket-activated instance on `127.0.0.2:53` — the
installer should disable it (with a warning) since we run our own.

### Why not full recursion (unbound)

Considered and rejected *for this goal*. Running a recursive resolver removes
the third-party resolver, but every query to the root, TLD and authoritative
servers still goes out in **plaintext port 53** — so the ISP (and anyone else
on path) can still reconstruct exactly which records you're pulling, arguably
in more detail than one encrypted session to a single resolver. QNAME
minimization trims what each authoritative operator learns; it does nothing
about the on-path observer. Recursion protects you from the *resolver
operator*; encryption protects you from the *network path*. This item is
about the network path.

Unbound remains interesting as a separate future item for people whose threat
model really is "don't trust any resolver operator" — but it is not a
substitute for this.

### Two selectable upstream modes (same proxy, one setting)

The architecture is singular and does not change between modes:

```
dnsmasq → dnscrypt-proxy (127.0.0.1:5335) → [ encrypted hop ] → resolver
```

The local proxy is mandatory either way, because dnsmasq speaks neither DoH
nor DNSCrypt. What the operator selects is only the shape of the encrypted
hop, and **both modes are offered** — they suit different tastes and the cost
of supporting both is one config branch:

| Mode | Path | ISP sees | Resolver sees | Trade |
|---|---|---|---|---|
| **A — Direct encrypted** (default) | proxy → resolver | nothing useful | your IP **and** your queries | simplest, fastest, widest provider choice (DoH or DNSCrypt) |
| **B — Anonymized relay** | proxy → relay → resolver | nothing useful | your queries, **not** your IP (relay sees IP, not queries) | no single party holds both halves; adds a hop of latency, DNSCrypt-only, smaller provider set |

Mode A moves trust (ISP → resolver operator). Mode B splits it: the **relay**
sees your IP but not the query, the **resolver** sees the query but not your
IP, so no single party holds both halves.

Implementation is a mode selector in the UI that changes the rendered
dnscrypt-proxy config — same binary, same supervision, same fail-closed
logic, same validation. Mode B additionally requires the DNSCrypt protocol
(so `doh_servers = false`), DNSCrypt-capable `server_names`, the `relays`
source, and
`[anonymized_dns] routes = [{ server_name = '*', via = [...] }]`.

Caveats to surface in the UI: in mode B the relay and resolver must be run by
**different operators** or the split is theatre, and the provider presets
must therefore differ per mode (mode A can offer DoH providers; mode B must
offer DNSCrypt resolvers plus a separate relay list). Oblivious DoH is the
DoH-side equivalent of mode B and could join later as a third option without
disturbing either.

### Fail-closed vs fail-open

The decision that actually matters. If the proxy dies while plaintext
`server=` lines remain in the rendered config, queries silently fall back to
the ISP — availability preserved, the entire point of the feature quietly
defeated. Default **fail-closed**: when enabled, the proxy is the only
upstream, with an "encrypted upstream down" alert (item 5 is already built).
Offer an explicit *"fall back to plain DNS if the proxy is unreachable"*
toggle for uptime-first operators; implementation is just whether the plain
upstreams stay in the render, plus `strict-order` so the proxy is tried
first. Enabling must also force `no-resolv`, or `/etc/resolv.conf` becomes a
leak path.

### Composition with what already exists

- **Domain forwards** (`server=/corp/10.1.1.1`) are more specific than the
  default upstream, so internal domains keep bypassing the proxy — internal
  names never reach a public resolver. Worth stating explicitly in the UI.
- **Blocklists** answer locally, before anything is forwarded.
- **DNSSEC** validation in dnsmasq still works through the proxy.
- **Query Log** should label `127.0.0.1#5335` as "encrypted upstream" rather
  than showing a bare loopback address.
- **Lookup** source attribution gains an "encrypted upstream" kind.

### Scope / phasing

Bigger than a single-module feature: Dockerfile + installer changes, a second
supervised-service lifecycle, config rendering with its own validation
(`dnsmasq --test` cannot check a proxy config; dnscrypt-proxy has
`-check`), provider presets (Cloudflare, Quad9, Mullvad, AdGuard, custom),
health probing and alert wiring.

Phasing follows the mode split naturally: **mode A first** (it exercises the
whole pipeline — supervision, rendering, validation, health, fail-closed),
then **mode B as a selector value**, which adds a config branch and a relay
preset list but no new machinery.

Cheap **phase 0** if it should land sooner: an *"I already run a proxy"* mode
— provider presets plus a health check and correct labelling around a
loopback upstream the operator points at themselves. The upstreams field
technically supports that today with zero new machinery.

### Honest UI copy

The Settings card must not oversell this. It moves trust (ISP → resolver
operator, or splits it across relay + resolver); it does not make queries
private in absolute terms. Bootstrap resolution of the proxy's own resolver
list is also plaintext on first start — worth a footnote.

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
- **2026-08-05 — 4. Change history with diff and rollback.** Every apply
  recorded with identity, store snapshot and rendered config; diffs and
  validated one-click rollback on the History page (`/api/changelog`).
- **2026-08-05 — 5. Alerts / webhooks.** New-device, pool-utilization,
  service-down/restart and cert-expiry checks on the stats tick;
  generic/ntfy/Slack webhook delivery with cooldowns (`/api/alerts`).
- **2026-08-05 — 6. Network reconnaissance for record hygiene.** Ping/ARP
  sweep over managed ranges/records/leases; unnamed devices, stale records,
  duplicate mappings on the Network Scan page (`/api/recon`).
