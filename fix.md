# Fix list — code review of 2026-09-17 (v0.4.5)

> **Status (2026-09-17): every item below is implemented in 0.4.6.** Guards:
> `tests/test_ipam_contract.py` (IPAM push/read-back + SSO surface, written
> against 0.4.5 first, then re-run after each change) and
> `tests/test_review_fixes.py` (one regression test per fix). Full suite:
> 188 tests green. The only behaviour changes a deployment must plan for are
> fix 1 (installer moves state to `/var/lib/dnsmaq-mgr`, migrating in place)
> and fix 4/6 (Docker image rebuild + container recreate).

Ordered by severity. Each item states the defect, the evidence, the proposed
fix, and — because NexusIPAM is a live mirror *source* for both DNS nodes —
whether the fix can touch the IPAM → node push path and what guards it.

## Read this first: the IPAM integration contract

In deployments where NexusIPAM is the system of record, the DNS nodes are
mirrors of IPAM: IPAM pushes `hosts` (and optionally `dhcp` and `netboot`)
to each node's mirror-receive endpoint, and reads DHCP state back with a
read-only API token. Site-specific verification data (node addresses,
current serials, token names, pinning modes) lives in the private
infrastructure notes, never in this repository.

What IPAM depends on (from NexusIPAM's `pushout.py`, `adopt.py`,
`leases.py`):

1. `POST /api/mirror/receive` with `Authorization: Bearer dmm_…`, body
   `{source, serial, serials{section: n}, sections[], data{}}`. Receiver
   rejects only strictly lower serials; equal serial re-applies idempotently
   (IPAM's "push now" relies on this to heal a node). Response
   `{success, action}`; errors are JSON `{success:false, error}` with 4xx.
2. Record ids: IPAM sends `id` values shaped `[a-z]_[0-9a-f]{6}` and expects
   `_keep_id` to preserve them (round-trip gate).
3. Read-back with a **readonly API token** (`Authorization: Bearer dm_…`):
   `GET /api/dhcp` and `GET /api/dhcp/leases`.
4. Section locks (`settings.mirror_sources`) must survive every node-side
   operation, or local edits and IPAM pushes will fight.
5. TLS: IPAM targets carry a `verify` mode (`insecure` or
   `fingerprint:<sha256>`). A regenerated node certificate breaks a pinned
   target until it is re-pinned in IPAM (Settings → Push targets).
6. IPAM only advances a section's serial when the rendered content changes.
   Anything on a node that silently reverts a locked section will **not** be
   healed automatically — only by a manual push run from IPAM.

Typical live shape (verified 2026-09-17 on a two-node site, both 0.4.5):
`hosts`, `dhcp` and `netboot` locked to source `nexus-ipam` with identical
per-section serials on both nodes, no node-to-node peers left, DHCP master
toggle off (cold-standby stores). One node is a bare-metal systemd install,
the other the Docker image.

**Invariant for every fix below: `dnsmaqmgr/mirror.py` and the
`/api/mirror/receive` contract are not modified.** Add the contract test in
the last section before starting, and run it after every fix.

Deployment guards that apply to every fix:

- Take `GET /api/backup?include_accounts=1` from each node before deploying.
- Note the IPAM push-target `verify` mode for each node before touching
  certificates. Never regenerate a node cert without re-pinning.
- After deploying to a node: `GET /api/mirror/status` must still show
  `accept: true`, `has_token: true`, and the same locked sections with the
  same serials; then run "push now" from IPAM for that target and confirm
  `applied via none|reload` and unchanged serials.
- Docker-node redeploys recreate the container: keep the `/data` volume (it
  holds `auth.json` with the read token, `state/settings.json` with the
  mirror token hash and locks, and `certs/`). Expect one failed IPAM push if
  a push lands during the restart; it is not retried automatically.

---

## 1. Bare-metal install leaves a root-escalation path open — HIGH (security)

**Where:** `install.sh:70-76` (and `app.py:18` `app = create_app()` at import).

**Defect:** the installer re-owns the code to root but leaves `/opt/dnsmaq-mgr`
itself owned by `dnsmaqmgr`, because it doubles as `DATA_DIR` (`auth.json`,
`history.db`, `sso.json` live at its root). Directory write permission lets
the service user rename `app.py`, or drop a `flask/` package beside it, and
the sudoers rule `venv/bin/python app.py dhcp-probe` then runs it as root.
The sudoers line also grants `systemctl status dnsmasq`, which the app never
calls and which spawns a root pager from a tty.

**Fix:**
- Separate code from data: `/opt/dnsmaq-mgr` root-owned 0755; data in
  `/var/lib/dnsmaq-mgr` (app-owned 0700) via `Environment=DNSMAQ_DATA_DIR` in
  the unit. Installer migrates an existing in-place data tree
  (`auth.json`, `sso.json`, `history.db*`, `state/`, `certs/`, `render/`,
  `leases/`, `blocklists/`, `changelog/`, `encdns/`) and rewrites the
  `conf-dir=` drop-in to the new render path.
- Move `cli.dispatch()` above `create_app()` in `app.py` so the sudo'd probe
  never imports the app or touches the data tree (sudo strips
  `DNSMAQ_DATA_DIR`, so today the probe's `ensure_dirs()` runs as root
  against the wrong tree).
- Remove `systemctl status dnsmasq` from the sudoers rule.

**IPAM impact: MEDIUM, operational only (bare-metal node).** The mirror token hash, the
section locks, the IPAM read token and the certificate all live in the data
tree. A botched migration = IPAM pushes return 401, or the cert fingerprint
changes. Guard: migrate, then check `/api/mirror/status` and the cert
fingerprint (`openssl s_client`) are identical before and after; run an IPAM
"push now". The Docker node (`/data` volume) is unaffected.

## 2. Creating a user over an existing name silently replaces the account — HIGH

**Where:** `dnsmaqmgr/core/auth.py:398-416` (`users_create`); also
`users_set_password` at 439.

**Evidence:** `POST /api/users {username:"admin", password:"p",
role:"readonly"}` returned 200 and demoted the only admin; the last-admin
guard in `users_set_role` is bypassed and the session lost every write.
Neither route enforces `MIN_PASSWORD_LEN` (only `change_password` and the CLI
do).

**Fix:** 409 when the username exists; apply `MIN_PASSWORD_LEN` in both
routes.

**IPAM impact: none.** IPAM authenticates with tokens, never creates users.

## 3. Host-record edits never bump the mirror serial — HIGH (mirroring)

**Where:** `dnsmaqmgr/dnsmasq.py:530` (`apply_change`, serial loop) and
`dns.py:68` (`_section` returns `'hosts'`).

**Evidence:** after `POST /api/dns/hosts` the dns store serial stayed at 0;
`build_payload(['hosts'])` reports the same serial forever. `'hosts'` is a
section name, not a store name, so `set(sections) & set(store_names)` skips
it. The receiver's per-section staleness check is therefore a no-op for the
most edited section, and an out-of-order push can overwrite a newer one.

**Fix:** map sections to stores before bumping, e.g.
`SECTION_STORE = {'hosts': 'dns'}`; bump `set(SECTION_STORE.get(s, s) for s
in sections) & store_names` once each.

**IPAM impact: none on the receive path, verified by reading
`mirror.py:133-142, 251-257`.** The receiver compares the *incoming* serials
against `mirror_sources[source].serials`; the node's own dns store serial is
never consulted. With the fix, an IPAM push that carries `hosts` will bump the
node's own dns serial (via `apply_change(sections=['hosts'])`), which only
matters if the node pushes onward to a dnsmaq peer — the reviewed site has no node-to-node peers.
Guard: contract test asserts a `serials` map lower than stored → 409, equal →
200, after the change.

## 4. Network Scan is dead in Docker — HIGH (Docker nodes only)

**Where:** `Dockerfile:8-10`.

**Evidence:** `docker run --rm --entrypoint sh ghcr.io/brainchillz/nexus-dnsmasq-mgr:latest -c 'command -v ping ip'`
→ both missing. `recon._ping` gets `FileNotFoundError` for every target and
`neighbor_table()` / `probe._local_ipv4s()` get "Command not found", so the
scan reports nothing alive and the DHCP-conflict probe cannot filter the
node's own addresses.

**Fix:** add `iputils-ping iproute2` to the apt line. Rebuild via CI (never
locally), pull and recreate the Docker node with the same volume.

**IPAM impact: LOW.** Container recreate = short DNS gap on the Docker node and one
possible failed push. State is on the volume. Guard: after recreate, check
`/api/mirror/status` on the node, then IPAM "push now" → `applied via none`.

## 5. Rollback and restore revert mirror state they must not touch — HIGH (mirroring)

**Where:** `dnsmaqmgr/changelog.py:173-183` (`changelog_rollback`);
`backup.py:120-138, 257-259` (`_staged_settings`, restore mutate).

**Evidence:** after rotating the mirror token and enabling accept, rolling
back to an older entry restored the *old* `mirror_token_hash` and turned
`mirror_accept` off (test in session). The same wholesale settings restore
also reverts `mirror_sources` (locks + serials), and both paths overwrite the
`hosts`, `dhcp` and `netboot` stores even though they are mirror-locked.

**Why this matters here:** on an IPAM-fed node a rollback or restore would (a) revert
IPAM's pushed records to an older snapshot, (b) possibly break the mirror
token so the next push 401s, and (c) since IPAM advances serials only on
content change, the node would stay reverted until someone runs "push now" in
IPAM. Neither IPAM's push panel nor the node would show it as drifted.

**Fix:**
- Rollback and restore carry forward from the *current* store:
  `mirror_token_hash`, `mirror_accept`, `mirror_sources` (same treatment
  serials already get).
- Rollback and restore refuse to overwrite a store/section that is currently
  mirror-locked (return 409 naming the source, "detach first"), or skip those
  sections and say so in the response. Refuse is simpler and safer.
- Document: after any rollback/restore on a node, run "push now" from IPAM.

**IPAM impact: POSITIVE.** This closes a real desync path. Guard: contract
test — with `hosts` locked to `nexus-ipam`, `POST /api/changelog/<id>/rollback`
must not change `mirror_sources` or the hosts store.

## 6. `docker stop` cannot stop the container cleanly — MEDIUM (Docker)

**Where:** `app.py` (no signal handler; app is PID 1).

**Defect:** PID 1 without a SIGTERM handler ignores the signal, so Docker
waits its 10 s grace period and SIGKILLs dnsmasq and dnscrypt-proxy.

**Fix:** register a `signal.SIGTERM`/`SIGINT` handler in `app.py` that calls
`get_controller().stop()`, `encdns.get_proxy().stop()` and exits; or add
`init: true` to `docker-compose.yml`.

**IPAM impact: none** (only makes Docker-node restarts faster and cleaner).

## 7. Every structural change raises a "dnsmasq restarted" alert — MEDIUM

**Where:** `dnsmaqmgr/alerts.py:134-144` (`_check_service`).

**Defect:** the counter-reset detection cannot tell the app's own restart
from a crash, so every range edit or blocklist refresh fires `service_down`
once per 6 h cooldown.

**Fix:** in `apply_change`, when `action == 'restart'`, record
`alerts_state['expected_restart_ts']`; `_check_service` ignores a counter
reset that follows it within one tick. Keep the generic webhook payload
`{event, title, message, host, ts, source}` unchanged — IPAM's plan consumes
`new_device` from it (not wired yet, but the shape is documented).

**IPAM impact: none.**

## 8. Child restart after a forced kill reports success while the process is dead — MEDIUM

**Where:** `dnsmaqmgr/dnsmasq.py:477-487` (`ChildController.restart`), same
pattern in `stop()`.

**Evidence:** with a SIGTERM-ignoring stub, `restart()` returned `(True, '')`
with the old pid; `status()` read stopped for ~1 s; the watcher then
respawned it with backoff. In `apply_change` this surfaces as a false
"dnsmasq did not come back after restart".

**Fix:** `proc.wait()` after `proc.kill()`; reset `_backoff` to 1 on a
successful respawn that stays up.

**IPAM impact: none** (Docker child mode only; makes push responses on Docker nodes
more truthful).

## 9. Smaller defects

| # | Where | Defect | Fix | IPAM impact |
|---|---|---|---|---|
| 9a | `static/js/settings.js:331` | blank cache-size field posts `cache_size: 0` → `cache-size=0`, caching silently off | reject blank client-side, or omit the key when blank | none |
| 9b | `static/js/peers.js:139`, `README.md` vs `peers.py:256` | UniFi "full mirror" defaults on in UI/README, off in the API validator | make it off everywhere (destructive default) | none (IPAM has its own UniFi adapter) |
| 9c | `settings.py:96-116` | upstreams belong to the mirrored `dns` section but `settings_save` never calls `locked_error('dns')` | add the check when `upstreams` is in the payload | none today: `dns` is not locked on the reviewed nodes. If IPAM ever pushes `dns`, this becomes the desired lock |
| 9d | `auth.py:188-202` | `must_change` is browser-enforced only | in `require_login`, limit a session whose user has `must_change` to the password route. **Session identities only** — token identities have no such flag | none, provided the token path is untouched (IPAM's read token uses `/api/dhcp`, `/api/dhcp/leases`) |
| 9e | `auth.py:212-219` | login throttle keys on `remote_addr`; behind the reverse proxy the README suggests, one attacker locks everyone out | honor `X-Forwarded-For` only when `DNSMAQ_TRUSTED_PROXY` is set | none |
| 9f | `core/tls.py:23-27` | self-signed cert has no SAN, browsers reject it even when trusted | add `-addext "subjectAltName=DNS:<host>,IP:<ip>"` for **new** certs only | **only if a node cert is regenerated** → re-pin in IPAM first. Do not regenerate on live IPAM-fed nodes as part of this fix |
| 9g | `dns.py:126`, `peers.py:274,290,324`, `core/tls.py:84`, `auth.py:368-489` | `request.get_json()` on a JSON array body 500s | use `json_object()` | none (`mirror_receive` already guards) |
| 9h | `alerts.py:242-267` | `STORE_LOCK` held across the encdns probe and five CHAOS queries (up to ~7 s per tick), blocking every apply including an IPAM push | collect outside the lock, write state under it | POSITIVE (removes a periodic window where a push waits) |
| 9i | `dnsmasq.py:262-273, 302-318` | every apply re-reads, regexes and copies every blocklist file for `dnsmasq --test`; seconds per host edit with large lists | cache rendered blocklist text keyed by domains-file mtime; output must stay byte-identical | none, but each IPAM push is an apply — this makes pushes faster |
| 9j | `Dockerfile:30`, `install.sh:171`, repo `tftp/` | 69/udp and TFTP remnants after TFTP removal | drop them | none |
| 9k | `README.md` | `DNSMAQ_COOKIE_SECURE` undocumented | document | none |
| 9l | `netboot.py:214-230` | `netboot_settings` loads the store outside the lock and saves inside the lambda (stale read-modify-write) | reload inside `mutate()` like the other routes | none (netboot is mirror-locked on IPAM-fed nodes; the route 409s before this) |
| 9m | `peers.py:272-307` | peer add/update/delete write `peers.json` without `STORE_LOCK`, racing the push-status writer | take `STORE_LOCK` | none (no peers configured) |

## Regression test to add before starting: `tests/test_ipam_contract.py`

Replays exactly what IPAM sends and reads, so any fix that breaks the path
fails CI:

1. Enable accept, mint a mirror token.
2. POST `/api/mirror/receive` with `source: "nexus-ipam"`, `sections:
   ["dhcp","hosts","netboot"]`, `serials: {hosts: 39, dhcp: 22, netboot: 1}`,
   `serial: 39`, host records carrying `id: "h_xxxxxx"`, a dhcp block with a
   tagged range + `option:router`/`option:dns-server` options + one
   reservation, and a netboot entry with `server` set. Expect 200, ids
   preserved, `mirror_status.locked == [dhcp, hosts, netboot]`.
3. Re-send the identical payload → 200 (idempotent). Send `serials.hosts: 38`
   → 409 with the other sections untouched.
4. Local `POST /api/dns/hosts` → 409 (locked). `POST /api/settings` with
   `upstreams` → 200 (dns not locked).
5. Mint a **readonly** API token; `GET /api/dhcp` and `GET /api/dhcp/leases`
   with `Authorization: Bearer dm_…` → 200; a POST with it → 403.
6. `POST /api/changelog/<oldest>/rollback` and `POST /api/backup/restore`
   must leave `mirror_sources`, `mirror_token_hash` and `mirror_accept`
   unchanged (this assertion will fail until fix 5 lands — mark xfail until
   then).

## Suggested order

1. Contract test (above).
2. Fix 3, 5, 8, 9h, 9i, 9l, 9m, 7 — backend, no deployment risk, one release.
3. Fix 2, 9d, 9e, 9g — auth/validation, same release.
4. Fix 4, 6 — Docker; CI build, recreate the Docker node with the volume, verify push.
5. Fix 1 — installer with data migration; test on a scratch VM first, then
   the live bare-metal node with the deployment guards above.
6. 9a, 9b, 9c, 9f, 9j, 9k — cosmetic/docs, any time. 9f never triggers a
   regeneration on live nodes.
