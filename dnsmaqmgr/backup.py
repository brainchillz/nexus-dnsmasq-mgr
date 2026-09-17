"""Full-state backup / restore: one JSON file holding every store —
settings, dns, dhcp, netboot, blocklists, peers — with accounts (users +
API tokens, hashes only) optional. Makes bare-metal ↔ Docker migrations a
download and an upload.

Restore is all-or-nothing: every record is re-validated with the same
validators the interactive routes use (a hand-edited backup must not be able
to inject config lines), then the whole set goes through apply_change — so
`dnsmasq --test` gates the swap and a rejected restore rolls back cleanly.
The peers store and accounts are written only after that apply succeeds
(they are outside the apply snapshot, so writing them earlier would leak
through a rollback). Blocklist domain files are not part of the backup —
they are re-fetched from their URLs after a restore.

Both endpoints are admin-only: the export carries peer mirror tokens and
credential hashes, which a read-only account must not see.
"""
import os
import re
import copy
import json
import time
import threading
from datetime import datetime
from flask import Blueprint, jsonify, request, send_file

from .core.auth import RE_USERNAME, _is_admin, load_config, save_config
from .core.config import APP_VERSION, DATA_DIR, write_json_atomic
from .core.runcmd import err, json_object
from .core.store import DEFAULTS, STORE_LOCK, load_store, save_store
from .core.validators import RE_COMMENT, RE_FINGERPRINT, is_ipv4
from .dnsmasq import apply_change

bp = Blueprint('backup', __name__)

BACKUP_STORES = ('settings', 'dns', 'dhcp', 'netboot', 'blocklists', 'alerts',
                 'encdns', 'peers')
# Settings keys outside settings._validated's remit, restored explicitly.
SETTINGS_TOGGLES = ('dns_enabled', 'dhcp_enabled', 'mirror_accept')


def export_payload(include_accounts=False):
    with STORE_LOCK:
        stores = {n: load_store(n) for n in BACKUP_STORES}
    payload = {'app': 'dnsmaq-mgr', 'version': APP_VERSION,
               'created': int(time.time()), 'stores': stores}
    if include_accounts:
        cfg = load_config()
        # Password/token hashes only — the secrets themselves are never stored.
        payload['accounts'] = {'users': cfg.get('users', {}),
                               'tokens': cfg.get('tokens', [])}
    return payload


@bp.route('/api/backup')
def backup_export():
    if not _is_admin():
        return err('Administrator access required', 403)
    payload = export_payload((request.args.get('include_accounts') or '').lower()
                             in ('1', 'true', 'yes'))
    resp = jsonify(payload)
    resp.headers['Content-Disposition'] = (
        'attachment; filename=dnsmaq-backup-%s.json'
        % datetime.now().strftime('%Y%m%d-%H%M%S'))
    return resp


# ─── Restore validation ───────────────────────────────────────────────

def _staged_dns(src):
    from . import dns as dns_mod
    from .mirror import _keep_id
    out = {'serial': int(src.get('serial') or 0)}
    for coll, prefix in (('hosts', 'h'), ('cnames', 'c'),
                         ('addresses', 'a'), ('forwards', 'f')):
        recs = []
        for raw in src.get(coll) or []:
            rec, e = dns_mod._validate(coll, raw)
            if e:
                raise ValueError('dns %s: %s' % (coll, e))
            rec['id'] = _keep_id(raw, prefix)
            recs.append(rec)
        out[coll] = recs
    return out


def _staged_dhcp(src):
    from . import dhcp as dhcp_mod
    from .mirror import _keep_id
    out = {'serial': int(src.get('serial') or 0)}
    for coll, prefix in (('ranges', 'r'), ('static_leases', 's'), ('options', 'o')):
        recs = []
        for raw in src.get(coll) or []:
            rec, e = dhcp_mod._validate(coll, raw)
            if e:
                raise ValueError('dhcp %s: %s' % (coll, e))
            # dnsmasq refuses to START on duplicate dhcp-host lines and --test
            # does not catch it — a restore must not brick the service.
            dup = dhcp_mod._dup_check(coll, recs, rec)
            if dup:
                raise ValueError('dhcp %s: %s' % (coll, dup))
            rec['id'] = _keep_id(raw, prefix)
            recs.append(rec)
        out[coll] = recs
    return out


def _staged_netboot(src):
    from . import netboot as nb_mod
    from .mirror import _keep_id
    entries = []
    for raw in src.get('entries') or []:
        rec, e = nb_mod._validate_entry(raw)
        if e:
            raise ValueError('netboot: %s' % e)
        rec['id'] = _keep_id(raw, 'b')
        entries.append(rec)
    subnet = (src.get('proxy_subnet') or '').strip()
    if subnet and not is_ipv4(subnet):
        raise ValueError('netboot: invalid proxy subnet')
    prompt = str(src.get('pxe_prompt') or '')
    if not RE_COMMENT.match(prompt):
        raise ValueError('netboot: invalid pxe prompt')
    return {'serial': int(src.get('serial') or 0),
            'proxy_dhcp': bool(src.get('proxy_dhcp')), 'proxy_subnet': subnet,
            'pxe_prompt': prompt, 'entries': entries}


def _staged_settings(src):
    from . import settings as settings_mod
    delta, e = settings_mod._validated(src)
    if e:
        raise ValueError('settings: %s' % e)
    out = copy.deepcopy(DEFAULTS['settings'])
    out.update(delta)
    out['serial'] = int(src.get('serial') or 0)
    for k in SETTINGS_TOGGLES:
        out[k] = bool(src.get(k))
    th = src.get('mirror_token_hash')
    if th is not None and not (isinstance(th, str) and RE_FINGERPRINT.match(th)):
        raise ValueError('settings: invalid mirror token hash')
    out['mirror_token_hash'] = th
    sources = src.get('mirror_sources') or {}
    if not isinstance(sources, dict):
        raise ValueError('settings: invalid mirror sources')
    out['mirror_sources'] = sources
    # An established mirror TARGET keeps its own token, accept flag and
    # source locks: a source (IPAM, a primary) holds the matching token and
    # serials, and a restore must not swap them from under it. A node with
    # no token yet is a fresh migration target and takes the backup's.
    from .mirror import MIRROR_KEYS
    cur = load_store('settings')
    if cur.get('mirror_token_hash'):
        for k in MIRROR_KEYS:
            out[k] = cur.get(k)
    return out


def _staged_blocklists(src):
    from . import blocklists as bl_mod
    from .mirror import _keep_id
    allow = []
    for raw in src.get('allow') or []:
        dom = bl_mod.normalize_allow(raw)
        if not dom:
            raise ValueError('blocklists: invalid allowlist entry %r' % (raw,))
        allow.append(dom)
    recs = []
    for raw in src.get('lists') or []:
        rec, e = bl_mod._validate(raw, existing=raw)
        if e:
            raise ValueError('blocklists: %s' % e)
        rec['id'] = _keep_id(raw, 'l')
        # The domains file is not in the backup; force a refetch on the next
        # tick (and clear counts that would otherwise claim entries exist).
        rec.update({'entries': 0, 'last_fetch': 0, 'last_attempt': 0,
                    'last_status': ''})
        recs.append(rec)
    return {'serial': int(src.get('serial') or 0), 'lists': recs, 'allow': sorted(set(allow))}


def _staged_peers(src):
    from . import peers as peers_mod
    from .mirror import _keep_id
    recs = []
    for raw in src.get('peers') or []:
        rec, e = peers_mod._validate_peer(raw)
        if e:
            raise ValueError('peers: %s' % e)
        rec['id'] = _keep_id(raw, 'p')
        recs.append(rec)
    return {'peers': recs}


def _staged_accounts(src):
    users = src.get('users')
    tokens = src.get('tokens') or []
    if not isinstance(users, dict) or not users:
        raise ValueError('accounts: no users in backup')
    admins = 0
    for name, rec in users.items():
        if not RE_USERNAME.match(str(name)):
            raise ValueError('accounts: invalid username %r' % name)
        if isinstance(rec, str):
            admins += 1
            continue
        if not isinstance(rec, dict) or not rec.get('password'):
            raise ValueError('accounts: user %s has no password hash' % name)
        if rec.get('role', 'readonly') == 'admin':
            admins += 1
    if not admins:
        raise ValueError('accounts: backup contains no administrator')
    if not isinstance(tokens, list) or any(not isinstance(t, dict) for t in tokens):
        raise ValueError('accounts: invalid tokens list')
    return {'users': users, 'tokens': tokens}


def _staged_alerts(src):
    from . import alerts as alerts_mod
    cfg, e = alerts_mod._validate_config(src, copy.deepcopy(DEFAULTS['alerts']))
    if e:
        raise ValueError('alerts: %s' % e)
    return cfg


def _staged_encdns(src):
    from . import encdns as encdns_mod
    cfg, e = encdns_mod.validate_config(src, copy.deepcopy(DEFAULTS['encdns']))
    if e:
        raise ValueError('encdns: %s' % e)
    if cfg.get('enabled') and not encdns_mod.binary_path():
        # Restoring an enabled encrypted upstream onto a host without the
        # proxy would leave dnsmasq forwarding to a dead port (fail-closed
        # = no resolution at all). All-or-nothing beats a silently dark node.
        raise ValueError('encdns: backup enables the encrypted DNS upstream but '
                         'dnscrypt-proxy is not installed on this host — install '
                         'it first, or disable encdns in the backup')
    cfg['serial'] = int(src.get('serial') or 0)
    return cfg


STAGERS = {'settings': _staged_settings, 'dns': _staged_dns, 'dhcp': _staged_dhcp,
           'netboot': _staged_netboot, 'blocklists': _staged_blocklists,
           'alerts': _staged_alerts, 'encdns': _staged_encdns}


@bp.route('/api/backup/restore', methods=['POST'])
def backup_restore():
    if not _is_admin():
        return err('Administrator access required', 403)
    body, e = json_object()
    if e:
        return e
    return restore_payload(body.get('backup'), bool(body.get('include_accounts')))


def restore_payload(payload, include_accounts=False):
    """Validate and apply one backup payload (upload or local snapshot)."""
    if not isinstance(payload, dict) or payload.get('app') != 'dnsmaq-mgr':
        return err('Not a DNSMAQ-MGR backup file', 422)
    stores = payload.get('stores')
    if not isinstance(stores, dict):
        return err('Backup has no stores object', 422)

    staged, staged_peers, staged_accounts = {}, None, None
    try:
        for name, stage in STAGERS.items():
            if name in stores:
                staged[name] = stage(stores[name] or {})
        if 'peers' in stores:
            staged_peers = _staged_peers(stores['peers'] or {})
        if include_accounts and 'accounts' in payload:
            staged_accounts = _staged_accounts(payload['accounts'] or {})
    except ValueError as ve:
        return err('Backup failed validation — nothing restored: %s' % ve, 422)
    except Exception as ex:
        return err('Malformed backup: %s' % ex, 422)
    if not staged and not staged_peers and not staged_accounts:
        return err('Backup contains nothing to restore', 422)

    # alerts is outside apply_change's rollback snapshot — write it only after
    # the apply holds, alongside peers/accounts.
    staged_alerts = staged.pop('alerts', None)

    # Stores a mirror source owns are the source's to write, not a backup's.
    from .mirror import locked_store_error
    locked = locked_store_error(set(staged))
    if locked:
        return locked

    def mutate():
        for name, data in staged.items():
            save_store(name, data)

    res = apply_change(mutate, sections=['hosts', 'dns', 'dhcp', 'netboot'])
    if isinstance(res, tuple):
        return res

    # Outside the apply snapshot — written only after the config swap held.
    if staged_alerts is not None:
        save_store('alerts', staged_alerts)
    if staged_peers is not None:
        save_store('peers', staged_peers)
    if staged_accounts is not None:
        cfg = load_config()   # keep this node's session secret_key
        cfg['users'] = staged_accounts['users']
        cfg['tokens'] = staged_accounts['tokens']
        save_config(cfg)

    # Restored blocklists have no domains files yet — fetch them now.
    if staged.get('blocklists', {}).get('lists'):
        from . import blocklists as bl_mod
        threading.Thread(target=bl_mod.refresh_due, daemon=True).start()

    return jsonify({'success': True,
                    'restored': sorted(staged)
                    + (['alerts'] if staged_alerts is not None else [])
                    + (['peers'] if staged_peers else []),
                    'accounts_restored': staged_accounts is not None,
                    'blocklists_refreshing': bool(staged.get('blocklists', {}).get('lists')),
                    **res})


# ─── Scheduled local snapshots ────────────────────────────────────────
# Nightly full-state files under DATA_DIR/backups (accounts included, so a
# snapshot restores a node completely), pruned to `keep`. Driven by the
# stats ticker; the hour is local time.

BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
RE_SNAPSHOT = re.compile(r'^dnsmaq-backup-\d{8}-\d{6}\.json\Z')


def _snapshots():
    try:
        names = sorted(n for n in os.listdir(BACKUPS_DIR) if RE_SNAPSHOT.match(n))
    except OSError:
        return []
    out = []
    for n in names:
        try:
            st = os.stat(os.path.join(BACKUPS_DIR, n))
            out.append({'name': n, 'size': st.st_size, 'ts': int(st.st_mtime)})
        except OSError:
            pass
    return out


def run_snapshot(keep=None):
    """Write one snapshot now and prune. Returns (ok, detail)."""
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    try:
        os.chmod(BACKUPS_DIR, 0o700)
    except OSError:
        pass
    name = 'dnsmaq-backup-%s.json' % datetime.now().strftime('%Y%m%d-%H%M%S')
    try:
        write_json_atomic(os.path.join(BACKUPS_DIR, name), export_payload(True), 0o600)
    except Exception as e:
        with STORE_LOCK:
            cfg = load_store('backups')
            cfg.update({'last_run': int(time.time()), 'last_status': 'error: %s' % e})
            save_store('backups', cfg)
        return False, str(e)
    with STORE_LOCK:
        cfg = load_store('backups')
        keep = int(keep if keep is not None else cfg.get('keep') or 14)
        cfg.update({'last_run': int(time.time()), 'last_status': 'ok'})
        save_store('backups', cfg)
    for old in _snapshots()[:-keep] if keep > 0 else []:
        try:
            os.remove(os.path.join(BACKUPS_DIR, old['name']))
        except OSError:
            pass
    return True, name


def tick():
    """Ticker hook: one snapshot per day once the configured hour has passed."""
    cfg = load_store('backups')
    if not cfg.get('enabled'):
        return
    now = datetime.now()
    slot = now.replace(hour=int(cfg.get('hour') or 0) % 24, minute=0, second=0, microsecond=0)
    if now < slot:
        return
    if int(cfg.get('last_run') or 0) >= int(slot.timestamp()):
        return
    run_snapshot()


def _validate_backups_cfg(data, cur):
    cfg = dict(cur)
    if 'enabled' in data:
        cfg['enabled'] = bool(data['enabled'])
    for key, lo, hi in (('keep', 1, 365), ('hour', 0, 23)):
        if key in data:
            try:
                n = int(data[key])
            except (TypeError, ValueError):
                return None, 'Invalid %s' % key
            if not lo <= n <= hi:
                return None, '%s must be %d–%d' % (key, lo, hi)
            cfg[key] = n
    return cfg, None


@bp.route('/api/backups')
def backups_list():
    if not _is_admin():
        return err('Administrator access required', 403)
    return jsonify({'success': True, **load_store('backups'), 'dir': BACKUPS_DIR,
                    'snapshots': _snapshots()[::-1]})


@bp.route('/api/backups', methods=['POST'])
def backups_save():
    body, e = json_object()
    if e:
        return e
    with STORE_LOCK:
        cfg, verr = _validate_backups_cfg(body, load_store('backups'))
        if verr:
            return err(verr)
        save_store('backups', cfg)
    return jsonify({'success': True, **cfg})


@bp.route('/api/backups/run', methods=['POST'])
def backups_run():
    ok, detail = run_snapshot()
    if not ok:
        return err('Snapshot failed: %s' % detail, 500)
    return jsonify({'success': True, 'name': detail, 'snapshots': _snapshots()[::-1]})


def _snapshot_path(name):
    if not RE_SNAPSHOT.match(name or ''):
        return None
    path = os.path.join(BACKUPS_DIR, name)
    return path if os.path.isfile(path) else None


@bp.route('/api/backups/<name>')
def backups_download(name):
    if not _is_admin():
        return err('Administrator access required', 403)
    path = _snapshot_path(name)
    if not path:
        return err('No such snapshot', 404)
    return send_file(path, mimetype='application/json', as_attachment=True, download_name=name)


@bp.route('/api/backups/<name>', methods=['DELETE'])
def backups_delete(name):
    path = _snapshot_path(name)
    if not path:
        return err('No such snapshot', 404)
    os.remove(path)
    return jsonify({'success': True, 'snapshots': _snapshots()[::-1]})


@bp.route('/api/backups/<name>/restore', methods=['POST'])
def backups_restore(name):
    if not _is_admin():
        return err('Administrator access required', 403)
    body, e = json_object()
    if e:
        return e
    path = _snapshot_path(name)
    if not path:
        return err('No such snapshot', 404)
    try:
        with open(path) as f:
            payload = json.load(f)
    except (OSError, ValueError) as ex:
        return err('Snapshot unreadable: %s' % ex, 500)
    return restore_payload(payload, bool(body.get('include_accounts')))
