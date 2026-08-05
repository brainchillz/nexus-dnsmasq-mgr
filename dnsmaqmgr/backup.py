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
import copy
import time
import threading
from datetime import datetime
from flask import Blueprint, jsonify, request

from .core.auth import RE_USERNAME, _is_admin, load_config, save_config
from .core.config import APP_VERSION
from .core.runcmd import err, json_object
from .core.store import DEFAULTS, STORE_LOCK, load_store, save_store
from .core.validators import RE_COMMENT, RE_FINGERPRINT, is_ipv4
from .dnsmasq import apply_change

bp = Blueprint('backup', __name__)

BACKUP_STORES = ('settings', 'dns', 'dhcp', 'netboot', 'blocklists', 'peers')
# Settings keys outside settings._validated's remit, restored explicitly.
SETTINGS_TOGGLES = ('dns_enabled', 'dhcp_enabled', 'mirror_accept')


@bp.route('/api/backup')
def backup_export():
    if not _is_admin():
        return err('Administrator access required', 403)
    with STORE_LOCK:
        stores = {n: load_store(n) for n in BACKUP_STORES}
    payload = {'app': 'dnsmaq-mgr', 'version': APP_VERSION,
               'created': int(time.time()), 'stores': stores}
    if (request.args.get('include_accounts') or '').lower() in ('1', 'true', 'yes'):
        cfg = load_config()
        # Password/token hashes only — the secrets themselves are never stored.
        payload['accounts'] = {'users': cfg.get('users', {}),
                               'tokens': cfg.get('tokens', [])}
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
    return out


def _staged_blocklists(src):
    from . import blocklists as bl_mod
    from .mirror import _keep_id
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
    return {'serial': int(src.get('serial') or 0), 'lists': recs}


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


STAGERS = {'settings': _staged_settings, 'dns': _staged_dns, 'dhcp': _staged_dhcp,
           'netboot': _staged_netboot, 'blocklists': _staged_blocklists}


@bp.route('/api/backup/restore', methods=['POST'])
def backup_restore():
    if not _is_admin():
        return err('Administrator access required', 403)
    body, e = json_object()
    if e:
        return e
    payload = body.get('backup')
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
        if body.get('include_accounts') and 'accounts' in payload:
            staged_accounts = _staged_accounts(payload['accounts'] or {})
    except ValueError as ve:
        return err('Backup failed validation — nothing restored: %s' % ve, 422)
    except Exception as ex:
        return err('Malformed backup: %s' % ex, 422)
    if not staged and not staged_peers and not staged_accounts:
        return err('Backup contains nothing to restore', 422)

    def mutate():
        for name, data in staged.items():
            save_store(name, data)

    res = apply_change(mutate, sections=['hosts', 'dns', 'dhcp', 'netboot'])
    if isinstance(res, tuple):
        return res

    # Outside the apply snapshot — written only after the config swap held.
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
                    'restored': sorted(staged) + (['peers'] if staged_peers else []),
                    'accounts_restored': staged_accounts is not None,
                    'blocklists_refreshing': bool(staged.get('blocklists', {}).get('lists')),
                    **res})
