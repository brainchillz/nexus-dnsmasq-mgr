"""Mirror receive side: this node accepts config pushed from a primary
DNSMAQ-MGR instance.

Auth is a dedicated bearer token (generated here, SHA-256 stored — same
scheme as API tokens) checked by the handler itself; /api/mirror/receive is
exempt from the session guard. Sections received from a source become
READ-ONLY in this node's UI (locked_error is called by every mutating route
of a lockable section) — deterministic, instead of last-write-wins silently
reverting local edits on the next push. "Detach" unlocks a section until the
next push re-locks it.
"""
import hmac
import time
import hashlib
import secrets
from flask import Blueprint, jsonify, request

from .core.runcmd import err, json_object
from .core.store import load_store, save_store, new_id, STORE_LOCK
from .core.validators import RE_ID, RE_SOURCE
from .dnsmasq import apply_change

bp = Blueprint('mirror', __name__)

MIRROR_TOKEN_PREFIX = 'dmm_'
SECTIONS = ('hosts', 'dns', 'dhcp', 'netboot')


def locked_sections():
    """Sections currently managed by a mirror source (read-only here)."""
    sources = load_store('settings').get('mirror_sources', {})
    locked = set()
    for src in sources.values():
        locked.update(src.get('sections', []))
    return locked


def locked_error(section):
    """err() response if the section is mirror-locked, else None."""
    sources = load_store('settings').get('mirror_sources', {})
    for name, src in sources.items():
        if section in src.get('sections', []):
            return err("Section '%s' is mirrored from '%s' and read-only on this node "
                       "(detach it on the Mirroring page to edit locally)" % (section, name), 409)
    return None


def _keep_id(rec, prefix):
    rid = rec.get('id') or ''
    return rid if RE_ID.match(rid) else new_id(prefix)


@bp.route('/api/mirror/status')
def mirror_status():
    s = load_store('settings')
    return jsonify({'accept': bool(s.get('mirror_accept')),
                    'has_token': bool(s.get('mirror_token_hash')),
                    'sources': s.get('mirror_sources', {}),
                    'locked': sorted(locked_sections())})


@bp.route('/api/mirror/token', methods=['POST'])
def mirror_token():
    """Generate/rotate the mirror token. Secret shown exactly once."""
    secret = MIRROR_TOKEN_PREFIX + secrets.token_urlsafe(32)
    # Read-modify-write under the store lock so a concurrent settings save (or
    # apply_change's snapshot/restore) can't discard the just-rotated hash.
    with STORE_LOCK:
        s = load_store('settings')
        s['mirror_token_hash'] = hashlib.sha256(secret.encode()).hexdigest()
        save_store('settings', s)
    return jsonify({'success': True, 'token': secret})


@bp.route('/api/mirror/accept', methods=['POST'])
def mirror_accept():
    body, e = json_object()
    if e:
        return e
    enabled = bool(body.get('enabled'))
    with STORE_LOCK:
        s = load_store('settings')
        if enabled and not s.get('mirror_token_hash'):
            return err('Generate a mirror token first')
        s['mirror_accept'] = enabled
        save_store('settings', s)
    return jsonify({'success': True, 'accept': enabled})


@bp.route('/api/mirror/sources/<source>/detach', methods=['POST'])
def mirror_detach(source):
    with STORE_LOCK:
        s = load_store('settings')
        if source not in s.get('mirror_sources', {}):
            return err('No such source', 404)
        del s['mirror_sources'][source]
        save_store('settings', s)
    return jsonify({'success': True})


@bp.route('/api/mirror/receive', methods=['POST'])
def mirror_receive():
    # PUBLIC endpoint (no session) — authenticated here by the mirror token.
    s = load_store('settings')
    if not s.get('mirror_accept'):
        return err('This node does not accept mirrored config', 403)
    auth = request.headers.get('Authorization', '')
    token = auth[7:].strip() if auth.startswith('Bearer ') else ''
    stored = s.get('mirror_token_hash') or ''
    if not token or not stored or \
            not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), stored):
        return err('Invalid mirror token', 401)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return err('Expected a JSON object', 422)
    source = str(payload.get('source') or '')
    if not RE_SOURCE.match(source):
        return err('Invalid source name')
    try:
        serial = int(payload.get('serial'))
    except (TypeError, ValueError):
        return err('Invalid serial')
    sections = [x for x in (payload.get('sections') or []) if x in SECTIONS]
    if not sections:
        return err('No valid sections in payload')
    data = payload.get('data') or {}

    # Per-section staleness: each store has its own counter, so a single scalar
    # wrongly rejects a fresh dhcp-only push whenever the dns counter leads.
    # Compare each section against its own last-seen serial; fall back to the
    # scalar for a legacy sender that sends no `serials` map.
    src_prev = s.get('mirror_sources', {}).get(source, {}) or {}
    incoming = payload.get('serials') if isinstance(payload.get('serials'), dict) else None
    prev_serials = src_prev.get('serials', {})
    if incoming is not None:
        stale = [sec for sec in sections
                 if int(incoming.get(sec, serial)) < int(prev_serials.get(sec, -1))]
        if stale:
            return err('Stale serial for section(s): %s' % ', '.join(stale), 409)
    elif serial < int(src_prev.get('serial', -1)):
        return err('Stale serial (%s < %s)' % (serial, src_prev.get('serial')), 409)

    # Re-validate every record with the same validators local edits go
    # through — a compromised primary must not be able to inject config lines.
    from . import dns as dns_mod, dhcp as dhcp_mod, netboot as nb_mod
    staged = {}
    try:
        if 'hosts' in sections:
            recs = []
            for raw in data.get('hosts') or []:
                rec, e = dns_mod._validate('hosts', raw)
                if e:
                    return err('hosts: %s' % e, 422)
                rec['id'] = _keep_id(raw, 'h')
                recs.append(rec)
            staged['hosts'] = recs
        if 'dns' in sections:
            d = data.get('dns') or {}
            block = {}
            for coll, prefix in (('cnames', 'c'), ('addresses', 'a'), ('forwards', 'f')):
                recs = []
                for raw in d.get(coll) or []:
                    rec, e = dns_mod._validate(coll, raw)
                    if e:
                        return err('%s: %s' % (coll, e), 422)
                    rec['id'] = _keep_id(raw, prefix)
                    recs.append(rec)
                block[coll] = recs
            ups = [str(u).strip() for u in (d.get('upstreams') or []) if str(u).strip()]
            from .core.validators import is_upstream
            if any(not is_upstream(u) for u in ups):
                return err('dns: invalid upstream', 422)
            block['upstreams'] = ups
            staged['dns'] = block
        if 'dhcp' in sections:
            d = data.get('dhcp') or {}
            block = {}
            for coll, prefix in (('ranges', 'r'), ('static_leases', 's'), ('options', 'o')):
                recs = []
                for raw in d.get(coll) or []:
                    rec, e = dhcp_mod._validate(coll, raw)
                    if e:
                        return err('%s: %s' % (coll, e), 422)
                    rec['id'] = _keep_id(raw, prefix)
                    recs.append(rec)
                block[coll] = recs
            staged['dhcp'] = block
        if 'netboot' in sections:
            d = data.get('netboot') or {}
            entries = []
            for raw in d.get('entries') or []:
                rec, e = nb_mod._validate_entry(raw)
                if e:
                    return err('netboot: %s' % e, 422)
                rec['id'] = _keep_id(raw, 'b')
                entries.append(rec)
            # Route netboot scalars through the same checks the settings route
            # uses. No TFTP fields any more — boot is DHCP-only.
            from .core.validators import RE_COMMENT, is_ipv4
            subnet = (d.get('proxy_subnet') or '').strip()
            if subnet and not is_ipv4(subnet):
                return err('netboot: invalid proxy subnet', 422)
            prompt = str(d.get('pxe_prompt') or '')
            if not RE_COMMENT.match(prompt):
                return err('netboot: invalid pxe prompt', 422)
            nb_settings = {'proxy_dhcp': bool(d.get('proxy_dhcp')),
                           'proxy_subnet': subnet, 'pxe_prompt': prompt,
                           'entries': entries}
            staged['netboot'] = nb_settings
    except Exception as e:
        return err('Malformed payload: %s' % e, 422)

    def mutate():
        if 'hosts' in staged or 'dns' in staged:
            d = load_store('dns')
            if 'hosts' in staged:
                d['hosts'] = staged['hosts']
            if 'dns' in staged:
                d['cnames'] = staged['dns']['cnames']
                d['addresses'] = staged['dns']['addresses']
                d['forwards'] = staged['dns']['forwards']
            save_store('dns', d)
        if 'dhcp' in staged:
            h = load_store('dhcp')
            h.update(staged['dhcp'])
            save_store('dhcp', h)
        if 'netboot' in staged:
            nb = load_store('netboot')
            nb.update(staged['netboot'])
            save_store('netboot', nb)
        st = load_store('settings')
        if 'dns' in staged:
            st['upstreams'] = staged['dns']['upstreams']
        src_rec = st.setdefault('mirror_sources', {}).setdefault(source, {})
        merged = dict(src_rec.get('serials', {}))
        for sec in sections:
            merged[sec] = int((incoming or {}).get(sec, serial))
        src_rec.update({'serial': serial, 'serials': merged,
                        'last_received': int(time.time()), 'sections': sections})
        save_store('settings', st)

    res = apply_change(mutate, sections=sections, from_mirror=True)
    if isinstance(res, tuple):
        body, code = res
        return body, (422 if code == 400 else code)
    return jsonify({'success': True, 'applied_sections': sections, 'serial': serial, **res})
