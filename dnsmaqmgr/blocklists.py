"""Blocklist subscriptions: subscribe to a list URL (StevenBlack, hagezi, …),
refresh it on a schedule, and render it as address=/domain/0.0.0.0 lines.

Each list renders into its OWN conf file (dnsmasq.d/50-block-<id>.conf) from a
fetched domains file under BLOCKLISTS_DIR, so a broken fetch can never take
out the rest of the config: the fetch is parsed and validated domain-by-domain
here, the previous domains file is restored if `dnsmasq --test` rejects the
render, and the store only records success after the apply pipeline swaps the
files in. Scheduled refresh rides the existing stats ticker (stats.py calls
refresh_due() every tick).

Accepted input formats, mixed freely within one list: hosts lines
(`0.0.0.0 domain`), bare domains, dnsmasq `address=/domain/…`, and adblock
`||domain^`. Everything else (cosmetic rules, comments, real hosts entries)
is skipped and counted.
"""
import os
import re
import time
import urllib.request
from flask import Blueprint, jsonify, request

from .core.config import APP_VERSION, BLOCKLISTS_DIR, write_text_atomic
from .core.runcmd import err, json_object
from .core.store import STORE_LOCK, load_store, save_store, new_id, find_record
from .core.validators import RE_COMMENT, RE_DOMAIN, RE_LIST_URL, is_ipv4, is_ipv6
from .dns import BOILERPLATE_NAMES
from .dnsmasq import apply_change, blocklist_domains_path

bp = Blueprint('blocklists', __name__)

MAX_FETCH_BYTES = 40_000_000
FETCH_TIMEOUT = 60
DEFAULT_REFRESH_HOURS = 24
MAX_NAME_LEN = 64

RE_ADBLOCK = re.compile(r'^\|\|([A-Za-z0-9_.-]+)\^$')
# hosts-format sink addresses (the left column of a blocklist hosts line).
SINK_IPS = {'0.0.0.0', '127.0.0.1', '::', '::1', '0'}


# ─── Parsing & fetching ───────────────────────────────────────────────

def parse_blocklist_text(text):
    """Extract blocked domains from raw list text. Returns (sorted domains,
    skipped-line count). Every domain must pass RE_DOMAIN — rendering is text
    concatenation, so this is the barrier against a hostile list smuggling
    extra dnsmasq directives."""
    domains, skipped = set(), 0
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        cands = []
        if line.startswith('||'):
            m = RE_ADBLOCK.match(line)
            cands = [m.group(1)] if m else []
        elif line.startswith('address='):
            parts = line.split('=', 1)[1].split('/')
            cands = [p for p in parts[1:-1] if p]
        else:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in SINK_IPS:
                cands = parts[1:]
            elif len(parts) == 1:
                cands = parts
        good = 0
        for c in cands:
            c = c.lower().rstrip('.')
            if (RE_DOMAIN.match(c) and c not in BOILERPLATE_NAMES
                    and not is_ipv4(c) and not is_ipv6(c)):
                domains.add(c)
                good += 1
        if not good:
            skipped += 1
    return sorted(domains), skipped


def fetch_list_text(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'DNSMAQ-MGR/%s' % APP_VERSION})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        data = r.read(MAX_FETCH_BYTES + 1)
    if len(data) > MAX_FETCH_BYTES:
        raise ValueError('list exceeds %d MB' % (MAX_FETCH_BYTES // 1_000_000))
    return data.decode('utf-8', errors='replace')


# ─── Refresh pipeline ─────────────────────────────────────────────────

def _note(list_id, **fields):
    """Record fetch status on a list without touching the rendered config."""
    with STORE_LOCK:
        b = load_store('blocklists')
        rec = find_record(b['lists'], list_id)
        if rec:
            rec.update(fields)
            save_store('blocklists', b)


def refresh_list(list_id):
    """Fetch one list and apply it. Returns (ok, detail). A failed fetch or a
    rejected render leaves the previous domains file and config in place."""
    rec = find_record(load_store('blocklists')['lists'], list_id)
    if not rec:
        return False, 'No such list'
    now = int(time.time())
    try:
        text = fetch_list_text(rec['url'])
        domains, skipped = parse_blocklist_text(text)
        if not domains:
            raise ValueError('no valid domains found (%d lines skipped)' % skipped)
    except Exception as e:
        _note(list_id, last_status='error: %s' % e, last_attempt=now)
        return False, str(e)

    path = blocklist_domains_path(list_id)
    try:
        with open(path) as f:
            prev = f.read()
    except OSError:
        prev = None
    write_text_atomic(path, '\n'.join(domains) + '\n', 0o600)

    def mutate():
        b = load_store('blocklists')
        r = find_record(b['lists'], list_id)
        if r:
            r.update({'entries': len(domains), 'skipped': skipped,
                      'last_fetch': now, 'last_attempt': now, 'last_status': 'ok'})
            save_store('blocklists', b)

    try:
        res = apply_change(mutate, sections=['blocklists'])
        failed = isinstance(res, tuple)
        detail = res[0].get_json().get('error', '') if failed else ''
    except RuntimeError:
        # apply_change signals a rejected render via err()/jsonify, which needs
        # an app context — the ticker thread has none. The stores are already
        # rolled back by the time the error response is built, so treating the
        # RuntimeError as a plain failure here is safe.
        failed, detail = True, 'rejected by dnsmasq --test'
    if failed:
        # Put the previous domains file back too (the store rollback in
        # apply_change cannot know about it).
        if prev is None:
            try:
                os.remove(path)
            except OSError:
                pass
        else:
            write_text_atomic(path, prev, 0o600)
        _note(list_id, last_status='error: %s' % (detail or 'rejected by dnsmasq --test'),
              last_attempt=now)
        return False, detail or 'rejected by dnsmasq --test'
    return True, res


def refresh_due():
    """Called from the stats ticker: refresh every enabled list whose interval
    has elapsed. A failing list retries at most hourly instead of every tick."""
    now = int(time.time())
    for rec in load_store('blocklists').get('lists', []):
        if not rec.get('enabled', True):
            continue
        hours = int(rec.get('refresh_hours') or DEFAULT_REFRESH_HOURS)
        interval = hours * 3600
        if str(rec.get('last_status', '')).startswith('error'):
            interval = min(interval, 3600)
        if now - int(rec.get('last_attempt') or 0) >= interval:
            try:
                refresh_list(rec['id'])
            except Exception as e:
                print('blocklist refresh failed for %s: %s' % (rec.get('name'), e),
                      flush=True)


# ─── Lookup support ───────────────────────────────────────────────────

class BlockIndex:
    """Suffix-matching index over the enabled lists' fetched domains, mirroring
    address=/domain/ semantics (a listed domain covers its subdomains)."""

    def __init__(self, sets):
        self._sets = sets  # [(list name, frozenset of domains)]

    def match(self, name):
        """Return (list_name, matched_domain) for the most specific hit, or None."""
        labels = name.lower().rstrip('.').split('.')
        for i in range(len(labels)):
            cand = '.'.join(labels[i:])
            for lname, dset in self._sets:
                if cand in dset:
                    return (lname, cand)
        return None


def load_block_index():
    sets = []
    for rec in load_store('blocklists').get('lists', []):
        if not rec.get('enabled', True):
            continue
        try:
            with open(blocklist_domains_path(rec['id'])) as f:
                sets.append((rec.get('name') or rec['id'],
                             frozenset(l.strip() for l in f if l.strip())))
        except OSError:
            pass
    return BlockIndex(sets)


# ─── Routes ───────────────────────────────────────────────────────────

def _validate(data, existing=None):
    name = (data.get('name') or '').strip()
    url = (data.get('url') or '').strip()
    if not name or len(name) > MAX_NAME_LEN or not RE_COMMENT.match(name):
        return None, 'Invalid list name'
    if not RE_LIST_URL.match(url):
        return None, 'Invalid list URL (http(s)://…)'
    try:
        hours = int(data.get('refresh_hours', (existing or {}).get('refresh_hours',
                                                                   DEFAULT_REFRESH_HOURS)))
    except (TypeError, ValueError):
        return None, 'Invalid refresh interval'
    if not 1 <= hours <= 720:
        return None, 'Refresh interval must be 1–720 hours'
    ex = existing or {}
    return {'name': name, 'url': url, 'refresh_hours': hours,
            'enabled': bool(data.get('enabled', ex.get('enabled', True))),
            'entries': ex.get('entries', 0), 'skipped': ex.get('skipped', 0),
            'last_fetch': ex.get('last_fetch', 0), 'last_attempt': ex.get('last_attempt', 0),
            'last_status': ex.get('last_status', '')}, None


@bp.route('/api/blocklists')
def blocklists_get():
    return jsonify(load_store('blocklists'))


@bp.route('/api/blocklists', methods=['POST'])
def blocklists_add():
    body, e = json_object()
    if e:
        return e
    rec, verr = _validate(body)
    if verr:
        return err(verr)
    rec['id'] = new_id('l')

    def mutate():
        b = load_store('blocklists')
        b['lists'].append(rec)
        save_store('blocklists', b)

    res = apply_change(mutate, sections=['blocklists'])
    if isinstance(res, tuple):
        return res
    # First fetch happens synchronously so the response carries a real entry
    # count (or the fetch error) instead of a "pending" placeholder.
    ok, detail = refresh_list(rec['id'])
    fresh = find_record(load_store('blocklists')['lists'], rec['id']) or rec
    return jsonify({'success': True, 'id': rec['id'], 'fetch_ok': ok,
                    'fetch_detail': (detail if not ok else ''),
                    'entries': fresh.get('entries', 0), **res})


@bp.route('/api/blocklists/<rid>', methods=['POST'])
def blocklists_update(rid):
    b = load_store('blocklists')
    existing = find_record(b['lists'], rid)
    if not existing:
        return err('No such list', 404)
    body, e = json_object()
    if e:
        return e
    rec, verr = _validate({**existing, **body}, existing=existing)
    if verr:
        return err(verr)
    rec['id'] = rid
    url_changed = rec['url'] != existing.get('url')

    def mutate():
        b2 = load_store('blocklists')
        b2['lists'] = [rec if it.get('id') == rid else it for it in b2['lists']]
        save_store('blocklists', b2)

    res = apply_change(mutate, sections=['blocklists'])
    if isinstance(res, tuple):
        return res
    fetch_ok, fetch_detail = True, ''
    if url_changed:
        fetch_ok, fetch_detail = refresh_list(rid)
    return jsonify({'success': True, 'fetch_ok': fetch_ok,
                    'fetch_detail': (fetch_detail if not fetch_ok else ''), **res})


@bp.route('/api/blocklists/<rid>', methods=['DELETE'])
def blocklists_delete(rid):
    if not find_record(load_store('blocklists')['lists'], rid):
        return err('No such list', 404)

    def mutate():
        b = load_store('blocklists')
        b['lists'] = [it for it in b['lists'] if it.get('id') != rid]
        save_store('blocklists', b)

    res = apply_change(mutate, sections=['blocklists'])
    if isinstance(res, tuple):
        return res
    try:
        os.remove(blocklist_domains_path(rid))
    except OSError:
        pass
    return jsonify({'success': True, **res})


@bp.route('/api/blocklists/<rid>/refresh', methods=['POST'])
def blocklists_refresh(rid):
    ok, detail = refresh_list(rid)
    if not ok:
        return err('Refresh failed: %s' % detail, 502)
    fresh = find_record(load_store('blocklists')['lists'], rid) or {}
    return jsonify({'success': True, 'entries': fresh.get('entries', 0),
                    'skipped': fresh.get('skipped', 0), **detail})
