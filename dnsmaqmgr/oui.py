"""IEEE OUI vendor lookup: MAC prefix → manufacturer.

The registry (MA-L, ~40k assignments) is fetched from the IEEE the way
blocklists are fetched — on demand or on the stats tick — parsed into
{6-hex-prefix: name} and kept as DATA_DIR/oui.json. Lookups annotate the
lease table, Network Scan and new-device alerts, which is what turns an
"unnamed device aa:bb:cc:…" into "…(Espressif)". No lookup ever leaves the
box: the table is local once fetched.
"""
import os
import csv
import io
import json
import time
import threading
import urllib.request
from flask import Blueprint, jsonify

from .core.config import APP_VERSION, DATA_DIR, write_json_atomic
from .core.runcmd import err, json_object
from .core.store import STORE_LOCK, load_store, save_store

bp = Blueprint('oui', __name__)

OUI_URLS = ['https://standards-oui.ieee.org/oui/oui.csv',
            'https://standards-oui.ieee.org/oui.csv']
OUI_FILE = os.path.join(DATA_DIR, 'oui.json')
MAX_BYTES = 20_000_000
FETCH_TIMEOUT = 60
REFRESH_DAYS = 30
RETRY_SECONDS = 3600

_table = None
_table_mtime = None
_lock = threading.Lock()


def parse_oui_csv(text):
    """IEEE CSV (Registry,Assignment,Organization Name,Organization Address)
    → {'AABBCC': 'Name'}. Tolerant of the odd malformed row."""
    out = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) < 3 or row[0].strip().upper() == 'REGISTRY':
            continue
        prefix = row[1].strip().upper().replace('-', '').replace(':', '')
        name = row[2].strip()
        if len(prefix) == 6 and all(c in '0123456789ABCDEF' for c in prefix) and name:
            out[prefix] = name[:80]
    return out


def _load():
    global _table, _table_mtime
    try:
        mtime = os.path.getmtime(OUI_FILE)
    except OSError:
        _table, _table_mtime = {}, None
        return _table
    with _lock:
        if _table is None or mtime != _table_mtime:
            try:
                with open(OUI_FILE) as f:
                    _table = json.load(f)
            except (OSError, ValueError):
                _table = {}
            _table_mtime = mtime
    return _table


def vendor(mac):
    """Manufacturer for a MAC ('' when unknown or the table is not fetched).
    Locally administered addresses (randomised phone MACs) are named as such
    rather than looked up — they carry no vendor."""
    m = (mac or '').replace(':', '').replace('-', '').upper()
    if len(m) < 6 or any(c not in '0123456789ABCDEF' for c in m[:6]):
        return ''
    if int(m[1], 16) & 2:
        return '(randomised/private MAC)'
    return _load().get(m[:6], '')


def annotate(items, key='mac', field='vendor'):
    for it in items:
        it[field] = vendor(it.get(key, ''))
    return items


def fetch():
    """Download and install the table. Returns (ok, detail)."""
    last = ''
    for url in OUI_URLS:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'DNSMAQ-MGR/%s' % APP_VERSION})
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
                data = r.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise ValueError('registry exceeds %d MB' % (MAX_BYTES // 1_000_000))
            table = parse_oui_csv(data.decode('utf-8', errors='replace'))
            if len(table) < 1000:
                raise ValueError('parsed only %d assignments — not the registry' % len(table))
            write_json_atomic(OUI_FILE, table, 0o600)
            with STORE_LOCK:
                st = load_store('oui')
                st.update({'fetched': int(time.time()), 'count': len(table), 'last_status': 'ok',
                           'last_attempt': int(time.time())})
                save_store('oui', st)
            return True, '%d assignments' % len(table)
        except Exception as e:
            last = str(e)
    with STORE_LOCK:
        st = load_store('oui')
        st.update({'last_status': 'error: %s' % last, 'last_attempt': int(time.time())})
        save_store('oui', st)
    return False, last


def refresh_due():
    """Ticker hook: first fetch when nothing is installed yet, then every
    REFRESH_DAYS; a failure retries hourly."""
    st = load_store('oui')
    if not st.get('auto_refresh', True):
        return
    now = int(time.time())
    if str(st.get('last_status', '')).startswith('error') and \
            now - int(st.get('last_attempt') or 0) < RETRY_SECONDS:
        return
    if not st.get('fetched') or now - int(st['fetched']) >= REFRESH_DAYS * 86400:
        fetch()


@bp.route('/api/oui')
def oui_get():
    st = load_store('oui')
    return jsonify({'success': True, **st, 'present': os.path.exists(OUI_FILE)})


@bp.route('/api/oui', methods=['POST'])
def oui_save():
    data, e = json_object()
    if e:
        return e
    with STORE_LOCK:
        st = load_store('oui')
        if 'auto_refresh' in data:
            st['auto_refresh'] = bool(data['auto_refresh'])
        save_store('oui', st)
    return jsonify({'success': True, **st})


@bp.route('/api/oui/refresh', methods=['POST'])
def oui_refresh():
    ok, detail = fetch()
    if not ok:
        return err('OUI fetch failed: %s' % detail, 502)
    return jsonify({'success': True, 'detail': detail, **load_store('oui')})


@bp.route('/api/oui/lookup/<mac>')
def oui_lookup(mac):
    return jsonify({'success': True, 'mac': mac, 'vendor': vendor(mac)})
