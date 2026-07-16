"""JSON state stores — one file per domain under DATA_DIR/state/.

The app's stores are the source of truth; the dnsmasq config is rendered from
them. A single module-level lock serializes every load-mutate-save-render
cycle (STORE_LOCK is taken by dnsmasq.apply_change, not here) — at this scale
one lock is simpler and eliminates render/apply races entirely.
"""
import os
import copy
import secrets
import threading

from .config import STATE_DIR, write_json_atomic

STORE_LOCK = threading.RLock()

DEFAULTS = {
    'settings': {
        'serial': 0,
        'dns_enabled': True,
        'dhcp_enabled': False,
        'domain': 'lan',
        'expand_hosts': True,
        'interfaces': [],
        'listen_addresses': [],
        'bind_interfaces': True,
        'upstreams': ['1.1.1.1', '9.9.9.9'],
        'no_resolv': True,
        'cache_size': 1000,
        'domain_needed': True,
        'bogus_priv': True,
        'dnssec': False,
        'dhcp_authoritative': True,
        'log_queries': False,
        'log_dhcp': False,
        'extra_options': '',
        'mirror_accept': False,
        'mirror_token_hash': None,
        'mirror_sources': {},
    },
    'dns': {'serial': 0, 'hosts': [], 'cnames': [], 'addresses': [], 'forwards': []},
    'dhcp': {'serial': 0, 'ranges': [], 'static_leases': [], 'options': []},
    'netboot': {'serial': 0, 'tftp_enabled': False, 'tftp_root': '', 'tftp_secure': True,
                'proxy_dhcp': False, 'proxy_subnet': '', 'pxe_prompt': '', 'entries': []},
    'peers': {'peers': []},
    'stats_cursor': {},
}


def _path(name):
    return os.path.join(STATE_DIR, name + '.json')


def load_store(name):
    """Load a store, layering the file over its defaults so new keys added in
    later versions appear with sane values on old installs."""
    import json
    base = copy.deepcopy(DEFAULTS[name])
    try:
        with open(_path(name)) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return base
    if isinstance(base, dict) and isinstance(data, dict):
        base.update(data)
        return base
    return data


def save_store(name, data):
    write_json_atomic(_path(name), data, 0o600)


def bump_serial(name, data):
    data['serial'] = int(data.get('serial', 0)) + 1
    save_store(name, data)
    return data['serial']


def new_id(prefix):
    return '%s_%s' % (prefix, secrets.token_hex(3))


def find_record(items, rid):
    for it in items:
        if it.get('id') == rid:
            return it
    return None
