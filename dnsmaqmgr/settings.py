"""Global settings + feature toggles."""
from flask import Blueprint, jsonify, request

from .core.runcmd import err
from .core.store import load_store, save_store
from .core.validators import (RE_DOMAIN, RE_IFACE, is_ip, is_upstream)
from .dnsmasq import apply_change

bp = Blueprint('settings', __name__)

MAX_EXTRA = 20000

# Simple boolean settings applied verbatim.
BOOL_KEYS = ('expand_hosts', 'bind_interfaces', 'no_resolv', 'domain_needed',
             'bogus_priv', 'dnssec', 'dhcp_authoritative', 'log_queries', 'log_dhcp')

# Never sent to the browser.
PRIVATE_KEYS = ('mirror_token_hash',)


def public_settings(s=None):
    s = dict(s if s is not None else load_store('settings'))
    for k in PRIVATE_KEYS:
        s.pop(k, None)
    return s


def _validated(data, cur):
    """Validate an incoming settings payload against the current store; returns
    (new_settings, None) or (None, error message)."""
    s = dict(cur)
    if 'domain' in data:
        dom = (data['domain'] or '').strip()
        if dom and not RE_DOMAIN.match(dom):
            return None, 'Invalid domain'
        s['domain'] = dom
    if 'interfaces' in data:
        ifaces = [str(i).strip() for i in (data['interfaces'] or []) if str(i).strip()]
        if any(not RE_IFACE.match(i) for i in ifaces):
            return None, 'Invalid interface name'
        s['interfaces'] = ifaces
    if 'listen_addresses' in data:
        addrs = [str(a).strip() for a in (data['listen_addresses'] or []) if str(a).strip()]
        if any(not is_ip(a) for a in addrs):
            return None, 'Invalid listen address'
        s['listen_addresses'] = addrs
    if 'upstreams' in data:
        ups = [str(u).strip() for u in (data['upstreams'] or []) if str(u).strip()]
        if any(not is_upstream(u) for u in ups):
            return None, 'Invalid upstream server (use IP or IP#port)'
        s['upstreams'] = ups
    if 'cache_size' in data:
        try:
            n = int(data['cache_size'])
        except (TypeError, ValueError):
            return None, 'Invalid cache size'
        if not 0 <= n <= 10_000_000:
            return None, 'Cache size out of range'
        s['cache_size'] = n
    if 'extra_options' in data:
        extra = str(data['extra_options'] or '')
        if len(extra) > MAX_EXTRA or '\x00' in extra:
            return None, 'Extra options too large'
        s['extra_options'] = extra
    for k in BOOL_KEYS:
        if k in data:
            s[k] = bool(data[k])
    return s, None


@bp.route('/api/settings')
def settings_get():
    return jsonify(public_settings())


@bp.route('/api/settings', methods=['POST'])
def settings_save():
    data = request.get_json() or {}
    cur = load_store('settings')
    new, e = _validated(data, cur)
    if e:
        return err(e)
    # Upstreams ride in the mirrored 'dns' section, so settings saves push it.
    res = apply_change(lambda: save_store('settings', new), sections=['dns'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, 'settings': public_settings(), **res})


@bp.route('/api/settings/toggles', methods=['POST'])
def settings_toggles():
    data = request.get_json() or {}
    cur = load_store('settings')
    probe_note = None
    # Guard against a second DHCP server on the same network: before the
    # toggle goes live, broadcast a DHCPDISCOVER and warn if a foreign server
    # answers. `force: true` (the user confirmed) skips the guard; a probe
    # that cannot run never blocks the toggle, only the warning.
    if data.get('dhcp_enabled') and not cur.get('dhcp_enabled') and not data.get('force'):
        from .probe import probe_for_foreign_dhcp
        result = probe_for_foreign_dhcp(cur.get('interfaces') or [])
        if result['servers']:
            names = ', '.join(s['server'] for s in result['servers'])
            return jsonify({'success': False, 'conflict': True,
                            'servers': result['servers'],
                            'error': 'Another DHCP server is already active on this '
                                     'network: %s' % names}), 409
        probe_note = result.get('error')
    for k in ('dns_enabled', 'dhcp_enabled'):
        if k in data:
            cur[k] = bool(data[k])
    res = apply_change(lambda: save_store('settings', cur), sections=['settings'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True,
                    'dns_enabled': cur['dns_enabled'],
                    'dhcp_enabled': cur['dhcp_enabled'],
                    'probe_note': probe_note, **res})
