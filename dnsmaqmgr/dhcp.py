"""DHCP: pools/ranges, static leases, options, plus the live leases table."""
import time
import ipaddress
from flask import Blueprint, jsonify, request

from .core.config import LEASES_FILE
from .core.runcmd import err
from .core.store import load_store, save_store, new_id, find_record
from .core.validators import (RE_COMMENT, RE_DHCP_OPTION, RE_HOSTNAME, RE_IFACE,
                              RE_LEASE, RE_MAC, RE_OPT_VALUE, RE_TAG, is_ipv4)
from .dnsmasq import apply_change
from .mirror import locked_error

bp = Blueprint('dhcp', __name__)

COLLS = ('ranges', 'static_leases', 'options')


def _common(data):
    rec = {'enabled': bool(data.get('enabled', True)),
           'comment': str(data.get('comment') or '')}
    if not RE_COMMENT.match(rec['comment']):
        return None, 'Invalid comment'
    tag = (data.get('tag') or '').strip()
    if tag and not RE_TAG.match(tag):
        return None, 'Invalid tag'
    rec['tag'] = tag
    return rec, None


def _validate(coll, data):
    rec, e = _common(data)
    if e:
        return None, e
    if coll == 'ranges':
        start = (data.get('start') or '').strip()
        end = (data.get('end') or '').strip()
        netmask = (data.get('netmask') or '').strip()
        lease = (data.get('lease') or '12h').strip()
        iface = (data.get('interface') or '').strip()
        if not is_ipv4(start) or not is_ipv4(end):
            return None, 'Start and end must be IPv4 addresses'
        if int(ipaddress.IPv4Address(end)) < int(ipaddress.IPv4Address(start)):
            return None, 'Range end is before its start'
        if netmask and not is_ipv4(netmask):
            return None, 'Invalid netmask'
        if not RE_LEASE.match(lease):
            return None, 'Invalid lease time (e.g. 12h, 90m, infinite)'
        if iface and not RE_IFACE.match(iface):
            return None, 'Invalid interface'
        if iface and rec.get('tag'):
            # dnsmasq: "only one tag allowed" — interface: and set: are
            # mutually exclusive within a single dhcp-range.
            return None, 'A range can have a tag or an interface, not both'
        rec.update({'start': start, 'end': end, 'netmask': netmask,
                    'lease': lease, 'interface': iface})
    elif coll == 'static_leases':
        mac = (data.get('mac') or '').strip().lower()
        ip = (data.get('ip') or '').strip()
        hostname = (data.get('hostname') or '').strip()
        if not RE_MAC.match(mac):
            return None, 'Invalid MAC address'
        if not is_ipv4(ip):
            return None, 'Invalid IPv4 address'
        if hostname and not RE_HOSTNAME.match(hostname):
            return None, 'Invalid hostname'
        rec.update({'mac': mac, 'ip': ip, 'hostname': hostname})
    elif coll == 'options':
        option = str(data.get('option') or '').strip()
        value = str(data.get('value') or '').strip()
        if not RE_DHCP_OPTION.match(option):
            return None, 'Invalid option (number or option:name)'
        if value and not RE_OPT_VALUE.match(value):
            return None, 'Invalid option value'
        rec.update({'option': option, 'value': value})
    return rec, None


def _dup_check(coll, items, rec, skip_id=None):
    if coll == 'static_leases':
        for it in items:
            if it.get('id') != skip_id and it.get('mac') == rec['mac']:
                return 'A static lease for %s already exists' % rec['mac']
    return None


@bp.route('/api/dhcp')
def dhcp_get():
    return jsonify(load_store('dhcp'))


@bp.route('/api/dhcp/<coll>', methods=['POST'])
def dhcp_add(coll):
    if coll not in COLLS:
        return err('Unknown collection', 404)
    locked = locked_error('dhcp')
    if locked:
        return locked
    rec, e = _validate(coll, request.get_json() or {})
    if e:
        return err(e)
    d = load_store('dhcp')
    dup = _dup_check(coll, d[coll], rec)
    if dup:
        return err(dup, 409)
    rec['id'] = new_id(coll[0])

    def mutate():
        d2 = load_store('dhcp')
        d2[coll].append(rec)
        save_store('dhcp', d2)

    res = apply_change(mutate, sections=['dhcp'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, 'id': rec['id'], **res})


@bp.route('/api/dhcp/<coll>/<rid>', methods=['POST'])
def dhcp_update(coll, rid):
    if coll not in COLLS:
        return err('Unknown collection', 404)
    locked = locked_error('dhcp')
    if locked:
        return locked
    d = load_store('dhcp')
    if not find_record(d[coll], rid):
        return err('No such record', 404)
    rec, e = _validate(coll, request.get_json() or {})
    if e:
        return err(e)
    dup = _dup_check(coll, d[coll], rec, skip_id=rid)
    if dup:
        return err(dup, 409)
    rec['id'] = rid

    def mutate():
        d2 = load_store('dhcp')
        d2[coll] = [rec if it.get('id') == rid else it for it in d2[coll]]
        save_store('dhcp', d2)

    res = apply_change(mutate, sections=['dhcp'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, **res})


@bp.route('/api/dhcp/<coll>/<rid>', methods=['DELETE'])
def dhcp_delete(coll, rid):
    if coll not in COLLS:
        return err('Unknown collection', 404)
    locked = locked_error('dhcp')
    if locked:
        return locked
    d = load_store('dhcp')
    if not find_record(d[coll], rid):
        return err('No such record', 404)

    def mutate():
        d2 = load_store('dhcp')
        d2[coll] = [it for it in d2[coll] if it.get('id') != rid]
        save_store('dhcp', d2)

    res = apply_change(mutate, sections=['dhcp'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, **res})


# ─── Live leases ──────────────────────────────────────────────────────

def parse_leases(path=LEASES_FILE):
    """Parse dnsmasq.leases: `expiry mac ip hostname client-id` per line."""
    leases = []
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                try:
                    expiry = int(parts[0])
                except ValueError:
                    continue
                leases.append({'expiry': expiry, 'mac': parts[1], 'ip': parts[2],
                               'hostname': parts[3] if parts[3] != '*' else '',
                               'client_id': parts[4] if len(parts) > 4 else ''})
    except OSError:
        pass
    return leases


@bp.route('/api/dhcp/leases')
def dhcp_leases():
    now = int(time.time())
    leases = parse_leases()
    for l in leases:
        l['expires_in'] = max(0, l['expiry'] - now) if l['expiry'] else None
    statics = {s['mac'] for s in load_store('dhcp').get('static_leases', [])}
    for l in leases:
        l['static'] = l['mac'] in statics
    return jsonify({'leases': leases, 'count': len(leases)})


@bp.route('/api/dhcp/leases/reserve', methods=['POST'])
def dhcp_reserve():
    """Turn a live lease into a static reservation."""
    locked = locked_error('dhcp')
    if locked:
        return locked
    rec, e = _validate('static_leases', request.get_json() or {})
    if e:
        return err(e)
    d = load_store('dhcp')
    dup = _dup_check('static_leases', d['static_leases'], rec)
    if dup:
        return err(dup, 409)
    rec['id'] = new_id('s')

    def mutate():
        d2 = load_store('dhcp')
        d2['static_leases'].append(rec)
        save_store('dhcp', d2)

    res = apply_change(mutate, sections=['dhcp'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, 'id': rec['id'], **res})
