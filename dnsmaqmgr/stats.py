"""Statistics: dnsmasq exposes its counters as CHAOS-class TXT records
(cachesize.bind, hits.bind, ...) queried over DNS itself — no log parsing.
The query is built raw on a UDP socket, so there is no DNS library
dependency. DHCP consumption comes from the app-owned leases file.

Counters are cumulative since dnsmasq start; the history store records
per-tick deltas via a cursor file (a negative delta means dnsmasq restarted —
the current value IS the delta since restart).

A single in-app daemon thread ticks every TICK_SECONDS on both bare metal and
Docker — the tick is one UDP query plus one small file read, so it does not
warrant systemd timer scaffolding (and Docker has no systemd anyway).
"""
import os
import time
import struct
import secrets
import socket
import ipaddress
import threading
from flask import Blueprint, jsonify

from .core.config import DNS_PORT, LEASES_FILE, TICK_SECONDS
from .core.store import load_store, save_store
from .dhcp import parse_leases

bp = Blueprint('stats', __name__)

CHAOS_NAMES = {
    'cachesize': 'cachesize.bind',
    'insertions': 'insertions.bind',
    'evictions': 'evictions.bind',
    'hits': 'hits.bind',
    'misses': 'misses.bind',
}
COUNTER_KEYS = ('hits', 'misses', 'evictions', 'insertions')  # cumulative → deltas


def _build_query(name, qtype=16, qclass=3):
    qid = secrets.randbits(16)
    header = struct.pack('!HHHHHH', qid, 0, 1, 0, 0, 0)
    qname = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    return header + qname + struct.pack('!HH', qtype, qclass), qid


def _skip_name(buf, pos):
    while pos < len(buf):
        ln = buf[pos]
        if ln == 0:
            return pos + 1
        if ln & 0xC0 == 0xC0:  # compression pointer: 2 bytes, ends the name
            return pos + 2
        pos += 1 + ln
    return pos


def _parse_txt(buf, qid):
    """Return the list of TXT strings from the first answer, or None."""
    if len(buf) < 12:
        return None
    rid, flags, qd, an = struct.unpack('!HHHH', buf[:8])
    if rid != qid or an < 1:
        return None
    pos = 12
    for _ in range(qd):
        pos = _skip_name(buf, pos) + 4
    pos = _skip_name(buf, pos)
    if pos + 10 > len(buf):
        return None
    rtype, rclass, _ttl, rdlen = struct.unpack('!HHIH', buf[pos:pos + 10])
    pos += 10
    if rtype != 16 or pos + rdlen > len(buf):
        return None
    strings, end = [], pos + rdlen
    while pos < end:
        ln = buf[pos]
        strings.append(buf[pos + 1:pos + 1 + ln].decode(errors='replace'))
        pos += 1 + ln
    return strings


def chaos_txt(name, server='127.0.0.1', port=DNS_PORT, timeout=1.0):
    """Query one CHAOS TXT name; returns the first TXT string or None."""
    query, qid = _build_query(name)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (server, port))
            buf, _ = s.recvfrom(4096)
        strings = _parse_txt(buf, qid)
        return strings[0] if strings else None
    except OSError:
        return None


def collect_dns_counters():
    """Current absolute counters from dnsmasq, or {} when DNS is unreachable."""
    vals = {}
    for key, name in CHAOS_NAMES.items():
        v = chaos_txt(name)
        if v is None:
            return {}
        try:
            vals[key] = int(v)
        except ValueError:
            return {}
    return vals


def pool_utilization(dhcp=None, leases=None):
    """Per-range active lease counts: [{tag,start,end,size,used,pct}]."""
    if dhcp is None:
        dhcp = load_store('dhcp')
    if leases is None:
        leases = parse_leases()
    lease_ips = []
    for l in leases:
        try:
            lease_ips.append(int(ipaddress.IPv4Address(l['ip'])))
        except (ValueError, KeyError):
            pass
    pools = []
    for r in dhcp.get('ranges', []):
        if not r.get('enabled', True):
            continue
        try:
            lo = int(ipaddress.IPv4Address(r['start']))
            hi = int(ipaddress.IPv4Address(r['end']))
        except ValueError:
            continue
        size = hi - lo + 1
        used = sum(1 for ip in lease_ips if lo <= ip <= hi)
        pools.append({'tag': r.get('tag') or r['start'], 'start': r['start'],
                      'end': r['end'], 'size': size, 'used': used,
                      'pct': round(used * 100.0 / size, 1) if size else 0.0})
    return pools


def collect_samples():
    """(metric, label, value) rows for the history store: DNS counter deltas
    via the on-disk cursor + DHCP gauges."""
    rows = []
    settings = load_store('settings')
    if settings.get('dns_enabled', True):
        vals = collect_dns_counters()
        if vals:
            rows.append(('dns_cache_size', '', vals['cachesize']))
            cursor = load_store('stats_cursor')
            have_last = bool(cursor.get('ts'))
            for key in COUNTER_KEYS:
                cur = vals[key]
                if have_last:
                    last = int(cursor.get(key, 0))
                    delta = cur - last
                    if delta < 0:  # dnsmasq restarted; counters reset
                        delta = cur
                    rows.append(('dns_%s' % key, '', delta))
                cursor[key] = cur
            cursor['ts'] = int(time.time())
            save_store('stats_cursor', cursor)
    leases = parse_leases()
    rows.append(('dhcp_leases', '', len(leases)))
    for p in pool_utilization(leases=leases):
        rows.append(('dhcp_pool_util', p['tag'], p['pct']))
    return rows


# ─── In-app ticker ─────────────────────────────────────────────────────

_ticker_started = False

def start_ticker():
    global _ticker_started
    if _ticker_started:
        return
    _ticker_started = True

    def loop():
        from .core import history
        from . import blocklists, alerts
        while True:
            time.sleep(TICK_SECONDS)
            try:
                history.cli_history_tick()
            except Exception as e:
                print('stats tick failed: %s' % e, flush=True)
            try:
                blocklists.refresh_due()
            except Exception as e:
                print('blocklist refresh tick failed: %s' % e, flush=True)
            try:
                alerts.tick()
            except Exception as e:
                print('alerts tick failed: %s' % e, flush=True)

    threading.Thread(target=loop, daemon=True).start()


# ─── Routes ────────────────────────────────────────────────────────────

@bp.route('/api/stats/current')
def stats_current():
    settings = load_store('settings')
    out = {'dns': None, 'dhcp': None}
    if settings.get('dns_enabled', True):
        vals = collect_dns_counters()
        if vals:
            total = vals['hits'] + vals['misses']
            vals['hit_ratio'] = round(vals['hits'] * 100.0 / total, 1) if total else None
            out['dns'] = vals
    leases = parse_leases()
    out['dhcp'] = {'active_leases': len(leases), 'pools': pool_utilization(leases=leases)}
    try:
        out['leases_mtime'] = int(os.path.getmtime(LEASES_FILE))
    except OSError:
        out['leases_mtime'] = None
    return jsonify(out)
