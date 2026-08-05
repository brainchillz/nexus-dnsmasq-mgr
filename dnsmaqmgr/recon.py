"""Network reconnaissance for record hygiene.

An on-demand ping/ARP sweep over the addresses this app already cares about —
enabled DHCP ranges, managed host-record IPs, active lease IPs — cross-
referenced against the stores:

  * unnamed_devices   — a live device (IP+MAC) with no host record and no
                        lease hostname
  * stale_records     — a managed host record whose A address answered
                        nothing and holds no lease (the 2026-08-05 stale-
                        record incident, found proactively)
  * duplicates        — one name → several IPs, one IP → several names, and
                        record-vs-lease disagreements (lease hostname matches
                        a record but the IP differs)

Deliberately NOT a general scanner: targets come only from the app's own
configuration (no arbitrary CIDR input), capped at MAX_TARGETS. Pings run
unprivileged (`ping -c1`) in a thread pool; MACs come from the kernel
neighbor table afterwards, which the pings themselves populate for on-link
subnets. One scan at a time, in a background thread; the last result is
persisted in the 'recon' store so it survives restarts.
"""
import re
import time
import ipaddress
import threading
import subprocess
from concurrent.futures import ThreadPoolExecutor
from flask import Blueprint, jsonify

from .core.runcmd import err, run
from .core.store import load_store, save_store
from .dhcp import parse_leases

bp = Blueprint('recon', __name__)

MAX_TARGETS = 2048
PING_WORKERS = 64
PING_TIMEOUT = 3

_state_lock = threading.Lock()
_scan = {'running': False, 'progress': 0, 'total': 0, 'started': 0}

RE_NEIGH = re.compile(r'^(\d+\.\d+\.\d+\.\d+)\s+.*\blladdr\s+([0-9a-f:]{17})\s+(\S+)')


def _ping(ip):
    """One unprivileged ping. Patched out in tests."""
    try:
        r = subprocess.run(['ping', '-c', '1', '-W', '1', '-n', ip],
                           capture_output=True, timeout=PING_TIMEOUT)
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def neighbor_table():
    """{ip: mac} from the kernel's IPv4 neighbor table (no privilege needed)."""
    out, _, rc = run(['ip', '-4', 'neigh', 'show'], no_sudo=True, timeout=10)
    neigh = {}
    if rc != 0:
        return neigh
    for line in (out or '').splitlines():
        m = RE_NEIGH.match(line.strip())
        if m and m.group(3).upper() not in ('FAILED', 'INCOMPLETE'):
            neigh[m.group(1)] = m.group(2)
    return neigh


def scan_targets():
    """Target IPs from the app's own config. Returns (sorted ips, truncated)."""
    ips = set()
    dhcp = load_store('dhcp')
    for r in dhcp.get('ranges', []):
        if not r.get('enabled', True):
            continue
        try:
            lo = int(ipaddress.IPv4Address(r['start']))
            hi = int(ipaddress.IPv4Address(r['end']))
        except (ValueError, KeyError):
            continue
        for n in range(lo, min(hi, lo + MAX_TARGETS) + 1):
            ips.add(str(ipaddress.IPv4Address(n)))
    for h in load_store('dns').get('hosts', []):
        if h.get('enabled', True) and h.get('a'):
            ips.add(h['a'])
    for l in parse_leases():
        ips.add(l['ip'])
    truncated = len(ips) > MAX_TARGETS
    return sorted(ips, key=lambda s: int(ipaddress.IPv4Address(s)))[:MAX_TARGETS], truncated


def _expand(name, settings):
    n = name.lower().rstrip('.')
    names = {n}
    dom = (settings.get('domain') or '').lower()
    if dom and settings.get('expand_hosts'):
        if '.' not in n:
            names.add('%s.%s' % (n, dom))
        elif n.endswith('.' + dom):
            names.add(n[:-len(dom) - 1])
    return names


def cross_reference(alive, neigh, hosts, leases, settings):
    """The hygiene report. `alive` is a set of pinged-alive IPs; `neigh`
    {ip: mac}. Pure — unit-testable without a network."""
    live = set(alive) | set(neigh)
    lease_by_ip = {l['ip']: l for l in leases}
    recs = [h for h in hosts if h.get('enabled', True) and h.get('a')]

    names_by_ip = {}
    for h in recs:
        names_by_ip.setdefault(h['a'], []).append(h['name'])

    unnamed = []
    for ip in sorted(live, key=lambda s: int(ipaddress.IPv4Address(s))):
        lease = lease_by_ip.get(ip)
        if ip in names_by_ip or (lease and lease.get('hostname')):
            continue
        unnamed.append({'ip': ip, 'mac': neigh.get(ip, '') or (lease or {}).get('mac', ''),
                        'alive': ip in alive, 'has_lease': bool(lease)})

    stale = []
    for h in recs:
        ip = h['a']
        if ip not in live and ip not in lease_by_ip:
            stale.append({'name': h['name'], 'ip': ip, 'id': h.get('id', ''),
                          'comment': h.get('comment', '')})

    duplicates = []
    by_name = {}
    for h in recs:
        by_name.setdefault(h['name'].lower(), set()).add(h['a'])
    for name, ips in sorted(by_name.items()):
        if len(ips) > 1:
            duplicates.append({'kind': 'name_multiple_ips', 'name': name,
                               'detail': 'record maps to %s' % ', '.join(sorted(ips))})
    for ip, names in sorted(names_by_ip.items()):
        if len(set(n.lower() for n in names)) > 1:
            duplicates.append({'kind': 'ip_multiple_names', 'name': ip,
                               'detail': 'IP named by %s' % ', '.join(sorted(names))})
    for l in leases:
        hn = (l.get('hostname') or '').lower()
        if not hn:
            continue
        for h in recs:
            if hn in _expand(h['name'], settings) and l['ip'] != h['a']:
                duplicates.append({'kind': 'record_lease_mismatch', 'name': h['name'],
                                   'detail': 'record says %s but %s holds lease %s'
                                             % (h['a'], l['mac'], l['ip'])})

    return {'unnamed_devices': unnamed, 'stale_records': stale,
            'duplicates': duplicates,
            'alive': len(alive), 'neighbors': len(neigh)}


def _run_scan(targets, truncated):
    started = time.time()
    alive = set()
    try:
        with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
            for ip, ok in zip(targets, ex.map(_ping, targets)):
                with _state_lock:
                    _scan['progress'] += 1
                if ok:
                    alive.add(ip)
        neigh = neighbor_table()
        # Store the RAW scan data; the hygiene report is recomputed on read so
        # fixing a finding (e.g. creating a record for an unnamed device)
        # updates the report immediately, without a rescan.
        save_store('recon', {'last': {
            'ts': int(started), 'duration': round(time.time() - started, 1),
            'targets': len(targets), 'truncated': truncated,
            'alive_ips': sorted(alive), 'neigh': neigh}})
    except Exception as e:
        print('recon scan failed: %s' % e, flush=True)
    finally:
        with _state_lock:
            _scan['running'] = False


@bp.route('/api/recon')
def recon_get():
    with _state_lock:
        status = dict(_scan)
    last = load_store('recon').get('last')
    if last and 'alive_ips' in last:
        result = cross_reference(set(last['alive_ips']), last.get('neigh') or {},
                                 load_store('dns').get('hosts', []),
                                 parse_leases(), load_store('settings'))
        result.update({k: last.get(k) for k in ('ts', 'duration', 'targets', 'truncated')})
        last = result
    return jsonify({**status, 'last': last})


@bp.route('/api/recon/scan', methods=['POST'])
def recon_scan():
    targets, truncated = scan_targets()
    if not targets:
        return err('Nothing to scan — no DHCP ranges, host records or leases')
    with _state_lock:
        if _scan['running']:
            return err('A scan is already running', 409)
        _scan.update({'running': True, 'progress': 0, 'total': len(targets),
                      'started': int(time.time())})
    threading.Thread(target=_run_scan, args=(targets, truncated), daemon=True).start()
    return jsonify({'success': True, 'targets': len(targets), 'truncated': truncated})
