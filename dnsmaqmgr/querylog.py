"""Live query log viewer: parse dnsmasq's `log-queries` output into recent
queries plus aggregates (top domains, top clients, NXDOMAINs, blocked hits,
which upstream answered).

The source is whatever the platform already collects — journalctl on bare
metal (the sudoers rule pins `-n 200`), the supervised child's ring buffer in
Docker — so this is a poll-parse view over a sliding window, not a persistent
query database. The app renders `log-queries=extra` when logging is enabled;
the extra serial + client/port prefix lets a query line be correlated with its
forwarded/reply/config lines. Lines without the prefix (older logs, log-dhcp
noise) still contribute to the aggregate counters.
"""
import re
from collections import Counter
from flask import Blueprint, jsonify

from .core.store import load_store
from .dnsmasq import get_controller

bp = Blueprint('querylog', __name__)

MAX_ENTRIES = 200

# One tolerant pattern for the three line shapes we care about, prefix-agnostic
# (journalctl adds `Mon dd hh:mm:ss host dnsmasq[pid]:`, stderr logging just
# `dnsmasq: …`). The optional `<serial> <client>/<port>` group is the
# log-queries=extra correlation handle.
LINE_RE = re.compile(
    r'^(?P<prefix>.*?)'
    r'(?:(?P<serial>\d+)\s+(?P<client>\S+)/(?P<port>\d+)\s+)?'
    r'(?:'
    r'query\[(?P<qtype>[^\]]+)\]\s+(?P<qname>\S+)\s+from\s+(?P<qfrom>\S+)'
    r'|forwarded\s+(?P<fname>\S+)\s+to\s+(?P<fto>\S+)'
    r'|(?P<akind>reply|cached(?:-stale)?|config|DHCP|/\S+)\s+(?P<aname>\S+)\s+is\s+(?P<aval>.+?)'
    r')\s*$'
)
TS_RE = re.compile(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)')

BLOCK_VALUES = {'0.0.0.0', '::'}


def _source_label(akind):
    if akind == 'reply':
        return 'upstream'
    if akind.startswith('cached'):
        return 'cache'
    if akind == 'config':
        return 'config'
    if akind == 'DHCP':
        return 'dhcp'
    return 'hosts'          # `/path/to/hosts name is addr`


def parse_query_log(lines):
    """Parse a window of dnsmasq log lines. Returns (entries, aggregates)."""
    entries = []            # query entries, oldest first
    by_key = {}             # (serial, client) -> entry, for extra-format logs
    domains, clients, upstreams = Counter(), Counter(), Counter()
    blocked_domains, sources = Counter(), Counter()
    nxdomain = 0

    for line in lines:
        m = LINE_RE.match(line)
        if not m:
            continue
        key = (m['serial'], m['client']) if m['serial'] else None
        ts = TS_RE.search(m['prefix'] or '')
        ts = ts.group(1) if ts else ''

        if m['qname']:
            name = m['qname'].lower()
            entry = {'time': ts, 'qtype': m['qtype'], 'name': name,
                     'client': m['qfrom'], 'upstreams': [], 'answers': [],
                     'status': 'pending'}
            entries.append(entry)
            if key:
                by_key[key] = entry
            domains[name] += 1
            clients[m['qfrom']] += 1
        elif m['fname']:
            upstreams[m['fto']] += 1
            entry = by_key.get(key)
            if entry is not None and m['fto'] not in entry['upstreams']:
                entry['upstreams'].append(m['fto'])
                entry['status'] = 'forwarded'
        elif m['akind']:
            src = _source_label(m['akind'])
            val = m['aval'].strip()
            is_block = src == 'config' and val in BLOCK_VALUES
            if is_block:
                blocked_domains[m['aname'].lower()] += 1
            if val == 'NXDOMAIN':
                nxdomain += 1
            sources[src] += 1
            entry = by_key.get(key)
            if entry is not None:
                entry['answers'].append({'source': src, 'value': val})
                entry['status'] = 'blocked' if is_block else \
                    ('nxdomain' if val == 'NXDOMAIN' else 'answered')

    aggregates = {
        'queries': sum(domains.values()),
        'nxdomain': nxdomain,
        'blocked': sum(blocked_domains.values()),
        'top_domains': domains.most_common(10),
        'top_clients': clients.most_common(10),
        'top_blocked': blocked_domains.most_common(10),
        'upstreams': upstreams.most_common(10),
        'answer_sources': sources.most_common(),
    }
    return entries, aggregates


@bp.route('/api/querylog')
def querylog_get():
    settings = load_store('settings')
    ctl = get_controller()
    # journalctl access is sudo-pinned to exactly `-n 200`; the child ring
    # buffer holds up to 2000 lines.
    raw = ctl.logs(2000 if ctl.mode == 'child' else 200) or ''
    lines = raw.splitlines()
    entries, aggregates = parse_query_log(lines)
    return jsonify({'success': True,
                    'enabled': bool(settings.get('log_queries')),
                    'mode': ctl.mode, 'window_lines': len(lines),
                    'entries': entries[-MAX_ENTRIES:], **aggregates})
