"""Lookup / diagnosis: query the running dnsmasq for a name and attribute
every answer to its source — managed host record, managed override/CNAME,
blocklist, the system /etc/hosts (file + line), a foreign dnsmasq.d file,
a DHCP lease hostname, or upstream/cache.

Born from a real incident: the UI showed one A record for a name while the
server answered two — the stray answer was a stale /etc/hosts line, invisible
to the app. dnsmasq reads /etc/hosts by default, plus (on bare metal) any
/etc/dnsmasq.d fragment beside the app's drop-in; this module makes those
sources visible. The audit endpoint runs the same scan across every managed
host name so the UI can warn about shadowing before anyone hits it.

The DNS query is built raw on a UDP socket (same approach as stats.py) — the
app keeps its no-dependency rule; only A/AAAA/CNAME need decoding.
"""
import os
import glob
import struct
import socket
import secrets
from flask import Blueprint, jsonify, request

from .core.config import CONF_DIR, DNS_PORT, ETC_HOSTS, SUPERVISE
from .core.runcmd import err
from .core.store import load_store
from .core.validators import valid_hostname_fqdn
from .dhcp import parse_leases

bp = Blueprint('lookup', __name__)

QTYPES = {'A': 1, 'AAAA': 28}
TYPE_NAMES = {1: 'A', 5: 'CNAME', 28: 'AAAA'}


# ─── Minimal DNS client (A/AAAA/CNAME, compression-aware) ─────────────

def _build_query(name, qtype):
    qid = secrets.randbits(16)
    header = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0)  # RD set
    qname = b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00'
    return header + qname + struct.pack('!HH', qtype, 1), qid


def _read_name(buf, pos):
    """Decode a (possibly compressed) name. Returns (name, pos-after-field)."""
    labels, end, seen = [], None, set()
    while pos < len(buf):
        ln = buf[pos]
        if ln == 0:
            if end is None:
                end = pos + 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                break
            if end is None:
                end = pos + 2
            ptr = ((ln & 0x3F) << 8) | buf[pos + 1]
            if ptr in seen:      # pointer loop in a malformed packet
                break
            seen.add(ptr)
            pos = ptr
            continue
        labels.append(buf[pos + 1:pos + 1 + ln].decode(errors='replace'))
        pos += 1 + ln
    return '.'.join(labels), (end if end is not None else pos)


def _parse_response(buf, qid):
    """Returns (rcode, answers) or (None, []) on a packet we can't use."""
    if len(buf) < 12:
        return None, []
    rid, flags, qd, an, _ns, _ar = struct.unpack('!HHHHHH', buf[:12])
    if rid != qid:
        return None, []
    pos = 12
    for _ in range(qd):
        pos = _read_name(buf, pos)[1] + 4
    answers = []
    for _ in range(an):
        owner, pos = _read_name(buf, pos)
        if pos + 10 > len(buf):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack('!HHIH', buf[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(buf):
            break
        rdata = buf[pos:pos + rdlen]
        if rtype == 1 and rdlen == 4:
            value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28 and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 5:
            value = _read_name(buf, pos)[0]
        else:
            value = rdata.hex()
        answers.append({'name': owner.lower(), 'type': TYPE_NAMES.get(rtype, str(rtype)),
                        'ttl': ttl, 'value': value})
        pos += rdlen
    return flags & 0xF, answers


def query_dnsmasq(name, qtype, server='127.0.0.1', port=DNS_PORT, timeout=2.0):
    """One question to the local dnsmasq. Returns (rcode, answers);
    rcode None means no usable response."""
    query, qid = _build_query(name, qtype)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(query, (server, port))
            buf, _ = s.recvfrom(65535)
        return _parse_response(buf, qid)
    except OSError:
        return None, []


# ─── Source scans ─────────────────────────────────────────────────────

def _expand_names(name, settings):
    """The name plus its expand-hosts twin (bare <-> domain-qualified), all
    lowercase — dnsmasq answers for either form when expand-hosts is on."""
    n = name.lower().rstrip('.')
    names = {n}
    dom = (settings.get('domain') or '').lower()
    if dom and settings.get('expand_hosts'):
        if '.' not in n:
            names.add('%s.%s' % (n, dom))
        elif n.endswith('.' + dom):
            names.add(n[:-len(dom) - 1])
    return names


def scan_hosts_file(names, path=None):
    """Lines in a unix hosts file whose hostnames intersect `names`.
    Returns [{'file','line','ip','names'}] with 1-based line numbers."""
    path = path or ETC_HOSTS
    hits = []
    try:
        with open(path) as f:
            for lineno, raw in enumerate(f, 1):
                parts = raw.split('#', 1)[0].split()
                if len(parts) < 2:
                    continue
                matched = [t for t in parts[1:] if t.lower().rstrip('.') in names]
                if matched:
                    hits.append({'file': path, 'line': lineno,
                                 'ip': parts[0], 'names': matched})
    except OSError:
        pass
    return hits


def _covers(domain, name):
    """address=/server= semantics: the domain itself or any subdomain."""
    return name == domain or name.endswith('.' + domain)


def _foreign_conf_files():
    """dnsmasq config fragments OUTSIDE the app's render dir. In Docker
    (SUPERVISE) dnsmasq runs with -C /dev/null and only our conf-dir, so there
    are none; on bare metal the distro unit also reads /etc/dnsmasq.conf and
    /etc/dnsmasq.d. DNSMAQ_FOREIGN_CONF (colon-separated) overrides for tests
    or exotic layouts."""
    override = os.environ.get('DNSMAQ_FOREIGN_CONF')
    if override is not None:
        paths = [p for p in override.split(':') if p]
    elif SUPERVISE:
        return []
    else:
        paths = ['/etc/dnsmasq.conf', '/etc/dnsmasq.d']
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, '*.conf'))))
        elif os.path.isfile(p):
            files.append(p)
    ours = os.path.realpath(CONF_DIR)
    return [f for f in files
            if not os.path.realpath(f).startswith(ours + os.sep)]


def scan_foreign_conf(names):
    """DNS-defining directives in foreign dnsmasq config that touch any of
    `names`, following addn-hosts= one level deep. Returns
    [{'file','line','directive','text','ip'}] (ip where extractable)."""
    hits, extra_hosts = [], []
    for path in _foreign_conf_files():
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError:
            continue
        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            key, _, val = line.partition('=')
            key = key.strip()
            val = val.strip()
            hit_ip = ''
            matched = False
            if key in ('address', 'server'):
                parts = val.split('/')
                doms = [p.lower() for p in parts[1:-1] if p]
                matched = any(_covers(d, n) for d in doms for n in names)
                hit_ip = parts[-1] if parts else ''
            elif key == 'host-record':
                fields = [x.strip() for x in val.split(',')]
                matched = any(x.lower().rstrip('.') in names for x in fields)
                hit_ip = next((x for x in fields if x and (x[0].isdigit() or ':' in x)), '')
            elif key == 'cname':
                alias = val.split(',', 1)[0].strip().lower()
                matched = alias in names
            elif key == 'addn-hosts':
                extra_hosts.append(val)
            if matched:
                hits.append({'file': path, 'line': lineno, 'directive': key,
                             'text': line, 'ip': hit_ip})
    for hf in extra_hosts:
        for h in scan_hosts_file(names, path=hf):
            hits.append({'file': h['file'], 'line': h['line'], 'directive': 'hosts',
                         'text': '%s %s' % (h['ip'], ' '.join(h['names'])), 'ip': h['ip']})
    return hits


# ─── Attribution ──────────────────────────────────────────────────────

def _build_context(settings, dns):
    from . import blocklists as bl
    return {
        'settings': settings,
        'hosts': [h for h in dns.get('hosts', []) if h.get('enabled', True)],
        'cnames': [c for c in dns.get('cnames', []) if c.get('enabled', True)],
        'addresses': [a for a in dns.get('addresses', []) if a.get('enabled', True)],
        'forwards': [f for f in dns.get('forwards', []) if f.get('enabled', True)],
        'leases': parse_leases(),
        'blockindex': bl.load_block_index(),
        'encdns': load_store('encdns'),
    }


def _attribute(ans, ctx):
    """Attach a source dict to one answer: {kind, detail, managed, warn}
    (+ file/line for file-based sources)."""
    settings = ctx['settings']
    owner_names = _expand_names(ans['name'], settings)
    val = ans['value']

    if ans['type'] == 'CNAME':
        for c in ctx['cnames']:
            if c['alias'].lower() in owner_names:
                return {'kind': 'cname', 'managed': True, 'warn': False,
                        'detail': 'managed CNAME %s → %s' % (c['alias'], c['target'])}

    for a in sorted(ctx['addresses'], key=lambda r: -len(r['domain'])):
        dom = a['domain'].lower()
        if any(_covers(dom, n) for n in owner_names) and a['ip'] == val:
            return {'kind': 'override', 'managed': True, 'warn': False,
                    'detail': 'managed domain override address=/%s/%s' % (a['domain'], a['ip'])}

    if val in ('0.0.0.0', '::'):
        for n in owner_names:
            listed = ctx['blockindex'].match(n)
            if listed:
                return {'kind': 'blocklist', 'managed': True, 'warn': False,
                        'detail': 'blocked by list "%s" (%s)' % (listed[0], listed[1])}

    for h in ctx['hosts']:
        if h['name'].lower().rstrip('.') in owner_names or \
                _expand_names(h['name'], settings) & owner_names:
            if val in (h.get('a'), h.get('aaaa')):
                return {'kind': 'host', 'managed': True, 'warn': False,
                        'detail': 'managed host record %s' % h['name']}

    if not settings.get('no_hosts'):
        for hit in scan_hosts_file(owner_names):
            if hit['ip'] == val:
                return {'kind': 'etc-hosts', 'managed': False, 'warn': True,
                        'file': hit['file'], 'line': hit['line'],
                        'detail': '%s line %d — not managed by this app'
                                  % (hit['file'], hit['line'])}

    for hit in scan_foreign_conf(owner_names):
        if not hit['ip'] or hit['ip'] == val:
            return {'kind': 'foreign-conf', 'managed': False, 'warn': True,
                    'file': hit['file'], 'line': hit['line'],
                    'detail': '%s line %d (%s) — not managed by this app'
                              % (hit['file'], hit['line'], hit['text'])}

    dom = (settings.get('domain') or '').lower()
    for l in ctx['leases']:
        hn = (l.get('hostname') or '').lower()
        if not hn:
            continue
        lease_names = {hn} | ({'%s.%s' % (hn, dom)} if dom else set())
        if lease_names & owner_names and l.get('ip') == val:
            return {'kind': 'lease', 'managed': False, 'warn': False,
                    'detail': 'DHCP lease hostname (%s, %s)' % (l['mac'], l['ip'])}

    for fw in sorted(ctx['forwards'], key=lambda r: -len(r['domain'])):
        if any(_covers(fw['domain'].lower(), n) for n in owner_names):
            return {'kind': 'forward', 'managed': True, 'warn': False,
                    'detail': 'forwarded upstream via server=/%s/%s'
                              % (fw['domain'], fw['upstream'])}

    enc = ctx.get('encdns') or {}
    if enc.get('enabled'):
        detail = ('answered via the encrypted upstream (dnscrypt-proxy on '
                  '127.0.0.1#%d)' % int(enc.get('listen_port') or 5335))
        if enc.get('fallback_plain'):
            detail += ', or a plain fallback upstream'
        return {'kind': 'encrypted-upstream', 'managed': False, 'warn': False,
                'detail': detail}
    return {'kind': 'upstream', 'managed': False, 'warn': False,
            'detail': 'answered by an upstream resolver (or cache): %s'
                      % ', '.join(settings.get('upstreams', []) or ['system default'])}


@bp.route('/api/lookup')
def lookup():
    name = (request.args.get('name') or '').strip().rstrip('.')
    if not valid_hostname_fqdn(name):
        return err('Enter a hostname or FQDN to look up')
    settings = load_store('settings')
    dns = load_store('dns')

    answers, rcodes = [], {}
    for t in ('A', 'AAAA'):
        rcode, ans = query_dnsmasq(name, QTYPES[t])
        rcodes[t] = rcode
        for a in ans:
            if not any(a['type'] == b['type'] and a['value'] == b['value']
                       and a['name'] == b['name'] for b in answers):
                answers.append(a)
    if all(v is None for v in rcodes.values()):
        return err('dnsmasq did not answer on 127.0.0.1:%d — is DNS enabled and running?'
                   % DNS_PORT, 502)

    ctx = _build_context(settings, dns)
    for a in answers:
        a['source'] = _attribute(a, ctx)

    # The incident check, both directions: unmanaged answers the UI can't
    # explain, and managed values the server did NOT return (shadowed).
    warnings = []
    for a in answers:
        if a['source']['warn']:
            warnings.append('%s record %s = %s comes from %s.'
                            % (a['type'], a['name'], a['value'], a['source']['detail']))
    names = _expand_names(name, settings)
    got_values = {a['value'] for a in answers}
    for h in ctx['hosts']:
        if h['name'].lower().rstrip('.') in names or _expand_names(h['name'], settings) & names:
            for key, label in (('a', 'A'), ('aaaa', 'AAAA')):
                want = h.get(key)
                if want and want not in got_values:
                    warnings.append('Managed host record defines %s %s = %s, but the server '
                                    'did not return it — possibly shadowed by another source.'
                                    % (label, h['name'], want))

    nxdomain = not answers and any(v == 3 for v in rcodes.values() if v is not None)
    return jsonify({'success': True, 'name': name, 'answers': answers,
                    'nxdomain': nxdomain, 'warnings': warnings,
                    'no_hosts': bool(settings.get('no_hosts'))})


@bp.route('/api/lookup/audit')
def lookup_audit():
    """Scan every managed host name for shadowing definitions in /etc/hosts
    and foreign dnsmasq config. Drives the warning banners in the UI."""
    settings = load_store('settings')
    dns = load_store('dns')
    by_name = {}
    for h in dns.get('hosts', []):
        if not h.get('enabled', True):
            continue
        for n in _expand_names(h['name'], settings):
            by_name.setdefault(n, h)

    conflicts = []
    if by_name and not settings.get('no_hosts'):
        for hit in scan_hosts_file(set(by_name)):
            for matched in hit['names']:
                rec = by_name.get(matched.lower().rstrip('.'))
                if rec and hit['ip'] not in (rec.get('a'), rec.get('aaaa')):
                    conflicts.append({'kind': 'etc-hosts', 'name': matched,
                                      'file': hit['file'], 'line': hit['line'],
                                      'ip': hit['ip'],
                                      'expected': rec.get('a') or rec.get('aaaa')})
    if by_name:
        for hit in scan_foreign_conf(set(by_name)):
            conflicts.append({'kind': 'foreign-conf', 'name': '',
                              'file': hit['file'], 'line': hit['line'],
                              'ip': hit['ip'], 'text': hit['text'], 'expected': ''})
    return jsonify({'success': True, 'conflicts': conflicts,
                    'no_hosts': bool(settings.get('no_hosts')),
                    'checked': len(by_name)})
