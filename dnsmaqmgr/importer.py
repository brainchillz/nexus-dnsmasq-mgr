"""Existing-config importer: parse a dnsmasq.conf / dnsmasq.d tree into the
app's stores.

Onboarding tool. The parser is pure (text in, structured preview out) and
the apply step pushes everything through the SAME validators the interactive
routes use, then one apply_change — so a hand-written config that dnsmasq
tolerated but the app would refuse is reported line by line, never
half-imported. Directives the app manages structurally map to stores;
everything else is offered as Extra Options; things the app owns outright
(conf-dir, dhcp-leasefile, pid-file, …) are dropped and listed as skipped.
"""
import os
import glob
from flask import Blueprint, jsonify

from .core.config import CONF_DIR, SUPERVISE
from .core.runcmd import err, json_object
from .core.store import load_store, save_store, new_id
from .core.validators import RE_LEASE, RE_MAC, is_ipv4, is_ipv6, is_upstream
from .dnsmasq import apply_change

bp = Blueprint('importer', __name__)

MAX_TEXT = 2_000_000
SECTIONS = ('settings', 'hosts', 'dns', 'dhcp', 'netboot', 'extra')

BOOL_FLAGS = {'expand-hosts': 'expand_hosts', 'bind-interfaces': 'bind_interfaces',
              'no-resolv': 'no_resolv', 'domain-needed': 'domain_needed',
              'bogus-priv': 'bogus_priv', 'dnssec': 'dnssec',
              'log-queries': 'log_queries', 'log-dhcp': 'log_dhcp',
              'dhcp-authoritative': 'dhcp_authoritative', 'no-hosts': 'no_hosts'}
# Owned by the app's own render; importing them would fight it.
OWNED = {'conf-dir', 'conf-file', 'dhcp-leasefile', 'pid-file', 'user', 'group',
         'trust-anchor', 'log-facility', 'keep-in-foreground', 'dhcp-hostsfile',
         'dhcp-optsfile', 'hostsdir', 'dhcp-script'}


def _blank():
    return {'settings': {}, 'hosts': [], 'cnames': [], 'addresses': [], 'forwards': [],
            'ranges': [], 'static_leases': [], 'options': [], 'entries': [],
            'extra': [], 'skipped': [], 'hosts_files': [], 'upstreams': []}


def _skip(res, line, why):
    res['skipped'].append({'line': line, 'reason': why})


def parse_conf_text(text, res=None):
    """Parse dnsmasq config text. Returns the preview structure."""
    res = res if res is not None else _blank()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        key, has_val, val = line.partition('=')
        key, val = key.strip(), val.strip()
        if key.startswith('--'):
            key = key[2:]
        if key in OWNED:
            _skip(res, line, 'managed by the app')
            continue
        if key in BOOL_FLAGS and not has_val:
            res['settings'][BOOL_FLAGS[key]] = True
            continue
        if key == 'domain':
            dom = val.split(',', 1)[0].strip()
            if dom and 'domain' not in res['settings']:
                res['settings']['domain'] = dom
            else:
                _skip(res, line, 'second domain= (only one local domain is modelled)')
            continue
        if key == 'interface':
            res['settings'].setdefault('interfaces', []).append(val)
            continue
        if key == 'listen-address':
            res['settings'].setdefault('listen_addresses', []).extend(
                [x.strip() for x in val.split(',') if x.strip()])
            continue
        if key == 'cache-size':
            res['settings']['cache_size'] = val
            continue
        if key == 'server':
            if val.startswith('/'):
                parts = val.split('/')
                doms, target = [p for p in parts[1:-1] if p], parts[-1]
                if target in ('#', '') or not is_upstream(target):
                    _skip(res, line, 'server=/domain/ with no upstream address is not modelled')
                    continue
                for d in doms:
                    res['forwards'].append({'domain': d, 'upstream': target, 'comment': 'imported'})
            elif is_upstream(val):
                res['upstreams'].append(val)
            else:
                _skip(res, line, 'unsupported server= form')
            continue
        if key == 'address':
            parts = val.split('/')
            doms, ip = [p for p in parts[1:-1] if p], parts[-1]
            if not doms or not (is_ipv4(ip) or is_ipv6(ip)):
                _skip(res, line, 'unsupported address= form')
                continue
            for d in doms:
                res['addresses'].append({'domain': d, 'ip': ip, 'comment': 'imported'})
            continue
        if key == 'cname':
            # cname=<alias>[,<alias>...],<target>[,<ttl>]
            parts = [x.strip() for x in val.split(',') if x.strip()]
            if parts and parts[-1].isdigit():
                parts.pop()
            if len(parts) >= 2:
                for alias in parts[:-1]:
                    res['cnames'].append({'alias': alias, 'target': parts[-1], 'comment': 'imported'})
            else:
                _skip(res, line, 'cname needs alias,target')
            continue
        if key == 'host-record':
            parts = [x.strip() for x in val.split(',') if x.strip()]
            names = [p for p in parts if not (is_ipv4(p) or is_ipv6(p)) and not p.isdigit()]
            ips = [p for p in parts if is_ipv4(p) or is_ipv6(p)]
            if not names or not ips:
                _skip(res, line, 'host-record needs a name and an address')
                continue
            for n in names:
                rec = {'name': n, 'a': '', 'aaaa': '', 'comment': 'imported'}
                for ip in ips:
                    rec['a' if is_ipv4(ip) else 'aaaa'] = ip
                res['hosts'].append(rec)
            continue
        if key == 'addn-hosts':
            res['hosts_files'].append(val)
            continue
        if key == 'dhcp-range':
            r = _parse_range(val)
            if r is None:
                _skip(res, line, 'unsupported dhcp-range form (static/proxy/IPv6 ranges are not modelled)')
            else:
                res['ranges'].append(r)
            continue
        if key == 'dhcp-host':
            h = _parse_host(val)
            if h is None:
                _skip(res, line, 'dhcp-host needs a MAC and an IPv4 address')
            else:
                res['static_leases'].append(h)
            continue
        if key == 'dhcp-option':
            o = _parse_option(val)
            if o is None:
                _skip(res, line, 'unsupported dhcp-option form (encap/vendor/multi-tag)')
            else:
                res['options'].append(o)
            continue
        if key == 'dhcp-boot':
            b = _parse_boot(val)
            if b is None:
                _skip(res, line, 'dhcp-boot without a boot server address (required here)')
            else:
                res['entries'].append(b)
            continue
        res['extra'].append(line)
    return res


def _split_prefixes(val):
    """Peel leading tag:/set:/interface: items off a comma list."""
    parts = [x.strip() for x in val.split(',')]
    tags, sets, iface = [], [], ''
    while parts and ':' in parts[0] and parts[0].split(':', 1)[0] in ('tag', 'set', 'interface'):
        k, v = parts.pop(0).split(':', 1)
        (tags if k == 'tag' else sets if k == 'set' else []).append(v)
        if k == 'interface':
            iface = v
    return tags, sets, iface, parts


def _parse_range(val):
    tags, sets, iface, parts = _split_prefixes(val)
    if not parts or not is_ipv4(parts[0]):
        return None
    start = parts[0]
    rest = parts[1:]
    if not rest or not is_ipv4(rest[0]):
        return None                                  # static / proxy / mode
    end = rest.pop(0)
    netmask = rest.pop(0) if rest and is_ipv4(rest[0]) else ''
    if rest and is_ipv4(rest[0]):
        rest.pop(0)                                  # broadcast: dnsmasq derives it
    lease = rest.pop(0) if rest and RE_LEASE.match(rest[0]) else '12h'
    if len(sets) > 1 or (sets and iface):
        return None
    return {'start': start, 'end': end, 'netmask': netmask, 'lease': lease,
            'tag': sets[0] if sets else '', 'interface': iface, 'comment': 'imported'}


def _parse_host(val):
    parts = [x.strip() for x in val.split(',') if x.strip()]
    mac = ip = hostname = tag = ''
    for p in parts:
        low = p.lower()
        if RE_MAC.match(low):
            mac = low
        elif p.startswith('set:'):
            tag = p[4:]
        elif p.startswith(('id:', 'tag:')) or p == 'ignore' or RE_LEASE.match(p) and p[-1] in 'smhdw':
            if p == 'ignore':
                return None
        elif is_ipv4(p):
            ip = p
        elif not hostname and not p.isdigit():
            hostname = p
    if not mac or not ip:
        return None
    return {'mac': mac, 'ip': ip, 'hostname': hostname, 'tag': tag, 'comment': 'imported'}


def _parse_option(val):
    tags, _sets, _iface, parts = _split_prefixes(val)
    if len(tags) > 1 or not parts:
        return None
    opt = parts[0]
    if opt.startswith(('encap:', 'vi-encap:', 'vendor:')):
        return None
    if opt.startswith('option:') or opt.startswith('option6:') or opt.isdigit():
        pass
    else:
        return None
    return {'tag': tags[0] if tags else '', 'option': opt,
            'value': ','.join(parts[1:]), 'comment': 'imported'}


def _parse_boot(val):
    tags, _s, _i, parts = _split_prefixes(val)
    if not parts or not parts[0]:
        return None
    filename = parts[0]
    server = ''
    for p in parts[1:]:
        if p and (is_ipv4(p) or '.' in p):
            server = p
    if not server:
        return None
    return {'name': os.path.basename(filename)[:64] or 'imported', 'filename': filename,
            'server': server, 'arches': [], 'comment': 'imported', 'enabled': True}


def scan_host():
    """Bare metal: the distro's own dnsmasq config (never the app's render
    dir). Returns (text, files_read)."""
    if SUPERVISE:
        return '', []
    paths = ['/etc/dnsmasq.conf'] + sorted(glob.glob('/etc/dnsmasq.d/*.conf'))
    ours = os.path.realpath(CONF_DIR)
    chunks, files = [], []
    for p in paths:
        if os.path.realpath(p).startswith(ours + os.sep):
            continue
        try:
            with open(p) as f:
                chunks.append('# --- %s\n%s' % (p, f.read()))
            files.append(p)
        except OSError:
            continue
    return '\n'.join(chunks), files


def _preview_from(data):
    text = str(data.get('text') or '')
    files = []
    if data.get('scan'):
        text, files = scan_host()
        if not files:
            return None, err('Nothing to scan: no readable /etc/dnsmasq.conf or /etc/dnsmasq.d/*.conf'
                             + (' (Docker mode)' if SUPERVISE else ''))
    if len(text) > MAX_TEXT:
        return None, err('Config too large (max 2 MB)')
    if not text.strip():
        return None, err('Paste a dnsmasq configuration or choose Scan')
    res = parse_conf_text(text)
    # addn-hosts files referenced by the config: fold their entries in.
    from .dns import parse_hosts_text
    for hf in res['hosts_files']:
        try:
            with open(hf) as f:
                entries, _sk, _inv = parse_hosts_text(f.read())
        except OSError:
            _skip(res, 'addn-hosts=%s' % hf, 'file not readable from here')
            continue
        for name, key, ip in entries:
            rec = next((h for h in res['hosts'] if h['name'] == name), None)
            if rec is None:
                rec = {'name': name, 'a': '', 'aaaa': '', 'comment': 'imported from %s' % hf}
                res['hosts'].append(rec)
            rec[key] = ip
    res['files'] = files
    return res, None


def _counts(res):
    return {'settings': len(res['settings']) + (1 if res['upstreams'] else 0),
            'hosts': len(res['hosts']),
            'dns': len(res['cnames']) + len(res['addresses']) + len(res['forwards']),
            'dhcp': len(res['ranges']) + len(res['static_leases']) + len(res['options']),
            'netboot': len(res['entries']), 'extra': len(res['extra']),
            'skipped': len(res['skipped'])}


@bp.route('/api/import/preview', methods=['POST'])
def import_preview():
    data, e = json_object()
    if e:
        return e
    res, e = _preview_from(data)
    if e:
        return e
    return jsonify({'success': True, 'counts': _counts(res), 'preview': res})


@bp.route('/api/import/apply', methods=['POST'])
def import_apply():
    from . import dns as dns_mod, dhcp as dhcp_mod, netboot as nb_mod, settings as settings_mod
    from .mirror import locked_error
    data, e = json_object()
    if e:
        return e
    res, e = _preview_from(data)
    if e:
        return e
    wanted = [s for s in (data.get('sections') or SECTIONS) if s in SECTIONS]
    replace = bool(data.get('replace'))
    for sec in ('hosts', 'dns', 'dhcp', 'netboot'):
        if sec in wanted:
            locked = locked_error(sec)
            if locked:
                return locked

    # Validate everything first, exactly as the interactive routes would.
    staged, problems = {}, []
    if 'settings' in wanted:
        s = dict(res['settings'])
        if res['upstreams']:
            s['upstreams'] = list(dict.fromkeys(res['upstreams']))
        delta, verr = settings_mod._validated(s)
        if verr:
            problems.append('settings: %s' % verr)
        staged['settings'] = delta or {}
    if 'hosts' in wanted:
        recs = []
        for raw in res['hosts']:
            rec, verr = dns_mod._validate('hosts', raw)
            (problems.append('host %s: %s' % (raw.get('name'), verr)) if verr else recs.append(rec))
        staged['hosts'] = recs
    if 'dns' in wanted:
        blk = {}
        for coll in ('cnames', 'addresses', 'forwards'):
            recs = []
            for raw in res[coll]:
                rec, verr = dns_mod._validate(coll, raw)
                (problems.append('%s %s: %s' % (coll, raw, verr)) if verr else recs.append(rec))
            blk[coll] = recs
        staged['dns'] = blk
    if 'dhcp' in wanted:
        blk = {}
        for coll in ('ranges', 'static_leases', 'options'):
            recs = []
            for raw in res[coll]:
                rec, verr = dhcp_mod._validate(coll, raw)
                (problems.append('%s %s: %s' % (coll, raw, verr)) if verr else recs.append(rec))
            blk[coll] = recs
        staged['dhcp'] = blk
    if 'netboot' in wanted:
        recs = []
        for raw in res['entries']:
            rec, verr = nb_mod._validate_entry(raw)
            (problems.append('netboot %s: %s' % (raw.get('filename'), verr)) if verr else recs.append(rec))
        staged['netboot'] = recs
    if 'extra' in wanted:
        staged['extra'] = '\n'.join(res['extra'])
    if problems and not data.get('skip_invalid'):
        return jsonify({'success': False, 'error': '%d line(s) failed validation — fix them, or '
                        'retry with skip_invalid to import the rest' % len(problems),
                        'problems': problems[:50]}), 422

    counts = {'added': 0, 'updated': 0, 'unchanged': 0}

    def _merge(existing, new, keyf, prefix):
        # Match on the natural key; a matched record is updated only when a
        # MATERIAL field differs (comment/enabled are the operator's, not the
        # import's — an existing disabled record stays disabled).
        soft = ('id', 'comment', 'enabled')
        out = [] if replace else list(existing)
        index = {keyf(r): r for r in out}
        for rec in new:
            k = keyf(rec)
            cur = index.get(k)
            if cur is None:
                rec['id'] = new_id(prefix)
                out.append(rec); index[k] = rec; counts['added'] += 1
            elif any(cur.get(x) != rec.get(x) for x in rec if x not in soft):
                merged = {**cur, **{x: rec[x] for x in rec if x not in soft}}
                out[out.index(cur)] = merged; index[k] = merged; counts['updated'] += 1
            else:
                counts['unchanged'] += 1
        return out

    def mutate():
        if 'settings' in staged or 'extra' in staged:
            st = load_store('settings')
            st.update(staged.get('settings', {}))
            if 'extra' in staged:
                cur = st.get('extra_options') or ''
                if replace or not cur.strip():
                    st['extra_options'] = staged['extra']
                else:
                    # Append only lines not already there: dnsmasq refuses a
                    # repeated single-value keyword, so re-importing must be
                    # a no-op rather than a duplicate.
                    have = {l.strip() for l in cur.splitlines()}
                    new = [l for l in staged['extra'].splitlines() if l.strip() not in have]
                    st['extra_options'] = cur.rstrip('\n') + ('\n' + '\n'.join(new) if new else '')
            save_store('settings', st)
        if 'hosts' in staged or 'dns' in staged:
            d = load_store('dns')
            if 'hosts' in staged:
                d['hosts'] = _merge(d['hosts'], staged['hosts'],
                                    lambda r: (r['name'].lower(), r.get('a'), r.get('aaaa')), 'h')
            if 'dns' in staged:
                d['cnames'] = _merge(d['cnames'], staged['dns']['cnames'], lambda r: r['alias'].lower(), 'c')
                d['addresses'] = _merge(d['addresses'], staged['dns']['addresses'],
                                        lambda r: (r['domain'].lower(), r['ip']), 'a')
                d['forwards'] = _merge(d['forwards'], staged['dns']['forwards'],
                                       lambda r: (r['domain'].lower(), r['upstream']), 'f')
            save_store('dns', d)
        if 'dhcp' in staged:
            h = load_store('dhcp')
            h['ranges'] = _merge(h['ranges'], staged['dhcp']['ranges'], lambda r: (r['start'], r['end']), 'r')
            h['static_leases'] = _merge(h['static_leases'], staged['dhcp']['static_leases'],
                                        lambda r: r['mac'], 's')
            h['options'] = _merge(h['options'], staged['dhcp']['options'],
                                  lambda r: (r.get('tag'), r['option']), 'o')
            save_store('dhcp', h)
        if 'netboot' in staged:
            nb = load_store('netboot')
            nb['entries'] = _merge(nb['entries'], staged['netboot'], lambda r: (r['filename'], r['server']), 'b')
            save_store('netboot', nb)

    sections = [s for s in ('hosts', 'dns', 'dhcp', 'netboot') if s in staged]
    r = apply_change(mutate, sections=sections or ['settings'])
    if isinstance(r, tuple):
        return r
    return jsonify({'success': True, **counts, 'problems': problems, 'imported': sorted(staged), **r})
