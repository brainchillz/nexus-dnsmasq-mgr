"""DNS overrides: host records (the hosts-file payload), CNAMEs, domain
overrides (address=/dom/ip) and domain forwards (server=/dom/upstream)."""
from flask import Blueprint, jsonify, request

from .core.runcmd import err, json_object
from .core.store import load_store, save_store, new_id, find_record
from .core.validators import (RE_COMMENT, RE_DOMAIN, is_ipv4, is_ipv6,
                              is_upstream, valid_hostname_fqdn)
from .dnsmasq import apply_change
from .mirror import locked_error

bp = Blueprint('dns', __name__)

COLLS = ('hosts', 'cnames', 'addresses', 'forwards')


def _common(data):
    """Validate the fields shared by every record type."""
    rec = {'enabled': bool(data.get('enabled', True)),
           'comment': str(data.get('comment') or '')}
    if not RE_COMMENT.match(rec['comment']):
        return None, 'Invalid comment'
    return rec, None


def _validate(coll, data):
    rec, e = _common(data)
    if e:
        return None, e
    if coll == 'hosts':
        name = (data.get('name') or '').strip()
        a = (data.get('a') or '').strip()
        aaaa = (data.get('aaaa') or '').strip()
        if not valid_hostname_fqdn(name):
            return None, 'Invalid hostname'
        if not a and not aaaa:
            return None, 'At least one of A (IPv4) or AAAA (IPv6) is required'
        if a and not is_ipv4(a):
            return None, 'Invalid IPv4 address'
        if aaaa and not is_ipv6(aaaa):
            return None, 'Invalid IPv6 address'
        rec.update({'name': name, 'a': a, 'aaaa': aaaa})
    elif coll == 'cnames':
        alias = (data.get('alias') or '').strip()
        target = (data.get('target') or '').strip()
        if not valid_hostname_fqdn(alias) or not valid_hostname_fqdn(target):
            return None, 'Invalid alias or target'
        rec.update({'alias': alias, 'target': target})
    elif coll == 'addresses':
        domain = (data.get('domain') or '').strip()
        ip = (data.get('ip') or '').strip()
        if not RE_DOMAIN.match(domain):
            return None, 'Invalid domain'
        if not (is_ipv4(ip) or is_ipv6(ip)):
            return None, 'Invalid IP address'
        rec.update({'domain': domain, 'ip': ip})
    elif coll == 'forwards':
        domain = (data.get('domain') or '').strip()
        upstream = (data.get('upstream') or '').strip()
        if not RE_DOMAIN.match(domain):
            return None, 'Invalid domain'
        if not is_upstream(upstream):
            return None, 'Invalid upstream (use IP or IP#port)'
        rec.update({'domain': domain, 'upstream': upstream})
    return rec, None


def _section(coll):
    return 'hosts' if coll == 'hosts' else 'dns'


@bp.route('/api/dns')
def dns_get():
    return jsonify(load_store('dns'))


# Names every stock hosts file carries that nobody wants imported.
BOILERPLATE_NAMES = {
    'localhost', 'localhost.localdomain', 'localhost4', 'localhost6',
    'broadcasthost', 'ip6-localhost', 'ip6-loopback', 'ip6-localnet',
    'ip6-mcastprefix', 'ip6-allnodes', 'ip6-allrouters', 'ip6-allhosts',
}
MAX_IMPORT_BYTES = 2_000_000


def parse_hosts_text(text, skip_boilerplate=True):
    """Parse standard unix hosts-file text into (entries, skipped, invalid).
    entries: [(name, 'a'|'aaaa', ip)] — one per name, aliases included."""
    entries, skipped, invalid = [], 0, 0
    for raw_line in text.splitlines():
        line = raw_line.split('#', 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            invalid += 1
            continue
        ip = parts[0]
        if is_ipv4(ip):
            key = 'a'
        elif is_ipv6(ip):
            key = 'aaaa'
        else:
            invalid += 1
            continue
        for name in parts[1:]:
            name = name.rstrip('.')
            if skip_boilerplate and name.lower() in BOILERPLATE_NAMES:
                skipped += 1
                continue
            if not valid_hostname_fqdn(name):
                invalid += 1
                continue
            entries.append((name, key, ip))
    return entries, skipped, invalid


@bp.route('/api/dns/import', methods=['POST'])
def dns_import():
    """Import a standard unix hosts file into the host-records store.
    Merge mode updates records with a matching name; replace mode swaps the
    whole list. One validate+apply cycle for the entire import."""
    locked = locked_error('hosts')
    if locked:
        return locked
    data = request.get_json() or {}
    text = str(data.get('text') or '')
    if not text.strip():
        return err('Nothing to import')
    if len(text) > MAX_IMPORT_BYTES:
        return err('Import too large (max 2 MB)')
    replace = bool(data.get('replace'))
    entries, skipped, invalid = parse_hosts_text(
        text, skip_boilerplate=bool(data.get('skip_boilerplate', True)))
    if not entries:
        return err('No usable host entries found (%d invalid, %d boilerplate skipped)'
                   % (invalid, skipped))

    counts = {'added': 0, 'updated': 0, 'unchanged': 0,
              'skipped': skipped, 'invalid': invalid}

    def mutate():
        d = load_store('dns')
        hosts = [] if replace else list(d['hosts'])
        by_name = {h['name']: h for h in hosts}
        for name, key, ip in entries:
            rec = by_name.get(name)
            if rec is None:
                rec = {'id': new_id('h'), 'name': name, 'a': '', 'aaaa': '',
                       'enabled': True, 'comment': 'imported'}
                rec[key] = ip
                hosts.append(rec)
                by_name[name] = rec
                counts['added'] += 1
            elif rec.get(key) != ip:
                rec[key] = ip
                counts['updated'] += 1
            else:
                counts['unchanged'] += 1
        d['hosts'] = hosts
        save_store('dns', d)

    res = apply_change(mutate, sections=['hosts'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, **counts, **res})


@bp.route('/api/dns/<coll>', methods=['POST'])
def dns_add(coll):
    if coll not in COLLS:
        return err('Unknown collection', 404)
    locked = locked_error(_section(coll))
    if locked:
        return locked
    body, e = json_object()
    if e:
        return e
    rec, e = _validate(coll, body)
    if e:
        return err(e)
    rec['id'] = new_id(coll[0])

    def mutate():
        d = load_store('dns')
        d[coll].append(rec)
        save_store('dns', d)

    res = apply_change(mutate, sections=[_section(coll)])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, 'id': rec['id'], **res})


@bp.route('/api/dns/<coll>/<rid>', methods=['POST'])
def dns_update(coll, rid):
    if coll not in COLLS:
        return err('Unknown collection', 404)
    locked = locked_error(_section(coll))
    if locked:
        return locked
    d = load_store('dns')
    existing = find_record(d[coll], rid)
    if not existing:
        return err('No such record', 404)
    body, e = json_object()
    if e:
        return e
    # PARTIAL UPDATE: layer the request over the stored record so an omitted
    # field keeps its value — an update that only sends `a` no longer wipes
    # `aaaa`/`comment` or flips a disabled record back to enabled.
    rec, e = _validate(coll, {**existing, **body})
    if e:
        return err(e)
    rec['id'] = rid

    def mutate():
        d2 = load_store('dns')
        d2[coll] = [rec if it.get('id') == rid else it for it in d2[coll]]
        save_store('dns', d2)

    res = apply_change(mutate, sections=[_section(coll)])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, **res})


@bp.route('/api/dns/<coll>/<rid>', methods=['DELETE'])
def dns_delete(coll, rid):
    if coll not in COLLS:
        return err('Unknown collection', 404)
    locked = locked_error(_section(coll))
    if locked:
        return locked
    d = load_store('dns')
    if not find_record(d[coll], rid):
        return err('No such record', 404)

    def mutate():
        d2 = load_store('dns')
        d2[coll] = [it for it in d2[coll] if it.get('id') != rid]
        save_store('dns', d2)

    res = apply_change(mutate, sections=[_section(coll)])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, **res})
