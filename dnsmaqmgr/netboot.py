"""Network boot: DHCP boot options and proxy-DHCP with arch-matched entries
(PXE BIOS / UEFI / HTTP boot via dhcp-match on option:client-arch). Points
clients at an external boot server (next-server) — the app hosts no TFTP."""
from flask import Blueprint, jsonify, request

from .core.runcmd import err, json_object
from .core.store import load_store, save_store, new_id, find_record
from .core.validators import (RE_ARCH, RE_BOOT_FILE, RE_COMMENT,
                              is_ipv4, valid_hostname_fqdn)
from .dnsmasq import apply_change, PXE_CSA
from .mirror import locked_error

bp = Blueprint('netboot', __name__)

MAX_ENTRY_NAME = 64


def _validate_entry(data):
    rec = {'enabled': bool(data.get('enabled', True)),
           'comment': str(data.get('comment') or '')}
    if not RE_COMMENT.match(rec['comment']):
        return None, 'Invalid comment'
    name = (data.get('name') or '').strip()
    if not name or len(name) > MAX_ENTRY_NAME or '\n' in name or '"' in name:
        return None, 'Invalid entry name'
    filename = (data.get('filename') or '').strip()
    if not RE_BOOT_FILE.match(filename):
        return None, 'Invalid boot filename'
    # The boot server (next-server) is required: the app hands clients a
    # filename to fetch from an EXTERNAL TFTP/HTTP server — it no longer runs
    # a TFTP server of its own, so there is nothing to fall back to.
    server = (data.get('server') or '').strip()
    if not server:
        return None, 'A boot server (next-server IP or hostname) is required'
    if not (is_ipv4(server) or valid_hostname_fqdn(server)):
        return None, 'Invalid boot server'
    arches = [str(a).strip() for a in (data.get('arches') or []) if str(a).strip() != '']
    for a in arches:
        if not RE_ARCH.match(a) or not 0 <= int(a) <= 255:
            return None, 'Invalid client architecture value'
    rec.update({'name': name, 'filename': filename, 'server': server, 'arches': arches})
    return rec, None


@bp.route('/api/netboot')
def netboot_get():
    nb = dict(load_store('netboot'))
    nb['arch_names'] = PXE_CSA
    return jsonify(nb)


@bp.route('/api/netboot/settings', methods=['POST'])
def netboot_settings():
    locked = locked_error('netboot')
    if locked:
        return locked
    data, e = json_object()
    if e:
        return e
    nb = load_store('netboot')
    if 'proxy_dhcp' in data:
        nb['proxy_dhcp'] = bool(data['proxy_dhcp'])
    if 'proxy_subnet' in data:
        subnet = (data['proxy_subnet'] or '').strip()
        if subnet and not is_ipv4(subnet):
            return err('Proxy subnet must be an IPv4 network address (e.g. 10.0.0.0)')
        nb['proxy_subnet'] = subnet
    if 'pxe_prompt' in data:
        prompt = str(data['pxe_prompt'] or '')
        if not RE_COMMENT.match(prompt):
            return err('Invalid PXE prompt')
        nb['pxe_prompt'] = prompt
    if nb.get('proxy_dhcp') and not nb.get('proxy_subnet'):
        return err('Proxy-DHCP needs a subnet')

    res = apply_change(lambda: save_store('netboot', nb), sections=['netboot'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, **res})


@bp.route('/api/netboot/entries', methods=['POST'])
def netboot_entry_add():
    locked = locked_error('netboot')
    if locked:
        return locked
    body, e = json_object()
    if e:
        return e
    rec, e = _validate_entry(body)
    if e:
        return err(e)
    rec['id'] = new_id('b')

    def mutate():
        nb = load_store('netboot')
        nb['entries'].append(rec)
        save_store('netboot', nb)

    res = apply_change(mutate, sections=['netboot'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, 'id': rec['id'], **res})


@bp.route('/api/netboot/entries/<rid>', methods=['POST'])
def netboot_entry_update(rid):
    locked = locked_error('netboot')
    if locked:
        return locked
    nb = load_store('netboot')
    existing = find_record(nb['entries'], rid)
    if not existing:
        return err('No such entry', 404)
    body, e = json_object()
    if e:
        return e
    # PARTIAL UPDATE: layer over the stored entry so an omitted field is kept.
    rec, e = _validate_entry({**existing, **body})
    if e:
        return err(e)
    rec['id'] = rid

    def mutate():
        nb2 = load_store('netboot')
        nb2['entries'] = [rec if it.get('id') == rid else it for it in nb2['entries']]
        save_store('netboot', nb2)

    res = apply_change(mutate, sections=['netboot'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, **res})


@bp.route('/api/netboot/entries/<rid>', methods=['DELETE'])
def netboot_entry_delete(rid):
    locked = locked_error('netboot')
    if locked:
        return locked
    nb = load_store('netboot')
    if not find_record(nb['entries'], rid):
        return err('No such entry', 404)

    def mutate():
        nb2 = load_store('netboot')
        nb2['entries'] = [it for it in nb2['entries'] if it.get('id') != rid]
        save_store('netboot', nb2)

    res = apply_change(mutate, sections=['netboot'])
    if isinstance(res, tuple):
        return res
    return jsonify({'success': True, **res})
