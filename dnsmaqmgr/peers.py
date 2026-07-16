"""Mirror push side: peers are other DNSMAQ-MGR instances this node pushes
config to over their HTTPS API (Authorization: Bearer <peer token>).

TLS verification per peer: 'system' CAs, 'insecure', or certificate
fingerprint pinning (sha256 of the DER cert) — the right fit for
self-signed fleets. Pushes fire automatically from apply_change (background
thread) and manually via Sync now."""
import json
import ssl
import time
import socket
import hashlib
import http.client
import threading
import urllib.parse
from flask import Blueprint, jsonify, request

from .core.runcmd import err
from .core.store import STORE_LOCK, load_store, save_store, new_id
from .core.validators import RE_FINGERPRINT, RE_SOURCE, RE_URL
from .mirror import SECTIONS

bp = Blueprint('peers', __name__)

PUSH_TIMEOUT = 10
_push_lock = threading.Lock()  # serialize pushes so status updates don't race


def build_payload(sections):
    """Assemble the mirror payload for the given sections from local stores."""
    sections = [x for x in sections if x in SECTIONS]
    dns = load_store('dns')
    dhcp = load_store('dhcp')
    netboot = load_store('netboot')
    settings = load_store('settings')
    data, serial = {}, 0
    if 'hosts' in sections:
        data['hosts'] = dns['hosts']
        serial = max(serial, int(dns.get('serial', 0)))
    if 'dns' in sections:
        data['dns'] = {'cnames': dns['cnames'], 'addresses': dns['addresses'],
                       'forwards': dns['forwards'], 'upstreams': settings.get('upstreams', [])}
        serial = max(serial, int(dns.get('serial', 0)), int(settings.get('serial', 0)))
    if 'dhcp' in sections:
        data['dhcp'] = {'ranges': dhcp['ranges'], 'static_leases': dhcp['static_leases'],
                        'options': dhcp['options']}
        serial = max(serial, int(dhcp.get('serial', 0)))
    if 'netboot' in sections:
        nb = dict(netboot)
        nb.pop('serial', None)
        data['netboot'] = nb
        serial = max(serial, int(netboot.get('serial', 0)))
    return {'source': socket.gethostname() or 'dnsmaq-mgr', 'serial': serial,
            'sections': sections, 'data': data}


def _split_url(url):
    u = urllib.parse.urlparse(url)
    if u.scheme != 'https' or not u.hostname:
        raise ValueError('Peer URL must be https://host[:port]')
    return u.hostname, u.port or 8443


def _ssl_context(verify):
    if verify == 'system':
        return ssl.create_default_context()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_json(url, path, body, token, verify):
    """POST to a peer, honoring its TLS verify mode. Returns (status, json)."""
    host, port = _split_url(url)
    conn = http.client.HTTPSConnection(host, port, timeout=PUSH_TIMEOUT,
                                       context=_ssl_context(verify))
    try:
        conn.connect()
        if verify.startswith('fingerprint:'):
            der = conn.sock.getpeercert(binary_form=True)
            got = hashlib.sha256(der or b'').hexdigest()
            if got != verify.split(':', 1)[1]:
                raise ssl.SSLError('peer certificate fingerprint mismatch (got %s)' % got[:16])
        conn.request('POST', path, body=json.dumps(body),
                     headers={'Content-Type': 'application/json',
                              'Authorization': 'Bearer %s' % token})
        r = conn.getresponse()
        text = r.read().decode(errors='replace')
        try:
            return r.status, json.loads(text)
        except ValueError:
            return r.status, {'error': text[:300]}
    finally:
        conn.close()


def push_to_peer(peer, sections):
    """Push the requested sections (intersected with the peer's subscription)
    to one peer; updates the peer's last_sync/last_status in the store."""
    wanted = [x for x in sections if x in peer.get('sections', [])]
    status = None
    if not wanted:
        return None
    payload = build_payload(wanted)
    try:
        code, body = _post_json(peer['url'], '/api/mirror/receive', payload,
                                peer['token'], peer.get('verify', 'system'))
        if code == 200 and body.get('success'):
            status = 'ok'
        else:
            status = 'error: %s' % (body.get('error') or 'HTTP %s' % code)
    except Exception as e:
        status = 'error: %s' % e
    with STORE_LOCK:
        cfg = load_store('peers')
        for p in cfg['peers']:
            if p['id'] == peer['id']:
                p['last_sync'] = int(time.time())
                p['last_status'] = status
                if status == 'ok':
                    p['last_serial'] = payload['serial']
        save_store('peers', cfg)
    return status


def push_all(sections):
    """Push to every enabled peer. Called in a background thread after apply."""
    with _push_lock:
        cfg = load_store('peers')
        for peer in cfg.get('peers', []):
            if peer.get('enabled', True):
                push_to_peer(peer, sections)


def _public(p):
    out = dict(p)
    out['token'] = bool(p.get('token'))  # never echo the secret back
    return out


def _validate_peer(data, existing=None):
    name = (data.get('name') or '').strip()
    url = (data.get('url') or '').strip().rstrip('/')
    token = (data.get('token') or '').strip()
    verify = (data.get('verify') or 'system').strip()
    sections = [x for x in (data.get('sections') or []) if x in SECTIONS]
    if not RE_SOURCE.match(name):
        return None, 'Invalid peer name'
    if not RE_URL.match(url):
        return None, 'Peer URL must be https://host[:port]'
    if not sections:
        return None, 'Choose at least one section to mirror'
    if verify not in ('system', 'insecure') and not (
            verify.startswith('fingerprint:') and RE_FINGERPRINT.match(verify[12:])):
        return None, 'Invalid TLS verification mode'
    if not token and not (existing and existing.get('token')):
        return None, 'Peer mirror token required'
    rec = {'name': name, 'url': url, 'sections': sections, 'verify': verify,
           'enabled': bool(data.get('enabled', True)),
           'token': token or existing.get('token'),
           'last_sync': (existing or {}).get('last_sync'),
           'last_status': (existing or {}).get('last_status'),
           'last_serial': (existing or {}).get('last_serial')}
    return rec, None


@bp.route('/api/peers')
def peers_list():
    return jsonify({'peers': [_public(p) for p in load_store('peers')['peers']]})


@bp.route('/api/peers', methods=['POST'])
def peers_add():
    rec, e = _validate_peer(request.get_json() or {})
    if e:
        return err(e)
    rec['id'] = new_id('p')
    cfg = load_store('peers')
    cfg['peers'].append(rec)
    save_store('peers', cfg)
    return jsonify({'success': True, 'id': rec['id']})


@bp.route('/api/peers/<pid>', methods=['POST'])
def peers_update(pid):
    cfg = load_store('peers')
    existing = next((p for p in cfg['peers'] if p['id'] == pid), None)
    if not existing:
        return err('No such peer', 404)
    rec, e = _validate_peer(request.get_json() or {}, existing=existing)
    if e:
        return err(e)
    rec['id'] = pid
    cfg['peers'] = [rec if p['id'] == pid else p for p in cfg['peers']]
    save_store('peers', cfg)
    return jsonify({'success': True})


@bp.route('/api/peers/<pid>', methods=['DELETE'])
def peers_delete(pid):
    cfg = load_store('peers')
    before = len(cfg['peers'])
    cfg['peers'] = [p for p in cfg['peers'] if p['id'] != pid]
    if len(cfg['peers']) == before:
        return err('No such peer', 404)
    save_store('peers', cfg)
    return jsonify({'success': True})


@bp.route('/api/peers/<pid>/sync', methods=['POST'])
def peers_sync(pid):
    peer = next((p for p in load_store('peers')['peers'] if p['id'] == pid), None)
    if not peer:
        return err('No such peer', 404)
    status = push_to_peer(peer, peer.get('sections', []))
    if status != 'ok':
        return err(status or 'Nothing to push', 502)
    return jsonify({'success': True, 'status': status})


@bp.route('/api/peers/fetch-fingerprint', methods=['POST'])
def peers_fetch_fingerprint():
    """Fetch a candidate cert fingerprint so the UI can offer 'pin this cert'."""
    url = ((request.get_json() or {}).get('url') or '').strip().rstrip('/')
    if not RE_URL.match(url):
        return err('URL must be https://host[:port]')
    try:
        host, port = _split_url(url)
        ctx = _ssl_context('insecure')
        with socket.create_connection((host, port), timeout=PUSH_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        fp = hashlib.sha256(der or b'').hexdigest()
        return jsonify({'success': True, 'fingerprint': fp})
    except Exception as e:
        return err('Could not fetch certificate: %s' % e, 502)
