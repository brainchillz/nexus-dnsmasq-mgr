"""Mirror push side: peers are targets this node pushes config to.

Two kinds:

* 'dnsmaq' (default) — another DNSMAQ-MGR instance, over its HTTPS API
  (Authorization: Bearer <peer token>). Any section can be mirrored.
* 'unifi' — a UniFi Cloud Gateway, whose Static DNS is reconciled against our
  host records by the unifi adapter. Only the 'hosts' section maps; UniFi has
  no analogue for DHCP or netboot, and cannot receive or lock sections, so a
  UniFi peer is push-only.

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

from . import unifi
from .core.runcmd import err
from .core.store import STORE_LOCK, load_store, save_store, new_id
from .core.validators import RE_FINGERPRINT, RE_SOURCE, RE_URL
from .mirror import SECTIONS

bp = Blueprint('peers', __name__)

PUSH_TIMEOUT = 10
KINDS = ('dnsmaq', 'unifi')
# UniFi Static DNS holds address records only; nothing else has an analogue.
UNIFI_SECTIONS = ('hosts',)
_push_lock = threading.Lock()  # serialize pushes so status updates don't race


def build_payload(sections):
    """Assemble the mirror payload for the given sections from local stores.

    Carries a PER-SECTION serial map (`serials`) alongside the legacy scalar
    `serial` (the max). Each store has an independent counter, so a single
    scalar can't tell a stale dhcp push from a fresh one when the dns counter
    happens to lead — the receiver compares per section."""
    sections = [x for x in sections if x in SECTIONS]
    with STORE_LOCK:            # one consistent cross-store snapshot
        dns = load_store('dns')
        dhcp = load_store('dhcp')
        netboot = load_store('netboot')
        settings = load_store('settings')
    data, serials = {}, {}
    if 'hosts' in sections:
        data['hosts'] = dns['hosts']
        serials['hosts'] = int(dns.get('serial', 0))
    if 'dns' in sections:
        data['dns'] = {'cnames': dns['cnames'], 'addresses': dns['addresses'],
                       'forwards': dns['forwards'], 'upstreams': settings.get('upstreams', [])}
        serials['dns'] = max(int(dns.get('serial', 0)), int(settings.get('serial', 0)))
    if 'dhcp' in sections:
        data['dhcp'] = {'ranges': dhcp['ranges'], 'static_leases': dhcp['static_leases'],
                        'options': dhcp['options']}
        serials['dhcp'] = int(dhcp.get('serial', 0))
    if 'netboot' in sections:
        nb = dict(netboot)
        nb.pop('serial', None)
        data['netboot'] = nb
        serials['netboot'] = int(netboot.get('serial', 0))
    serial = max(serials.values()) if serials else 0
    return {'source': socket.gethostname() or 'dnsmaq-mgr', 'serial': serial,
            'serials': serials, 'sections': sections, 'data': data}


def _split_url(url, default_port=8443):
    u = urllib.parse.urlparse(url)
    if u.scheme != 'https' or not u.hostname:
        raise ValueError('Peer URL must be https://host[:port]')
    return u.hostname, u.port or default_port


def default_port_for(kind):
    """DNSMAQ-MGR listens on 8443; a UniFi gateway's UniFi OS API is on 443."""
    return 443 if kind == 'unifi' else 8443


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


def _unifi_client(peer):
    """Connect and authenticate to a gateway. Patched out in tests."""
    session = unifi.HttpsSession(peer['url'], peer.get('verify', 'system'),
                                 timeout=PUSH_TIMEOUT)
    client = unifi.UniFiClient(session, peer.get('unifi_site') or 'default')
    client.login(peer.get('unifi_username') or '', peer.get('unifi_password') or '')
    return client


def _push_unifi(peer):
    """Reconcile a gateway's Static DNS with the host store.

    Returns (status, serial). Only the host store is involved, so the serial
    reported is the DNS store's.
    """
    dns = load_store('dns')
    serial = int(dns.get('serial', 0))
    client = None
    try:
        client = _unifi_client(peer)
        summary = unifi.sync_hosts(peer, dns.get('hosts', []), client=client)
        return unifi.status_line(summary), serial
    except Exception as e:
        return 'error: %s' % e, serial
    finally:
        if client is not None:
            client.logout()


def push_to_peer(peer, sections):
    """Push the requested sections (intersected with the peer's subscription)
    to one peer; updates the peer's last_sync/last_status in the store."""
    wanted = [x for x in sections if x in peer.get('sections', [])]
    if not wanted:
        return None

    if peer.get('kind') == 'unifi':
        status, serial = _push_unifi(peer)
    else:
        payload = build_payload(wanted)
        serial = payload['serial']
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
                    p['last_serial'] = serial
        save_store('peers', cfg)
    return status


def push_all(sections, downstream_only=False):
    """Push to every enabled peer. Called in a background thread after apply.

    downstream_only limits the push to peers that can never push back
    (kind 'unifi' — a gateway's local DNS records are a pure renderer).
    Mirror-received applies use it: skipping peers entirely there (the old
    behaviour) is what prevents A→B→A loops, but it also left UniFi peers
    stale whenever this node's data arrives BY mirror — e.g. a secondary
    mirroring hosts onward to a gateway, or an upstream IPAM feeding this
    node. Loop-safe peers can and should still be brought up to date."""
    with _push_lock:
        cfg = load_store('peers')
        for peer in cfg.get('peers', []):
            if not peer.get('enabled', True):
                continue
            if downstream_only and peer.get('kind', 'dnsmaq') != 'unifi':
                continue
            push_to_peer(peer, sections)


def _public(p):
    out = dict(p)
    out['token'] = bool(p.get('token'))  # never echo the secret back
    if 'unifi_password' in out:
        out['unifi_password'] = bool(p.get('unifi_password'))
    out.setdefault('kind', 'dnsmaq')
    return out


def _validate_peer(data, existing=None):
    name = (data.get('name') or '').strip()
    url = (data.get('url') or '').strip().rstrip('/')
    kind = (data.get('kind') or (existing or {}).get('kind') or 'dnsmaq').strip()
    verify = (data.get('verify') or 'system').strip()
    sections = [x for x in (data.get('sections') or []) if x in SECTIONS]
    if not RE_SOURCE.match(name):
        return None, 'Invalid peer name'
    if kind not in KINDS:
        return None, 'Unknown peer type'
    if not RE_URL.match(url):
        return None, 'Peer URL must be https://host[:port]'
    if not sections:
        return None, 'Choose at least one section to mirror'
    if verify not in ('system', 'insecure') and not (
            verify.startswith('fingerprint:') and RE_FINGERPRINT.match(verify[12:])):
        return None, 'Invalid TLS verification mode'

    rec = {'name': name, 'url': url, 'kind': kind, 'sections': sections,
           'verify': verify, 'enabled': bool(data.get('enabled', True)),
           'last_sync': (existing or {}).get('last_sync'),
           'last_status': (existing or {}).get('last_status'),
           'last_serial': (existing or {}).get('last_serial')}

    if kind == 'unifi':
        username = (data.get('unifi_username') or '').strip()
        password = (data.get('unifi_password') or '').strip()
        site = (data.get('unifi_site') or 'default').strip()
        kept = (existing or {}).get('unifi_password')
        if [x for x in sections if x not in UNIFI_SECTIONS]:
            return None, 'A UniFi gateway can only mirror the hosts section'
        if not username:
            return None, 'Gateway username required'
        if not password and not kept:
            return None, 'Gateway password required'
        if not RE_SOURCE.match(site):
            return None, 'Invalid UniFi site name'
        rec.update({'unifi_username': username, 'unifi_password': password or kept,
                    'unifi_site': site,
                    # Default OFF: a sync is additive unless the operator opts in
                    # to reconciliation, so a first sync never silently deletes
                    # pre-existing gateway Static DNS entries it did not create.
                    'unifi_delete_extra': bool(data.get('unifi_delete_extra', False)),
                    'unifi_claim_client_dns': bool(data.get('unifi_claim_client_dns'))})
        return rec, None

    token = (data.get('token') or '').strip()
    if not token and not (existing and existing.get('token')):
        return None, 'Peer mirror token required'
    rec['token'] = token or existing.get('token')
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
    data = request.get_json() or {}
    url = (data.get('url') or '').strip().rstrip('/')
    kind = (data.get('kind') or 'dnsmaq').strip()
    if not RE_URL.match(url):
        return err('URL must be https://host[:port]')
    try:
        host, port = _split_url(url, default_port_for(kind))
        ctx = _ssl_context('insecure')
        with socket.create_connection((host, port), timeout=PUSH_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        fp = hashlib.sha256(der or b'').hexdigest()
        return jsonify({'success': True, 'fingerprint': fp})
    except Exception as e:
        return err('Could not fetch certificate: %s' % e, 502)
