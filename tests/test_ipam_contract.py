"""Contract test for the NexusIPAM → node push path and the SSO path.

NexusIPAM is a mirror SOURCE: it POSTs `hosts` (and `dhcp`, `netboot`) to
/api/mirror/receive with a per-section serial map, and reads DHCP state back
with a read-only API token. These tests replay exactly that shape so any
change to the receiver, the auth guard, rollback or restore that would break
the integration fails here first. The SSO half pins the public callback and
the /api/me hint an issuer-enrolled node relies on.
"""
import hashlib

import pytest

TOKEN = 'dmm_ipam-contract-token'
SOURCE = 'nexus-ipam'


def _arm(client):
    from dnsmaqmgr.core.store import load_store, save_store
    s = load_store('settings')
    s['mirror_accept'] = True
    s['mirror_token_hash'] = hashlib.sha256(TOKEN.encode()).hexdigest()
    save_store('settings', s)
    return {'Authorization': 'Bearer %s' % TOKEN}


def ipam_payload(serials=None, hosts=None):
    """What pushout.push_target() sends for a three-section target."""
    serials = serials or {'hosts': 39, 'dhcp': 22, 'netboot': 1}
    return {
        'source': SOURCE,
        'serial': max(serials.values()),
        'serials': dict(serials),
        'sections': sorted(serials),
        'data': {
            'hosts': hosts if hosts is not None else [
                {'id': 'h_1a2b3c', 'name': 'nas.lan', 'comment': 'storage',
                 'enabled': True, 'a': '10.0.0.5', 'aaaa': ''},
                {'id': 'h_4d5e6f', 'name': 'nas.lan', 'comment': '',
                 'enabled': True, 'a': '', 'aaaa': 'fd00::5'},
                {'name': 'printer.lan', 'comment': '', 'enabled': True,
                 'a': '10.0.0.6', 'aaaa': ''},          # no id → node mints one
            ],
            'dhcp': {
                'ranges': [{'start': '10.0.0.100', 'end': '10.0.0.199',
                            'netmask': '255.255.255.0', 'lease': '12h',
                            'tag': 'lan', 'enabled': True, 'comment': 'lan'}],
                'static_leases': [{'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.0.0.7',
                                   'hostname': 'cam1'}],
                'options': [{'tag': 'lan', 'option': 'option:router', 'value': '10.0.0.1'},
                            {'tag': 'lan', 'option': 'option:dns-server',
                             'value': '10.0.0.2,10.0.0.3'}],
            },
            'netboot': {'entries': [{'name': 'lan', 'filename': 'netboot.xyz.kpxe',
                                     'server': '10.0.0.20', 'arches': [],
                                     'enabled': True, 'comment': 'PXE for lan'}]},
        },
    }


def _readonly_token(client):
    r = client.post('/api/tokens', json={'name': 'ipam-ro', 'role': 'readonly'})
    assert r.status_code == 200, r.json
    return {'Authorization': 'Bearer %s' % r.json['token']}


@pytest.fixture
def real_auth(monkeypatch):
    """Token tests need the real auth file, not the conftest stub."""
    from dnsmaqmgr.core import auth
    monkeypatch.setattr(auth, '_users',
                        lambda: auth.load_config().get('users', {}))
    auth.save_config({'users': {'admin': {'password': 'x', 'role': 'admin'}}})


def test_ipam_push_applies_locks_and_keeps_ids(client):
    headers = _arm(client)
    r = client.post('/api/mirror/receive', json=ipam_payload(), headers=headers)
    assert r.status_code == 200 and r.json['success'], r.json
    assert r.json['applied_sections'] == ['dhcp', 'hosts', 'netboot']

    st = client.get('/api/mirror/status').json
    assert st['locked'] == ['dhcp', 'hosts', 'netboot']
    src = st['sources'][SOURCE]
    assert src['serials'] == {'hosts': 39, 'dhcp': 22, 'netboot': 1}
    assert src['serial'] == 39

    hosts = client.get('/api/dns').json['hosts']
    assert [h['id'] for h in hosts[:2]] == ['h_1a2b3c', 'h_4d5e6f']   # round-trip gate
    assert hosts[2]['id'].startswith('h_')
    dhcp = client.get('/api/dhcp').json
    assert dhcp['ranges'][0]['tag'] == 'lan'
    assert dhcp['static_leases'][0]['mac'] == 'aa:bb:cc:dd:ee:01'
    assert client.get('/api/netboot').json['entries'][0]['server'] == '10.0.0.20'

    cfg = client.get('/api/dnsmasq/config').json['files']
    assert '10.0.0.5 nas.lan' in cfg['hosts.d/managed-hosts']
    assert 'fd00::5 nas.lan' in cfg['hosts.d/managed-hosts']


def test_ipam_repush_is_idempotent_and_stale_is_refused(client):
    headers = _arm(client)
    assert client.post('/api/mirror/receive', json=ipam_payload(), headers=headers).status_code == 200
    # "push now" from IPAM re-sends the same serials: must apply, not 409.
    r = client.post('/api/mirror/receive', json=ipam_payload(), headers=headers)
    assert r.status_code == 200 and r.json['action'] == 'none'
    # A lower serial for ONE section refuses the whole push, others untouched.
    r = client.post('/api/mirror/receive',
                    json=ipam_payload({'hosts': 38, 'dhcp': 22, 'netboot': 1}),
                    headers=headers)
    assert r.status_code == 409 and 'hosts' in r.json['error']
    assert client.get('/api/mirror/status').json['sources'][SOURCE]['serials']['hosts'] == 39
    # A higher serial advances it.
    r = client.post('/api/mirror/receive',
                    json=ipam_payload({'hosts': 40, 'dhcp': 22, 'netboot': 1}),
                    headers=headers)
    assert r.status_code == 200
    assert client.get('/api/mirror/status').json['sources'][SOURCE]['serials']['hosts'] == 40


def test_ipam_locks_block_local_edits_but_not_node_local_settings(client):
    headers = _arm(client)
    assert client.post('/api/mirror/receive', json=ipam_payload(), headers=headers).status_code == 200
    assert client.post('/api/dns/hosts', json={'name': 'x.lan', 'a': '10.0.0.9'}).status_code == 409
    assert client.post('/api/dhcp/ranges', json={'start': '10.0.1.1', 'end': '10.0.1.9'}).status_code == 409
    assert client.post('/api/netboot/settings', json={'pxe_prompt': 'x'}).status_code == 409
    # `dns` is NOT pushed by IPAM, so node-local resolver settings stay editable.
    assert client.post('/api/settings', json={'upstreams': ['9.9.9.9']}).status_code == 200
    assert client.post('/api/dns/cnames', json={'alias': 'www.lan', 'target': 'nas.lan'}).status_code == 200


def test_ipam_readonly_token_reads_dhcp_state(client, real_auth):
    headers = _arm(client)
    assert client.post('/api/mirror/receive', json=ipam_payload(), headers=headers).status_code == 200
    ro = _readonly_token(client)
    with client.session_transaction() as sess:
        sess.clear()                       # token only, no cookie
    assert client.get('/api/dhcp', headers=ro).status_code == 200
    r = client.get('/api/dhcp/leases', headers=ro)
    assert r.status_code == 200 and 'leases' in r.json
    assert client.get('/api/mirror/status', headers=ro).status_code == 200
    # read-only means read-only
    assert client.post('/api/dns/cnames', json={'alias': 'a.lan', 'target': 'b.lan'},
                       headers=ro).status_code == 403
    # and the mirror token is never a read credential
    assert client.get('/api/dhcp', headers=headers).status_code == 401


def test_rollback_and_restore_cannot_desync_a_mirrored_node(client, monkeypatch):
    """A node fed by IPAM must never silently revert what IPAM pushed, nor lose
    its mirror token/locks: IPAM only re-pushes on content change."""
    from dnsmaqmgr import blocklists as bl
    monkeypatch.setattr(bl, 'refresh_due', lambda: None)
    # local change first, so there is an older changelog entry to roll back to
    client.post('/api/dns/cnames', json={'alias': 'old.lan', 'target': 'nas.lan'})
    backup = client.get('/api/backup').json
    headers = _arm(client)
    assert client.post('/api/mirror/receive', json=ipam_payload(), headers=headers).status_code == 200
    before = client.get('/api/mirror/status').json
    oldest = client.get('/api/changelog').json['entries'][-1]['id']

    r = client.post('/api/changelog/%s/rollback' % oldest, json={})
    assert r.status_code == 409, r.json
    r = client.post('/api/backup/restore', json={'backup': backup})
    assert r.status_code == 409, r.json

    after = client.get('/api/mirror/status').json
    assert after == before
    assert client.get('/api/dns').json['hosts'][0]['id'] == 'h_1a2b3c'
    # IPAM's next push still lands
    assert client.post('/api/mirror/receive', json=ipam_payload(), headers=headers).status_code == 200


# ─── SSO relying-party surface ───────────────────────────────────────────

def test_sso_callback_and_me_hint_surface(client, monkeypatch):
    """The issuer only knows two things about this node: /sso/callback is
    public, and /api/me tells the login screen whether to offer SSO."""
    from dnsmaqmgr.core import sso
    # unconfigured: callback is a 404, /api/me carries no hint
    with client.session_transaction() as sess:
        sess.clear()
    assert client.get('/sso/callback?a=x').status_code == 404
    r = client.get('/api/me')
    assert r.status_code == 401 and 'sso' not in r.json

    # configured: callback is reachable WITHOUT a session and a bad assertion
    # bounces to the login screen rather than erroring
    monkeypatch.setattr(sso, 'SSO_ISSUER', 'https://sso.example')
    monkeypatch.setattr(sso, 'SSO_PUBKEY', 'A' * 43)     # 32 bytes once decoded
    r = client.get('/api/me')
    assert r.status_code == 401 and r.json['sso']['issuer'] == 'https://sso.example'
    r = client.get('/sso/callback?a=not.a.token&next=//evil')
    assert r.status_code == 302 and r.headers['Location'].endswith('/?sso_error=1')
