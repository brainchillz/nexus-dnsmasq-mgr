"""Mirror receive-side behavior: token auth, serial replay guard, section
locking, payload re-validation."""
import hashlib


def _arm_mirror(client, token='dmm_test-token-abc'):
    from dnsmaqmgr.core.store import load_store, save_store
    s = load_store('settings')
    s['mirror_accept'] = True
    s['mirror_token_hash'] = hashlib.sha256(token.encode()).hexdigest()
    save_store('settings', s)
    return {'Authorization': 'Bearer %s' % token, 'Content-Type': 'application/json'}


def _payload(serial=1, hosts=None):
    return {'source': 'primary1', 'serial': serial, 'sections': ['hosts'],
            'data': {'hosts': hosts or [
                {'id': 'h_aaaaaa', 'name': 'm.lan', 'a': '10.0.0.9', 'enabled': True, 'comment': ''}]}}


def test_receive_requires_accept_and_token(client):
    r = client.post('/api/mirror/receive', json=_payload())
    assert r.status_code == 403  # accept off

    headers = _arm_mirror(client)
    r = client.post('/api/mirror/receive', json=_payload(),
                    headers={'Authorization': 'Bearer wrong'})
    assert r.status_code == 401

    r = client.post('/api/mirror/receive', json=_payload(), headers=headers)
    assert r.status_code == 200 and r.json['success']
    assert client.get('/api/dns').json['hosts'][0]['name'] == 'm.lan'


def test_replay_guard_and_lock(client):
    headers = _arm_mirror(client)
    assert client.post('/api/mirror/receive', json=_payload(serial=5), headers=headers).status_code == 200
    # older serial refused
    assert client.post('/api/mirror/receive', json=_payload(serial=4), headers=headers).status_code == 409
    # equal serial accepted (idempotent manual re-sync)
    assert client.post('/api/mirror/receive', json=_payload(serial=5), headers=headers).status_code == 200

    # mirrored section is read-only locally
    r = client.post('/api/dns/hosts', json={'name': 'local.lan', 'a': '10.9.9.9'})
    assert r.status_code == 409
    assert 'mirrored from' in r.json['error']

    # detach unlocks
    assert client.post('/api/mirror/sources/primary1/detach', json={}).json['success']
    assert client.post('/api/dns/hosts', json={'name': 'local.lan', 'a': '10.9.9.9'}).status_code == 200


def test_receive_revalidates_records(client):
    headers = _arm_mirror(client)
    evil = _payload(hosts=[{'id': 'h_bbbbbb', 'name': 'x.lan\nport=0', 'a': '10.0.0.9',
                            'enabled': True, 'comment': ''}])
    r = client.post('/api/mirror/receive', json=evil, headers=headers)
    assert r.status_code == 422


def test_receive_refuses_duplicate_static_lease_macs_and_ips(client):
    """dnsmasq refuses to start on a duplicate dhcp-host MAC or IP and --test
    does not catch it. The UI routes already guard this; the mirror path (which
    a peer's re-push also travels) must not be the one way to deliver a store
    that kills dnsmasq at its next restart."""
    headers = _arm_mirror(client)

    def dhcp_payload(leases, serial=1):
        return {'source': 'primary1', 'serial': serial, 'sections': ['dhcp'],
                'data': {'dhcp': {'ranges': [], 'options': [],
                                  'static_leases': leases}}}

    dup_mac = [{'mac': 'aa:bb:cc:00:00:01', 'ip': '10.0.0.10', 'hostname': 'a'},
               {'mac': 'aa:bb:cc:00:00:01', 'ip': '10.0.0.11', 'hostname': 'b'}]
    r = client.post('/api/mirror/receive', json=dhcp_payload(dup_mac), headers=headers)
    assert r.status_code == 422 and 'duplicate MAC' in r.json['error']

    dup_ip = [{'mac': 'aa:bb:cc:00:00:01', 'ip': '10.0.0.10', 'hostname': 'a'},
              {'mac': 'aa:bb:cc:00:00:02', 'ip': '10.0.0.10', 'hostname': 'b'}]
    r = client.post('/api/mirror/receive', json=dhcp_payload(dup_ip), headers=headers)
    assert r.status_code == 422 and 'duplicate IP' in r.json['error']

    # A refused push must not have advanced the serial or touched the store.
    assert client.get('/api/dhcp').json.get('static_leases', []) == []

    # Repeated hostnames are the UI's courtesy check, not a restart-killer —
    # a mirror source may legitimately push two scopes whose FQDNs share a
    # first label.
    ok = [{'mac': 'aa:bb:cc:00:00:01', 'ip': '10.0.0.10', 'hostname': 'web'},
          {'mac': 'aa:bb:cc:00:00:02', 'ip': '10.0.0.11', 'hostname': 'web'}]
    r = client.post('/api/mirror/receive', json=dhcp_payload(ok), headers=headers)
    assert r.status_code == 200, r.json
    assert len(client.get('/api/dhcp').json['static_leases']) == 2


def test_status_reports_sources(client):
    headers = _arm_mirror(client)
    client.post('/api/mirror/receive', json=_payload(serial=7), headers=headers)
    st = client.get('/api/mirror/status').json
    assert st['accept'] is True
    assert 'hosts' in st['locked']
    assert st['sources']['primary1']['serial'] == 7


def test_mirror_receive_pushes_downstream_only_peers(client, monkeypatch):
    """A mirror-received apply must still update loop-safe downstream peers
    (UniFi local DNS renders our hosts) while never re-pushing to dnsmaq
    peers (that is the A->B->A loop guard)."""
    from dnsmaqmgr import peers, dnsmasq as dm

    calls = []
    monkeypatch.setattr(peers, 'push_all',
                        lambda sections, downstream_only=False:
                        calls.append((tuple(sections), downstream_only)))

    class SyncThread:            # run the push inline so the test can assert
        def __init__(self, target, args=(), daemon=None):
            self._t, self._a = target, args
        def start(self):
            self._t(*self._a)
    monkeypatch.setattr(dm.threading, 'Thread', SyncThread)

    headers = _arm_mirror(client)
    r = client.post('/api/mirror/receive', json=_payload(), headers=headers)
    assert r.status_code == 200
    assert calls == [(('hosts',), True)]      # pushed, downstream-only

    # ...and an ordinary local apply (hosts is mirror-locked now, so use an
    # unlocked section) still pushes to everyone.
    calls.clear()
    r = client.post('/api/dns/addresses', json={'domain': 'ads.example', 'ip': '0.0.0.0'})
    assert r.status_code == 200
    assert calls and calls[0][1] is False


def test_push_all_downstream_filter(monkeypatch):
    from dnsmaqmgr import peers
    from dnsmaqmgr.core.store import load_store, save_store
    cfg = load_store('peers')
    cfg['peers'] = [{'name': 'mirror2', 'kind': 'dnsmaq', 'enabled': True},
                    {'name': 'gw', 'kind': 'unifi', 'enabled': True},
                    {'name': 'gw-off', 'kind': 'unifi', 'enabled': False}]
    save_store('peers', cfg)
    pushed = []
    monkeypatch.setattr(peers, 'push_to_peer',
                        lambda peer, sections: pushed.append(peer['name']))
    peers.push_all(['hosts'], downstream_only=True)
    assert pushed == ['gw']
    pushed.clear()
    peers.push_all(['hosts'])
    assert pushed == ['mirror2', 'gw']
