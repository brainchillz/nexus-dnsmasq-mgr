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


def test_status_reports_sources(client):
    headers = _arm_mirror(client)
    client.post('/api/mirror/receive', json=_payload(serial=7), headers=headers)
    st = client.get('/api/mirror/status').json
    assert st['accept'] is True
    assert 'hosts' in st['locked']
    assert st['sources']['primary1']['serial'] == 7
