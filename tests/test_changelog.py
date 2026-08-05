"""Change history: recording, identity, diffs, rollback, pruning."""
from dnsmaqmgr import changelog


def test_changes_are_recorded_with_identity(client):
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    r = client.get('/api/changelog')
    entries = r.json['entries']
    assert len(entries) == 1
    e = entries[0]
    assert e['user'] == 'admin'
    assert e['sections'] == ['hosts']
    assert e['action'] == 'reload'
    assert e['counts']['hosts'] == 1


def test_diff_between_entries(client):
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    rid = client.get('/api/dns').json['hosts'][0]['id']
    client.post('/api/dns/hosts/%s' % rid, json={'a': '10.0.0.6'})

    entries = client.get('/api/changelog').json['entries']   # newest first
    assert len(entries) == 2
    d = client.get('/api/changelog/%s/diff' % entries[0]['id']).json
    assert d['against'] == entries[1]['id']
    hosts_diff = d['diffs']['hosts.d/managed-hosts']
    assert '-10.0.0.5 nas.lan' in hosts_diff
    assert '+10.0.0.6 nas.lan' in hosts_diff

    # oldest entry has nothing before it
    d0 = client.get('/api/changelog/%s/diff' % entries[1]['id']).json
    assert d0['first'] is True


def test_rollback_restores_and_is_recorded(client):
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    first = client.get('/api/changelog').json['entries'][0]['id']
    serial_after_first = client.get('/api/dns').json['serial']

    rid = client.get('/api/dns').json['hosts'][0]['id']
    client.post('/api/dns/hosts/%s' % rid, json={'a': '10.0.0.6'})
    assert client.get('/api/dns').json['hosts'][0]['a'] == '10.0.0.6'

    r = client.post('/api/changelog/%s/rollback' % first, json={})
    assert r.status_code == 200 and r.json['success']

    d = client.get('/api/dns').json
    assert d['hosts'][0]['a'] == '10.0.0.5'
    # serial moved FORWARD despite content moving back (mirror staleness)
    assert d['serial'] > serial_after_first
    # the rollback itself is a new history entry
    entries = client.get('/api/changelog').json['entries']
    assert len(entries) == 3
    # rendered config actually rolled back too
    cfg = client.get('/api/dnsmasq/config').json['files']
    assert '10.0.0.5 nas.lan' in cfg['hosts.d/managed-hosts']


def test_rollback_unknown_entry(client):
    assert client.post('/api/changelog/0000000000000-abcdef/rollback',
                       json={}).status_code == 404
    assert client.get('/api/changelog/../../etc/passwd/diff').status_code == 404


def test_prune_keeps_last_n(client, monkeypatch):
    monkeypatch.setattr(changelog, 'CHANGELOG_KEEP', 3)
    for i in range(5):
        client.post('/api/dns/hosts', json={'name': 'h%d.lan' % i, 'a': '10.0.0.%d' % (10 + i)})
    entries = client.get('/api/changelog').json['entries']
    assert len(entries) == 3
    assert entries[0]['counts']['hosts'] == 5   # newest snapshot intact


def test_noise_entries_skipped():
    """action 'none' with unchanged config stores (e.g. a blocklist refresh
    that fetched identical data) must not clutter the timeline."""
    stores = {'settings': {'serial': 1}, 'dns': {'serial': 1, 'hosts': []},
              'dhcp': {'serial': 1}, 'netboot': {'serial': 1},
              'blocklists': {'serial': 1, 'lists': [{'id': 'l_1', 'last_fetch': 1}]}}
    after = {**stores, 'blocklists': {'serial': 2, 'lists': [{'id': 'l_1', 'last_fetch': 999}]}}
    changelog.record(sections=['blocklists'], action='none', changed=[],
                     before=stores, after=after, rendered={})
    assert changelog._entry_ids() == []
