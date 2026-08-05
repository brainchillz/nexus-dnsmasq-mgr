"""Full-state backup / restore round-trips and validation."""
import copy

from dnsmaqmgr import blocklists as bl


def _populate(client, monkeypatch):
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    client.post('/api/dns/addresses', json={'domain': 'ads.example.com', 'ip': '0.0.0.0'})
    client.post('/api/settings/toggles', json={'dhcp_enabled': True})
    client.post('/api/dhcp/ranges', json={'start': '10.0.0.100', 'end': '10.0.0.199',
                                          'netmask': '255.255.255.0'})
    client.post('/api/dhcp/static_leases', json={'mac': 'aa:bb:cc:dd:ee:ff',
                                                 'ip': '10.0.0.10', 'hostname': 'printer'})
    monkeypatch.setattr(bl, 'fetch_list_text', lambda url: 'blocked.example.com\n')
    client.post('/api/blocklists', json={'name': 'mylist', 'url': 'https://x.example/h'})


def test_backup_roundtrip(client, monkeypatch):
    _populate(client, monkeypatch)
    # restore kicks a background refetch thread; keep the test deterministic
    monkeypatch.setattr(bl, 'refresh_due', lambda: None)
    b = client.get('/api/backup').json
    assert b['app'] == 'dnsmaq-mgr'
    assert 'accounts' not in b
    assert len(b['stores']['dns']['hosts']) == 1
    host_id = b['stores']['dns']['hosts'][0]['id']

    # wreck the live config, then restore
    client.delete('/api/dns/hosts/%s' % host_id)
    client.post('/api/settings', json={'domain': 'other', 'no_hosts': True})
    assert client.get('/api/dns').json['hosts'] == []

    r = client.post('/api/backup/restore', json={'backup': b})
    assert r.status_code == 200 and r.json['success']
    assert 'dns' in r.json['restored'] and 'settings' in r.json['restored']
    assert r.json['blocklists_refreshing'] is True

    d = client.get('/api/dns').json
    assert d['hosts'][0]['name'] == 'nas.lan' and d['hosts'][0]['id'] == host_id
    s = client.get('/api/settings').json
    assert s['domain'] == 'lan' and s['no_hosts'] is False
    h = client.get('/api/dhcp').json
    assert h['static_leases'][0]['mac'] == 'aa:bb:cc:dd:ee:ff'
    lists = client.get('/api/blocklists').json['lists']
    assert lists[0]['name'] == 'mylist'
    # domains data is not in the backup — the list is queued for a refetch
    assert lists[0]['last_fetch'] == 0

    cfg = client.get('/api/dnsmasq/config').json['files']
    assert '10.0.0.5 nas.lan' in cfg['hosts.d/managed-hosts']
    assert 'address=/ads.example.com/0.0.0.0' in cfg['dnsmasq.d/10-dns.conf']


def test_restore_rejects_tampered_backup_atomically(client, monkeypatch):
    _populate(client, monkeypatch)
    b = client.get('/api/backup').json
    before_hosts = client.get('/api/dns').json['hosts']

    evil = copy.deepcopy(b)
    evil['stores']['dns']['hosts'][0]['name'] = 'evil\nport=0'
    r = client.post('/api/backup/restore', json={'backup': evil})
    assert r.status_code == 422
    assert 'nothing restored' in r.json['error']
    assert client.get('/api/dns').json['hosts'] == before_hosts

    # duplicate static-lease MACs would brick dnsmasq at restart, not --test
    evil = copy.deepcopy(b)
    lease = dict(evil['stores']['dhcp']['static_leases'][0], ip='10.0.0.11',
                 hostname='other', id='s_aaaaaa')
    evil['stores']['dhcp']['static_leases'].append(lease)
    assert client.post('/api/backup/restore', json={'backup': evil}).status_code == 422


def test_restore_rejects_non_backup(client):
    assert client.post('/api/backup/restore', json={'backup': {'app': 'x'}}).status_code == 422
    assert client.post('/api/backup/restore', json={}).status_code == 422
    assert client.post('/api/backup/restore',
                       json={'backup': {'app': 'dnsmaq-mgr'}}).status_code == 422


def test_backup_accounts_optional_and_validated(client, monkeypatch):
    from dnsmaqmgr.core import auth
    cfg = {'secret_key': 'k',
           'users': {'admin': {'password': 'hash', 'role': 'admin'},
                     'viewer': {'password': 'hash2', 'role': 'readonly'}},
           'tokens': []}
    monkeypatch.setattr(auth, 'load_config', lambda: cfg)
    saved = {}
    monkeypatch.setattr(auth, 'save_config', lambda c: saved.update(c))
    import dnsmaqmgr.backup as backup_mod
    monkeypatch.setattr(backup_mod, 'load_config', auth.load_config)
    monkeypatch.setattr(backup_mod, 'save_config', auth.save_config)

    b = client.get('/api/backup?include_accounts=1').json
    assert set(b['accounts']['users']) == {'admin', 'viewer'}

    # restore WITHOUT accounts: auth untouched
    r = client.post('/api/backup/restore', json={'backup': b})
    assert r.json['success'] and r.json['accounts_restored'] is False
    assert not saved

    # restore WITH accounts
    r = client.post('/api/backup/restore', json={'backup': b, 'include_accounts': True})
    assert r.json['accounts_restored'] is True
    assert set(saved['users']) == {'admin', 'viewer'}
    assert saved['secret_key'] == 'k'      # session secret preserved

    # a backup with no admin left must be refused
    b2 = copy.deepcopy(b)
    b2['accounts']['users'] = {'viewer': {'password': 'h', 'role': 'readonly'}}
    r = client.post('/api/backup/restore', json={'backup': b2, 'include_accounts': True})
    assert r.status_code == 422 and 'administrator' in r.json['error']
