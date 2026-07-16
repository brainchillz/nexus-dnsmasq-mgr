"""CRUD round-trips through the API with the service controller stubbed."""


def test_dns_host_crud(client):
    r = client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    assert r.status_code == 200 and r.json['success']
    rid = r.json['id']
    assert r.json['action'] == 'reload'  # hosts edits are HUP-only

    r = client.get('/api/dns')
    assert any(h['id'] == rid for h in r.json['hosts'])

    r = client.post(f'/api/dns/hosts/{rid}', json={'name': 'nas.lan', 'a': '10.0.0.6'})
    assert r.json['success']

    r = client.delete(f'/api/dns/hosts/{rid}')
    assert r.json['success']
    assert client.get('/api/dns').json['hosts'] == []


def test_dns_host_validation(client):
    assert client.post('/api/dns/hosts', json={'name': 'bad name!', 'a': '10.0.0.5'}).status_code == 400
    assert client.post('/api/dns/hosts', json={'name': 'x.lan'}).status_code == 400  # no A/AAAA
    assert client.post('/api/dns/hosts', json={'name': 'x.lan', 'a': 'not-an-ip'}).status_code == 400
    # newline smuggling must never reach the rendered config
    assert client.post('/api/dns/addresses',
                       json={'domain': 'a.com\nport=0', 'ip': '0.0.0.0'}).status_code == 400


def test_dhcp_range_crud_and_restart_classification(client):
    client.post('/api/settings/toggles', json={'dhcp_enabled': True})
    r = client.post('/api/dhcp/ranges', json={'start': '10.0.0.100', 'end': '10.0.0.199',
                                              'netmask': '255.255.255.0', 'lease': '12h',
                                              'tag': 'lan'})
    assert r.json['success']
    assert r.json['action'] == 'restart'  # structural change

    # static lease edits ride the hostsfile -> HUP only
    r = client.post('/api/dhcp/static_leases', json={'mac': 'aa:bb:cc:dd:ee:ff',
                                                     'ip': '10.0.0.10', 'hostname': 'printer'})
    assert r.json['success']
    assert r.json['action'] == 'reload'


def test_dhcp_validation(client):
    client.post('/api/settings/toggles', json={'dhcp_enabled': True})
    bad = [
        {'start': '10.0.0.200', 'end': '10.0.0.100'},                      # end < start
        {'start': 'x', 'end': '10.0.0.100'},                               # bad ip
        {'start': '10.0.0.1', 'end': '10.0.0.2', 'lease': 'nope'},         # bad lease
        {'start': '10.0.0.1', 'end': '10.0.0.2', 'tag': 'a', 'interface': 'eth0'},  # both
    ]
    for body in bad:
        assert client.post('/api/dhcp/ranges', json=body).status_code == 400

    assert client.post('/api/dhcp/static_leases',
                       json={'mac': 'nope', 'ip': '10.0.0.1'}).status_code == 400
    r = client.post('/api/dhcp/static_leases', json={'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.0.0.3'})
    assert r.json['success']
    # duplicate MAC refused
    assert client.post('/api/dhcp/static_leases',
                       json={'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.0.0.4'}).status_code == 409


def test_settings_rollback_on_invalid_config(client):
    r = client.post('/api/settings', json={'extra_options': 'garbage-option=1'})
    assert r.status_code == 400
    assert 'bad option' in r.json['error']
    # rolled back — store unchanged
    assert client.get('/api/settings').json['extra_options'] == ''


def test_toggles(client):
    r = client.post('/api/settings/toggles', json={'dns_enabled': False})
    assert r.json['success'] and r.json['dns_enabled'] is False
    cfg = client.get('/api/dnsmasq/config').json['files']
    assert 'port=0' in cfg['dnsmasq.d/00-main.conf']
    r = client.post('/api/settings/toggles', json={'dns_enabled': True})
    assert 'port=0' not in client.get('/api/dnsmasq/config').json['files']['dnsmasq.d/00-main.conf']


def test_netboot_entry(client):
    r = client.post('/api/netboot/entries', json={'name': 'UEFI x64', 'arches': ['7'],
                                                  'filename': 'ipxe.efi'})
    assert r.json['success']
    assert client.post('/api/netboot/entries',
                       json={'name': 'bad', 'filename': '../etc/passwd;x'}).status_code == 400
    assert client.post('/api/netboot/settings',
                       json={'proxy_dhcp': True}).status_code == 400  # subnet required
