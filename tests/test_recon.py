"""Network recon: target selection, cross-referencing, and the scan API."""
import threading

from dnsmaqmgr import recon
from dnsmaqmgr.core.config import LEASES_FILE


def _write_leases(rows):
    with open(LEASES_FILE, 'w') as f:
        for mac, ip, host in rows:
            f.write('9999999999 %s %s %s *\n' % (mac, ip, host or '*'))


def test_scan_targets_from_own_config(client):
    client.post('/api/settings/toggles', json={'dhcp_enabled': True})
    client.post('/api/dhcp/ranges', json={'start': '10.0.0.100', 'end': '10.0.0.102'})
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    _write_leases([('aa:bb:cc:dd:ee:01', '10.0.0.200', 'laptop')])
    targets, truncated = recon.scan_targets()
    assert targets == ['10.0.0.5', '10.0.0.100', '10.0.0.101', '10.0.0.102', '10.0.0.200']
    assert truncated is False


def test_cross_reference():
    hosts = [
        {'id': 'h_1', 'name': 'nas.lan', 'a': '10.0.0.5', 'enabled': True},
        {'id': 'h_2', 'name': 'ghost.lan', 'a': '10.0.0.66', 'enabled': True,
         'comment': 'old vm'},
        {'id': 'h_3', 'name': 'nas.lan', 'a': '10.0.0.50', 'enabled': True},  # dup name
        {'id': 'h_4', 'name': 'off.lan', 'a': '10.0.0.99', 'enabled': False}, # disabled: ignored
    ]
    leases = [
        {'ip': '10.0.0.50', 'mac': 'aa:bb:cc:dd:ee:01', 'hostname': 'laptop'},
        {'ip': '10.0.0.51', 'mac': 'aa:bb:cc:dd:ee:02', 'hostname': ''},      # unnamed
        {'ip': '10.0.0.60', 'mac': 'aa:bb:cc:dd:ee:03', 'hostname': 'nas'},   # ip mismatch
    ]
    alive = {'10.0.0.5', '10.0.0.50', '10.0.0.51', '10.0.0.60'}
    neigh = {'10.0.0.51': 'aa:bb:cc:dd:ee:02', '10.0.0.77': 'aa:bb:cc:dd:ee:77'}
    settings = {'domain': 'lan', 'expand_hosts': True}

    r = recon.cross_reference(alive, neigh, hosts, leases, settings)

    unnamed_ips = {d['ip'] for d in r['unnamed_devices']}
    assert '10.0.0.51' in unnamed_ips          # live lease, no hostname
    assert '10.0.0.77' in unnamed_ips          # ARP-only device
    assert '10.0.0.50' not in unnamed_ips      # has a lease hostname
    assert '10.0.0.5' not in unnamed_ips       # has a host record

    assert [s['name'] for s in r['stale_records']] == ['ghost.lan']

    kinds = {(d['kind'], d['name']) for d in r['duplicates']}
    assert ('name_multiple_ips', 'nas.lan') in kinds
    # lease 'nas' expands to nas.lan which maps to 10.0.0.5/7, lease says .60
    assert any(k == 'record_lease_mismatch' for k, _ in kinds)


def test_scan_api_roundtrip(client, monkeypatch):
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    client.post('/api/dns/hosts', json={'name': 'ghost.lan', 'a': '10.0.0.66'})
    monkeypatch.setattr(recon, '_ping', lambda ip: ip == '10.0.0.5')
    monkeypatch.setattr(recon, 'neighbor_table',
                        lambda: {'10.0.0.5': 'aa:bb:cc:dd:ee:05'})

    r = client.post('/api/recon/scan', json={})
    assert r.json['success'] and r.json['targets'] == 2

    # conftest no-ops time.sleep, so wait on an Event for real wall-clock time
    pause = threading.Event()
    for _ in range(100):
        st = client.get('/api/recon').json
        if not st['running']:
            break
        pause.wait(0.05)
    assert not st['running']
    last = st['last']
    assert last['targets'] == 2 and last['alive'] == 1
    assert [s['name'] for s in last['stale_records']] == ['ghost.lan']
    assert last['unnamed_devices'] == []       # 10.0.0.5 has a record


def test_create_record_clears_unnamed_without_rescan(client):
    """The scan stores raw data and the report recomputes on read — naming a
    device (the '+ Create record' flow) removes it from the findings
    immediately, no rescan needed."""
    from dnsmaqmgr.core.store import save_store
    save_store('recon', {'last': {
        'ts': 1, 'duration': 0.5, 'targets': 3, 'truncated': False,
        'alive_ips': ['192.168.35.248'],
        'neigh': {'192.168.35.248': 'aa:bb:cc:dd:ee:48'}}})

    st = client.get('/api/recon').json
    assert [d['ip'] for d in st['last']['unnamed_devices']] == ['192.168.35.248']
    assert st['last']['unnamed_devices'][0]['mac'] == 'aa:bb:cc:dd:ee:48'

    r = client.post('/api/dns/hosts', json={'name': 'switch-rack1.lan',
                                            'a': '192.168.35.248',
                                            'comment': 'network — core switch'})
    assert r.json['success']

    st = client.get('/api/recon').json
    assert st['last']['unnamed_devices'] == []
    assert st['last']['targets'] == 3      # scan metadata carried through


def test_scan_requires_targets(client):
    assert client.post('/api/recon/scan', json={}).status_code == 400


def test_neighbor_table_parsing(monkeypatch):
    out = ('192.168.35.74 dev eno1 lladdr aa:bb:cc:dd:ee:74 REACHABLE\n'
           '192.168.35.75 dev eno1 lladdr aa:bb:cc:dd:ee:75 STALE\n'
           '192.168.35.76 dev eno1  FAILED\n'
           '192.168.35.77 dev eno1 lladdr aa:bb:cc:dd:ee:77 INCOMPLETE\n')
    monkeypatch.setattr(recon, 'run', lambda *a, **k: (out, '', 0))
    n = recon.neighbor_table()
    assert n == {'192.168.35.74': 'aa:bb:cc:dd:ee:74',
                 '192.168.35.75': 'aa:bb:cc:dd:ee:75'}