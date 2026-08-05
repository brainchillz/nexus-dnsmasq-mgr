"""Alerts: config validation, condition checks, delivery formats, cooldowns."""
import json

from dnsmaqmgr import alerts
from dnsmaqmgr.core.config import LEASES_FILE
from dnsmaqmgr.core.store import load_store, save_store


def _write_leases(rows):
    with open(LEASES_FILE, 'w') as f:
        for expiry, mac, ip, host in rows:
            f.write('%d %s %s %s *\n' % (expiry, mac, ip, host or '*'))


def _arm(client, **over):
    body = {'enabled': True, 'webhook_url': 'https://alerts.example/hook', **over}
    r = client.post('/api/alerts', json=body)
    assert r.json['success']


def test_config_validation(client):
    assert client.post('/api/alerts', json={'enabled': True}).status_code == 400  # no URL
    assert client.post('/api/alerts', json={'webhook_url': 'ftp://x'}).status_code == 400
    assert client.post('/api/alerts', json={'format': 'pigeon'}).status_code == 400
    assert client.post('/api/alerts', json={'pool_threshold': 10}).status_code == 400
    _arm(client, format='ntfy', pool_threshold=85, cert_days=30)
    cfg = client.get('/api/alerts').json
    assert cfg['enabled'] and cfg['format'] == 'ntfy' and cfg['pool_threshold'] == 85


def test_new_device_baseline_then_alert(client, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, 'deliver', lambda cfg, e, t, m: (sent.append((e, m)), (True, 'ok'))[1])
    # only the new_device check — keeps the tick from probing DNS/cert state
    _arm(client, events={'new_device': True, 'pool_high': False,
                         'service_down': False, 'cert_expiry': False})
    _write_leases([(9999999999, 'aa:bb:cc:dd:ee:01', '10.0.0.50', 'laptop')])
    alerts.tick()                       # first tick baselines silently
    assert sent == []
    assert load_store('alerts_state')['baseline_done'] is True

    _write_leases([(9999999999, 'aa:bb:cc:dd:ee:01', '10.0.0.50', 'laptop'),
                   (9999999999, 'aa:bb:cc:dd:ee:99', '10.0.0.51', 'intruder')])
    alerts.tick()
    assert len(sent) == 1
    assert sent[0][0] == 'new_device' and 'aa:bb:cc:dd:ee:99' in sent[0][1]

    alerts.tick()                       # now known — no repeat
    assert len(sent) == 1
    recent = client.get('/api/alerts').json['recent']
    assert recent and recent[0]['event'] == 'new_device' and recent[0]['delivered']


def test_pool_high_with_hysteresis(client, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, 'deliver', lambda cfg, e, t, m: (sent.append((e, m)), (True, 'ok'))[1])
    _arm(client, events={'new_device': False, 'pool_high': True,
                         'service_down': False, 'cert_expiry': False})
    client.post('/api/settings/toggles', json={'dhcp_enabled': True})
    client.post('/api/dhcp/ranges', json={'start': '10.0.0.100', 'end': '10.0.0.103',
                                          'tag': 'lan'})
    _write_leases([(9999999999, 'aa:bb:cc:dd:ee:%02x' % i, '10.0.0.10%d' % i, '')
                   for i in range(4)])   # 4/4 = 100%
    alerts.tick()
    assert len(sent) == 1 and sent[0][0] == 'pool_high' and '100' in sent[0][1]
    alerts.tick()                        # still full — hysteresis holds
    assert len(sent) == 1


def test_service_restart_detection(monkeypatch):
    from dnsmaqmgr import stats, dnsmasq as dm

    class _Up:
        def status(self):
            return {'running': True, 'state': 'active'}

    monkeypatch.setattr(dm, '_controller', _Up())
    state = {'counter_sum': 1000}
    monkeypatch.setattr(stats, 'collect_dns_counters',
                        lambda: {'hits': 10, 'misses': 5, 'insertions': 5,
                                 'evictions': 0, 'cachesize': 150})
    found = alerts._check_service(state, {'dns_enabled': True})
    assert len(found) == 1 and 'restarted' in found[0][2]
    assert state['counter_sum'] == 20
    assert alerts._check_service(state, {'dns_enabled': True}) == []


def test_cert_expiry_check(monkeypatch):
    monkeypatch.setattr(alerts, 'cert_info',
                        lambda: {'present': True, 'expires': 'Aug 10 12:00:00 2026 GMT'})
    found = alerts._check_cert({'cert_days': 14})
    assert len(found) == 1 and found[0][1] == 'cert_expiry'
    assert alerts._check_cert({'cert_days': 2}) == []


class _FakeResponse:
    status = 200
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def test_deliver_formats(monkeypatch):
    reqs = []
    monkeypatch.setattr(alerts.urllib.request, 'urlopen',
                        lambda req, timeout=0: (reqs.append(req), _FakeResponse())[1])
    base = {'webhook_url': 'https://x.example/hook'}

    ok, _ = alerts.deliver({**base, 'format': 'generic'}, 'test', 'Title', 'Msg')
    assert ok
    body = json.loads(reqs[-1].data)
    assert body['event'] == 'test' and body['message'] == 'Msg'

    alerts.deliver({**base, 'format': 'ntfy'}, 'service_down', 'Down', 'gone')
    assert reqs[-1].get_header('Title') == 'Down'
    assert reqs[-1].get_header('Priority') == 'high'
    assert b'gone' in reqs[-1].data

    alerts.deliver({**base, 'format': 'slack'}, 'test', 'Title', 'Msg')
    assert 'text' in json.loads(reqs[-1].data)


def test_test_endpoint(client, monkeypatch):
    assert client.post('/api/alerts/test', json={}).status_code == 400  # no URL yet
    _arm(client, enabled=False)
    monkeypatch.setattr(alerts, 'deliver', lambda *a: (True, 'HTTP 200'))
    assert client.post('/api/alerts/test', json={}).json['success']
    monkeypatch.setattr(alerts, 'deliver', lambda *a: (False, 'boom'))
    assert client.post('/api/alerts/test', json={}).status_code == 502
