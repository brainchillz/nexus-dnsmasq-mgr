"""Encrypted DNS upstream: proxy TOML render, dnsmasq render integration
(fail-closed vs fallback), config validation, API flow, alerts, query-log
labelling, lookup attribution, backup round-trip."""
import os
import copy

import pytest

from dnsmaqmgr import encdns
from dnsmaqmgr import dnsmasq as dm
from dnsmaqmgr.core.config import ENCDNS_CONF, RENDER_DIR
from dnsmaqmgr.core.store import DEFAULTS, load_store, save_store


def _cfg(**kw):
    c = copy.deepcopy(DEFAULTS['encdns'])
    c.update(kw)
    return c


def _settings(**kw):
    s = copy.deepcopy(DEFAULTS['settings'])
    s.update(kw)
    return s


@pytest.fixture(autouse=True)
def _clean_encdns():
    yield
    encdns._proxy = None
    if os.path.exists(ENCDNS_CONF):
        os.remove(ENCDNS_CONF)


class FakeProxy:
    mode, name = 'encdns-child', 'dnscrypt-proxy'

    def __init__(self, running=False):
        self.running = running
        self.starts = self.restarts = 0

    def status(self):
        return {'running': self.running,
                'state': 'active' if self.running else 'stopped',
                'pid': 4242 if self.running else None}

    def start(self):
        self.running = True
        self.starts += 1
        return True, ''

    def restart(self):
        self.running = True
        self.restarts += 1
        return True, ''

    def stop(self):
        self.running = False

    def logs(self, lines=200):
        return ''


def _stub_proxy(monkeypatch, running=False, healthy=True):
    fake = FakeProxy(running)
    monkeypatch.setattr(encdns, '_proxy', fake)
    monkeypatch.setattr(encdns, 'binary_path', lambda: '/usr/sbin/dnscrypt-proxy')
    monkeypatch.setattr(encdns, 'check_proxy_config', lambda text: (True, 'ok'))
    monkeypatch.setattr(encdns, 'probe', lambda port, timeout=2.0: healthy)
    return fake


# ─── Proxy TOML rendering ─────────────────────────────────────────────

def test_proxy_toml_direct():
    text = encdns.render_proxy_config(_cfg(enabled=True, providers=['quad9', 'cloudflare']))
    assert "listen_addresses = ['127.0.0.1:5335']" in text
    assert "'quad9-doh-ip4-port443-filter-pri'" in text
    assert "'cloudflare'" in text
    assert 'doh_servers = true' in text
    assert '[anonymized_dns]' not in text
    assert '[sources.relays]' not in text
    assert 'cache = false' in text            # dnsmasq caches, not the proxy
    assert "cache_file = '" in text


def test_proxy_toml_relay():
    text = encdns.render_proxy_config(_cfg(enabled=True, mode='relay',
                                           providers=['quad9', 'cloudflare'],
                                           relays=['anon-cs-fr', 'anon-serbica']))
    assert 'doh_servers = false' in text      # anonymized routing is DNSCrypt-only
    assert "'quad9-dnscrypt-ip4-filter-pri'" in text
    assert "'cloudflare'" not in text         # no DNSCrypt resolver -> dropped
    assert '[sources.relays]' in text
    assert "via=['anon-cs-fr', 'anon-serbica']" in text


def test_proxy_toml_pre21_compat():
    """Ubuntu 24.04 ships dnscrypt-proxy 2.0.45; unknown TOML keys are fatal,
    so the render must speak that generation's dialect."""
    old = encdns.render_proxy_config(_cfg(enabled=True, providers=['quad9']),
                                     version='2.0.45')
    assert 'fallback_resolvers =' in old
    assert 'bootstrap_resolvers' not in old
    assert 'odoh_servers' not in old
    new = encdns.render_proxy_config(_cfg(enabled=True, providers=['quad9']),
                                     version='2.1.8')
    assert 'bootstrap_resolvers =' in new and 'odoh_servers = false' in new
    # unknown version → current dialect
    assert 'bootstrap_resolvers =' in encdns.render_proxy_config(
        _cfg(enabled=True, providers=['quad9']))


def test_proxy_toml_custom_servers_and_port():
    text = encdns.render_proxy_config(_cfg(enabled=True, providers=[],
                                           custom_servers=['my-resolver'],
                                           listen_port=5399))
    assert "listen_addresses = ['127.0.0.1:5399']" in text
    assert "server_names = ['my-resolver']" in text


# ─── dnsmasq render integration ───────────────────────────────────────

def test_render_main_fail_closed():
    text = dm.render_main(_settings(no_resolv=False), _cfg(enabled=True))
    assert 'server=127.0.0.1#5335' in text
    assert 'server=1.1.1.1' not in text       # plain upstreams dropped
    assert 'server=9.9.9.9' not in text
    assert 'no-resolv' in text                # forced: resolv.conf is a leak path
    assert 'strict-order' not in text


def test_render_main_fallback_plain():
    text = dm.render_main(_settings(), _cfg(enabled=True, fallback_plain=True))
    assert 'server=127.0.0.1#5335' in text
    assert 'server=1.1.1.1' in text
    assert 'strict-order' in text
    # proxy line must come first so strict-order tries it before the plain ones
    assert text.index('server=127.0.0.1#5335') < text.index('server=1.1.1.1')


def test_render_main_disabled_is_unchanged():
    assert dm.render_main(_settings()) == dm.render_main(_settings(), _cfg())


# ─── Validation ───────────────────────────────────────────────────────

def test_validate_config():
    base = _cfg()
    ok, e = encdns.validate_config({'enabled': True, 'providers': ['quad9']}, base)
    assert e is None and ok['enabled']
    assert encdns.validate_config({'mode': 'carrier-pigeon'}, base)[1]
    assert encdns.validate_config({'providers': ['nsa']}, base)[1]
    assert encdns.validate_config({'custom_servers': ["bad'name"]}, base)[1]
    assert encdns.validate_config({'relays': ['x\ny']}, base)[1]
    assert encdns.validate_config({'listen_port': 53}, base)[1]       # privileged
    assert encdns.validate_config({'enabled': True, 'providers': []}, base)[1]
    # relay mode: needs relays, and needs a DNSCrypt-capable resolver
    assert encdns.validate_config({'enabled': True, 'mode': 'relay',
                                   'providers': ['quad9']}, base)[1]
    assert encdns.validate_config({'enabled': True, 'mode': 'relay',
                                   'providers': ['cloudflare'],
                                   'relays': ['anon-cs-fr']}, base)[1]
    ok, e = encdns.validate_config({'enabled': True, 'mode': 'relay',
                                    'providers': ['quad9'],
                                    'relays': ['anon-cs-fr']}, base)
    assert e is None


# ─── API flow ─────────────────────────────────────────────────────────

def _main_conf():
    with open(os.path.join(RENDER_DIR, 'dnsmasq.d/00-main.conf')) as f:
        return f.read()


def test_api_enable_then_disable(client, monkeypatch):
    fake = _stub_proxy(monkeypatch)
    r = client.post('/api/encdns', json={'enabled': True, 'providers': ['quad9']})
    assert r.json['success'] and r.json['action'] == 'restart'
    assert fake.running and fake.starts == 1
    assert 'quad9-doh-ip4-port443-filter-pri' in open(ENCDNS_CONF).read()
    conf = _main_conf()
    assert 'server=127.0.0.1#5335' in conf and 'server=1.1.1.1' not in conf

    st = client.get('/api/encdns').json
    assert st['enabled'] and st['status']['running'] and st['status']['healthy']

    # plain upstream edits while encrypted must NOT leak into the render
    r = client.post('/api/settings', json={'upstreams': ['8.8.8.8']})
    assert r.json['success']
    assert 'server=8.8.8.8' not in _main_conf()

    r = client.post('/api/encdns', json={'enabled': False})
    assert r.json['success']
    assert not fake.running
    conf = _main_conf()
    assert 'server=127.0.0.1#5335' not in conf and 'server=8.8.8.8' in conf


def test_api_enable_needs_binary(client, monkeypatch):
    monkeypatch.setattr(encdns, 'binary_path', lambda: None)
    r = client.post('/api/encdns', json={'enabled': True, 'providers': ['quad9']})
    assert r.status_code == 400 and 'not installed' in r.json['error']
    assert not load_store('encdns')['enabled']


def test_api_rejected_proxy_config_changes_nothing(client, monkeypatch):
    fake = _stub_proxy(monkeypatch)
    monkeypatch.setattr(encdns, 'check_proxy_config', lambda text: (False, 'boom'))
    r = client.post('/api/encdns', json={'enabled': True, 'providers': ['quad9']})
    assert r.status_code == 400 and 'boom' in r.json['error']
    assert not load_store('encdns')['enabled'] and not fake.running
    assert 'server=127.0.0.1#5335' not in _main_conf()


def test_api_relay_mode(client, monkeypatch):
    _stub_proxy(monkeypatch)
    r = client.post('/api/encdns', json={'enabled': True, 'mode': 'relay',
                                         'providers': ['quad9'],
                                         'relays': ['anon-cs-fr']})
    assert r.json['success']
    toml = open(ENCDNS_CONF).read()
    assert 'doh_servers = false' in toml and "via=['anon-cs-fr']" in toml


# ─── Alerts ───────────────────────────────────────────────────────────

def test_alert_fires_when_proxy_down(client, monkeypatch):
    from dnsmaqmgr import alerts
    _stub_proxy(monkeypatch, running=False)
    save_store('encdns', _cfg(enabled=True))
    sent = []
    monkeypatch.setattr(alerts, 'deliver',
                        lambda cfg, e, t, m: (sent.append((e, m)), (True, 'ok'))[1])
    client.post('/api/alerts', json={
        'enabled': True, 'webhook_url': 'https://alerts.example/hook',
        'events': {'new_device': False, 'pool_high': False,
                   'service_down': False, 'cert_expiry': False,
                   'encdns_down': True}})
    alerts.tick()
    assert len(sent) == 1 and sent[0][0] == 'encdns_down'
    assert 'fail-closed' in sent[0][1]
    alerts.tick()                              # cooldown holds
    assert len(sent) == 1


def test_alert_running_but_unhealthy(client, monkeypatch):
    from dnsmaqmgr import alerts
    _stub_proxy(monkeypatch, running=True, healthy=False)
    save_store('encdns', _cfg(enabled=True))
    found = alerts._check_encdns()
    assert found and found[0][1] == 'encdns_down' and 'not answering' in found[0][2]


def test_no_alert_when_disabled_or_healthy(client, monkeypatch):
    from dnsmaqmgr import alerts
    _stub_proxy(monkeypatch, running=True, healthy=True)
    assert alerts._check_encdns() == []        # disabled
    save_store('encdns', _cfg(enabled=True))
    assert alerts._check_encdns() == []        # healthy


# ─── Query log labelling ──────────────────────────────────────────────

def test_querylog_labels_encrypted_upstream(client, monkeypatch):
    save_store('encdns', _cfg(enabled=True))
    lines = [
        'Aug  5 12:00:01 dnsmasq[1]: 1 10.0.0.2/531 query[A] example.com from 10.0.0.2',
        'Aug  5 12:00:01 dnsmasq[1]: 1 10.0.0.2/531 forwarded example.com to 127.0.0.1#5335',
    ]
    monkeypatch.setattr(dm._controller, 'logs', lambda n=200: '\n'.join(lines))
    r = client.get('/api/querylog').json
    ups = dict(r['upstreams'])
    assert 'encrypted upstream (127.0.0.1#5335)' in ups
    assert '127.0.0.1#5335' not in ups
    assert r['entries'][0]['upstreams'] == ['encrypted upstream (127.0.0.1#5335)']


# ─── Lookup attribution ───────────────────────────────────────────────

def test_lookup_attributes_encrypted_upstream(client, monkeypatch):
    from dnsmaqmgr import lookup as lk
    save_store('encdns', _cfg(enabled=True))
    monkeypatch.setattr(lk, 'query_dnsmasq',
                        lambda name, qtype, **kw: (0, [{'name': 'example.org',
                                                        'type': 'A', 'ttl': 60,
                                                        'value': '93.184.216.34'}])
                        if qtype == 1 else (0, []))
    r = client.get('/api/lookup?name=example.org').json
    src = r['answers'][0]['source']
    assert src['kind'] == 'encrypted-upstream'
    assert 'dnscrypt-proxy' in src['detail']


# ─── Backup round-trip ────────────────────────────────────────────────

def test_backup_roundtrip(client, monkeypatch):
    fake = _stub_proxy(monkeypatch)
    client.post('/api/encdns', json={'enabled': True, 'providers': ['adguard'],
                                     'fallback_plain': True})
    backup = client.get('/api/backup').json
    assert backup['stores']['encdns']['enabled']

    client.post('/api/encdns', json={'enabled': False, 'providers': ['quad9']})
    assert not load_store('encdns')['enabled']

    r = client.post('/api/backup/restore', json={'backup': backup})
    assert r.json['success'] and 'encdns' in r.json['restored']
    cfg = load_store('encdns')
    assert cfg['enabled'] and cfg['providers'] == ['adguard'] and cfg['fallback_plain']
    assert fake.running                        # post-apply sync restarted it
    assert 'server=127.0.0.1#5335' in _main_conf()


def test_restore_enabled_without_binary_rejected(client, monkeypatch):
    fake = _stub_proxy(monkeypatch)
    client.post('/api/encdns', json={'enabled': True, 'providers': ['quad9']})
    backup = client.get('/api/backup').json
    client.post('/api/encdns', json={'enabled': False})

    monkeypatch.setattr(encdns, 'binary_path', lambda: None)
    r = client.post('/api/backup/restore', json={'backup': backup})
    assert r.status_code == 422 and 'dnscrypt-proxy is not installed' in r.json['error']
    assert not load_store('encdns')['enabled']


def test_provider_swap_flushes_dnsmasq_cache(client, monkeypatch):
    """Swapping providers on the same port leaves dnsmasq's render identical,
    so nothing would touch dnsmasq — but its cache still holds the OLD
    provider's answers (a filtering provider's 0.0.0.0 sinkholes). The save
    must SIGHUP dnsmasq to drop them."""
    from dnsmaqmgr import dnsmasq as dm
    fake = _stub_proxy(monkeypatch)
    r = client.post('/api/encdns', json={'enabled': True, 'providers': ['adguard']})
    assert r.json['success'] and r.json['action'] == 'restart'

    calls = []
    monkeypatch.setattr(dm._controller, 'reload', lambda: (calls.append(1), (True, ''))[1])
    r = client.post('/api/encdns', json={'enabled': True, 'providers': ['cloudflare']})
    assert r.json['success']
    assert r.json['action'] == 'reload' and r.json['service_ok']
    assert calls == [1]                            # dnsmasq cache dropped
    assert fake.restarts == 1                      # proxy picked up the new provider

    # A failed flush is reported, not swallowed.
    monkeypatch.setattr(dm._controller, 'reload', lambda: (False, 'boom'))
    r = client.post('/api/encdns', json={'enabled': True, 'providers': ['quad9']})
    assert r.json['success'] and r.json['action'] == 'reload'
    assert not r.json['service_ok'] and 'boom' in r.json['service_detail']


def test_flush_endpoint(client, monkeypatch):
    from dnsmaqmgr import dnsmasq as dm
    calls = []
    monkeypatch.setattr(dm._controller, 'reload', lambda: (calls.append(1), (True, ''))[1])
    assert client.post('/api/dnsmasq/flush').json['success'] and calls == [1]
    monkeypatch.setattr(dm._controller, 'reload', lambda: (False, 'no pid'))
    r = client.post('/api/dnsmasq/flush')
    assert r.status_code == 500 and 'no pid' in r.json['error']
