"""Blocklist subscriptions: parsing, fetch/apply pipeline, render isolation,
pruning, and lookup attribution."""
import os

from dnsmaqmgr import blocklists as bl
from dnsmaqmgr import dnsmasq as dm
from dnsmaqmgr.core.config import RENDER_DIR


SAMPLE = """\
# StevenBlack-style hosts section
127.0.0.1 localhost
0.0.0.0 0.0.0.0
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.net more-ads.example.com

# plain domains
plain.example.org

# dnsmasq format
address=/dnsm.example.com/0.0.0.0

# adblock format
||adblock.example.com^
||not-a-block.example.com^$third-party

# junk that must never reach the config
1.2.3.4 realhost.example.com
address=/evil.example.com\x00bad/0.0.0.0
"""


def test_parse_blocklist_text_formats_and_injection():
    domains, skipped = bl.parse_blocklist_text(SAMPLE)
    assert set(domains) == {
        'ads.example.com', 'tracker.example.net', 'more-ads.example.com',
        'plain.example.org', 'dnsm.example.com', 'adblock.example.com',
    }
    assert skipped >= 4          # localhost, 0.0.0.0, adblock-option line, real host, bad address
    # a crafted "domain" with a newline can never come back
    domains, _ = bl.parse_blocklist_text('0.0.0.0 evil.com\ninjected=1')
    assert domains == ['evil.com']


def _fake_fetch(monkeypatch, text):
    monkeypatch.setattr(bl, 'fetch_list_text', lambda url: text)


def test_blocklist_add_renders_own_conf(client, monkeypatch):
    _fake_fetch(monkeypatch, '0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n')
    r = client.post('/api/blocklists', json={'name': 'testlist',
                                             'url': 'https://example.com/hosts'})
    assert r.status_code == 200 and r.json['success']
    assert r.json['fetch_ok'] and r.json['entries'] == 2
    lid = r.json['id']

    cfg = client.get('/api/dnsmasq/config').json['files']
    conf = cfg['dnsmasq.d/50-block-%s.conf' % lid]
    assert 'address=/ads.example.com/0.0.0.0' in conf
    assert 'address=/tracker.example.net/0.0.0.0' in conf
    # the block rides its own file, not the shared dns conf
    assert 'ads.example.com' not in cfg['dnsmasq.d/10-dns.conf']

    # disable -> conf file pruned from the render dir; enable -> back
    path = os.path.join(RENDER_DIR, 'dnsmasq.d/50-block-%s.conf' % lid)
    assert os.path.exists(path)
    r = client.post('/api/blocklists/%s' % lid, json={'enabled': False})
    assert r.json['success'] and r.json['action'] == 'restart'
    assert not os.path.exists(path)
    client.post('/api/blocklists/%s' % lid, json={'enabled': True})
    assert os.path.exists(path)

    # delete -> conf and domains file both gone
    assert client.delete('/api/blocklists/%s' % lid).json['success']
    assert not os.path.exists(path)
    assert not os.path.exists(dm.blocklist_domains_path(lid))


def test_blocklist_failed_fetch_changes_nothing(client, monkeypatch):
    def boom(url):
        raise OSError('connection refused')
    monkeypatch.setattr(bl, 'fetch_list_text', boom)
    r = client.post('/api/blocklists', json={'name': 'broken',
                                             'url': 'https://example.com/nope'})
    assert r.json['success'] and r.json['fetch_ok'] is False
    lid = r.json['id']
    lists = client.get('/api/blocklists').json['lists']
    rec = next(l for l in lists if l['id'] == lid)
    assert rec['entries'] == 0
    assert rec['last_status'].startswith('error')
    # enabled but unfetched: the conf file exists but blocks nothing
    conf = client.get('/api/dnsmasq/config').json['files']['dnsmasq.d/50-block-%s.conf' % lid]
    assert 'address=' not in conf

    # manual refresh with a now-working fetch recovers
    _fake_fetch(monkeypatch, 'ads.example.com\n')
    r = client.post('/api/blocklists/%s/refresh' % lid, json={})
    assert r.json['success'] and r.json['entries'] == 1


def test_blocklist_refresh_keeps_previous_on_failure(client, monkeypatch):
    _fake_fetch(monkeypatch, '0.0.0.0 ads.example.com\n')
    lid = client.post('/api/blocklists', json={'name': 'l', 'url': 'https://x.example/h'}).json['id']

    def boom(url):
        raise OSError('timeout')
    monkeypatch.setattr(bl, 'fetch_list_text', boom)
    assert client.post('/api/blocklists/%s/refresh' % lid, json={}).status_code == 502
    # previous fetch still live
    conf = client.get('/api/dnsmasq/config').json['files']['dnsmasq.d/50-block-%s.conf' % lid]
    assert 'address=/ads.example.com/0.0.0.0' in conf


def test_blocklist_validation(client):
    bad = [
        {'name': '', 'url': 'https://x.example/h'},
        {'name': 'x', 'url': 'ftp://x.example/h'},
        {'name': 'x', 'url': 'https://x.example/h h'},
        {'name': 'x', 'url': 'https://x.example/h', 'refresh_hours': 0},
        {'name': 'bad\nname', 'url': 'https://x.example/h'},
    ]
    for body in bad:
        assert client.post('/api/blocklists', json=body).status_code == 400


def test_lookup_attributes_blocklist(client, monkeypatch):
    from dnsmaqmgr import lookup
    _fake_fetch(monkeypatch, '0.0.0.0 ads.example.com\n')
    client.post('/api/blocklists', json={'name': 'mylist', 'url': 'https://x.example/h'})
    monkeypatch.setattr(lookup, 'query_dnsmasq', lambda name, qtype, **kw:
                        (0, [{'name': 'sub.ads.example.com', 'type': 'A', 'ttl': 0,
                              'value': '0.0.0.0'}]) if qtype == 1 else (0, []))
    r = client.get('/api/lookup?name=sub.ads.example.com')
    src = r.json['answers'][0]['source']
    assert src['kind'] == 'blocklist' and 'mylist' in src['detail']
    assert not r.json['warnings']
