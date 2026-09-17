"""Feature tests: metrics/health, blocklist allowlist, OUI lookup, lease
events, config importer, scheduled snapshots, lease release."""
import os
import json
import time

import pytest


# ─── /metrics and /api/health ─────────────────────────────────────────

def test_metrics_exposition_and_health(client, monkeypatch):
    from dnsmaqmgr import stats
    monkeypatch.setattr(stats, 'collect_dns_counters',
                        lambda: {'cachesize': 150, 'insertions': 5, 'evictions': 1, 'hits': 40, 'misses': 10})
    client.post('/api/dhcp/ranges', json={'start': '10.0.0.100', 'end': '10.0.0.109', 'tag': 'lan'})
    r = client.get('/metrics')
    assert r.status_code == 200 and r.mimetype == 'text/plain'
    text = r.get_data(as_text=True)
    assert 'dnsmasq_up 1' in text
    assert 'dnsmasq_cache_hits_total 40' in text
    assert 'dnsmasq_dhcp_pool_size{pool="lan"} 10' in text
    assert '# TYPE dnsmasq_cache_hits_total counter' in text
    # health is public: no session, no token
    with client.session_transaction() as sess:
        sess.clear()
    r = client.get('/api/health')
    assert r.status_code == 200 and r.json == {'status': 'ok'}
    from dnsmaqmgr import dnsmasq as dm
    class Down:
        mode = 'test'
        def status(self): return {'running': False, 'state': 'failed'}
    monkeypatch.setattr(dm, '_controller', Down())
    r = client.get('/api/health')
    assert r.status_code == 503 and r.json['status'] == 'degraded'
    # metrics is NOT public
    assert client.get('/metrics').status_code == 401


# ─── Blocklist allowlist ──────────────────────────────────────────────

def _fake_list(client, monkeypatch, domains):
    from dnsmaqmgr import blocklists as bl
    monkeypatch.setattr(bl, 'fetch_list_text', lambda url: '\n'.join('0.0.0.0 %s' % d for d in domains))
    r = client.post('/api/blocklists', json={'name': 'L', 'url': 'https://example.org/list'})
    assert r.status_code == 200 and r.json['fetch_ok'], r.json
    return r.json['id']


def test_allowlist_exempts_names_and_subdomains(client, monkeypatch):
    lid = _fake_list(client, monkeypatch, ['ads.example', 'tracker.example', 'cdn.tracker.example'])
    files = client.get('/api/dnsmasq/config').json['files']
    conf = files['dnsmasq.d/50-block-%s.conf' % lid]
    assert 'address=/tracker.example/0.0.0.0' in conf and 'address=/cdn.tracker.example/0.0.0.0' in conf
    assert '# (empty)' in files['dnsmasq.d/40-allow.conf']

    r = client.post('/api/blocklists/allow', json={'domain': 'Tracker.Example.'})
    assert r.status_code == 200 and r.json['allow'] == ['tracker.example'], r.json
    assert r.json['action'] == 'restart'
    files = client.get('/api/dnsmasq/config').json['files']
    conf = files['dnsmasq.d/50-block-%s.conf' % lid]
    assert 'address=/ads.example/0.0.0.0' in conf
    assert 'tracker.example' not in conf                   # the name and what is beneath it
    assert 'server=/tracker.example/#' in files['dnsmasq.d/40-allow.conf']

    # lookup attribution agrees
    from dnsmaqmgr.blocklists import load_block_index
    idx = load_block_index()
    assert idx.match('ads.example') == ('L', 'ads.example')
    assert idx.match('cdn.tracker.example') is None
    assert idx.match('deep.cdn.tracker.example') is None

    assert client.post('/api/blocklists/allow', json={'domain': 'not a domain'}).status_code == 400
    assert client.delete('/api/blocklists/allow/nothere.example').status_code == 404
    r = client.delete('/api/blocklists/allow/tracker.example')
    assert r.status_code == 200 and r.json['allow'] == []
    conf = client.get('/api/dnsmasq/config').json['files']['dnsmasq.d/50-block-%s.conf' % lid]
    assert 'address=/tracker.example/0.0.0.0' in conf


def test_allowlist_survives_backup_roundtrip(client, monkeypatch):
    from dnsmaqmgr import blocklists as bl
    monkeypatch.setattr(bl, 'refresh_due', lambda: None)
    client.post('/api/blocklists/allow', json={'domain': 'keep.example'})
    b = client.get('/api/backup').json
    assert b['stores']['blocklists']['allow'] == ['keep.example']
    client.delete('/api/blocklists/allow/keep.example')
    assert client.post('/api/backup/restore', json={'backup': b}).status_code == 200
    assert client.get('/api/blocklists').json['allow'] == ['keep.example']
    b['stores']['blocklists']['allow'] = ['bad domain']
    assert client.post('/api/backup/restore', json={'backup': b}).status_code == 422


# ─── OUI vendor lookup ────────────────────────────────────────────────

OUI_CSV = '''Registry,Assignment,Organization Name,Organization Address
MA-L,001A2B,Example Widgets Inc,1 Main St
MA-L,001122,"Acme, Ltd",Somewhere
MA-L,ZZZZZZ,Broken Row,
'''


def test_oui_parse_and_lookup(client, monkeypatch, tmp_path):
    from dnsmaqmgr import oui
    table = oui.parse_oui_csv(OUI_CSV)
    assert table == {'001A2B': 'Example Widgets Inc', '001122': 'Acme, Ltd'}
    monkeypatch.setattr(oui, 'OUI_FILE', str(tmp_path / 'oui.json'))
    monkeypatch.setattr(oui, '_table', None)
    assert oui.vendor('00:1a:2b:12:34:56') == ''            # not fetched yet
    (tmp_path / 'oui.json').write_text(json.dumps(table))
    assert oui.vendor('00:1a:2b:12:34:56') == 'Example Widgets Inc'
    assert oui.vendor('00-11-22-00-00-00') == 'Acme, Ltd'
    assert oui.vendor('00:de:ad:00:00:01') == ''
    assert oui.vendor('02:11:22:33:44:55') == '(randomised/private MAC)'
    assert oui.vendor('garbage') == ''

    # fetch path with a stubbed download
    class R:
        status = 200
        def __init__(self, data): self._d = data
        def read(self, n=-1): return self._d
        def __enter__(self): return self
        def __exit__(self, *a): pass
    big = OUI_CSV + ''.join('MA-L,%06X,Vendor %d,x\n' % (i, i) for i in range(1200))
    monkeypatch.setattr(oui.urllib.request, 'urlopen', lambda req, timeout=0: R(big.encode()))
    ok, detail = oui.fetch()
    assert ok and 'assignments' in detail
    st = client.get('/api/oui').json
    assert st['count'] >= 1200 and st['last_status'] == 'ok' and st['present']
    r = client.get('/api/oui/lookup/00:1a:2b:00:00:00')
    assert r.json['vendor'] == 'Example Widgets Inc'
    # leases carry the vendor
    from dnsmaqmgr.core.config import LEASES_FILE
    with open(LEASES_FILE, 'w') as f:
        f.write('%d 00:1a:2b:00:00:07 10.0.0.7 cam1 *\n' % (int(time.time()) + 3600))
    leases = client.get('/api/dhcp/leases').json['leases']
    assert leases[0]['vendor'] == 'Example Widgets Inc'


# ─── Lease events (dhcp-script hook) ──────────────────────────────────

def test_lease_event_hook_rendered_and_events_corroborated(client, monkeypatch):
    from dnsmaqmgr import events, dnsmasq as dm
    from dnsmaqmgr.core.config import LEASES_FILE
    files = client.get('/api/dnsmasq/config').json['files']
    assert files['lease-event.sh'].startswith('#!/bin/bash')
    assert '/dev/udp/127.0.0.1/%d' % events.EVENT_PORT in files['lease-event.sh']
    assert oct(os.stat(os.path.join(dm.RENDER_DIR, 'lease-event.sh')).st_mode & 0o777) == '0o755'
    assert 'dhcp-script=' not in files['dnsmasq.d/00-main.conf']      # DHCP off
    client.post('/api/settings/toggles', json={'dhcp_enabled': True})
    main = client.get('/api/dnsmasq/config').json['files']['dnsmasq.d/00-main.conf']
    assert 'dhcp-script=%s' % dm.HOOK_SCRIPT in main
    client.post('/api/settings', json={'lease_events': False})
    assert 'dhcp-script=' not in client.get('/api/dnsmasq/config').json['files']['dnsmasq.d/00-main.conf']

    assert events.parse_event('add aa:bb:cc:dd:ee:01 10.0.0.7 cam1') == \
        {'action': 'add', 'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.0.0.7', 'hostname': 'cam1'}
    assert events.parse_event('add aa:bb:cc:dd:ee:01 10.0.0.7 bad host\nname') is not None
    assert events.parse_event('nuke aa:bb:cc:dd:ee:01 10.0.0.7') is None
    assert events.parse_event('add notamac 10.0.0.7') is None
    # a datagram the leases file does not back is ignored
    monkeypatch.setattr(events.time, 'sleep', lambda s: None)
    assert events.handle('add aa:bb:cc:dd:ee:01 10.0.0.7 cam1') is None
    with open(LEASES_FILE, 'w') as f:
        f.write('%d aa:bb:cc:dd:ee:01 10.0.0.7 cam1 *\n' % (int(time.time()) + 3600))
    sent = []
    from dnsmaqmgr import alerts
    monkeypatch.setattr(alerts, 'lease_event', lambda ev: sent.append(ev))
    ev = events.handle('add aa:bb:cc:dd:ee:01 10.0.0.7 cam1')
    assert ev and ev['action'] == 'add' and sent and sent[0]['mac'] == 'aa:bb:cc:dd:ee:01'
    assert events.handle('del aa:bb:cc:dd:ee:01 10.0.0.7') is None    # still held → not a real expiry
    r = client.get('/api/dhcp/events').json
    assert r['events'][0]['ip'] == '10.0.0.7' and r['port'] == events.EVENT_PORT


def test_lease_event_alert_is_immediate_and_deduped(client, monkeypatch):
    from dnsmaqmgr import alerts
    from dnsmaqmgr.core.store import load_store, save_store
    client.post('/api/alerts', json={'enabled': True, 'webhook_url': 'https://hook.example/x'})
    st = load_store('alerts_state'); st['baseline_done'] = True; save_store('alerts_state', st)
    delivered = []
    monkeypatch.setattr(alerts, 'deliver', lambda cfg, ev, t, m: (delivered.append(m), (True, 'HTTP 200'))[1])
    ev = {'action': 'add', 'mac': 'aa:bb:cc:dd:ee:02', 'ip': '10.0.0.8', 'hostname': 'tv'}
    assert alerts.lease_event(ev) is True
    assert delivered and 'aa:bb:cc:dd:ee:02' in delivered[0] and '(tv)' in delivered[0]
    assert alerts.lease_event(ev) is False              # now known
    assert 'aa:bb:cc:dd:ee:02' in load_store('alerts_state')['known_macs']
    # the periodic tick does not re-alert the same MAC either
    from dnsmaqmgr.core.config import LEASES_FILE
    with open(LEASES_FILE, 'w') as f:
        f.write('%d aa:bb:cc:dd:ee:02 10.0.0.8 tv *\n' % (int(time.time()) + 3600))
    monkeypatch.setattr(alerts, '_check_service', lambda s, st: [])
    monkeypatch.setattr(alerts, '_check_encdns', lambda: [])
    monkeypatch.setattr(alerts, '_check_shadowing', lambda: [])
    monkeypatch.setattr(alerts, '_check_cert', lambda c: [])
    alerts.tick()
    assert len(delivered) == 1


def test_lease_release_route(client, monkeypatch):
    from dnsmaqmgr import dhcp
    from dnsmaqmgr.core.config import LEASES_FILE
    calls = []
    monkeypatch.setattr(dhcp, 'run', lambda args, **kw: (calls.append(args), ('', '', 0))[1])
    client.post('/api/settings', json={'interfaces': ['eth0']})
    assert client.post('/api/dhcp/leases/release', json={'mac': 'aa:bb:cc:dd:ee:03', 'ip': '10.0.0.9'}).status_code == 404
    with open(LEASES_FILE, 'w') as f:
        f.write('%d aa:bb:cc:dd:ee:03 10.0.0.9 x *\n' % (int(time.time()) + 3600))
    r = client.post('/api/dhcp/leases/release', json={'mac': 'AA:BB:CC:DD:EE:03', 'ip': '10.0.0.9'})
    assert r.status_code == 200, r.json
    assert calls[-1] == ['dhcp_release', 'eth0', '10.0.0.9', 'aa:bb:cc:dd:ee:03']
    assert client.post('/api/dhcp/leases/release', json={'mac': 'zz', 'ip': '10.0.0.9'}).status_code == 400


# ─── Config importer ──────────────────────────────────────────────────

SAMPLE_CONF = '''
# a typical hand-written dnsmasq.conf
domain-needed
bogus-priv
no-resolv
server=8.8.8.8
server=1.1.1.1#5353
server=/corp.example/10.1.1.1
server=/void.example/#
address=/ads.example/0.0.0.0
address=/a.example/b.example/10.0.0.50
cname=www.lan,web.lan
cname=x.lan,y.lan,web.lan,300
host-record=web.lan,10.0.0.20,fd00::20
domain=lan
expand-hosts
interface=eth0
listen-address=127.0.0.1
cache-size=5000
dhcp-range=set:lan,10.0.0.100,10.0.0.199,255.255.255.0,10.0.0.255,24h
dhcp-range=10.0.1.100,10.0.1.199,12h
dhcp-range=10.0.2.0,static
dhcp-range=fd00::,ra-only
dhcp-host=aa:bb:cc:dd:ee:01,10.0.0.5,nas
dhcp-host=AA:BB:CC:DD:EE:02,set:iot,10.0.0.6,cam,infinite
dhcp-host=aa:bb:cc:dd:ee:03,ignore
dhcp-option=tag:lan,option:router,10.0.0.1
dhcp-option=option:dns-server,10.0.0.2,10.0.0.3
dhcp-option=vendor:PXEClient,1,0.0.0.0
dhcp-option=tag:a,tag:b,option:ntp-server,10.0.0.4
dhcp-boot=tag:lan,pxelinux.0,boot,10.0.0.20
dhcp-boot=undionly.kpxe
dhcp-authoritative
log-queries
conf-dir=/etc/dnsmasq.d
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
local-ttl=10
rebind-domain-ok=/plex.direct/
'''


def test_importer_parses_a_real_world_conf():
    from dnsmaqmgr.importer import parse_conf_text
    res = parse_conf_text(SAMPLE_CONF)
    assert res['settings'] == {'domain_needed': True, 'bogus_priv': True, 'no_resolv': True,
                               'domain': 'lan', 'expand_hosts': True, 'interfaces': ['eth0'],
                               'listen_addresses': ['127.0.0.1'], 'cache_size': '5000',
                               'dhcp_authoritative': True, 'log_queries': True}
    assert res['upstreams'] == ['8.8.8.8', '1.1.1.1#5353']
    assert res['forwards'] == [{'domain': 'corp.example', 'upstream': '10.1.1.1', 'comment': 'imported'}]
    assert [a['domain'] for a in res['addresses']] == ['ads.example', 'a.example', 'b.example']
    assert res['cnames'] == [{'alias': 'www.lan', 'target': 'web.lan', 'comment': 'imported'},
                             {'alias': 'x.lan', 'target': 'web.lan', 'comment': 'imported'},
                             {'alias': 'y.lan', 'target': 'web.lan', 'comment': 'imported'}]
    assert res['hosts'] == [{'name': 'web.lan', 'a': '10.0.0.20', 'aaaa': 'fd00::20', 'comment': 'imported'}]
    assert res['ranges'] == [
        {'start': '10.0.0.100', 'end': '10.0.0.199', 'netmask': '255.255.255.0', 'lease': '24h',
         'tag': 'lan', 'interface': '', 'comment': 'imported'},
        {'start': '10.0.1.100', 'end': '10.0.1.199', 'netmask': '', 'lease': '12h',
         'tag': '', 'interface': '', 'comment': 'imported'}]
    assert res['static_leases'] == [
        {'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.0.0.5', 'hostname': 'nas', 'tag': '', 'comment': 'imported'},
        {'mac': 'aa:bb:cc:dd:ee:02', 'ip': '10.0.0.6', 'hostname': 'cam', 'tag': 'iot', 'comment': 'imported'}]
    assert res['options'] == [
        {'tag': 'lan', 'option': 'option:router', 'value': '10.0.0.1', 'comment': 'imported'},
        {'tag': '', 'option': 'option:dns-server', 'value': '10.0.0.2,10.0.0.3', 'comment': 'imported'}]
    assert res['entries'] == [{'name': 'pxelinux.0', 'filename': 'pxelinux.0', 'server': '10.0.0.20',
                               'arches': [], 'comment': 'imported', 'enabled': True}]
    assert res['extra'] == ['local-ttl=10', 'rebind-domain-ok=/plex.direct/']
    reasons = {s['line']: s['reason'] for s in res['skipped']}
    assert 'conf-dir=/etc/dnsmasq.d' in reasons and 'dhcp-leasefile=/var/lib/misc/dnsmasq.leases' in reasons
    assert 'server=/void.example/#' in reasons
    assert 'dhcp-range=10.0.2.0,static' in reasons and 'dhcp-range=fd00::,ra-only' in reasons
    assert 'dhcp-host=aa:bb:cc:dd:ee:03,ignore' in reasons
    assert 'dhcp-option=vendor:PXEClient,1,0.0.0.0' in reasons
    assert 'dhcp-option=tag:a,tag:b,option:ntp-server,10.0.0.4' in reasons
    assert 'dhcp-boot=undionly.kpxe' in reasons


def test_importer_preview_and_apply_merge(client):
    r = client.post('/api/import/preview', json={'text': SAMPLE_CONF})
    assert r.status_code == 200
    assert r.json['counts'] == {'settings': 11, 'hosts': 1, 'dns': 7, 'dhcp': 6, 'netboot': 1,
                                'extra': 2, 'skipped': 9}
    assert client.post('/api/import/preview', json={'text': '   '}).status_code == 400

    # an existing record that the import also carries is left alone (merge)
    client.post('/api/dns/hosts', json={'name': 'web.lan', 'a': '10.0.0.20', 'aaaa': 'fd00::20'})
    r = client.post('/api/import/apply', json={'text': SAMPLE_CONF})
    assert r.status_code == 200, r.json
    assert r.json['unchanged'] == 1 and r.json['added'] == 14
    d = client.get('/api/dns').json
    assert len(d['hosts']) == 1 and len(d['cnames']) == 3 and len(d['addresses']) == 3
    s = client.get('/api/settings').json
    assert s['upstreams'] == ['8.8.8.8', '1.1.1.1#5353'] and s['cache_size'] == 5000 and s['interfaces'] == ['eth0']
    assert s['extra_options'] == 'local-ttl=10\nrebind-domain-ok=/plex.direct/'
    h = client.get('/api/dhcp').json
    assert len(h['ranges']) == 2 and h['static_leases'][1]['tag'] == 'iot'
    files = client.get('/api/dnsmasq/config').json['files']
    assert 'local-ttl=10' in files['dnsmasq.d/90-extra.conf']
    assert 'server=/corp.example/10.1.1.1' in files['dnsmasq.d/10-dns.conf']
    # second apply is a no-op
    r = client.post('/api/import/apply', json={'text': SAMPLE_CONF})
    assert r.json['added'] == 0 and r.json['action'] == 'none'
    # replace mode drops what is not in the import
    client.post('/api/dns/cnames', json={'alias': 'gone.lan', 'target': 'web.lan'})
    r = client.post('/api/import/apply', json={'text': SAMPLE_CONF, 'sections': ['dns'], 'replace': True})
    assert r.status_code == 200
    assert sorted(c['alias'] for c in client.get('/api/dns').json['cnames']) == ['www.lan', 'x.lan', 'y.lan']


def test_importer_rejects_invalid_lines_unless_skipped(client):
    text = 'dhcp-host=aa:bb:cc:dd:ee:01,10.0.0.5,bad_host!\naddress=/ok.example/10.0.0.1\n'
    r = client.post('/api/import/apply', json={'text': text})
    assert r.status_code == 422 and r.json['problems']
    assert client.get('/api/dns').json['addresses'] == []
    r = client.post('/api/import/apply', json={'text': text, 'skip_invalid': True})
    assert r.status_code == 200 and r.json['added'] == 1 and len(r.json['problems']) == 1


def test_importer_respects_mirror_locks(client):
    from dnsmaqmgr.core.store import load_store, save_store
    s = load_store('settings')
    s['mirror_sources'] = {'nexus-ipam': {'sections': ['hosts'], 'serial': 1, 'serials': {'hosts': 1}}}
    save_store('settings', s)
    r = client.post('/api/import/apply', json={'text': 'host-record=x.lan,10.0.0.1', 'sections': ['hosts']})
    assert r.status_code == 409
    r = client.post('/api/import/apply', json={'text': 'address=/x.example/0.0.0.0', 'sections': ['dns']})
    assert r.status_code == 200


# ─── Scheduled snapshots ──────────────────────────────────────────────

def test_snapshots_run_list_restore_delete(client, monkeypatch, tmp_path):
    from dnsmaqmgr import backup, blocklists as bl
    monkeypatch.setattr(backup, 'BACKUPS_DIR', str(tmp_path / 'backups'))
    monkeypatch.setattr(bl, 'refresh_due', lambda: None)
    client.post('/api/dns/hosts', json={'name': 'snap.lan', 'a': '10.0.0.3'})
    r = client.post('/api/backups', json={'enabled': True, 'hour': 3, 'keep': 2})
    assert r.status_code == 200 and r.json['keep'] == 2
    assert client.post('/api/backups', json={'keep': 0}).status_code == 400
    r = client.post('/api/backups/run', json={})
    assert r.status_code == 200 and r.json['name'].startswith('dnsmaq-backup-')
    name = r.json['name']
    payload = json.load(open(tmp_path / 'backups' / name))
    assert payload['app'] == 'dnsmaq-mgr' and 'accounts' in payload
    assert oct(os.stat(tmp_path / 'backups' / name).st_mode & 0o777) == '0o600'
    lst = client.get('/api/backups').json
    assert lst['snapshots'][0]['name'] == name and lst['last_status'] == 'ok'
    # keep=2 prunes the oldest (conftest no-ops time.sleep, so fake older files)
    for stamp in ('20200101-010101', '20200102-010101', '20200103-010101'):
        (tmp_path / 'backups' / ('dnsmaq-backup-%s.json' % stamp)).write_text('{}')
    client.post('/api/backups/run', json={})
    names = [f['name'] for f in client.get('/api/backups').json['snapshots']]
    assert len(names) == 2 and 'dnsmaq-backup-20200101-010101.json' not in names
    # restore from a snapshot
    hid = client.get('/api/dns').json['hosts'][0]['id']
    client.delete('/api/dns/hosts/%s' % hid)
    assert client.get('/api/dns').json['hosts'] == []
    latest = client.get('/api/backups').json['snapshots'][0]['name']
    r = client.post('/api/backups/%s/restore' % latest, json={})
    assert r.status_code == 200 and 'dns' in r.json['restored']
    assert client.get('/api/dns').json['hosts'][0]['name'] == 'snap.lan'
    assert client.get('/api/backups/%s' % latest).status_code == 200
    assert client.get('/api/backups/../../etc/passwd').status_code == 404
    assert client.delete('/api/backups/%s' % latest).status_code == 200
    assert client.delete('/api/backups/%s' % latest).status_code == 404


def test_snapshot_tick_runs_once_per_day_after_the_hour(client, monkeypatch, tmp_path):
    from dnsmaqmgr import backup
    from dnsmaqmgr.core.store import load_store, save_store
    monkeypatch.setattr(backup, 'BACKUPS_DIR', str(tmp_path / 'backups'))
    runs = []
    monkeypatch.setattr(backup, 'run_snapshot', lambda keep=None: (runs.append(1), (True, 'x'))[1])
    cfg = load_store('backups'); cfg.update({'enabled': True, 'hour': 0, 'last_run': 0}); save_store('backups', cfg)
    backup.tick()
    assert len(runs) == 1
    cfg = load_store('backups'); cfg['last_run'] = int(time.time()); save_store('backups', cfg)
    backup.tick()
    assert len(runs) == 1                                   # already ran today
    cfg['hour'] = 23; cfg['last_run'] = 0; save_store('backups', cfg)
    backup.tick()
    from datetime import datetime
    assert len(runs) == (2 if datetime.now().hour == 23 else 1)
    cfg['enabled'] = False; cfg['hour'] = 0; save_store('backups', cfg)
    backup.tick()
    assert len(runs) <= 2
