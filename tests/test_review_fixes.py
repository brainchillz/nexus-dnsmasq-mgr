"""Regression tests for the 2026-09-17 review fixes (fix.md)."""
import time
import subprocess


def test_user_create_over_existing_is_refused(client, monkeypatch):
    from dnsmaqmgr.core import auth
    monkeypatch.setattr(auth, '_users', lambda: auth.load_config().get('users', {}))
    auth.save_config({'users': {'admin': {'password': 'x', 'role': 'admin'}}})
    r = client.post('/api/users', json={'username': 'admin', 'password': 'longenough', 'role': 'readonly'})
    assert r.status_code == 409
    assert auth.load_config()['users']['admin']['role'] == 'admin'
    r = client.post('/api/users', json={'username': 'bob', 'password': 'short', 'role': 'admin'})
    assert r.status_code == 400 and 'at least' in r.json['error']
    assert client.post('/api/users', json={'username': 'bob', 'password': 'longenough', 'role': 'admin'}).status_code == 200
    assert client.post('/api/users/bob/password', json={'password': 'x'}).status_code == 400


def test_host_edits_bump_the_dns_serial(client):
    from dnsmaqmgr.core.store import load_store
    from dnsmaqmgr.peers import build_payload
    before = load_store('dns').get('serial', 0)
    assert client.post('/api/dns/hosts', json={'name': 'a.lan', 'a': '10.0.0.1'}).status_code == 200
    after = load_store('dns').get('serial', 0)
    assert after == before + 1
    assert build_payload(['hosts'])['serials']['hosts'] == after


def test_rollback_keeps_mirror_state(client):
    from dnsmaqmgr.core.store import load_store
    client.post('/api/dns/hosts', json={'name': 'a.lan', 'a': '10.0.0.1'})
    client.post('/api/mirror/token', json={})
    client.post('/api/mirror/accept', json={'enabled': True})
    h1 = load_store('settings')['mirror_token_hash']
    client.post('/api/dns/hosts', json={'name': 'b.lan', 'a': '10.0.0.2'})
    oldest = client.get('/api/changelog').json['entries'][-1]['id']
    assert client.post('/api/changelog/%s/rollback' % oldest, json={}).status_code == 200
    s = load_store('settings')
    assert s['mirror_token_hash'] == h1 and s['mirror_accept'] is True
    assert len(client.get('/api/dns').json['hosts']) == 1     # content DID roll back


def test_must_change_is_enforced_server_side(client, monkeypatch):
    from dnsmaqmgr.core import auth
    monkeypatch.setattr(auth, '_users',
                        lambda: {'admin': {'password': auth.generate_password_hash('oldpass123'),
                                           'role': 'admin', 'must_change': True}})
    r = client.get('/api/dns')
    assert r.status_code == 403 and r.json['must_change'] is True
    assert client.get('/api/me').status_code == 200
    assert client.post('/api/logout').status_code == 200


def test_expected_restart_suppresses_restart_alert(client):
    # `client` only to guarantee the data tree exists (create_app ran).
    from dnsmaqmgr import alerts
    from dnsmaqmgr.dnsmasq import note_expected_restart
    from dnsmaqmgr.core.store import load_store
    note_expected_restart()
    state = load_store('alerts_state')
    assert state['expected_restart_ts'] >= int(time.time()) - 2
    state['counter_sum'] = 1000
    counters = {'hits': 1, 'misses': 1, 'insertions': 1, 'evictions': 0, 'cachesize': 150}
    import dnsmaqmgr.stats as stats
    orig = stats.collect_dns_counters
    stats.collect_dns_counters = lambda: counters
    try:
        from dnsmaqmgr import dnsmasq as dm
        class Up:
            def status(self): return {'running': True, 'state': 'active'}
        orig_ctl = dm._controller
        dm._controller = Up()
        try:
            assert alerts._check_service(state, {'dns_enabled': True}) == []
            state['counter_sum'] = 1000
            state['expected_restart_ts'] = 0
            found = alerts._check_service(state, {'dns_enabled': True})
            assert found and found[0][0] == 'service_restart'
        finally:
            dm._controller = orig_ctl
    finally:
        stats.collect_dns_counters = orig


def test_child_restart_after_kill_is_reaped():
    from dnsmaqmgr.dnsmasq import ChildController
    class Stubborn(ChildController):
        name = 'stubborn'
        def _args(self):
            return ['sh', '-c', 'trap "" TERM; while :; do sleep 1; done']
    c = Stubborn()
    orig_wait = subprocess.Popen.wait
    # shorten the 10 s terminate grace so the test stays quick
    def fast_wait(self, timeout=None):
        return orig_wait(self, timeout=0.3 if timeout else None)
    subprocess.Popen.wait = fast_wait
    try:
        assert c.start() == (True, '')
        old = c._proc.pid
        ok, _ = c.restart()
        assert ok and c._proc.pid != old and c.status()['running']
    finally:
        c.stop()                        # still under the short wait
        subprocess.Popen.wait = orig_wait


def test_blocklist_render_cache_tracks_file_changes(tmp_path):
    from dnsmaqmgr import dnsmasq as dm
    p = tmp_path / 'l_abcdef.domains'
    p.write_text('ads.example\nbad.example\n')
    dm.blocklist_domains_path = lambda lid, _d=str(tmp_path): '%s/%s.domains' % (_d, lid)
    rec = {'id': 'l_abcdef', 'name': 'x', 'url': 'https://x'}
    out = dm.render_blocklist(rec)
    assert 'address=/ads.example/0.0.0.0\naddress=/bad.example/0.0.0.0\n' in out
    time.sleep(0.01)
    p.write_text('only.example\n')
    assert 'only.example' in dm.render_blocklist(rec) and 'ads.example' not in dm.render_blocklist(rec)
    p.unlink()
    assert '(not fetched yet)' in dm.render_blocklist(rec)


def test_non_object_bodies_are_400_everywhere(client):
    for path in ('/api/users', '/api/tokens', '/api/peers', '/api/peers/fetch-fingerprint',
                 '/api/tls/cert', '/api/dns/import', '/api/account/password'):
        r = client.post(path, json=[1, 2])
        assert r.status_code == 400, (path, r.status_code)


def test_upstreams_respect_a_dns_lock(client):
    from dnsmaqmgr.core.store import load_store, save_store
    s = load_store('settings')
    s['mirror_sources'] = {'primary': {'sections': ['dns'], 'serial': 1, 'serials': {'dns': 1}}}
    save_store('settings', s)
    assert client.post('/api/settings', json={'upstreams': ['9.9.9.9']}).status_code == 409
    assert client.post('/api/settings', json={'domain': 'lan2'}).status_code == 200
