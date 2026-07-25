"""UniFi Static DNS adapter: record mapping, diffing, the Device Local DNS
overlap rules, and the peer plumbing that drives it.

FakeGateway stands in for a real gateway at the HTTP layer, so the client's
request/response handling is exercised rather than mocked away — including
the StaticDnsOverlapsWithDeviceLocalDns rejection that shapes the whole design.
"""
import json

from dnsmaqmgr import unifi


class FakeGateway:
    """Minimal UniFi OS: auth, Static DNS CRUD, client Local DNS Records."""

    def __init__(self, static=None, clients=None, flavour='v2', fail_on=()):
        self.records = {}          # id -> record dict
        self.clients = {}          # id -> client dict
        self.flavour = flavour
        self.fail_on = set(fail_on)  # names whose create should 500
        self.logged_in = False
        self.calls = []
        self._n = 0
        for name, rtype, value in (static or []):
            self._add(name, rtype, value)
        for name, ip in (clients or []):
            self._n += 1
            cid = 'c%d' % self._n
            self.clients[cid] = {'_id': cid, 'local_dns_record': name,
                                 'local_dns_record_enabled': True,
                                 'fixed_ip': ip, 'use_fixedip': True}

    def _add(self, name, rtype, value):
        self._n += 1
        rid = 'r%d' % self._n
        self.records[rid] = {'_id': rid, 'key': name, 'record_type': rtype,
                             'value': value, 'enabled': True}
        return rid

    def _owned(self, name):
        return any(c['local_dns_record'].lower() == name.lower()
                   and c.get('local_dns_record_enabled')
                   for c in self.clients.values())

    # -- transport ---------------------------------------------------------

    def request(self, method, path, body=None, headers=None):
        self.calls.append((method, path))
        h = {'x-csrf-token': 'csrf-1'}

        if path == '/api/auth/login':
            self.logged_in = True
            return 200, {'unique_id': 'x'}, h
        if path == '/api/auth/logout':
            return 200, {}, h
        if not self.logged_in:
            return 401, {'error': 'Unauthorized'}, h

        static_v2 = '/proxy/network/v2/api/site/default/static-dns'
        static_v1 = '/proxy/network/api/s/default/rest/staticdns'
        base = static_v2 if self.flavour == 'v2' else static_v1
        # Only the configured flavour answers; the others 404, so discovery runs.
        if path.startswith(static_v2) and self.flavour != 'v2':
            return 404, {'error': 'not found'}, h
        if path.startswith(static_v1) and self.flavour != 'v1':
            return 404, {'error': 'not found'}, h

        if path == base:
            if method == 'GET':
                items = list(self.records.values())
                return 200, (items if self.flavour == 'v2'
                             else {'meta': {'rc': 'ok'}, 'data': items}), h
            if method == 'POST':
                name = body['key']
                if self._owned(name):
                    return 400, {'code': 'api.err.StaticDnsOverlapsWithDeviceLocalDns',
                                 'message': 'Overlaps with Device Local DNS'}, h
                if name in self.fail_on:
                    return 500, {'error': 'boom'}, h
                self._add(name, body['record_type'], body['value'])
                return 200, {'meta': {'rc': 'ok'}}, h

        if path.startswith(base + '/'):
            rid = path.rsplit('/', 1)[1]
            if rid not in self.records:
                return 404, {'error': 'no such record'}, h
            if method == 'PUT':
                self.records[rid].update(body)
                return 200, {'meta': {'rc': 'ok'}}, h
            if method == 'DELETE':
                del self.records[rid]
                return 200, {'meta': {'rc': 'ok'}}, h

        users = '/proxy/network/api/s/default/rest/user'
        if path == users and method == 'GET':
            return 200, {'data': list(self.clients.values())}, h
        if path.startswith(users + '/') and method == 'PUT':
            cid = path.rsplit('/', 1)[1]
            if cid not in self.clients:
                return 404, {'error': 'no such client'}, h
            self.clients[cid].update(body)
            return 200, {'meta': {'rc': 'ok'}}, h

        return 404, {'error': 'unhandled %s %s' % (method, path)}, h

    def close(self):
        pass

    # -- assertions helpers -----------------------------------------------

    def names(self):
        return {(r['key'].lower(), r['record_type']): r['value']
                for r in self.records.values()}


def _client(gw, site='default'):
    c = unifi.UniFiClient(gw, site)
    c.login('admin', 'pw')
    return c


HOSTS = [
    {'id': 'h_1', 'name': 'a.lan', 'a': '10.0.0.1', 'aaaa': '', 'enabled': True},
    {'id': 'h_2', 'name': 'b.lan', 'a': '10.0.0.2', 'aaaa': '', 'enabled': True},
]


# ─── record mapping ────────────────────────────────────────────────────────

def test_records_from_hosts_maps_a_and_aaaa():
    recs = unifi.records_from_hosts([
        {'name': 'dual.lan', 'a': '10.0.0.5', 'aaaa': '2001:db8::5', 'enabled': True},
        {'name': 'v6.lan', 'a': '', 'aaaa': '2001:db8::6', 'enabled': True},
        {'name': 'off.lan', 'a': '10.0.0.7', 'enabled': False},
        {'name': '', 'a': '10.0.0.8', 'enabled': True},
    ])
    assert ('dual.lan', 'A', '10.0.0.5') in recs
    assert ('dual.lan', 'AAAA', '2001:db8::5') in recs
    assert ('v6.lan', 'AAAA', '2001:db8::6') in recs
    assert not [r for r in recs if r[0] in ('off.lan', '')]


def test_records_from_hosts_first_mapping_wins():
    recs = unifi.records_from_hosts([
        {'name': 'dup.lan', 'a': '10.0.0.1', 'enabled': True},
        {'name': 'DUP.lan', 'a': '10.0.0.2', 'enabled': True},
    ])
    assert [r[2] for r in recs] == ['10.0.0.1']


# ─── diffing ───────────────────────────────────────────────────────────────

def test_plan_creates_updates_deletes():
    static = {('keep.lan', 'A'): {'id': 'r1', 'value': '10.0.0.1'},
              ('drift.lan', 'A'): {'id': 'r2', 'value': '10.0.0.9'},
              ('gone.lan', 'A'): {'id': 'r3', 'value': '10.0.0.3'}}
    p = unifi.plan([('keep.lan', 'A', '10.0.0.1'), ('drift.lan', 'A', '10.0.0.2'),
                    ('new.lan', 'A', '10.0.0.4')], static, {})
    assert [x[0] for x in p['create']] == ['new.lan']
    assert [x[1] for x in p['update']] == ['drift.lan']
    assert [x[1] for x in p['delete']] == ['gone.lan']
    assert p['unchanged'] == 1


def test_plan_without_mirror_keeps_extras():
    static = {('gone.lan', 'A'): {'id': 'r1', 'value': '10.0.0.3'}}
    p = unifi.plan([('new.lan', 'A', '10.0.0.4')], static, {}, mirror=False)
    assert p['delete'] == [] and len(p['create']) == 1


def test_plan_classifies_client_dns_overlap():
    client_dns = {'same.lan': {'id': 'c1', 'ip': '10.0.0.1'},
                  'differs.lan': {'id': 'c2', 'ip': '10.0.0.9'}}
    p = unifi.plan([('same.lan', 'A', '10.0.0.1'), ('differs.lan', 'A', '10.0.0.2')],
                   {}, client_dns)
    assert p['covered'] == ['same.lan']
    assert p['conflicts'] == [('differs.lan', '10.0.0.2', '10.0.0.9')]
    assert p['create'] == [] and p['claim'] == []


def test_plan_claim_takes_over_both_cases():
    client_dns = {'same.lan': {'id': 'c1', 'ip': '10.0.0.1'},
                  'differs.lan': {'id': 'c2', 'ip': '10.0.0.9'}}
    p = unifi.plan([('same.lan', 'A', '10.0.0.1'), ('differs.lan', 'A', '10.0.0.2')],
                   {}, client_dns, claim=True)
    assert sorted(x[0] for x in p['claim']) == ['differs.lan', 'same.lan']
    assert p['covered'] == [] and p['conflicts'] == []


# ─── client behaviour against the fake gateway ─────────────────────────────

def test_endpoint_discovery_v2_and_v1():
    for flavour in ('v2', 'v1'):
        gw = FakeGateway(static=[('x.lan', 'A', '10.0.0.1')], flavour=flavour)
        c = _client(gw)
        assert c.list_static()[('x.lan', 'A')]['value'] == '10.0.0.1'


def test_list_static_ignores_non_address_types():
    gw = FakeGateway()
    gw._add('alias.lan', 'CNAME', 'real.lan')
    gw._add('real.lan', 'A', '10.0.0.1')
    c = _client(gw)
    keys = set(_client(gw).list_static())
    assert ('real.lan', 'A') in keys
    assert not [k for k in keys if k[1] == 'CNAME']


def test_login_failure_is_reported():
    gw = FakeGateway()

    def deny(method, path, body=None, headers=None):
        return 401, {'error': 'Unauthorized'}, {}
    gw.request = deny
    try:
        unifi.UniFiClient(gw).login('admin', 'bad')
        assert False, 'expected UniFiError'
    except unifi.UniFiError as e:
        assert 'bad username or password' in str(e)


def test_create_overlap_raises_overlap():
    gw = FakeGateway(clients=[('owned.lan', '10.0.0.1')])
    c = _client(gw)
    try:
        c.create('owned.lan', 'A', '10.0.0.1')
        assert False, 'expected Overlap'
    except unifi.Overlap:
        pass


# ─── end-to-end sync ───────────────────────────────────────────────────────

def _peer(**kw):
    p = {'url': 'https://gw.example', 'verify': 'insecure', 'unifi_site': 'default',
         'unifi_username': 'admin', 'unifi_password': 'pw'}
    p.update(kw)
    return p


def test_sync_creates_and_mirrors_deletes():
    gw = FakeGateway(static=[('stale.lan', 'A', '10.0.0.9')])
    s = unifi.sync_hosts(_peer(), HOSTS, client=_client(gw))
    assert (s['created'], s['deleted'], s['failed']) == (2, 1, 0)
    assert gw.names() == {('a.lan', 'A'): '10.0.0.1', ('b.lan', 'A'): '10.0.0.2'}


def test_sync_is_idempotent():
    gw = FakeGateway()
    unifi.sync_hosts(_peer(), HOSTS, client=_client(gw))
    s = unifi.sync_hosts(_peer(), HOSTS, client=_client(gw))
    assert (s['created'], s['updated'], s['deleted']) == (0, 0, 0)
    assert s['unchanged'] == 2 and unifi.status_line(s) == 'ok'


def test_sync_updates_changed_address():
    gw = FakeGateway(static=[('a.lan', 'A', '10.0.0.99'), ('b.lan', 'A', '10.0.0.2')])
    s = unifi.sync_hosts(_peer(), HOSTS, client=_client(gw))
    assert s['updated'] == 1 and gw.names()[('a.lan', 'A')] == '10.0.0.1'


def test_sync_keeps_extras_when_mirror_off():
    gw = FakeGateway(static=[('stale.lan', 'A', '10.0.0.9')])
    s = unifi.sync_hosts(_peer(unifi_delete_extra=False), HOSTS, client=_client(gw))
    assert s['deleted'] == 0 and ('stale.lan', 'A') in gw.names()


def test_sync_reports_conflict_without_claim():
    gw = FakeGateway(clients=[('a.lan', '10.0.0.99')])
    s = unifi.sync_hosts(_peer(), HOSTS, client=_client(gw))
    assert s['conflicts'] == [('a.lan', '10.0.0.1', '10.0.0.99')]
    assert 'client DNS holds a.lan at 10.0.0.99' in unifi.status_line(s)
    assert ('a.lan', 'A') not in gw.names()  # not created


def test_sync_covered_when_client_dns_agrees():
    gw = FakeGateway(clients=[('a.lan', '10.0.0.1')])
    s = unifi.sync_hosts(_peer(), HOSTS, client=_client(gw))
    assert s['covered'] == 1 and s['conflicts'] == []
    assert unifi.status_line(s) == 'ok'


def test_sync_claim_releases_client_record_and_creates_static():
    gw = FakeGateway(clients=[('a.lan', '10.0.0.99')])
    s = unifi.sync_hosts(_peer(unifi_claim_client_dns=True), HOSTS, client=_client(gw))
    assert s['claimed'] == 1 and s['failed'] == 0
    assert gw.names()[('a.lan', 'A')] == '10.0.0.1'
    assert gw.clients['c1']['local_dns_record_enabled'] is False


def test_claim_preserves_dhcp_reservation():
    gw = FakeGateway(clients=[('a.lan', '10.0.0.99')])
    unifi.sync_hosts(_peer(unifi_claim_client_dns=True), HOSTS, client=_client(gw))
    c = gw.clients['c1']
    assert c['fixed_ip'] == '10.0.0.99' and c['use_fixedip'] is True


def test_sync_counts_write_failures_without_aborting():
    gw = FakeGateway(fail_on=('a.lan',))
    s = unifi.sync_hosts(_peer(), HOSTS, client=_client(gw))
    assert s['failed'] == 1 and s['created'] == 1  # b.lan still written
    assert 'a.lan' in s['errors'][0]
    assert unifi.status_line(s).startswith('error: 1 write(s) failed')


def test_sync_refuses_to_wipe_on_empty_hosts():
    gw = FakeGateway(static=[('x.lan', 'A', '10.0.0.1')])
    try:
        unifi.sync_hosts(_peer(), [], client=_client(gw))
        assert False, 'expected UniFiError'
    except unifi.UniFiError as e:
        assert 'refusing to wipe' in str(e)
    assert ('x.lan', 'A') in gw.names()


def test_sync_empty_hosts_allowed_when_not_mirroring():
    gw = FakeGateway(static=[('x.lan', 'A', '10.0.0.1')])
    s = unifi.sync_hosts(_peer(unifi_delete_extra=False), [], client=_client(gw))
    assert s['failed'] == 0 and ('x.lan', 'A') in gw.names()


# ─── peer plumbing ─────────────────────────────────────────────────────────

def test_unifi_peer_validation_and_secret_hiding(client):
    r = client.post('/api/peers', json={
        'name': 'greatwall', 'kind': 'unifi', 'url': 'https://192.168.34.1',
        'unifi_username': 'admin', 'unifi_password': 'secret', 'sections': ['hosts'],
        'verify': 'insecure'})
    assert r.status_code == 200, r.get_data(as_text=True)

    peers = client.get('/api/peers').json['peers']
    assert peers[0]['kind'] == 'unifi'
    assert peers[0]['unifi_password'] is True      # never echoed back
    assert 'token' not in peers[0] or peers[0]['token'] is False


def test_unifi_peer_requires_credentials_and_hosts_section():
    from dnsmaqmgr.peers import _validate_peer
    rec, e = _validate_peer({'name': 'gw', 'kind': 'unifi', 'url': 'https://10.0.0.1',
                             'sections': ['hosts'], 'unifi_username': 'admin'})
    assert rec is None and 'password' in e.lower()

    rec, e = _validate_peer({'name': 'gw', 'kind': 'unifi', 'url': 'https://10.0.0.1',
                             'sections': ['dhcp'], 'unifi_username': 'a',
                             'unifi_password': 'b'})
    assert rec is None and 'hosts' in e.lower()


def test_unifi_peer_keeps_password_when_blank_on_edit(client):
    r = client.post('/api/peers', json={
        'name': 'gw', 'kind': 'unifi', 'url': 'https://10.0.0.1',
        'unifi_username': 'admin', 'unifi_password': 'secret',
        'sections': ['hosts'], 'verify': 'insecure'})
    pid = r.json['id']
    assert client.post('/api/peers/%s' % pid, json={
        'name': 'gw', 'kind': 'unifi', 'url': 'https://10.0.0.1',
        'unifi_username': 'admin', 'unifi_password': '',
        'sections': ['hosts'], 'verify': 'insecure'}).status_code == 200

    from dnsmaqmgr.core.store import load_store
    assert load_store('peers')['peers'][0]['unifi_password'] == 'secret'


def test_fingerprint_fetch_uses_the_right_default_port():
    """A gateway's API is on 443, not the 8443 a DNSMAQ-MGR peer uses."""
    from dnsmaqmgr.peers import _split_url, default_port_for
    assert _split_url('https://10.0.0.1', default_port_for('unifi')) == ('10.0.0.1', 443)
    assert _split_url('https://10.0.0.1', default_port_for('dnsmaq')) == ('10.0.0.1', 8443)
    # An explicit port always wins.
    assert _split_url('https://10.0.0.1:8080', default_port_for('unifi')) == ('10.0.0.1', 8080)


def test_dnsmaq_peer_still_requires_token():
    from dnsmaqmgr.peers import _validate_peer
    rec, e = _validate_peer({'name': 'p', 'url': 'https://10.0.0.1',
                             'sections': ['hosts']})
    assert rec is None and 'token' in e.lower()


def test_push_to_unifi_peer_syncs_host_store(client, monkeypatch):
    """A UniFi peer pushes the host store through the adapter, and the peer's
    last_status reflects the result."""
    from dnsmaqmgr import peers as peers_mod
    from dnsmaqmgr.core.store import load_store, save_store

    gw = FakeGateway()
    monkeypatch.setattr(peers_mod, '_unifi_client',
                        lambda peer: _client(gw))

    d = load_store('dns')
    d['hosts'] = list(HOSTS)
    save_store('dns', d)

    pid = client.post('/api/peers', json={
        'name': 'gw', 'kind': 'unifi', 'url': 'https://10.0.0.1',
        'unifi_username': 'admin', 'unifi_password': 'pw',
        'sections': ['hosts'], 'verify': 'insecure'}).json['id']

    r = client.post('/api/peers/%s/sync' % pid, json={})
    assert r.status_code == 200, r.get_data(as_text=True)
    assert gw.names() == {('a.lan', 'A'): '10.0.0.1', ('b.lan', 'A'): '10.0.0.2'}

    peer = load_store('peers')['peers'][0]
    assert peer['last_status'] == 'ok' and peer['last_sync']


def test_push_to_unifi_peer_surfaces_conflict(client, monkeypatch):
    from dnsmaqmgr import peers as peers_mod
    from dnsmaqmgr.core.store import load_store, save_store

    gw = FakeGateway(clients=[('a.lan', '10.0.0.99')])
    monkeypatch.setattr(peers_mod, '_unifi_client', lambda peer: _client(gw))

    d = load_store('dns')
    d['hosts'] = list(HOSTS)
    save_store('dns', d)

    pid = client.post('/api/peers', json={
        'name': 'gw', 'kind': 'unifi', 'url': 'https://10.0.0.1',
        'unifi_username': 'admin', 'unifi_password': 'pw',
        'sections': ['hosts'], 'verify': 'insecure'}).json['id']

    assert client.post('/api/peers/%s/sync' % pid, json={}).status_code == 502
    assert 'client DNS holds' in load_store('peers')['peers'][0]['last_status']
