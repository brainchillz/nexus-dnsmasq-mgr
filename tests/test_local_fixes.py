"""Regression tests for the 2026-07-29 local-bug fixes."""
import json


# ─── validators (pure) ────────────────────────────────────────────────

def test_validators_reject_trailing_newline():
    from dnsmaqmgr.core.validators import (RE_COMMENT, RE_HOSTNAME, RE_MAC,
                                           RE_DOMAIN, is_upstream)
    assert RE_COMMENT.match('ok') and not RE_COMMENT.match('ok\n')
    assert RE_HOSTNAME.match('web01') and not RE_HOSTNAME.match('web01\n')
    assert RE_MAC.match('aa:bb:cc:dd:ee:ff') and not RE_MAC.match('aa:bb:cc:dd:ee:ff\n')
    assert RE_DOMAIN.match('lab.lan') and not RE_DOMAIN.match('lab.lan\n')


def test_is_upstream_unicode_port_does_not_crash():
    from dnsmaqmgr.core.validators import is_upstream
    assert is_upstream('1.2.3.4') is True
    assert is_upstream('1.2.3.4#53') is True
    assert is_upstream('1.2.3.4#²') is False        # superscript-2: no crash


def test_cache_size_zero_is_rendered():
    from dnsmaqmgr.dnsmasq import render_main
    assert 'cache-size=0' in render_main({'cache_size': 0})
    assert 'cache-size=1000' in render_main({'cache_size': 1000})


# ─── partial update + JSON guards (via the API) ───────────────────────

def test_dns_partial_update_keeps_unsent_fields(client):
    r = client.post('/api/dns/hosts', json={'name': 'nas', 'a': '10.0.0.5',
                                             'aaaa': '2001:db8::5', 'comment': 'storage',
                                             'enabled': False})
    rid = r.get_json()['id']
    # Update only the A record; aaaa/comment/enabled must survive.
    client.post('/api/dns/hosts/' + rid, json={'a': '10.0.0.6'})
    host = next(h for h in client.get('/api/dns').get_json()['hosts'] if h['id'] == rid)
    assert host['a'] == '10.0.0.6'
    assert host['aaaa'] == '2001:db8::5'
    assert host['comment'] == 'storage'
    assert host['enabled'] is False                      # NOT silently re-enabled


def test_non_dict_json_body_is_400_not_500(client):
    r = client.post('/api/dns/hosts', data=json.dumps([1, 2]),
                    content_type='application/json')
    assert r.status_code == 400


def test_interfaces_must_be_a_list(client):
    # A bare string used to iterate into ['e','t','h','0'] and commit garbage.
    r = client.post('/api/settings', json={'interfaces': 'eth0'})
    assert r.status_code == 400
    assert client.post('/api/settings', json={'interfaces': ['eth0']}).status_code == 200


def test_duplicate_ip_static_lease_rejected(client):
    a = client.post('/api/dhcp/static_leases',
                    json={'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.0.0.50'})
    assert a.status_code == 200
    dup = client.post('/api/dhcp/static_leases',
                      json={'mac': 'aa:bb:cc:dd:ee:02', 'ip': '10.0.0.50'})
    assert dup.status_code == 409                         # same IP, different MAC


# ─── mirror per-section serial ────────────────────────────────────────

def test_mirror_incremental_dhcp_push_not_rejected_when_dns_serial_leads(client):
    """The bug: one scalar serial per source rejected a fresh dhcp-only push
    once the dns counter led. With per-section serials it is accepted."""
    secret = client.post('/api/mirror/token').get_json()['token']
    client.post('/api/mirror/accept', json={'enabled': True})
    hdr = {'Authorization': 'Bearer ' + secret}

    # hosts push at a high serial establishes source state.
    r = client.post('/api/mirror/receive', headers=hdr, json={
        'source': 'primary', 'serial': 200, 'serials': {'hosts': 200},
        'sections': ['hosts'], 'data': {'hosts': []}})
    assert r.status_code == 200

    # a later dhcp-only push at a LOW serial must still apply, not 409.
    r = client.post('/api/mirror/receive', headers=hdr, json={
        'source': 'primary', 'serial': 10, 'serials': {'dhcp': 10},
        'sections': ['dhcp'], 'data': {'dhcp': {'ranges': [], 'static_leases': [], 'options': []}}})
    assert r.status_code == 200, r.get_json()

    # but a genuinely stale dhcp push (below the last dhcp serial) is rejected.
    r = client.post('/api/mirror/receive', headers=hdr, json={
        'source': 'primary', 'serial': 5, 'serials': {'dhcp': 5},
        'sections': ['dhcp'], 'data': {'dhcp': {'ranges': [], 'static_leases': [], 'options': []}}})
    assert r.status_code == 409
