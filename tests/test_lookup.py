"""Lookup / diagnosis tool: DNS packet parsing, source attribution, and the
shadowing audit (the 2026-08-05 stale-/etc/hosts incident, as a test)."""
import os
import struct

from dnsmaqmgr import lookup


def _dns_response(qid, answers, rcode=0):
    """Build a wire-format response for 'nas.lan' with the given answers
    [(rtype, rdata-bytes)], using a compression pointer for the owner name."""
    header = struct.pack('!HHHHHH', qid, 0x8180 | rcode, 1, len(answers), 0, 0)
    question = b'\x03nas\x03lan\x00' + struct.pack('!HH', 1, 1)
    body = b''
    for rtype, rdata in answers:
        body += b'\xc0\x0c' + struct.pack('!HHIH', rtype, 1, 60, len(rdata)) + rdata
    return header + question + body


def test_parse_response_a_and_cname():
    qid = 0x1234
    buf = _dns_response(qid, [
        (5, b'\x03srv\xc0\x10'),                 # CNAME srv.lan (pointer into 'lan')
        (1, bytes([10, 0, 0, 5])),               # A 10.0.0.5
    ])
    rcode, answers = lookup._parse_response(buf, qid)
    assert rcode == 0
    assert answers[0]['type'] == 'CNAME' and answers[0]['value'] == 'srv.lan'
    assert answers[1] == {'name': 'nas.lan', 'type': 'A', 'ttl': 60, 'value': '10.0.0.5'}


def test_parse_response_rejects_wrong_qid_and_garbage():
    buf = _dns_response(1, [(1, bytes([10, 0, 0, 5]))])
    assert lookup._parse_response(buf, 2) == (None, [])
    assert lookup._parse_response(b'\x00' * 5, 1) == (None, [])
    # compression pointer loop must terminate
    qid = 7
    evil = struct.pack('!HHHHHH', qid, 0x8180, 0, 1, 0, 0) + b'\xc0\x00'
    lookup._parse_response(evil, qid)  # must not hang or raise


def _fake_answers(monkeypatch, table):
    """Patch query_dnsmasq: table maps qtype-code -> (rcode, answers)."""
    monkeypatch.setattr(lookup, 'query_dnsmasq',
                        lambda name, qtype, **kw: table.get(qtype, (0, [])))


def test_lookup_attributes_managed_and_stray_hosts(client, monkeypatch, tmp_path):
    """The incident: UI shows one A record, the server answers two — the stray
    one must be attributed to /etc/hosts with a file+line and a warning."""
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    etc = tmp_path / 'hosts'
    etc.write_text('127.0.0.1 localhost\n10.0.0.99  nas.lan  # stale!\n')
    monkeypatch.setattr(lookup, 'ETC_HOSTS', str(etc))
    _fake_answers(monkeypatch, {1: (0, [
        {'name': 'nas.lan', 'type': 'A', 'ttl': 0, 'value': '10.0.0.5'},
        {'name': 'nas.lan', 'type': 'A', 'ttl': 0, 'value': '10.0.0.99'},
    ])})

    r = client.get('/api/lookup?name=nas.lan')
    assert r.status_code == 200
    by_val = {a['value']: a['source'] for a in r.json['answers']}
    assert by_val['10.0.0.5']['kind'] == 'host' and by_val['10.0.0.5']['managed']
    stray = by_val['10.0.0.99']
    assert stray['kind'] == 'etc-hosts' and stray['warn'] and stray['line'] == 2
    assert any('not managed' in w for w in r.json['warnings'])


def test_lookup_reports_shadowed_managed_record(client, monkeypatch):
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    _fake_answers(monkeypatch, {1: (0, [
        {'name': 'nas.lan', 'type': 'A', 'ttl': 0, 'value': '10.0.0.99'}])})
    monkeypatch.setattr(lookup, 'ETC_HOSTS', '/nonexistent')
    r = client.get('/api/lookup?name=nas.lan')
    assert any('did not return it' in w for w in r.json['warnings'])


def test_lookup_upstream_and_validation(client, monkeypatch):
    _fake_answers(monkeypatch, {1: (0, [
        {'name': 'example.com', 'type': 'A', 'ttl': 300, 'value': '93.184.216.34'}])})
    monkeypatch.setattr(lookup, 'ETC_HOSTS', '/nonexistent')
    r = client.get('/api/lookup?name=example.com')
    assert r.json['answers'][0]['source']['kind'] == 'upstream'
    assert client.get('/api/lookup?name=bad name!').status_code == 400
    assert client.get('/api/lookup').status_code == 400


def test_audit_flags_etc_hosts_shadowing(client, monkeypatch, tmp_path):
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    etc = tmp_path / 'hosts'
    etc.write_text('10.0.0.99 nas.lan\n10.0.0.5 nas.lan\n')
    monkeypatch.setattr(lookup, 'ETC_HOSTS', str(etc))
    r = client.get('/api/lookup/audit')
    confs = r.json['conflicts']
    # line 1 conflicts (wrong IP); line 2 agrees with the managed record
    assert len(confs) == 1
    assert confs[0]['kind'] == 'etc-hosts' and confs[0]['line'] == 1
    assert confs[0]['ip'] == '10.0.0.99' and confs[0]['expected'] == '10.0.0.5'


def test_audit_respects_no_hosts_and_scans_foreign_conf(client, monkeypatch, tmp_path):
    client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.5'})
    etc = tmp_path / 'hosts'
    etc.write_text('10.0.0.99 nas.lan\n')
    monkeypatch.setattr(lookup, 'ETC_HOSTS', str(etc))
    foreign = tmp_path / 'zz-other.conf'
    foreign.write_text('# comment\naddress=/nas.lan/1.2.3.4\n')
    monkeypatch.setenv('DNSMAQ_FOREIGN_CONF', str(foreign))

    r = client.get('/api/lookup/audit')
    kinds = {c['kind'] for c in r.json['conflicts']}
    assert kinds == {'etc-hosts', 'foreign-conf'}

    # no-hosts on: the /etc/hosts entry no longer matters
    client.post('/api/settings', json={'no_hosts': True})
    r = client.get('/api/lookup/audit')
    assert {c['kind'] for c in r.json['conflicts']} == {'foreign-conf'}


def test_no_hosts_renders(client):
    client.post('/api/settings', json={'no_hosts': True})
    cfg = client.get('/api/dnsmasq/config').json['files']
    assert 'no-hosts' in cfg['dnsmasq.d/10-dns.conf']
    client.post('/api/settings', json={'no_hosts': False})
    assert 'no-hosts' not in client.get('/api/dnsmasq/config').json['files']['dnsmasq.d/10-dns.conf']
