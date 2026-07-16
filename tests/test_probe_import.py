"""DHCP probe packet handling + hosts-file import."""
import struct
import socket

from dnsmaqmgr import probe
from dnsmaqmgr.dns import parse_hosts_text


# ─── probe packet build/parse ─────────────────────────────

def _fake_offer(xid, offer_ip='10.0.0.50', server_id='10.0.0.1', msg_type=2):
    pkt = struct.pack('!BBBBIHH', 2, 1, 6, 0, xid, 0, 0)
    pkt += socket.inet_aton('0.0.0.0')            # ciaddr
    pkt += socket.inet_aton(offer_ip)             # yiaddr
    pkt += b'\x00' * 8                            # siaddr/giaddr
    pkt += b'\x00' * 16 + b'\x00' * 64 + b'\x00' * 128
    pkt += b'\x63\x82\x53\x63'
    pkt += bytes([53, 1, msg_type])
    pkt += bytes([54, 4]) + socket.inet_aton(server_id)
    pkt += bytes([255])
    return pkt


def test_discover_packet_shape():
    pkt = probe.build_discover(0x1234, b'\x02\x00\xaa\xbb\xcc\xdd')
    assert len(pkt) >= 300
    assert pkt[0] == 1                                     # BOOTREQUEST
    assert struct.unpack('!I', pkt[4:8])[0] == 0x1234      # xid
    assert struct.unpack('!H', pkt[10:12])[0] == 0x8000    # broadcast flag
    assert pkt[236:240] == b'\x63\x82\x53\x63'             # cookie
    assert bytes([53, 1, 1]) in pkt                        # DISCOVER option


def test_parse_offer_roundtrip():
    got = probe.parse_offer(_fake_offer(0xabcd), 0xabcd)
    assert got == {'offer_ip': '10.0.0.50', 'server_id': '10.0.0.1'}


def test_parse_offer_rejects_wrong_xid_and_type():
    assert probe.parse_offer(_fake_offer(0xabcd), 0x9999) is None
    assert probe.parse_offer(_fake_offer(0xabcd, msg_type=5), 0xabcd) is None  # ACK, not OFFER
    assert probe.parse_offer(b'\x00' * 50, 0xabcd) is None


# ─── hosts-file parsing ───────────────────────────────────

HOSTS_SAMPLE = """
127.0.0.1   localhost
::1         localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes

# infra
10.0.0.5    nas nas.lan          # storage box
10.0.0.6    printer
fd00::5     nas.lan
not-an-ip   junk
10.0.0.7
"""


def test_parse_hosts_text_skips_boilerplate():
    entries, skipped, invalid = parse_hosts_text(HOSTS_SAMPLE)
    assert ('nas', 'a', '10.0.0.5') in entries
    assert ('nas.lan', 'a', '10.0.0.5') in entries
    assert ('printer', 'a', '10.0.0.6') in entries
    assert ('nas.lan', 'aaaa', 'fd00::5') in entries
    assert all(n not in ('localhost', 'ip6-allnodes') for n, _, _ in entries)
    assert skipped == 5          # localhost x2, ip6-localhost, ip6-loopback, ip6-allnodes
    assert invalid == 2          # bad ip line + ip-only line


def test_parse_hosts_text_keeps_boilerplate_when_asked():
    entries, skipped, _ = parse_hosts_text('127.0.0.1 localhost\n', skip_boilerplate=False)
    assert entries == [('localhost', 'a', '127.0.0.1')]
    assert skipped == 0


# ─── import endpoint ──────────────────────────────────────

def test_import_merge_and_replace(client):
    r = client.post('/api/dns/hosts', json={'name': 'nas.lan', 'a': '10.0.0.99'})
    assert r.status_code == 200

    r = client.post('/api/dns/import', json={'text': HOSTS_SAMPLE})
    assert r.status_code == 200
    j = r.json
    assert j['updated'] == 2            # nas.lan: A corrected AND AAAA filled in
    assert j['added'] == 2              # nas, printer
    hosts = {h['name']: h for h in client.get('/api/dns').json['hosts']}
    assert hosts['nas.lan']['a'] == '10.0.0.5'
    assert hosts['nas.lan']['aaaa'] == 'fd00::5'
    assert hosts['printer']['a'] == '10.0.0.6'

    r = client.post('/api/dns/import', json={'text': '10.1.1.1 only.lan\n', 'replace': True})
    assert r.status_code == 200
    hosts = client.get('/api/dns').json['hosts']
    assert [h['name'] for h in hosts] == ['only.lan']


def test_import_rejects_empty_and_garbage(client):
    assert client.post('/api/dns/import', json={'text': ''}).status_code == 400
    assert client.post('/api/dns/import',
                       json={'text': '# nothing\nbad line\n'}).status_code == 400


def test_toggle_conflict_shape(client, monkeypatch):
    """Enabling DHCP with a foreign server present returns the 409 conflict
    contract the UI's confirm flow relies on; force=true bypasses."""
    from dnsmaqmgr import settings as settings_mod
    import dnsmaqmgr.probe as probe_mod
    monkeypatch.setattr(probe_mod, 'probe_for_foreign_dhcp',
                        lambda ifaces: {'servers': [{'server': '10.0.0.1',
                                                     'offer_ip': '10.0.0.50',
                                                     'iface': ''}],
                                        'error': None})
    r = client.post('/api/settings/toggles', json={'dhcp_enabled': True})
    assert r.status_code == 409
    assert r.json['conflict'] is True
    assert r.json['servers'][0]['server'] == '10.0.0.1'
    assert client.get('/api/settings').json['dhcp_enabled'] is False  # unchanged

    r = client.post('/api/settings/toggles', json={'dhcp_enabled': True, 'force': True})
    assert r.status_code == 200 and r.json['dhcp_enabled'] is True
