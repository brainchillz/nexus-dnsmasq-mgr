"""Query log parsing: journalctl/stderr prefixes, log-queries=extra
correlation, aggregates."""
from dnsmaqmgr.querylog import parse_query_log

EXTRA_LINES = [
    'Aug  5 10:00:01 gw dnsmasq[123]: 7 192.168.1.10/51000 query[A] nas.lan from 192.168.1.10',
    'Aug  5 10:00:01 gw dnsmasq[123]: 7 192.168.1.10/51000 /opt/dnsmaq-mgr/render/hosts.d/managed-hosts nas.lan is 10.0.0.5',
    'Aug  5 10:00:02 gw dnsmasq[123]: 8 192.168.1.11/40000 query[A] ads.example.com from 192.168.1.11',
    'Aug  5 10:00:02 gw dnsmasq[123]: 8 192.168.1.11/40000 config ads.example.com is 0.0.0.0',
    'Aug  5 10:00:03 gw dnsmasq[123]: 9 192.168.1.10/51001 query[AAAA] missing.lan from 192.168.1.10',
    'Aug  5 10:00:03 gw dnsmasq[123]: 9 192.168.1.10/51001 config missing.lan is NXDOMAIN',
    'Aug  5 10:00:04 gw dnsmasq[123]: 10 192.168.1.12/5353 query[A] example.com from 192.168.1.12',
    'Aug  5 10:00:04 gw dnsmasq[123]: 10 192.168.1.12/5353 forwarded example.com to 1.1.1.1',
    'Aug  5 10:00:04 gw dnsmasq[123]: 10 192.168.1.12/5353 reply example.com is 93.184.216.34',
    'Aug  5 10:00:05 gw dnsmasq[123]: 11 192.168.1.12/5354 query[A] example.com from 192.168.1.12',
    'Aug  5 10:00:05 gw dnsmasq[123]: 11 192.168.1.12/5354 cached example.com is 93.184.216.34',
]


def test_parse_extra_format_correlates():
    entries, agg = parse_query_log(EXTRA_LINES)
    assert len(entries) == 5
    by_name = {}
    for e in entries:
        by_name.setdefault(e['name'], e)

    nas = by_name['nas.lan']
    assert nas['status'] == 'answered'
    assert nas['answers'][0]['source'] == 'hosts'

    ads = by_name['ads.example.com']
    assert ads['status'] == 'blocked'

    missing = by_name['missing.lan']
    assert missing['status'] == 'nxdomain'

    ex = by_name['example.com']            # first example.com query
    assert ex['upstreams'] == ['1.1.1.1']
    assert ex['answers'][0]['source'] == 'upstream'

    assert agg['queries'] == 5
    assert agg['blocked'] == 1 and agg['top_blocked'][0][0] == 'ads.example.com'
    assert agg['nxdomain'] == 1
    assert dict(agg['top_clients'])['192.168.1.12'] == 2
    assert dict(agg['upstreams'])['1.1.1.1'] == 1
    assert dict(agg['top_domains'])['example.com'] == 2


def test_parse_plain_format_still_aggregates():
    """Without log-queries=extra there is no serial/client prefix — entries
    still parse; answers just aren't correlated to their query."""
    lines = [
        'dnsmasq: query[A] nas.lan from 192.168.1.10',
        'dnsmasq: forwarded nas.lan to 9.9.9.9',
        'dnsmasq: reply nas.lan is 10.0.0.5',
    ]
    entries, agg = parse_query_log(lines)
    assert len(entries) == 1 and entries[0]['name'] == 'nas.lan'
    assert agg['queries'] == 1
    assert dict(agg['upstreams'])['9.9.9.9'] == 1


def test_parse_ignores_noise():
    lines = [
        'Aug  5 10:00:00 gw dnsmasq[123]: started, version 2.90',
        'Aug  5 10:00:00 gw dnsmasq-dhcp[123]: DHCPDISCOVER(eth0) aa:bb:cc:dd:ee:ff',
        'garbage',
        '',
    ]
    entries, agg = parse_query_log(lines)
    assert entries == [] and agg['queries'] == 0


def test_querylog_route(client):
    r = client.get('/api/querylog')
    assert r.status_code == 200
    assert r.json['enabled'] is False        # log_queries defaults off
    assert r.json['queries'] == 0
    client.post('/api/settings', json={'log_queries': True})
    assert client.get('/api/querylog').json['enabled'] is True
