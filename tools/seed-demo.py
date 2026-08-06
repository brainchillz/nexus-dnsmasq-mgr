#!/usr/bin/env python3
"""Seed a throwaway DNSMAQ-MGR instance with the README demo dataset.

Reproduces the docs/screenshots content: seven .lan host records, three
CNAMEs, an ad-sink domain override, two DHCP pools (lan/iot) with static
leases and options, 91 fabricated live leases, and ~50 cache-warming DNS
queries so the Overview stat cards show real numbers.

Run it against an ISOLATED container — the demo enables the DHCP server,
which must never reach a real LAN. The bridge network plus NET_ADMIN (which
dnsmasq needs for DHCP) is the safe recipe:

    docker run -d --name dnsmaq-demo --hostname dnsmasq-demo \\
      --cap-add=NET_ADMIN -p 127.0.0.1:8094:8094 \\
      -e DNSMAQ_TLS=0 -e DNSMAQ_PORT=8094 -e DNSMAQ_ADMIN_PASSWORD=demopass123 \\
      -e DNSMAQ_DATA_DIR=/data -e DNSMAQ_SUPERVISE=1 -e DNSMAQ_NO_SUDO=1 \\
      ghcr.io/brainchillz/nexus-dnsmasq-mgr:latest
    python3 tools/seed-demo.py --base http://127.0.0.1:8094 --password demopass123
    docker cp /tmp/demo.leases dnsmaq-demo:/data/leases/dnsmasq.leases

Then screenshot Overview / DNS Overrides / DHCP at 1440x900 and drop the
PNGs into docs/screenshots/.
"""
import argparse
import http.cookiejar
import json
import random
import socket
import time
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument('--base', default='http://127.0.0.1:8094')
ap.add_argument('--password', default='demopass123')
ap.add_argument('--leases-out', default='/tmp/demo.leases')
ap.add_argument('--dns-host', default='127.0.0.1',
                help='where to send the cache-warming queries (container: exec inside)')
ap.add_argument('--dns-port', type=int, default=0,
                help='0 = skip the warm-up (use docker exec when the port is not published)')
args = ap.parse_args()

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def post(path, body):
    req = urllib.request.Request(args.base + path, data=json.dumps(body).encode(),
                                 headers={'Content-Type': 'application/json'})
    try:
        with opener.open(req) as r:
            return json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        print('FAIL', path, e.code, e.read().decode(errors='replace')[:120])


post('/api/login', {'username': 'admin', 'password': args.password})
print('login ok')

for name, a, aaaa, comment in (
    ('nas.lan', '10.0.0.10', 'fd00::10', 'Synology'),
    ('proxmox.lan', '10.0.0.5', '', 'PVE host'),
    ('unifi.lan', '10.0.0.2', '', 'controller'),
    ('ha.lan', '10.0.0.21', '', 'Home Assistant'),
    ('grafana.lan', '10.0.0.22', '', ''),
    ('printer.lan', '10.0.0.31', '', 'laser, upstairs'),
    ('octopi.lan', '10.0.0.33', '', '3D printer'),
):
    post('/api/dns/hosts', {'name': name, 'a': a, 'aaaa': aaaa, 'comment': comment})

for alias, target in (('www.lan', 'nas.lan'), ('media.lan', 'nas.lan'),
                      ('dashboard.lan', 'grafana.lan')):
    post('/api/dns/cnames', {'alias': alias, 'target': target, 'comment': ''})

post('/api/dns/addresses', {'domain': 'doubleclick.net', 'ip': '0.0.0.0', 'comment': 'ad sink'})

post('/api/dhcp/ranges', {'start': '10.0.0.100', 'end': '10.0.0.199', 'netmask': '',
                          'lease': '12h', 'tag': 'lan', 'interface': ''})
post('/api/dhcp/ranges', {'start': '10.0.20.50', 'end': '10.0.20.150', 'netmask': '',
                          'lease': '24h', 'tag': 'iot', 'interface': ''})
for mac, ip, hostname in (('9c:6b:00:11:22:31', '10.0.0.31', 'printer'),
                          ('e4:5f:01:aa:10:21', '10.0.0.21', 'ha'),
                          ('b8:27:eb:44:09:33', '10.0.0.33', 'octopi')):
    post('/api/dhcp/static_leases', {'mac': mac, 'ip': ip, 'hostname': hostname, 'tag': 'lan'})
post('/api/dhcp/options', {'option': 'option:router', 'value': '10.0.0.1', 'tag': 'lan'})
post('/api/dhcp/options', {'option': '6', 'value': '10.0.0.53', 'tag': 'iot'})
post('/api/settings/toggles', {'dhcp_enabled': True, 'force': True})
print('seeded')

# 91 live leases (57 lan + 34 iot) for docker cp into the leases file.
NAMES = ['pixel-7', 'macbook-air', 'thinkpad', 'ipad', 'appletv', 'shield',
         'eero', 'chromecast', 'work-laptop', 'steamdeck', 'switch', 'ps5']
IOT = ['esp32', 'shelly-plug', 'tasmota', 'hue-bridge', 'cam-front', 'cam-back',
       'thermostat', 'doorbell', 'sonoff', 'wled']
now = int(time.time())
lines = []
for i in range(57):
    mac = '5e:%02x:00:4c:%02x:%02x' % (i % 256, (i * 7) % 256, (i * 13) % 256)
    lines.append('%d %s 10.0.0.%d %s-%d *' % (now + 3600 + i * 240, mac, 100 + i,
                                              NAMES[i % len(NAMES)], i % 9 + 1))
for i in range(34):
    mac = '8c:%02x:11:be:%02x:%02x' % (i % 256, (i * 5) % 256, (i * 11) % 256)
    lines.append('%d %s 10.0.20.%d %s-%d *' % (now + 7200 + i * 300, mac, 50 + i,
                                               IOT[i % len(IOT)], i % 6 + 1))
open(args.leases_out, 'w').write('\n'.join(lines) + '\n')
print('leases file: %s (%d)' % (args.leases_out, len(lines)))


def raw_query(name, host, port):
    tid = random.randint(0, 65535).to_bytes(2, 'big')
    parts = b''.join(len(p).to_bytes(1, 'big') + p.encode() for p in name.split('.'))
    pkt = tid + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + parts + b'\x00\x00\x01\x00\x01'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.sendto(pkt, (host, port))
    try:
        s.recv(512)
    except OSError:
        pass
    s.close()


if args.dns_port:
    for i in range(51):
        raw_query(['nas.lan', 'proxmox.lan', 'ha.lan', 'grafana.lan', 'www.lan'][i % 5],
                  args.dns_host, args.dns_port)
    print('cache warmed (51 queries)')
