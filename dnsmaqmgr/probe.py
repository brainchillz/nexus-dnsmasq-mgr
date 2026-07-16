"""Active DHCP-server probe: broadcast a real DHCPDISCOVER and collect the
OFFERs that come back. Used as a guard when the DHCP feature is being
enabled — if a foreign server answers, the UI warns before going live with a
second server on the same network.

Binding UDP port 68 needs privilege, so the probe runs as a CLI subcommand
(`app.py dhcp-probe [iface...]`) invoked through run() — root directly in
Docker, via an argument-pinned sudoers line on bare metal. Everything here is
best-effort: a probe that cannot run must never block the toggle, only skip
the warning.
"""
import os
import re
import json
import time
import struct
import secrets
import socket

from .core.runcmd import run

PROBE_TIMEOUT = 2.0
SO_BINDTODEVICE = 25


def _iface_mac(iface):
    try:
        with open('/sys/class/net/%s/address' % iface) as f:
            return bytes.fromhex(f.read().strip().replace(':', ''))
    except (OSError, ValueError):
        return None


def _random_mac():
    # Locally administered, unicast — never collides with real hardware.
    return bytes([0x02, 0x00]) + secrets.token_bytes(4)


def build_discover(xid, mac):
    pkt = struct.pack('!BBBBIHH', 1, 1, 6, 0, xid, 0, 0x8000)  # bootp header, broadcast flag
    pkt += b'\x00' * 16                                        # ciaddr/yiaddr/siaddr/giaddr
    pkt += mac + b'\x00' * (16 - len(mac))                     # chaddr
    pkt += b'\x00' * 64 + b'\x00' * 128                        # sname, file
    pkt += b'\x63\x82\x53\x63'                                 # magic cookie
    pkt += bytes([53, 1, 1])                                   # DHCPDISCOVER
    pkt += bytes([55, 3, 1, 3, 6])                             # param request: mask, router, dns
    pkt += bytes([255])
    return pkt + b'\x00' * max(0, 300 - len(pkt))              # min packet padding


def parse_offer(buf, xid):
    """Return {'offer_ip','server_id'} if buf is a DHCPOFFER for our xid."""
    if len(buf) < 244 or buf[0] != 2:
        return None
    if struct.unpack('!I', buf[4:8])[0] != xid:
        return None
    if buf[236:240] != b'\x63\x82\x53\x63':
        return None
    offer_ip = socket.inet_ntoa(buf[16:20])
    msg_type, server_id = None, None
    pos = 240
    while pos + 1 < len(buf):
        opt = buf[pos]
        if opt == 255:
            break
        if opt == 0:
            pos += 1
            continue
        ln = buf[pos + 1]
        val = buf[pos + 2:pos + 2 + ln]
        if opt == 53 and ln >= 1:
            msg_type = val[0]
        elif opt == 54 and ln >= 4:
            server_id = socket.inet_ntoa(val[:4])
        pos += 2 + ln
    if msg_type != 2:  # not an OFFER
        return None
    return {'offer_ip': offer_ip, 'server_id': server_id}


def probe_interface(iface=None, timeout=PROBE_TIMEOUT):
    """Broadcast one DISCOVER (on `iface`, or the default route when None) and
    collect distinct answering servers. Returns (servers, error)."""
    xid = secrets.randbits(32)
    mac = (_iface_mac(iface) if iface else None) or _random_mac()
    servers = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if iface:
                s.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE,
                             iface.encode() + b'\x00')
            s.bind(('', 68))
            s.sendto(build_discover(xid, mac), ('255.255.255.255', 67))
            deadline = time.time() + timeout
            while time.time() < deadline:
                s.settimeout(max(0.05, deadline - time.time()))
                try:
                    buf, addr = s.recvfrom(2048)
                except socket.timeout:
                    break
                offer = parse_offer(buf, xid)
                if offer:
                    server = offer['server_id'] or addr[0]
                    servers.setdefault(server, {'server': server,
                                                'offer_ip': offer['offer_ip'],
                                                'iface': iface or ''})
        finally:
            s.close()
    except OSError as e:
        return [], str(e)
    return list(servers.values()), None


def cli_dhcp_probe(argv=None):
    """CLI: `app.py dhcp-probe [iface ...]` — prints JSON, always exits 0.
    Runs privileged (root in Docker, sudo on bare metal) because port 68 is
    a privileged bind."""
    ifaces = [a for a in (argv[2:] if argv else []) if re.match(r'^[A-Za-z0-9._@-]{1,15}$', a)]
    all_servers, errors = [], []
    for iface in (ifaces or [None]):
        servers, err_ = probe_interface(iface)
        all_servers.extend(servers)
        if err_:
            errors.append('%s: %s' % (iface or 'default', err_))
    print(json.dumps({'servers': all_servers, 'errors': errors}))
    return 0


def _local_ipv4s():
    out, _, rc = run(['ip', '-4', '-o', 'addr', 'show'], no_sudo=True)
    return set(re.findall(r'inet (\d+\.\d+\.\d+\.\d+)', out or ''))


def probe_for_foreign_dhcp(interfaces):
    """Run the probe (privileged, via the CLI subcommand) and filter out this
    host's own addresses. Returns {'servers': [...], 'error': str|None}."""
    import sys
    from .core.config import APP_DIR
    cmd = [sys.executable, os.path.join(APP_DIR, 'app.py'), 'dhcp-probe'] + list(interfaces)
    out, e, rc = run(cmd, timeout=15)
    if rc != 0:
        return {'servers': [], 'error': (e or 'probe failed').strip().splitlines()[-1]}
    try:
        data = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {'servers': [], 'error': 'unparseable probe output'}
    local = _local_ipv4s()
    foreign = [s for s in data.get('servers', []) if s.get('server') not in local]
    error = '; '.join(data.get('errors') or []) or None
    return {'servers': foreign, 'error': error}
