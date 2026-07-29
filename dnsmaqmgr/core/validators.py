"""Input validators for everything that ends up in a rendered dnsmasq config
line. Rendering is text concatenation, so these regexes are the barrier that
keeps a stored value from smuggling extra directives (newlines, commas in
positional fields) into the config.
"""
import re
import ipaddress

RE_HOSTNAME = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?$')
RE_DOMAIN = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?'
                       r'(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*$')
RE_MAC = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
RE_LEASE = re.compile(r'^(\d+[smhdw]?|infinite)$')
RE_TAG = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
RE_IFACE = re.compile(r'^[A-Za-z0-9._@-]{1,15}$')
RE_DHCP_OPTION = re.compile(r'^(\d{1,3}|option6?:[a-z0-9-]{1,40})$')
# Option values are comma-joined into dhcp-opts lines; allow common value
# characters but never newlines. Commas are legitimate (list values).
RE_OPT_VALUE = re.compile(r'^[A-Za-z0-9 .,:/_"\'=\[\]-]{1,255}$')
RE_BOOT_FILE = re.compile(r'^[A-Za-z0-9._/-]{1,128}$')
RE_ID = re.compile(r'^[a-z]_[0-9a-f]{6}$')
RE_COMMENT = re.compile(r'^[^\r\n]{0,200}$')
RE_ARCH = re.compile(r'^\d{1,3}$')
RE_PATH = re.compile(r'^/[A-Za-z0-9._/-]{0,200}$')
RE_URL = re.compile(r'^https://[A-Za-z0-9.\[\]:_-]+(:\d{1,5})?$')
RE_FINGERPRINT = re.compile(r'^[0-9a-f]{64}$')
RE_SOURCE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')


def is_ipv4(s):
    try:
        ipaddress.IPv4Address(s)
        return True
    except (ValueError, TypeError):
        return False


def is_ipv6(s):
    # Reject scope-ids (fe80::1%zone): CPython accepts newlines, '=', ',' and
    # spaces inside the zone, and such a value would smuggle an extra directive
    # into a rendered dnsmasq line. is_ip/is_upstream inherit this guard.
    if '%' in str(s):
        return False
    try:
        ipaddress.IPv6Address(s)
        return True
    except (ValueError, TypeError):
        return False


def is_ip(s):
    return is_ipv4(s) or is_ipv6(s)


def is_upstream(s):
    """An upstream server: IP with optional #port (dnsmasq syntax)."""
    s = str(s or '')
    if '#' in s:
        host, _, port = s.partition('#')
        return is_ip(host) and port.isdigit() and 0 < int(port) < 65536
    return is_ip(s)


def valid_hostname_fqdn(s):
    """A bare hostname or a dotted FQDN (each label hostname-shaped)."""
    s = str(s or '')
    if not s or len(s) > 253:
        return False
    return all(RE_HOSTNAME.match(part) for part in s.rstrip('.').split('.'))
