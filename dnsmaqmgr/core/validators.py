"""Input validators for everything that ends up in a rendered dnsmasq config
line. Rendering is text concatenation, so these regexes are the barrier that
keeps a stored value from smuggling extra directives (newlines, commas in
positional fields) into the config.
"""
import re
import ipaddress

# Anchored with \Z, not $ — Python's `$` also matches just before a trailing
# newline, so `RE_X.match("value\n")` would succeed and a stored value could
# carry a newline into a rendered config line. \Z matches only the true end.
RE_HOSTNAME = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?\Z')
RE_DOMAIN = re.compile(r'^(?=.{1,253}\Z)[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?'
                       r'(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\Z')
RE_MAC = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z')
RE_LEASE = re.compile(r'^(\d+[smhdw]?|infinite)\Z')
RE_TAG = re.compile(r'^[A-Za-z0-9_-]{1,32}\Z')
RE_IFACE = re.compile(r'^[A-Za-z0-9._@-]{1,15}\Z')
RE_DHCP_OPTION = re.compile(r'^(\d{1,3}|option6?:[a-z0-9-]{1,40})\Z')
# Option values are comma-joined into dhcp-opts lines; allow common value
# characters but never newlines. Commas are legitimate (list values).
RE_OPT_VALUE = re.compile(r'^[A-Za-z0-9 .,:/_"\'=\[\]-]{1,255}\Z')
RE_BOOT_FILE = re.compile(r'^[A-Za-z0-9._/-]{1,128}\Z')
RE_ID = re.compile(r'^[a-z]_[0-9a-f]{6}\Z')
RE_COMMENT = re.compile(r'^[^\r\n]{0,200}\Z')
RE_ARCH = re.compile(r'^\d{1,3}\Z')
RE_URL = re.compile(r'^https://[A-Za-z0-9.\[\]:_-]+(:\d{1,5})?\Z')
# Blocklist source URLs carry paths (raw.githubusercontent.com/...). The URL is
# rendered into a conf comment line, so no whitespace/quotes — and \S alone
# would admit them via non-ASCII spaces, hence the explicit char class.
RE_LIST_URL = re.compile(r'^https?://[A-Za-z0-9.\[\]:_~/%&=?#+-]{1,500}\Z')
RE_FINGERPRINT = re.compile(r'^[0-9a-f]{64}\Z')
RE_SOURCE = re.compile(r'^[A-Za-z0-9._-]{1,64}\Z')


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
        # `isascii()` first: str.isdigit() is True for e.g. '²' but int() then
        # raises, 500-ing the request instead of failing validation cleanly.
        return (is_ip(host) and port.isascii() and port.isdigit()
                and 0 < int(port) < 65536)
    return is_ip(s)


def valid_hostname_fqdn(s):
    """A bare hostname or a dotted FQDN (each label hostname-shaped)."""
    s = str(s or '')
    if not s or len(s) > 253:
        return False
    return all(RE_HOSTNAME.match(part) for part in s.rstrip('.').split('.'))
