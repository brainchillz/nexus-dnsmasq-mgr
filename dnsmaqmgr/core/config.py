"""Core configuration: paths, env helpers, atomic JSON writes, platform detect.

Adapted from Nexus Dashboard core/config.py. All knobs are DNSMAQ_*
environment variables; the installer and Docker image set them, so names and
defaults are load-bearing once released.
"""
import os
import json
from datetime import timedelta

# APP_DIR is the directory holding the ROOT app.py entrypoint (the repo root or
# /opt install dir). DATA_DIR holds all mutable state (auth.json, certs/,
# state/, render/, leases/, history.db) — same as APP_DIR on bare metal,
# a volume (/data) in Docker.
APP_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATIC_DIR = os.path.join(APP_DIR, 'static')
TEMPLATES_DIR = os.path.join(APP_DIR, 'templates')

APP_VERSION = '0.4.4'

DATA_DIR = os.environ.get('DNSMAQ_DATA_DIR', APP_DIR)
STATE_DIR = os.path.join(DATA_DIR, 'state')
RENDER_DIR = os.path.join(DATA_DIR, 'render')
CONF_DIR = os.path.join(RENDER_DIR, 'dnsmasq.d')
HOSTS_DIR = os.path.join(RENDER_DIR, 'hosts.d')
MANAGED_HOSTS = os.path.join(HOSTS_DIR, 'managed-hosts')
DHCP_HOSTS_FILE = os.path.join(RENDER_DIR, 'dhcp-hosts')
DHCP_OPTS_FILE = os.path.join(RENDER_DIR, 'dhcp-opts')
LEASES_DIR = os.path.join(DATA_DIR, 'leases')
LEASES_FILE = os.path.join(LEASES_DIR, 'dnsmasq.leases')
# Fetched blocklist domain files (one validated domain per line, keyed by
# list id). App-private: only the rendered conf under RENDER_DIR is dnsmasq's.
BLOCKLISTS_DIR = os.path.join(DATA_DIR, 'blocklists')

# Encrypted DNS upstream (opt-in): the app supervises a dnscrypt-proxy child
# listening on loopback; dnsmasq forwards to it. The rendered TOML and the
# proxy's cached resolver/relay lists live here (app-private).
ENCDNS_DIR = os.path.join(DATA_DIR, 'encdns')
ENCDNS_CONF = os.path.join(ENCDNS_DIR, 'dnscrypt-proxy.toml')
DNSCRYPT_BIN = os.environ.get('DNSMAQ_DNSCRYPT_BIN', 'dnscrypt-proxy')

# The system hosts file dnsmasq reads by default (`no-hosts` disables that).
# The lookup/audit tools parse it to attribute answers; overridable for tests.
ETC_HOSTS = os.environ.get('DNSMAQ_ETC_HOSTS', '/etc/hosts')

# Change history: one JSON snapshot per applied change, pruned to the last N.
CHANGELOG_DIR = os.path.join(DATA_DIR, 'changelog')
CHANGELOG_KEEP = int(os.environ.get('DNSMAQ_CHANGELOG_KEEP', 50))


def env_bool(name, default):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.lower() in ('1', 'true', 'yes', 'on')


# Docker mode: the app supervises dnsmasq as a child process instead of
# driving systemd, and never prefixes commands with sudo.
SUPERVISE = env_bool('DNSMAQ_SUPERVISE', False)
NO_SUDO = env_bool('DNSMAQ_NO_SUDO', False)

# Stats sampling interval for the in-app ticker (seconds).
TICK_SECONDS = int(os.environ.get('DNSMAQ_TICK_SECONDS', 300))

# Port the stats collector queries dnsmasq's CHAOS counters on. Only needs
# changing when dnsmasq serves DNS on a non-standard port (e.g. `port=` in
# extra options, or a dev instance beside a live resolver).
DNS_PORT = int(os.environ.get('DNSMAQ_DNS_PORT', 53))

# The dnsmasq binary + systemd unit name (unit only used when not supervising).
DNSMASQ_BIN = os.environ.get('DNSMAQ_DNSMASQ_BIN', 'dnsmasq')
DNSMASQ_UNIT = os.environ.get('DNSMAQ_DNSMASQ_UNIT', 'dnsmasq')

# ─── TLS configuration ────────────────────────────────────────────────
# HTTPS by default with a self-signed certificate generated on first run.
# Replace it from the UI (Settings → TLS), drop PEM files at the paths below,
# or point DNSMAQ_TLS_CERT / DNSMAQ_TLS_KEY at your own. DNSMAQ_TLS=0 serves
# plain HTTP (e.g. behind a TLS-terminating reverse proxy).
TLS_ENABLED = env_bool('DNSMAQ_TLS', True)
WEB_PORT = int(os.environ.get('DNSMAQ_PORT', 8443 if TLS_ENABLED else 8080))
TLS_DIR = os.environ.get('DNSMAQ_TLS_DIR', os.path.join(DATA_DIR, 'certs'))
TLS_CERT = os.environ.get('DNSMAQ_TLS_CERT', os.path.join(TLS_DIR, 'dnsmaq-mgr.crt'))
TLS_KEY = os.environ.get('DNSMAQ_TLS_KEY', os.path.join(TLS_DIR, 'dnsmaq-mgr.key'))

SESSION_COOKIE_CONFIG = dict(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=env_bool('DNSMAQ_COOKIE_SECURE', TLS_ENABLED),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)


def write_json_atomic(path, data, mode=0o600):
    """Write JSON to ``path`` atomically: serialize into a temp file in the same
    directory, fsync it, then os.replace() over the target (an atomic rename on
    POSIX). A crash or full disk mid-write leaves the *original* file intact
    rather than a truncated one — critical for auth.json and the config stores,
    where a corrupt file would lock users out or wipe the dnsmasq config."""
    tmp = '%s.tmp.%d' % (path, os.getpid())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def write_text_atomic(path, text, mode=0o644):
    """Atomic text-file write, same pattern as write_json_atomic. Rendered
    dnsmasq config files are world-readable (dnsmasq runs as root but its
    nobody-user workers must be able to read them)."""
    tmp = '%s.tmp.%d' % (path, os.getpid())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def ensure_dirs():
    """Create the DATA_DIR tree on first boot (bare metal and Docker volume)."""
    for d in (STATE_DIR, CONF_DIR, HOSTS_DIR, LEASES_DIR, TLS_DIR, BLOCKLISTS_DIR,
              CHANGELOG_DIR, ENCDNS_DIR):
        os.makedirs(d, exist_ok=True)
    # State and certs are private to the app user; render/ must be readable by
    # dnsmasq (root).
    for d in (STATE_DIR, TLS_DIR, BLOCKLISTS_DIR, CHANGELOG_DIR, ENCDNS_DIR):
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    for d in (RENDER_DIR, CONF_DIR, HOSTS_DIR, LEASES_DIR):
        try:
            os.chmod(d, 0o755)
        except OSError:
            pass


# ─── Platform detection (Debian/Ubuntu vs RHEL/Rocky) ─────────────────
def _platform_from_osrelease(text):
    """Pure parser: given /etc/os-release contents, return
    {family: 'debian'|'rhel', id, version}. Defaults to 'debian' when unknown."""
    data = {}
    for line in (text or '').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        data[k.strip()] = v.strip().strip('"').strip("'")
    osid = (data.get('ID') or '').lower()
    like = set((data.get('ID_LIKE') or '').lower().split())
    rhel_ids = {'rhel', 'centos', 'rocky', 'almalinux', 'fedora'}
    debian_ids = {'debian', 'ubuntu'}
    if osid in rhel_ids or (rhel_ids & like):
        family = 'rhel'
    elif osid in debian_ids or (debian_ids & like):
        family = 'debian'
    else:
        family = 'debian'
    return {'family': family, 'id': osid, 'version': data.get('VERSION_ID', '')}


def detect_platform(path='/etc/os-release'):
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        text = ''
    return _platform_from_osrelease(text)


PLATFORM = detect_platform()
FAMILY = PLATFORM['family']
