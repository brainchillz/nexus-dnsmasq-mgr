"""Encrypted DNS upstream (opt-in): dnsmasq forwards to a supervised
dnscrypt-proxy child on loopback, which speaks DoH/DNSCrypt upstream.

    dnsmasq → dnscrypt-proxy (127.0.0.1:5335) → [ encrypted hop ] → resolver

Two selectable shapes for the encrypted hop, one setting apart:
  * direct — proxy → resolver. Moves trust from the ISP to the resolver
    operator (who sees your IP AND your queries). DoH or DNSCrypt.
  * relay  — proxy → anonymizing relay → resolver (DNSCrypt only). The relay
    sees your IP but not the queries; the resolver sees the queries but not
    your IP — no single party holds both halves. Only meaningful when relay
    and resolver are run by DIFFERENT operators.

Default is fail-closed: while enabled, the proxy is dnsmasq's ONLY upstream,
so a dead proxy means resolution stops rather than silently leaking plaintext
to the ISP (the alerts tick watches for that). The explicit fallback_plain
toggle keeps the plain upstreams in the render (proxy tried first via
strict-order) for uptime-first operators.

The proxy runs as an unprivileged child in BOTH platform modes (the listener
is a high port on loopback — no root, no sudoers rules), supervised exactly
like the Docker-mode dnsmasq child. The rendered TOML lives under
ENCDNS_DIR next to dnscrypt-proxy's cached resolver/relay lists.
"""
import os
import re
import shutil
import tempfile
from flask import Blueprint, jsonify

from .core.config import ENCDNS_DIR, ENCDNS_CONF, DNSCRYPT_BIN, write_text_atomic
from .core.runcmd import run, err, json_object
from .core.store import load_store, save_store

bp = Blueprint('encdns', __name__)

MODES = ('direct', 'relay')

# Interpolated into single-quoted TOML strings — the character class is the
# barrier that keeps a stored name from smuggling TOML (quotes, newlines).
RE_SERVER_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')

# Provider presets: dnscrypt-proxy server_names from the public-resolvers
# list, per mode. Relay mode requires the DNSCrypt protocol, so providers
# without a DNSCrypt resolver (Cloudflare, Mullvad) offer nothing there.
PROVIDERS = {
    'cloudflare': {'label': 'Cloudflare',
                   'direct': ['cloudflare'], 'relay': []},
    'quad9':      {'label': 'Quad9 (malware-filtering)',
                   'direct': ['quad9-doh-ip4-port443-filter-pri'],
                   'relay': ['quad9-dnscrypt-ip4-filter-pri']},
    'mullvad':    {'label': 'Mullvad',
                   'direct': ['mullvad-doh'], 'relay': []},
    'adguard':    {'label': 'AdGuard DNS (ad-blocking)',
                   'direct': ['adguard-dns-doh'], 'relay': ['adguard-dns']},
}

# The DNSCrypt project's resolver/relay lists: fetched by dnscrypt-proxy
# itself (minisign-verified), cached under ENCDNS_DIR.
SOURCE_URLS = {
    'public-resolvers': [
        'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
        'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md'],
    'relays': [
        'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
        'https://download.dnscrypt.info/resolvers-list/v3/relays.md'],
}
MINISIGN_KEY = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'

CHECK_TIMEOUT = 90   # -check may first download the resolver lists


def binary_path():
    return shutil.which(DNSCRYPT_BIN)


def server_names(cfg):
    """The dnscrypt-proxy server_names a config resolves to: preset names for
    the active mode plus any custom names, order-preserving, deduplicated."""
    mode = cfg.get('mode') or 'direct'
    names = []
    for p in cfg.get('providers', []):
        names += PROVIDERS.get(p, {}).get(mode, [])
    names += [n for n in cfg.get('custom_servers', [])]
    return list(dict.fromkeys(names))


# ─── Config rendering (pure: store dict in, TOML out) ─────────────────

def _source_block(name):
    return [
        "[sources.%s]" % name,
        "urls = [%s]" % ', '.join("'%s'" % u for u in SOURCE_URLS[name]),
        "cache_file = '%s'" % os.path.join(ENCDNS_DIR, '%s.md' % name),
        "minisign_key = '%s'" % MINISIGN_KEY,
        "refresh_delay = 73",
        "prefix = ''",
    ]


def render_proxy_config(cfg):
    """dnscrypt-proxy.toml from the encdns store. Every interpolated value is
    validated on the way into the store (RE_SERVER_NAME / int port), so plain
    string formatting cannot leak TOML syntax."""
    relay = (cfg.get('mode') or 'direct') == 'relay'
    port = int(cfg.get('listen_port') or 5335)
    lines = [
        '# Managed by DNSMAQ-MGR — do not edit; changes are overwritten on every apply.',
        "listen_addresses = ['127.0.0.1:%d']" % port,
        'server_names = [%s]' % ', '.join("'%s'" % n for n in server_names(cfg)),
        'max_clients = 250',
        'ipv4_servers = true',
        'ipv6_servers = false',
        'dnscrypt_servers = true',
        # Relay mode is DNSCrypt-only: anonymized routing cannot wrap DoH.
        'doh_servers = %s' % ('false' if relay else 'true'),
        'odoh_servers = false',
        'require_dnssec = false',
        'require_nolog = false',
        'require_nofilter = false',
        'force_tcp = false',
        'timeout = 5000',
        'keepalive = 30',
        'cert_refresh_delay = 240',
        # Bootstrap: resolving the resolver-list hosts themselves is plaintext
        # on first start — there is no chicken-and-egg-free alternative.
        "bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']",
        'ignore_system_dns = true',
        'netprobe_timeout = 60',
        "netprobe_address = '9.9.9.9:53'",
        'log_level = 2',
        'use_syslog = false',
        # dnsmasq in front of the proxy already caches; a second cache here
        # would only hide TTL behaviour from it.
        'cache = false',
        '',
    ] + _source_block('public-resolvers')
    if relay:
        lines += [''] + _source_block('relays') + [
            '',
            '[anonymized_dns]',
            'routes = [ { server_name=\'*\', via=[%s] } ]'
            % ', '.join("'%s'" % r for r in cfg.get('relays', [])),
            'skip_incompatible = true',
        ]
    return '\n'.join(lines) + '\n'


def check_proxy_config(text):
    """Validate a rendered TOML with `dnscrypt-proxy -check` (the proxy-side
    equivalent of `dnsmasq --test`). Downloads the resolver lists into
    ENCDNS_DIR on first run, so a passed check also means the sources are
    primed before the proxy starts. Returns (ok, output)."""
    if not binary_path():
        return False, '%s is not installed' % DNSCRYPT_BIN
    fd, path = tempfile.mkstemp(prefix='dnsmaq-encdns-', suffix='.toml')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text)
        out, e, rc = run([DNSCRYPT_BIN, '-check', '-config', path],
                         no_sudo=True, timeout=CHECK_TIMEOUT)
        return rc == 0, (e or out).strip()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# ─── Validation ────────────────────────────────────────────────────────

def validate_config(data, existing):
    """Merge a payload onto an existing config, validating every field.
    Returns (cfg, None) or (None, error). Shared by the save route and the
    backup restore path."""
    cfg = dict(existing)
    if 'enabled' in data:
        cfg['enabled'] = bool(data['enabled'])
    if 'mode' in data:
        if data['mode'] not in MODES:
            return None, 'Unknown mode (direct or relay)'
        cfg['mode'] = data['mode']
    if 'fallback_plain' in data:
        cfg['fallback_plain'] = bool(data['fallback_plain'])
    if 'providers' in data:
        provs = data['providers']
        if not isinstance(provs, list):
            return None, 'providers must be a list'
        unknown = [p for p in provs if p not in PROVIDERS]
        if unknown:
            return None, 'Unknown provider: %s' % ', '.join(map(str, unknown))
        cfg['providers'] = provs
    for key, what in (('custom_servers', 'custom server name'),
                      ('relays', 'relay name')):
        if key in data:
            raw = data[key]
            if not isinstance(raw, list):
                return None, '%s must be a list' % key
            vals = [str(x).strip() for x in raw if str(x).strip()]
            bad = [v for v in vals if not RE_SERVER_NAME.match(v)]
            if bad:
                return None, 'Invalid %s: %s' % (what, ', '.join(bad))
            cfg[key] = vals
    if 'listen_port' in data:
        try:
            port = int(data['listen_port'])
        except (TypeError, ValueError):
            return None, 'Invalid listen port'
        if not 1024 <= port <= 65535:
            return None, 'Listen port must be 1024–65535 (unprivileged)'
        cfg['listen_port'] = port
    if cfg.get('enabled'):
        if not server_names(cfg):
            if (cfg.get('mode') or 'direct') == 'relay':
                return None, ('None of the selected providers offer DNSCrypt '
                              '(required for relay mode) — pick Quad9/AdGuard '
                              'or add a DNSCrypt-capable custom server name')
            return None, 'Select at least one provider or add a custom server name'
        if (cfg.get('mode') or 'direct') == 'relay' and not cfg.get('relays'):
            return None, 'Relay mode needs at least one relay (e.g. anon-…)'
    return cfg, None


# ─── Supervision ──────────────────────────────────────────────────────

class ProxyController:
    """Created lazily below; class body defined at import time would need
    dnsmasq.ChildController, so the subclass is built in get_proxy()."""


_proxy = None


def get_proxy():
    global _proxy
    if _proxy is None:
        from .dnsmasq import ChildController

        class _ProxyController(ChildController):
            mode = 'encdns-child'
            name = 'dnscrypt-proxy'

            def _args(self):
                return [binary_path() or DNSCRYPT_BIN, '-config', ENCDNS_CONF]

        _proxy = _ProxyController()
    return _proxy


def sync_proxy():
    """Make the running proxy match the store — idempotent, safe to call from
    any apply path (boot, save, rollback, restore). Writes the TOML if it
    changed and starts/restarts/stops the child accordingly.
    Returns (ok, detail)."""
    cfg = load_store('encdns')
    ctl = get_proxy()
    if not cfg.get('enabled'):
        ctl.stop()
        return True, ''
    if not binary_path():
        return False, ('%s is not installed — encrypted upstream cannot start'
                       % DNSCRYPT_BIN)
    text = render_proxy_config(cfg)
    try:
        with open(ENCDNS_CONF) as f:
            changed = f.read() != text
    except OSError:
        changed = True
    if changed:
        write_text_atomic(ENCDNS_CONF, text, 0o600)
    if not ctl.status()['running']:
        return ctl.start()
    if changed:
        # dnscrypt-proxy does not re-read its config on SIGHUP.
        return ctl.restart()
    return True, ''


def probe(port, timeout=2.0):
    """One real query through the proxy (A example.com). True only on a clean
    NOERROR — a SERVFAIL means the encrypted hop itself is broken."""
    from .lookup import query_dnsmasq
    rcode, _ = query_dnsmasq('example.com', 1, server='127.0.0.1',
                             port=port, timeout=timeout)
    return rcode == 0


def health(do_probe=True):
    """Status summary for the UI and the alerts tick."""
    cfg = load_store('encdns')
    st = get_proxy().status()
    out = {'enabled': bool(cfg.get('enabled')), 'running': st['running'],
           'pid': st.get('pid'), 'port': int(cfg.get('listen_port') or 5335),
           'healthy': None, 'binary_present': bool(binary_path())}
    if out['enabled'] and out['running'] and do_probe:
        out['healthy'] = probe(out['port'])
    return out


def proxy_version():
    if not binary_path():
        return None
    out, _, rc = run([DNSCRYPT_BIN, '-version'], no_sudo=True, timeout=10)
    return out.strip().splitlines()[0] if rc == 0 and out.strip() else None


def startup():
    """Called once from app.py at boot: bring the proxy up (or make sure it is
    down) before dnsmasq starts answering with the rendered config."""
    ok, detail = sync_proxy()
    if not ok:
        print('WARNING: encrypted DNS upstream failed to start: %s' % detail,
              flush=True)


# ─── Routes ────────────────────────────────────────────────────────────

def _public(cfg):
    return {k: cfg[k] for k in ('enabled', 'mode', 'providers', 'custom_servers',
                                'relays', 'fallback_plain', 'listen_port')}


@bp.route('/api/encdns')
def encdns_get():
    cfg = load_store('encdns')
    return jsonify({'success': True, **_public(cfg),
                    'status': health(),
                    'version': proxy_version(),
                    'server_names': server_names(cfg),
                    'catalog': {k: {'label': v['label'],
                                    'direct': v['direct'], 'relay': v['relay']}
                                for k, v in PROVIDERS.items()},
                    'logs': get_proxy().logs(50)})


@bp.route('/api/encdns', methods=['POST'])
def encdns_save():
    from .dnsmasq import apply_change
    data, e = json_object()
    if e:
        return e
    cfg, verr = validate_config(data, load_store('encdns'))
    if verr:
        return err(verr)

    if cfg.get('enabled'):
        if not binary_path():
            return err('dnscrypt-proxy is not installed on this host — '
                       'install it (apt install dnscrypt-proxy) and retry')
        ok, output = check_proxy_config(render_proxy_config(cfg))
        if not ok:
            return err('dnscrypt-proxy rejected the configuration: %s' % output)

    def mutate():
        cur = load_store('encdns')
        cur.update({k: cfg[k] for k in _public(cfg)})
        save_store('encdns', cur)

    # Order matters against the fail-closed window: bring the proxy up with
    # the NEW config before dnsmasq is re-pointed at it; on a rejected apply
    # the store is rolled back and sync_proxy() below reverts the proxy too.
    if cfg.get('enabled'):
        write_text_atomic(ENCDNS_CONF, render_proxy_config(cfg), 0o600)
        ctl = get_proxy()
        ok, detail = ctl.restart() if ctl.status()['running'] else ctl.start()
        if not ok:
            sync_proxy()
            return err('dnscrypt-proxy failed to start: %s' % (detail or 'unknown'), 502)

    res = apply_change(mutate, sections=['encdns'])
    if isinstance(res, tuple):
        sync_proxy()   # store was rolled back — put the proxy back too
        return res
    return jsonify({'success': True, **_public(load_store('encdns')),
                    'status': health(do_probe=False), **res})
