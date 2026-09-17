"""Operational endpoints: Prometheus `/metrics` and an unauthenticated
`/api/health` for container HEALTHCHECKs and external monitors.

`/metrics` reuses the stats collector (CHAOS counters, leases file, pool
utilisation) and the controllers' status — no SQLite, no new sampling. It is
behind the normal auth guard: point Prometheus at it with a READ-ONLY API
token (`authorization: credentials: dm_…` in the scrape config).

`/api/health` is deliberately terse so an unauthenticated caller learns only
"is the resolver up": 200 when dnsmasq is running (and, if enabled, the
encrypted upstream child too), 503 otherwise.
"""
from flask import Blueprint, Response, jsonify

from .core.config import APP_VERSION
from .core.store import load_store
from .dhcp import parse_leases

bp = Blueprint('metrics', __name__)


def _esc(v):
    return str(v).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')


def _labels(**kw):
    return '{%s}' % ','.join('%s="%s"' % (k, _esc(v)) for k, v in kw.items()) if kw else ''


def render_metrics():
    """The exposition text. Pure over the app's own readers so it is cheap to
    scrape and cheap to test."""
    from .dnsmasq import get_controller
    from .stats import collect_dns_counters, pool_utilization
    from . import encdns
    settings = load_store('settings')
    out = []

    def m(name, mtype, help_, samples):
        out.append('# HELP %s %s' % (name, help_))
        out.append('# TYPE %s %s' % (name, mtype))
        for labels, value in samples:
            out.append('%s%s %s' % (name, labels, value))

    st = get_controller().status()
    m('dnsmasq_up', 'gauge', 'Whether the dnsmasq service is running.',
      [('', 1 if st.get('running') else 0)])
    m('dnsmaq_info', 'gauge', 'Application version and controller mode.',
      [(_labels(version=APP_VERSION, mode=get_controller().mode,
                dns_enabled=int(bool(settings.get('dns_enabled', True))),
                dhcp_enabled=int(bool(settings.get('dhcp_enabled')))), 1)])

    vals = collect_dns_counters() if settings.get('dns_enabled', True) else {}
    m('dnsmasq_dns_reachable', 'gauge', 'Whether the CHAOS counter query on loopback was answered.',
      [('', 1 if vals else 0)])
    if vals:
        m('dnsmasq_cache_size', 'gauge', 'Configured cache slots.', [('', vals['cachesize'])])
        m('dnsmasq_cache_insertions_total', 'counter', 'Cache insertions since dnsmasq start.',
          [('', vals['insertions'])])
        m('dnsmasq_cache_evictions_total', 'counter', 'Cache evictions since dnsmasq start.',
          [('', vals['evictions'])])
        m('dnsmasq_cache_hits_total', 'counter', 'Cache hits since dnsmasq start.',
          [('', vals['hits'])])
        m('dnsmasq_cache_misses_total', 'counter', 'Cache misses since dnsmasq start.',
          [('', vals['misses'])])

    leases = parse_leases()
    m('dnsmasq_dhcp_leases_active', 'gauge', 'Active DHCP leases in the leases file.',
      [('', len(leases))])
    pools = pool_utilization(leases=leases)
    m('dnsmasq_dhcp_pool_size', 'gauge', 'Addresses in each enabled DHCP range.',
      [(_labels(pool=p['tag']), p['size']) for p in pools])
    m('dnsmasq_dhcp_pool_used', 'gauge', 'Active leases inside each enabled DHCP range.',
      [(_labels(pool=p['tag']), p['used']) for p in pools])

    enc = encdns.health(do_probe=False)
    m('dnsmaq_encdns_enabled', 'gauge', 'Whether the encrypted DNS upstream is enabled.',
      [('', 1 if enc['enabled'] else 0)])
    m('dnsmaq_encdns_up', 'gauge', 'Whether the supervised dnscrypt-proxy child is running.',
      [('', 1 if enc['running'] else 0)])

    bl = load_store('blocklists')
    m('dnsmaq_blocklist_entries', 'gauge', 'Domains held by each enabled blocklist.',
      [(_labels(list=rec.get('name') or rec['id']), int(rec.get('entries') or 0))
       for rec in bl.get('lists', []) if rec.get('enabled', True)])
    m('dnsmaq_blocklist_allow_entries', 'gauge', 'Domains on the allowlist.',
      [('', len(bl.get('allow', [])))])

    src = settings.get('mirror_sources', {}) or {}
    m('dnsmaq_mirror_last_received_timestamp_seconds', 'gauge',
      'When each mirror source last pushed successfully.',
      [(_labels(source=name), int(rec.get('last_received') or 0)) for name, rec in src.items()])
    return '\n'.join(out) + '\n'


@bp.route('/metrics')
def metrics():
    return Response(render_metrics(), mimetype='text/plain; version=0.0.4; charset=utf-8')


@bp.route('/api/health')
def api_health():
    """Public liveness/readiness: no version, no counters, no config."""
    from .dnsmasq import get_controller
    from . import encdns
    ok = bool(get_controller().status().get('running'))
    enc = encdns.health(do_probe=False)
    if enc['enabled'] and not enc['running']:
        ok = False
    return jsonify({'status': 'ok' if ok else 'degraded'}), (200 if ok else 503)
