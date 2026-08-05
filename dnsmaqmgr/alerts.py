"""Alerts / webhooks, hung off the existing 5-minute stats tick.

Watched conditions:
  * new_device   — a MAC never seen before took a DHCP lease
  * pool_high    — a DHCP pool crossed the utilization threshold (with
                   hysteresis: re-arms when it drops 10 points below)
  * service_down — dnsmasq is not running, or its cumulative counters went
                   backwards (the daemon restarted/respawned)
  * cert_expiry  — the web UI TLS certificate is inside the warning window

Delivery is one webhook URL in one of three payload shapes: 'generic' (plain
JSON), 'ntfy' (text body + Title/Tags headers) or 'slack'
(Slack/Mattermost-compatible {"text": …}). Per-event-key cooldowns stop a
persistent condition from firing every tick. The first enabled tick baselines
known MACs and counters WITHOUT alerting, so switching alerts on doesn't
announce every device on the LAN.

Config lives in the 'alerts' store (included in backups); runtime state
(known MACs, cooldowns, recent history) in 'alerts_state' (not backed up).
"""
import json
import time
import socket
import urllib.request
from datetime import datetime
from flask import Blueprint, jsonify

from .core.auth import _is_admin
from .core.runcmd import err, json_object
from .core.store import STORE_LOCK, load_store, save_store
from .core.tls import cert_info
from .core.validators import RE_LIST_URL

bp = Blueprint('alerts', __name__)

FORMATS = ('generic', 'ntfy', 'slack')
EVENTS = ('new_device', 'pool_high', 'service_down', 'cert_expiry')
SEND_TIMEOUT = 10
RECENT_KEEP = 50

# Re-alert interval per persistent condition (seconds).
COOLDOWNS = {'service_down': 6 * 3600, 'cert_expiry': 24 * 3600}
DEFAULT_COOLDOWN = 6 * 3600


# ─── Delivery ─────────────────────────────────────────────────────────

def deliver(cfg, event, title, message):
    """POST one alert to the configured webhook. Returns (ok, detail)."""
    url = cfg.get('webhook_url') or ''
    fmt = cfg.get('format') or 'generic'
    host = socket.gethostname()
    try:
        if fmt == 'ntfy':
            req = urllib.request.Request(
                url, data=('%s: %s' % (host, message)).encode(),
                headers={'Title': title, 'Tags': 'warning',
                         'Priority': 'high' if event == 'service_down' else 'default'})
        elif fmt == 'slack':
            body = {'text': '*%s* — %s\n%s' % (title, host, message)}
            req = urllib.request.Request(
                url, data=json.dumps(body).encode(),
                headers={'Content-Type': 'application/json'})
        else:
            body = {'event': event, 'title': title, 'message': message,
                    'host': host, 'ts': int(time.time()), 'source': 'dnsmaq-mgr'}
            req = urllib.request.Request(
                url, data=json.dumps(body).encode(),
                headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=SEND_TIMEOUT) as r:
            return 200 <= r.status < 300, 'HTTP %d' % r.status
    except Exception as e:
        return False, str(e)


# ─── Condition checks (each returns a list of (key, event, title, msg)) ──

def _check_new_devices(state, leases, statics):
    found = []
    current = {l['mac'] for l in leases if l.get('mac')}
    if not state.get('baseline_done'):
        state['known_macs'] = sorted(current | statics)
        state['baseline_done'] = True
        return found
    known = set(state.get('known_macs', []))
    for l in leases:
        mac = l.get('mac')
        if mac and mac not in known and mac not in statics:
            found.append(('new_device:%s' % mac, 'new_device',
                          'New device on LAN',
                          '%s took lease %s%s' % (mac, l.get('ip', '?'),
                                                  (' (%s)' % l['hostname']) if l.get('hostname') else '')))
    state['known_macs'] = sorted(known | current | statics)
    return found


def _check_pools(cfg, state, leases):
    from .stats import pool_utilization
    found = []
    threshold = int(cfg.get('pool_threshold') or 90)
    alerted = set(state.get('alerted_pools', []))
    for p in pool_utilization(leases=leases):
        if p['pct'] >= threshold and p['tag'] not in alerted:
            alerted.add(p['tag'])
            found.append(('pool_high:%s' % p['tag'], 'pool_high',
                          'DHCP pool nearly full',
                          'Pool %s at %s%% (%d/%d leases, %s–%s)'
                          % (p['tag'], p['pct'], p['used'], p['size'],
                             p['start'], p['end'])))
        elif p['pct'] < threshold - 10:
            alerted.discard(p['tag'])
    state['alerted_pools'] = sorted(alerted)
    return found


def _check_service(state, settings):
    from .dnsmasq import get_controller
    from .stats import collect_dns_counters
    found = []
    st = get_controller().status()
    if not st.get('running'):
        found.append(('service_down', 'service_down', 'dnsmasq is DOWN',
                      'dnsmasq is not running (state: %s)' % st.get('state')))
        state['counter_sum'] = None
        return found
    if settings.get('dns_enabled', True):
        vals = collect_dns_counters()
        if vals:
            total = vals['hits'] + vals['misses'] + vals['insertions']
            last = state.get('counter_sum')
            if last is not None and total < last:
                found.append(('service_restart', 'service_down',
                              'dnsmasq restarted',
                              'dnsmasq counters reset — the daemon restarted '
                              'or respawned since the last check'))
            state['counter_sum'] = total
    return found


def _check_cert(cfg):
    info = cert_info()
    expires = info.get('expires')
    if not info.get('present') or not expires:
        return []
    try:
        dt = datetime.strptime(expires, '%b %d %H:%M:%S %Y %Z')
    except ValueError:
        return []
    days = (dt - datetime.now()).days
    if days <= int(cfg.get('cert_days') or 14):
        return [('cert_expiry', 'cert_expiry', 'Web certificate expiring',
                 'The web UI TLS certificate expires in %d day(s) (%s)'
                 % (max(days, 0), expires))]
    return []


def tick():
    """Called from the stats ticker. Evaluates all conditions and delivers
    whatever is due; never raises."""
    cfg = load_store('alerts')
    if not cfg.get('enabled') or not cfg.get('webhook_url'):
        return
    from .dhcp import parse_leases
    with STORE_LOCK:
        state = load_store('alerts_state')
        leases = parse_leases()
        statics = {s['mac'] for s in load_store('dhcp').get('static_leases', [])}
        settings = load_store('settings')

        events_cfg = cfg.get('events') or {}
        candidates = []
        if events_cfg.get('new_device', True):
            candidates += _check_new_devices(state, leases, statics)
        if events_cfg.get('pool_high', True):
            candidates += _check_pools(cfg, state, leases)
        if events_cfg.get('service_down', True):
            candidates += _check_service(state, settings)
        if events_cfg.get('cert_expiry', True):
            candidates += _check_cert(cfg)

        now = int(time.time())
        last_sent = state.get('last_sent', {})
        due = [(k, ev, t, m) for (k, ev, t, m) in candidates
               if now - int(last_sent.get(k, 0)) >= COOLDOWNS.get(k, DEFAULT_COOLDOWN)]
        save_store('alerts_state', state)   # baseline/hysteresis even if nothing due

    for key, event, title, message in due:
        ok, detail = deliver(cfg, event, title, message)
        with STORE_LOCK:
            state = load_store('alerts_state')
            state.setdefault('last_sent', {})[key] = now
            state.setdefault('recent', []).append(
                {'ts': now, 'event': event, 'title': title, 'message': message,
                 'delivered': ok, 'detail': detail})
            state['recent'] = state['recent'][-RECENT_KEEP:]
            save_store('alerts_state', state)


# ─── Routes ───────────────────────────────────────────────────────────

def _validate_config(data, existing):
    cfg = dict(existing)
    if 'enabled' in data:
        cfg['enabled'] = bool(data['enabled'])
    if 'webhook_url' in data:
        url = (data['webhook_url'] or '').strip()
        if url and not RE_LIST_URL.match(url):
            return None, 'Invalid webhook URL (http(s)://…)'
        cfg['webhook_url'] = url
    if 'format' in data:
        if data['format'] not in FORMATS:
            return None, 'Unknown payload format'
        cfg['format'] = data['format']
    if 'events' in data:
        if not isinstance(data['events'], dict):
            return None, 'events must be an object'
        cfg['events'] = {e: bool(data['events'].get(e, True)) for e in EVENTS}
    for key, lo, hi in (('pool_threshold', 50, 100), ('cert_days', 1, 90)):
        if key in data:
            try:
                n = int(data[key])
            except (TypeError, ValueError):
                return None, 'Invalid %s' % key
            if not lo <= n <= hi:
                return None, '%s must be %d–%d' % (key, lo, hi)
            cfg[key] = n
    if cfg.get('enabled') and not cfg.get('webhook_url'):
        return None, 'A webhook URL is required to enable alerts'
    return cfg, None


@bp.route('/api/alerts')
def alerts_get():
    if not _is_admin():
        # The webhook URL routinely embeds a secret (Slack hook, ntfy token).
        return err('Administrator access required', 403)
    state = load_store('alerts_state')
    return jsonify({**load_store('alerts'),
                    'recent': list(reversed(state.get('recent', []))),
                    'baseline_done': bool(state.get('baseline_done'))})


@bp.route('/api/alerts', methods=['POST'])
def alerts_save():
    data, e = json_object()
    if e:
        return e
    with STORE_LOCK:
        cfg, verr = _validate_config(data, load_store('alerts'))
        if verr:
            return err(verr)
        save_store('alerts', cfg)
    return jsonify({'success': True, **cfg})


@bp.route('/api/alerts/test', methods=['POST'])
def alerts_test():
    cfg = load_store('alerts')
    if not cfg.get('webhook_url'):
        return err('Configure a webhook URL first')
    ok, detail = deliver(cfg, 'test', 'DNSMAQ-MGR test alert',
                         'If you can read this, alert delivery works.')
    if not ok:
        return err('Delivery failed: %s' % detail, 502)
    return jsonify({'success': True, 'detail': detail})
