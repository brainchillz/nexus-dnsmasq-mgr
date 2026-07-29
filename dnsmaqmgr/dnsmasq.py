"""dnsmasq config rendering, validation, atomic apply, and service control.

This is the single choke point between the JSON stores and the running
dnsmasq: every mutating route calls apply_change(), which renders the full
config from the stores, validates it with `dnsmasq --test` against a temp
copy, atomically swaps the files in, and reloads (SIGHUP) or restarts the
daemon depending on what changed. dnsmasq re-reads addn-hosts /
dhcp-hostsfile / dhcp-optsfile on SIGHUP but nothing else — so host and
static-lease edits are free, structural edits restart (~100 ms).

Two controllers hide the platform difference: SystemdController drives the
distro dnsmasq unit via sudo systemctl (bare metal); ChildController runs
dnsmasq as a supervised child process (Docker, DNSMAQ_SUPERVISE=1).
"""
import os
import copy
import glob
import shutil
import signal
import tempfile
import threading
import subprocess
import time
from collections import deque
from flask import Blueprint, jsonify

from .core.config import (RENDER_DIR, CONF_DIR, MANAGED_HOSTS, DHCP_HOSTS_FILE,
                          DHCP_OPTS_FILE, LEASES_FILE, DNSMASQ_BIN,
                          DNSMASQ_UNIT, SUPERVISE, write_text_atomic)
from .core.runcmd import run, err
from .core.store import STORE_LOCK, load_store, save_store, bump_serial

bp = Blueprint('dnsmasqctl', __name__)

HEADER = '# Managed by DNSMAQ-MGR — do not edit; changes are overwritten on every apply.\n'

# Relative paths (under RENDER_DIR) that dnsmasq re-reads on SIGHUP. A change
# touching only these files never needs a restart.
HUP_ONLY = {'hosts.d/managed-hosts', 'dhcp-hosts', 'dhcp-opts'}

# ICANN DNSSEC root trust anchors (KSK-2017 and KSK-2024).
TRUST_ANCHORS = [
    '.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D',
    '.,38696,8,2,683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16',
]

# PXE client-arch (RFC 4578 option 93) -> dnsmasq pxe-service CSA keyword.
PXE_CSA = {'0': 'x86PC', '6': 'IA32_EFI', '7': 'BC_EFI', '9': 'x86-64_EFI',
           '10': 'ARM32_EFI', '11': 'ARM64_EFI'}


def _enabled(items):
    return [it for it in items if it.get('enabled', True)]


# ─── Render functions (pure: stores in, text out) ─────────────────────

def render_main(settings):
    lines = [HEADER]
    if not settings.get('dns_enabled', True):
        lines.append('# DNS disabled from the UI')
        lines.append('port=0')
    if settings.get('domain'):
        lines.append('domain=%s' % settings['domain'])
        if settings.get('expand_hosts'):
            lines.append('expand-hosts')
    for ifc in settings.get('interfaces', []):
        lines.append('interface=%s' % ifc)
    for addr in settings.get('listen_addresses', []):
        lines.append('listen-address=%s' % addr)
    if settings.get('interfaces') or settings.get('listen_addresses'):
        # Explicit listen restrictions must never exclude loopback — the stats
        # collector queries dnsmasq's CHAOS counters at 127.0.0.1.
        lines.append('listen-address=127.0.0.1')
    if settings.get('bind_interfaces'):
        lines.append('bind-interfaces')
    for up in settings.get('upstreams', []):
        lines.append('server=%s' % up)
    if settings.get('no_resolv'):
        lines.append('no-resolv')
    if settings.get('cache_size') is not None:
        # Emit even for 0 — `cache-size=0` disables caching, which is exactly
        # what the operator asked for; a falsy check would silently leave the
        # default (150) in place instead.
        lines.append('cache-size=%d' % int(settings['cache_size']))
    if settings.get('domain_needed'):
        lines.append('domain-needed')
    if settings.get('bogus_priv'):
        lines.append('bogus-priv')
    if settings.get('dnssec'):
        lines.append('dnssec')
        for ta in TRUST_ANCHORS:
            lines.append('trust-anchor=%s' % ta)
    if settings.get('log_queries'):
        lines.append('log-queries=extra')
    if settings.get('log_dhcp'):
        lines.append('log-dhcp')
    # App-owned leases file: lets the app read lease state without sudo on
    # every platform, and keeps leases on the Docker volume.
    lines.append('dhcp-leasefile=%s' % LEASES_FILE)
    return '\n'.join(lines) + '\n'


def render_dns(dns):
    lines = [HEADER, 'addn-hosts=%s' % MANAGED_HOSTS]
    for rec in _enabled(dns.get('addresses', [])):
        lines.append('address=/%s/%s' % (rec['domain'], rec['ip']))
    for rec in _enabled(dns.get('cnames', [])):
        lines.append('cname=%s,%s' % (rec['alias'], rec['target']))
    for rec in _enabled(dns.get('forwards', [])):
        lines.append('server=/%s/%s' % (rec['domain'], rec['upstream']))
    return '\n'.join(lines) + '\n'


def render_hosts(dns):
    lines = [HEADER]
    for rec in dns.get('hosts', []):
        comment = (' # %s' % rec['comment']) if rec.get('comment') else ''
        for ip_key in ('a', 'aaaa'):
            ip = rec.get(ip_key)
            if not ip:
                continue
            if rec.get('enabled', True):
                lines.append('%s %s%s' % (ip, rec['name'], comment))
            else:
                lines.append('# disabled: %s %s%s' % (ip, rec['name'], comment))
    return '\n'.join(lines) + '\n'


def render_dhcp(dhcp, settings):
    lines = [HEADER]
    if not settings.get('dhcp_enabled'):
        lines.append('# DHCP disabled from the UI')
        return '\n'.join(lines) + '\n'
    for r in _enabled(dhcp.get('ranges', [])):
        parts = []
        if r.get('interface'):
            parts.append('interface:%s' % r['interface'])
        if r.get('tag'):
            parts.append('set:%s' % r['tag'])
        parts += [r['start'], r['end']]
        if r.get('netmask'):
            parts.append(r['netmask'])
        parts.append(r.get('lease') or '12h')
        lines.append('dhcp-range=%s' % ','.join(parts))
    if settings.get('dhcp_authoritative'):
        lines.append('dhcp-authoritative')
    # Static leases and options live in hostsfile/optsfile because dnsmasq
    # re-reads those on SIGHUP — the most frequent DHCP edits never restart.
    lines.append('dhcp-hostsfile=%s' % DHCP_HOSTS_FILE)
    lines.append('dhcp-optsfile=%s' % DHCP_OPTS_FILE)
    return '\n'.join(lines) + '\n'


def render_dhcp_hosts(dhcp, settings):
    lines = [HEADER]
    if settings.get('dhcp_enabled'):
        for s in _enabled(dhcp.get('static_leases', [])):
            parts = [s['mac']]
            if s.get('tag'):
                parts.append('set:%s' % s['tag'])
            parts.append(s['ip'])
            if s.get('hostname'):
                parts.append(s['hostname'])
            lines.append(','.join(parts))
    return '\n'.join(lines) + '\n'


def render_dhcp_opts(dhcp, settings):
    lines = [HEADER]
    if settings.get('dhcp_enabled'):
        for o in _enabled(dhcp.get('options', [])):
            parts = []
            if o.get('tag'):
                parts.append('tag:%s' % o['tag'])
            opt = str(o['option'])
            parts.append(opt if (opt.startswith('option') or opt.isdigit()) else 'option:' + opt)
            if o.get('value'):
                parts.append(str(o['value']))
            lines.append(','.join(parts))
    return '\n'.join(lines) + '\n'


def render_boot(netboot, settings):
    """Boot directives only — the app points clients at an EXTERNAL boot server
    (next-server) and never serves files itself. `server` is required per entry
    (validated on the way in), so both dhcp-boot and pxe-service carry it."""
    lines = [HEADER]
    if settings.get('dhcp_enabled') or netboot.get('proxy_dhcp'):
        entries = _enabled(netboot.get('entries', []))
        for e in entries:
            server = e.get('server') or ''
            tail = ',,%s' % server if server else ''
            if e.get('arches'):
                for arch in e['arches']:
                    lines.append('dhcp-match=set:%s,option:client-arch,%s' % (e['id'], arch))
                lines.append('dhcp-boot=tag:%s,%s%s' % (e['id'], e['filename'], tail))
            else:
                lines.append('dhcp-boot=%s%s' % (e['filename'], tail))
        if netboot.get('proxy_dhcp') and netboot.get('proxy_subnet'):
            # Proxy-DHCP: offer boot info alongside a foreign DHCP server.
            lines.append('dhcp-range=%s,proxy' % netboot['proxy_subnet'])
            prompt = netboot.get('pxe_prompt') or 'Network boot'
            lines.append('pxe-prompt="%s",3' % prompt.replace('"', ''))
            for e in entries:
                server = e.get('server') or ''
                for arch in (e.get('arches') or ['0']):
                    csa = PXE_CSA.get(str(arch))
                    if csa:
                        # server is required in proxy mode — no local TFTP to
                        # fall back to.
                        svc = 'pxe-service=%s,"%s",%s' % (
                            csa, (e.get('name') or 'Boot').replace('"', ''), e['filename'])
                        lines.append(svc + (',%s' % server if server else ''))
    return '\n'.join(lines) + '\n'


def render_extra(settings):
    text = settings.get('extra_options') or ''
    return HEADER + (text.rstrip('\n') + '\n' if text.strip() else '# (no extra options)\n')


def render_all(stores=None):
    """Render every managed file. Returns {relpath-under-RENDER_DIR: text}."""
    if stores is None:
        stores = {name: load_store(name) for name in ('settings', 'dns', 'dhcp', 'netboot')}
    s, d, h, n = stores['settings'], stores['dns'], stores['dhcp'], stores['netboot']
    return {
        'dnsmasq.d/00-main.conf': render_main(s),
        'dnsmasq.d/10-dns.conf': render_dns(d),
        'dnsmasq.d/20-dhcp.conf': render_dhcp(h, s),
        'dnsmasq.d/30-boot.conf': render_boot(n, s),
        'dnsmasq.d/90-extra.conf': render_extra(s),
        'hosts.d/managed-hosts': render_hosts(d),
        'dhcp-hosts': render_dhcp_hosts(h, s),
        'dhcp-opts': render_dhcp_opts(h, s),
    }


# ─── Validation ────────────────────────────────────────────────────────

def validate_render(rendered):
    """Write the rendered conf fragments to a temp dir and syntax-check them
    with `dnsmasq --test`. Returns (ok, output)."""
    tmp = tempfile.mkdtemp(prefix='dnsmaq-validate-')
    try:
        confd = os.path.join(tmp, 'dnsmasq.d')
        os.makedirs(confd)
        for rel, text in rendered.items():
            if rel.startswith('dnsmasq.d/'):
                with open(os.path.join(confd, os.path.basename(rel)), 'w') as f:
                    f.write(text)
        testconf = os.path.join(tmp, 'test.conf')
        with open(testconf, 'w') as f:
            f.write('conf-dir=%s,*.conf\n' % confd)
        out, e, rc = run([DNSMASQ_BIN, '--test', '-C', testconf], no_sudo=True, timeout=15)
        return rc == 0, (e or out).strip()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _read_current():
    cur = {}
    for rel in render_all().keys():
        try:
            with open(os.path.join(RENDER_DIR, rel)) as f:
                cur[rel] = f.read()
        except OSError:
            cur[rel] = None
    return cur


def diff_render(rendered):
    """Classify the pending change: 'none', 'reload' (only SIGHUP-refreshable
    files changed) or 'restart' (any conf fragment changed)."""
    changed = []
    for rel, text in rendered.items():
        try:
            with open(os.path.join(RENDER_DIR, rel)) as f:
                if f.read() == text:
                    continue
        except OSError:
            pass
        changed.append(rel)
    if not changed:
        return 'none', changed
    if all(rel in HUP_ONLY for rel in changed):
        return 'reload', changed
    return 'restart', changed


def write_render(rendered):
    for rel, text in rendered.items():
        path = os.path.join(RENDER_DIR, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        write_text_atomic(path, text, 0o644)


def ensure_render():
    """First boot: materialize the rendered config so dnsmasq has something to
    read before the first UI edit. Never overwrites existing files."""
    rendered = render_all()
    missing = {rel: text for rel, text in rendered.items()
               if not os.path.exists(os.path.join(RENDER_DIR, rel))}
    if missing:
        write_render(missing)


# ─── Service controllers ──────────────────────────────────────────────

class SystemdController:
    """Drives the distro dnsmasq unit through the argument-pinned sudoers
    lines the installer writes."""
    mode = 'systemd'

    def status(self):
        out, _, rc = run(['systemctl', 'is-active', DNSMASQ_UNIT])
        running = out.strip() == 'active'
        return {'running': running, 'state': out.strip() or 'unknown'}

    def restart(self):
        _, e, rc = run(['systemctl', 'restart', DNSMASQ_UNIT], timeout=30)
        return rc == 0, e

    def reload(self):
        _, e, rc = run(['systemctl', 'kill', '-s', 'HUP', DNSMASQ_UNIT])
        return rc == 0, e

    def stop(self):
        run(['systemctl', 'stop', DNSMASQ_UNIT], timeout=30)

    def logs(self, lines=200):
        out, e, rc = run(['journalctl', '-u', DNSMASQ_UNIT, '-n', str(int(lines)),
                          '--no-pager'])
        return out if rc == 0 else (e or 'journalctl failed')


class ChildController:
    """Docker mode: the app IS the supervisor. dnsmasq runs as a child in the
    foreground; stderr is kept in a ring buffer for the logs UI; a monitor
    thread respawns it with backoff if it dies unexpectedly."""
    mode = 'child'

    def __init__(self):
        self._proc = None
        self._lock = threading.RLock()
        self._log = deque(maxlen=500)
        self._stopping = False
        self._backoff = 1

    def _spawn(self):
        # -C /dev/null: never read the image's /etc/dnsmasq.conf — the rendered
        # conf-dir is the entire configuration.
        args = [DNSMASQ_BIN, '--keep-in-foreground', '-C', '/dev/null',
                '--conf-dir=%s,*.conf' % CONF_DIR, '--log-facility=-']
        self._proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True)
        threading.Thread(target=self._pump, args=(self._proc,), daemon=True).start()
        threading.Thread(target=self._watch, args=(self._proc,), daemon=True).start()

    def _pump(self, proc):
        for line in proc.stdout:
            self._log.append(line.rstrip('\n'))

    def _watch(self, proc):
        proc.wait()
        with self._lock:
            if self._stopping or proc is not self._proc:
                return
            self._log.append('dnsmasq exited rc=%s — respawning in %ds'
                             % (proc.returncode, self._backoff))
        time.sleep(self._backoff)
        with self._lock:
            self._backoff = min(self._backoff * 2, 30)
            if not self._stopping and proc is self._proc:
                self._spawn()

    def start(self):
        with self._lock:
            self._stopping = False
            if self._proc and self._proc.poll() is None:
                return True, ''
            self._backoff = 1
            self._spawn()
        time.sleep(0.3)
        with self._lock:
            if self._proc.poll() is not None:
                return False, '\n'.join(list(self._log)[-10:])
        return True, ''

    def status(self):
        with self._lock:
            running = bool(self._proc and self._proc.poll() is None)
            pid = self._proc.pid if running else None
        return {'running': running, 'state': 'active' if running else 'stopped', 'pid': pid}

    def restart(self):
        with self._lock:
            self._stopping = True
            proc = self._proc
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        return self.start()

    def reload(self):
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self._proc.send_signal(signal.SIGHUP)
                return True, ''
        return self.start()

    def stop(self):
        with self._lock:
            self._stopping = True
            proc = self._proc
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

    def logs(self, lines=200):
        return '\n'.join(list(self._log)[-int(lines):])


_controller = None

def get_controller():
    global _controller
    if _controller is None:
        _controller = ChildController() if SUPERVISE else SystemdController()
    return _controller


def dnsmasq_version():
    out, _, rc = run([DNSMASQ_BIN, '--version'], no_sudo=True, timeout=10)
    if rc == 0 and out:
        return out.splitlines()[0].replace('Dnsmasq version', '').strip().split()[0]
    return None


# ─── Apply pipeline ────────────────────────────────────────────────────

def apply_change(mutate, sections=('settings',), from_mirror=False):
    """The single choke point for every config mutation.

    mutate() edits and saves the store(s); on validation failure the previous
    store contents are restored and an err() response tuple is returned.
    On success returns a dict {action, changed, service_ok, ...} for the route
    to merge into its JSON response.
    """
    store_names = ('settings', 'dns', 'dhcp', 'netboot')
    with STORE_LOCK:
        snapshot = {n: copy.deepcopy(load_store(n)) for n in store_names}
        mutate()
        rendered = render_all()
        ok, output = validate_render(rendered)
        if not ok:
            for n in store_names:
                save_store(n, snapshot[n])
            return err('dnsmasq rejected the configuration: %s' % output, 400)
        action, changed = diff_render(rendered)
        write_render(rendered)
        for n in set(sections) & set(store_names):
            data = load_store(n)
            bump_serial(n, data)

    ctl = get_controller()
    service_ok, detail = True, ''
    if action == 'reload':
        service_ok, detail = ctl.reload()
    elif action == 'restart':
        service_ok, detail = ctl.restart()
    if action != 'none':
        time.sleep(0.5)
        st = ctl.status()
        if not st.get('running'):
            service_ok, detail = False, detail or 'dnsmasq did not come back after %s' % action

    if not from_mirror:
        from . import peers as peers_mod
        threading.Thread(target=peers_mod.push_all, args=(list(sections),), daemon=True).start()

    return {'action': action, 'changed': changed,
            'service_ok': service_ok, 'service_detail': detail}


# ─── Routes ────────────────────────────────────────────────────────────

@bp.route('/api/dnsmasq/status')
def dnsmasq_status():
    ctl = get_controller()
    st = ctl.status()
    settings = load_store('settings')
    st.update({'mode': ctl.mode, 'version': dnsmasq_version(),
               'dns_enabled': settings.get('dns_enabled', True),
               'dhcp_enabled': settings.get('dhcp_enabled', False)})
    return jsonify(st)


@bp.route('/api/dnsmasq/config')
def dnsmasq_config():
    files = {}
    for rel in sorted(render_all().keys()):
        try:
            with open(os.path.join(RENDER_DIR, rel)) as f:
                files[rel] = f.read()
        except OSError:
            files[rel] = '(not rendered yet)'
    return jsonify({'files': files, 'render_dir': RENDER_DIR})


@bp.route('/api/dnsmasq/validate', methods=['POST'])
def dnsmasq_validate():
    with STORE_LOCK:
        rendered = render_all()
    ok, output = validate_render(rendered)
    action, changed = diff_render(rendered)
    return jsonify({'success': True, 'valid': ok, 'output': output or 'syntax check OK',
                    'pending_action': action, 'pending_files': changed})


@bp.route('/api/dnsmasq/apply', methods=['POST'])
def dnsmasq_apply():
    """Force a full re-render + restart (recovery hammer)."""
    with STORE_LOCK:
        rendered = render_all()
        ok, output = validate_render(rendered)
        if not ok:
            return err('dnsmasq rejected the configuration: %s' % output, 400)
        write_render(rendered)
    service_ok, detail = get_controller().restart()
    return jsonify({'success': True, 'service_ok': service_ok, 'service_detail': detail})


@bp.route('/api/dnsmasq/restart', methods=['POST'])
def dnsmasq_restart():
    service_ok, detail = get_controller().restart()
    if not service_ok:
        return err('Restart failed: %s' % detail, 500)
    return jsonify({'success': True})


@bp.route('/api/dnsmasq/logs')
def dnsmasq_logs():
    return jsonify({'logs': get_controller().logs()})
