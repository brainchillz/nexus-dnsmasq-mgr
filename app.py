#!/usr/bin/env python3
"""DNSMAQ-MGR — entrypoint.

`python app.py` boots the web UI (TLS by default, self-signed cert generated
on first run). `python app.py <command>` dispatches CLI subcommands
(set-password, history-tick, render) and exits without starting the server.

In Docker (DNSMAQ_SUPERVISE=1) this process also supervises dnsmasq itself
as a child process; on bare metal the systemd dnsmasq unit is driven via
sudo instead.
"""
import sys
import signal

from dnsmaqmgr import cli

if __name__ == '__main__':
    # CLI subcommands run BEFORE the app object exists: `dhcp-probe` is
    # invoked as root through sudo (environment stripped), and creating the
    # app would create/chmod the data tree as root in the wrong place.
    _rc = cli.dispatch(sys.argv)
    if _rc is not None:
        sys.exit(_rc)

from dnsmaqmgr import create_app
from dnsmaqmgr.core import config, auth, tls
from dnsmaqmgr import dnsmasq, stats, encdns

app = create_app()


def _shutdown(signum, _frame):
    """SIGTERM/SIGINT: stop the supervised children and exit. As PID 1 in a
    container the default disposition would IGNORE the signal, so `docker
    stop` waited out its grace period and SIGKILLed dnsmasq."""
    print('signal %d — stopping supervised children' % signum, flush=True)
    try:
        encdns.get_proxy().stop()
    except Exception:
        pass
    if config.SUPERVISE:
        try:
            dnsmasq.get_controller().stop()
        except Exception:
            pass
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    app.secret_key = auth.ensure_bootstrap()['secret_key']
    dnsmasq.ensure_render()
    # Encrypted upstream first: if enabled, dnsmasq's rendered config already
    # points at the proxy — it must be listening before dnsmasq answers.
    encdns.startup()
    if config.SUPERVISE:
        ok, detail = dnsmasq.get_controller().start()
        if not ok:
            print('WARNING: dnsmasq failed to start: %s' % detail, flush=True)
    stats.start_ticker()
    from dnsmaqmgr import events
    events.start_listener()
    ssl_context = None
    if config.TLS_ENABLED:
        tls.ensure_tls_cert()
        ssl_context = (config.TLS_CERT, config.TLS_KEY)
    app.run(host='0.0.0.0', port=config.WEB_PORT,
            ssl_context=ssl_context, debug=False, threaded=True)
