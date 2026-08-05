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

from dnsmaqmgr import create_app, cli
from dnsmaqmgr.core import config, auth, tls
from dnsmaqmgr import dnsmasq, stats, encdns

app = create_app()


if __name__ == '__main__':
    _rc = cli.dispatch(sys.argv)
    if _rc is not None:
        sys.exit(_rc)
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
    ssl_context = None
    if config.TLS_ENABLED:
        tls.ensure_tls_cert()
        ssl_context = (config.TLS_CERT, config.TLS_KEY)
    app.run(host='0.0.0.0', port=config.WEB_PORT,
            ssl_context=ssl_context, debug=False, threaded=True)
