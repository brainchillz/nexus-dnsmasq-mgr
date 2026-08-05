"""DNSMAQ-MGR — application factory.

Architecture follows Nexus Dashboard (Flask + vanilla JS, no build
step), with the module-registry indirection dropped: this app has a fixed,
focused feature set, so blueprints register directly here.
"""
from flask import Flask, send_from_directory

from .core.config import STATIC_DIR, TEMPLATES_DIR, SESSION_COOKIE_CONFIG, ensure_dirs


def create_app():
    ensure_dirs()
    app = Flask(__name__,
                static_folder=STATIC_DIR,
                static_url_path='/static',
                template_folder=TEMPLATES_DIR)
    app.config.update(SESSION_COOKIE_CONFIG)

    from .core import auth, tls, history
    from . import (dnsmasq, settings, dns, dhcp, netboot, stats, peers, mirror,
                   lookup, querylog, blocklists, backup, changelog, alerts, recon)

    app.before_request(auth.require_login)

    for mod in (auth, tls, history, dnsmasq, settings, dns, dhcp, netboot,
                stats, peers, mirror, lookup, querylog, blocklists, backup,
                changelog, alerts, recon):
        app.register_blueprint(mod.bp)

    @app.route('/')
    def index():
        return send_from_directory(TEMPLATES_DIR, 'index.html')

    return app
