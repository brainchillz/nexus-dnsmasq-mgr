#!/bin/sh
# Deliberately tiny: dnsmasq supervision lives IN the app (ChildController),
# so the app is PID 1 and container lifecycle == app lifecycle.
set -e
mkdir -p /data/state /data/certs /data/leases /data/encdns \
         /data/render/dnsmasq.d /data/render/hosts.d
exec /opt/dnsmaq-mgr/venv/bin/python /opt/dnsmaq-mgr/app.py
