FROM debian:bookworm-slim

# dnsmasq comes from the distro (the image bundles it — the app supervises it
# as a child process); Python needs are trivial, so debian-slim beats python:*.
RUN apt-get update && apt-get install -y --no-install-recommends \
        dnsmasq python3 python3-venv openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/dnsmaq-mgr/requirements.txt
RUN python3 -m venv /opt/dnsmaq-mgr/venv \
    && /opt/dnsmaq-mgr/venv/bin/pip install --no-cache-dir -r /opt/dnsmaq-mgr/requirements.txt

COPY app.py /opt/dnsmaq-mgr/app.py
COPY dnsmaqmgr /opt/dnsmaq-mgr/dnsmaqmgr
COPY templates /opt/dnsmaq-mgr/templates
COPY static /opt/dnsmaq-mgr/static
COPY docker/entrypoint.sh /opt/dnsmaq-mgr/entrypoint.sh
RUN chmod +x /opt/dnsmaq-mgr/entrypoint.sh

# /data holds everything mutable: auth.json, certs, state, rendered config,
# leases, tftp root, history.db.
ENV DNSMAQ_DATA_DIR=/data \
    DNSMAQ_SUPERVISE=1 \
    DNSMAQ_NO_SUDO=1

EXPOSE 8443/tcp 53/tcp 53/udp 67/udp 69/udp
VOLUME /data
WORKDIR /opt/dnsmaq-mgr

ENTRYPOINT ["/opt/dnsmaq-mgr/entrypoint.sh"]
