#!/bin/bash
# DNSMAQ-MGR bare-metal installer (Debian/Ubuntu).
# Installs to /opt/dnsmaq-mgr, runs as the dnsmaqmgr system user, drives the
# distro dnsmasq unit through argument-pinned sudoers rules, and points
# dnsmasq at the app's rendered config via a /etc/dnsmasq.d drop-in.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/dnsmaq-mgr"
APP_USER="dnsmaqmgr"
WEB_PORT="${DNSMAQ_PORT:-8443}"
TAKE_53=0
[ "$1" = "--take-port-53" ] && TAKE_53=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    error "Please run as root or with sudo"
    exit 1
fi

echo "=== DNSMAQ-MGR Installer (Debian/Ubuntu) ==="
echo ""

info "Installing prerequisite packages..."
apt-get update -qq
apt-get install -y -qq dnsmasq python3 python3-venv openssl curl >/dev/null

info "Creating service user..."
if ! id -u $APP_USER &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -M -d $APP_DIR $APP_USER
fi

info "Deploying application to $APP_DIR ..."
mkdir -p $APP_DIR
cp -r "$SCRIPT_DIR"/app.py "$SCRIPT_DIR"/dnsmaqmgr "$SCRIPT_DIR"/templates \
      "$SCRIPT_DIR"/static "$SCRIPT_DIR"/requirements.txt $APP_DIR/
rm -rf $APP_DIR/dnsmaqmgr/__pycache__ $APP_DIR/dnsmaqmgr/core/__pycache__

info "Creating virtualenv..."
if [ ! -d $APP_DIR/venv ]; then
    python3 -m venv $APP_DIR/venv
fi
$APP_DIR/venv/bin/pip install -q -r $APP_DIR/requirements.txt

info "Preparing data directories..."
mkdir -p $APP_DIR/state $APP_DIR/certs $APP_DIR/leases \
         $APP_DIR/render/dnsmasq.d $APP_DIR/render/hosts.d
chown -R $APP_USER:$APP_USER $APP_DIR
# The interpreter, entrypoint and package that the sudoers rules run as ROOT
# must not be writable by the service user — otherwise any write-as-app-user
# primitive becomes root. Re-own the code paths (only the data dirs below stay
# app-user-owned and writable).
chown -R root:root $APP_DIR/venv $APP_DIR/app.py $APP_DIR/dnsmaqmgr \
                   $APP_DIR/static $APP_DIR/templates
# dnsmasq (root at startup, 'nobody'/'dnsmasq' after priv-drop) must be able to
# read the rendered config and hosts trees.
chmod 755 $APP_DIR $APP_DIR/render $APP_DIR/render/dnsmasq.d \
          $APP_DIR/render/hosts.d $APP_DIR/leases
chmod 700 $APP_DIR/state $APP_DIR/certs

info "Writing sudoers rules (argument-pinned)..."
SYSTEMCTL="$(command -v systemctl)"
JOURNALCTL="$(command -v journalctl)"
cat > /etc/sudoers.d/dnsmaq-mgr <<EOF
# DNSMAQ-MGR: exactly the dnsmasq service actions the web app needs — nothing else.
$APP_USER ALL=(ALL) NOPASSWD: $SYSTEMCTL start dnsmasq, $SYSTEMCTL stop dnsmasq, $SYSTEMCTL restart dnsmasq, $SYSTEMCTL kill -s HUP dnsmasq, $SYSTEMCTL is-active dnsmasq, $SYSTEMCTL status dnsmasq
# Exact argv the app uses — NOT a trailing wildcard: '$JOURNALCTL -u dnsmasq *'
# would let the service user pass '-e' and drop into a root pager (\`!sh\`).
$APP_USER ALL=(ALL) NOPASSWD: $JOURNALCTL -u dnsmasq -n 200 --no-pager
# The DHCP-conflict probe needs to bind UDP port 68 (privileged). Two exact
# forms (no-args and args-after-a-space) so 'dhcp-probeX' can't match and fall
# through cli.dispatch to start the whole web server as root.
$APP_USER ALL=(ALL) NOPASSWD: $APP_DIR/venv/bin/python $APP_DIR/app.py dhcp-probe, $APP_DIR/venv/bin/python $APP_DIR/app.py dhcp-probe *
EOF
chmod 440 /etc/sudoers.d/dnsmaq-mgr
visudo -cf /etc/sudoers.d/dnsmaq-mgr >/dev/null

info "Rendering initial dnsmasq config..."
sudo -u $APP_USER DNSMAQ_DATA_DIR=$APP_DIR $APP_DIR/venv/bin/python $APP_DIR/app.py render

info "Pointing dnsmasq at the managed config..."
mkdir -p /etc/dnsmasq.d
cat > /etc/dnsmasq.d/zz-dnsmaq-mgr.conf <<EOF
# Managed by DNSMAQ-MGR — pulls in the app-rendered configuration.
conf-dir=$APP_DIR/render/dnsmasq.d,*.conf
EOF

# Warn about pre-existing config that could fight with the managed files.
for f in /etc/dnsmasq.conf /etc/dnsmasq.d/*.conf; do
    [ -f "$f" ] || continue
    case "$f" in */zz-dnsmaq-mgr.conf) continue ;; esac
    if grep -Eq '^\s*(port=|dhcp-range|dhcp-leasefile|addn-hosts|conf-dir)' "$f"; then
        warn "$f sets options DNSMAQ-MGR also manages — review it for conflicts."
    fi
done

# systemd-resolved holds 127.0.0.53:53. The managed config uses
# bind-interfaces, so the two can coexist — but most installs want dnsmasq to
# BE the resolver.
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    if [ "$TAKE_53" = "0" ] && [ -t 0 ]; then
        read -r -p "systemd-resolved is running. Disable its stub listener so dnsmasq fully owns port 53? [y/N] " ans
        [ "$ans" = "y" ] || [ "$ans" = "Y" ] && TAKE_53=1
    fi
    if [ "$TAKE_53" = "1" ]; then
        info "Disabling systemd-resolved stub listener..."
        mkdir -p /etc/systemd/resolved.conf.d
        printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/10-dnsmaq-mgr.conf
        ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
        systemctl restart systemd-resolved
    else
        warn "Keeping systemd-resolved's stub listener; dnsmasq binds the other interfaces."
        warn "Re-run with --take-port-53 if you change your mind."
    fi
fi

info "Installing systemd unit..."
cat > /etc/systemd/system/dnsmaq-mgr.service <<EOF
[Unit]
Description=DNSMAQ-MGR dnsmasq management web UI
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=DNSMAQ_DATA_DIR=$APP_DIR
Environment=DNSMAQ_PORT=$WEB_PORT
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/app.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now dnsmasq
systemctl restart dnsmasq
systemctl enable dnsmaq-mgr
systemctl restart dnsmaq-mgr

if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
    info "Allowing web UI port $WEB_PORT/tcp in ufw..."
    ufw allow $WEB_PORT/tcp >/dev/null
    warn "DNS/DHCP ports (53, 67/udp) were NOT opened automatically —"
    warn "open them for your LAN once you enable those features:"
    warn "  ufw allow from <lan-subnet> to any port 53; ufw allow 67/udp; ufw allow 69/udp"
fi

sleep 2
echo ""
info "Done. Web UI: https://$(hostname -I | awk '{print $1}'):$WEB_PORT"
info "First-run admin credentials were printed by the service on first start:"
info "  journalctl -u dnsmaq-mgr | grep -A3 'initial admin'"
info "Or set one now:  sudo -u $APP_USER DNSMAQ_DATA_DIR=$APP_DIR $APP_DIR/venv/bin/python $APP_DIR/app.py set-password admin"
