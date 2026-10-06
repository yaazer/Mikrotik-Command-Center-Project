#!/usr/bin/env bash
# Install -- or update -- Mikrotik Command Center as a systemd service on Debian 12/13 (and Ubuntu).
#
#   git clone -b main https://github.com/yaazer/Mikrotik-Command-Center-Project.git
#   cd Mikrotik-Command-Center-Project && sudo ./deploy/install-debian.sh
#
# Re-run it after a `git pull` to update: the code is replaced, your data and settings are kept.
#
#   program   /opt/mcc            (root-owned, read-only to the service)
#   data      /var/lib/mcc        (config, threats, actions, ignore rules, geolocation DB)
#   settings  /etc/mcc/mcc.env    (root-only: bind address, access token, optional passwords)
#   service   mcc.service         runs as the unprivileged user "mcc"
set -euo pipefail

APP=/opt/mcc
DATA=/var/lib/mcc
ETC=/etc/mcc
ENVF=$ETC/mcc.env
UNIT=/etc/systemd/system/mcc.service
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run it as root:  sudo $0"
[ -f "$SRC/mcc.py" ] && [ -d "$SRC/mcc" ] || die "run it from the MCC folder (can't find mcc.py next to deploy/)"
command -v systemctl >/dev/null || die "systemd is required"

# --- python 3.8+ (Debian 13 ships 3.13; MCC needs nothing beyond the standard library) ------------
if ! command -v python3 >/dev/null; then
  say "installing python3"
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "python3 is older than 3.8"
say "python $(python3 -c 'import platform; print(platform.python_version())')"

# --- service account ------------------------------------------------------------------------------
if ! id mcc >/dev/null 2>&1; then
  say "creating system user mcc"
  useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin mcc
fi
install -d -o mcc -g mcc -m 0750 "$DATA"

# --- program files (replaced atomically; data never lives here) -----------------------------------
if [ "$SRC" != "$APP" ]; then
  say "installing the program to $APP"
  rm -rf "$APP.new"
  mkdir -p "$APP.new"
  tar -C "$SRC" --exclude=./data --exclude=./.git --exclude='__pycache__' --exclude='*.pyc' -cf - . | tar -C "$APP.new" -xf -
  if [ -d "$APP" ]; then rm -rf "$APP.old"; mv "$APP" "$APP.old"; fi
  mv "$APP.new" "$APP"
  rm -rf "$APP.old"
fi
chown -R root:root "$APP"
chmod -R u=rwX,go=rX "$APP"
chmod 0755 "$APP/deploy/install-debian.sh"

# --- first install: copy data from a local ./data folder if one came along (e.g. moved from a PC) --
if [ -d "$SRC/data" ] && [ -z "$(ls -A "$DATA" 2>/dev/null)" ]; then
  say "copying existing data from $SRC/data"
  tar -C "$SRC/data" --exclude=./demo -cf - . | tar -C "$DATA" -xf -
  chown -R mcc:mcc "$DATA"
fi

# --- settings: created once, never overwritten ----------------------------------------------------
install -d -o root -g root -m 0755 "$ETC"
if [ ! -f "$ENVF" ]; then
  say "writing $ENVF (with a new access token)"
  TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
  umask 077
  cat >"$ENVF" <<EOF
# Mikrotik Command Center -- read by mcc.service. Root-only (0600): it can hold passwords.
# After editing:  sudo systemctl restart mcc

# Where the console listens. 0.0.0.0 = every interface (the access token is then required).
MCC_BIND=0.0.0.0
MCC_PORT=8840

# Access token: the console URL is http://<this-host>:8840/?token=<token>
MCC_TOKEN=$TOKEN

# Optional -- reconnect automatically after a restart or reboot. Without these, open Setup and enter
# the passwords after each restart (MCC keeps them in memory only). Connect once from Setup first:
# that saves the address and user; the password itself only ever lives here.
# Use a dedicated RouterOS user with limited rights (see README: "Give MCC its own RouterOS user").
#MCC_ROUTER_PASSWORD=
#MCC_SWITCH_PASSWORD=
EOF
  chmod 0600 "$ENVF"
fi

# --- systemd --------------------------------------------------------------------------------------
say "installing the service"
install -m 0644 "$APP/deploy/mcc.service" "$UNIT"
systemctl daemon-reload
systemctl enable mcc >/dev/null 2>&1

# --- make sure nothing else holds the console port ------------------------------------------------
# Typically a copy of MCC started by hand (`python3 mcc.py` in the clone) before the service existed:
# the service can't listen until it's gone. Anything that isn't MCC is left alone.
PORT="$(sed -n 's/^MCC_PORT=//p' "$ENVF" | tail -1)"; PORT="${PORT:-8840}"
systemctl stop mcc 2>/dev/null || true
holder() { ss -ltnpH "sport = :$PORT" 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1; }
for _ in 1 2 3; do
  PID="$(holder)"
  [ -n "$PID" ] || break
  CMD="$(tr '\0' ' ' </proc/"$PID"/cmdline 2>/dev/null || true)"
  if printf '%s' "$CMD" | grep -q 'mcc\.py'; then
    say "stopping a copy of MCC started by hand on port $PORT (pid $PID: $CMD)"
    kill "$PID" 2>/dev/null || true
    for _ in $(seq 1 20); do [ -d /proc/"$PID" ] || break; sleep 0.5; done
    [ -d /proc/"$PID" ] && kill -9 "$PID" 2>/dev/null || true
    sleep 1
  else
    die "port $PORT is used by another program (pid $PID: ${CMD:-unknown}). Stop it, or set another MCC_PORT in $ENVF and re-run."
  fi
done
systemctl start mcc

# --- firewall (Debian has none enabled by default; open the ports if ufw is on) -------------------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  say "opening ufw: $PORT/tcp (console), 2055/udp (flows), 5514/udp (syslog)"
  ufw allow "$PORT"/tcp >/dev/null; ufw allow 2055/udp >/dev/null; ufw allow 5514/udp >/dev/null
fi

# --- check it came up -----------------------------------------------------------------------------
for _ in $(seq 1 20); do
  systemctl is-active --quiet mcc && python3 - "$PORT" <<'EOF' && break
import socket, sys
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1).close()
except OSError:
    sys.exit(1)
EOF
  sleep 1
done
if ! systemctl is-active --quiet mcc; then
  journalctl -u mcc -n 30 --no-pager || true
  die "the service didn't start (log above)"
fi

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
TOKEN="$(sed -n 's/^MCC_TOKEN=//p' "$ENVF" | tail -1)"
echo
say "Mikrotik Command Center is running"
echo "    console   http://${IP:-<this-host>}:$PORT/?token=$TOKEN"
echo "    status    systemctl status mcc        logs: journalctl -u mcc -f"
echo "    settings  $ENVF  (then: systemctl restart mcc)"
echo "    data      $DATA"
echo "    update    git pull && sudo ./deploy/install-debian.sh"
echo
echo "    Router telemetry goes to this machine: in the console open Setup > Telemetry and approve the"
echo "    plan again (it points flows and syslog at ${IP:-this host})."
