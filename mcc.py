"""Mikrotik Command Center.

    python mcc.py              start the console; connect to your router from the Setup page
    python mcc.py --demo       a simulated router + switch + network with scripted incidents
    python mcc.py --replace    stop an MCC already running on the port, then start (i.e. restart)

On a server (see deploy/), settings can come from the environment instead of flags:
    MCC_BIND, MCC_PORT, MCC_DATA     like --bind / --port / --data
    MCC_TOKEN                        a fixed access token, so the console URL survives restarts
    MCC_ROUTER_PASSWORD              optional: reconnect to the router (host/user from Setup) at start
    MCC_SWITCH_PASSWORD              optional: the same for the switch

Python 3.8+ standard library only. Passwords are kept in memory and never written to disk.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import sys
import threading
import time
import webbrowser
from pathlib import Path

from mcc import __version__
from mcc.config import DATA_DIR, Config
from mcc.hub import Hub
from mcc.routeros import RouterOSError
from mcc.swos import SwOSError
from mcc.runctl import remove_run_file, stop_existing, write_run_file
from mcc.server import make_server

DEMO_BLOCKLIST = """# Demo blocklist -- one IP or CIDR per line.
# For your real network put a list you trust in data/blocklist.txt (e.g. Spamhaus DROP, FireHOL level1).
192.0.2.66        # the simulated "update-check.biz" command-and-control server
198.18.0.0/15     # benchmarking range: nothing legitimate should come from here
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Mikrotik Command Center")
    ap.add_argument("--demo", action="store_true", help="run against a simulated network")
    env = os.environ.get
    ap.add_argument("--bind", default=env("MCC_BIND") or None,
                    help="UI address (default 127.0.0.1; anything else requires the token)")
    ap.add_argument("--port", type=int, default=int(env("MCC_PORT")) if env("MCC_PORT") else None,
                    help="UI port (default 8840)")
    ap.add_argument("--speed", type=float, default=1.0, help="demo: incident script speed multiplier")
    ap.add_argument("--no-browser", action="store_true", help="don't open a browser")
    ap.add_argument("--data", default=env("MCC_DATA") or None,
                    help="data directory (default ./data, or ./data/demo with --demo)")
    ap.add_argument("--replace", action="store_true",
                    help="stop an MCC already running on this port first (restart)")
    args = ap.parse_args(argv)

    data_dir = Path(args.data) if args.data else (DATA_DIR / "demo" if args.demo else DATA_DIR)
    if args.replace:
        # before anything else: the running copy holds the UI port and the UDP collectors
        ui_port = args.port if args.port is not None else int(Config(data_dir).get("ui.port") or 8840)
        if not stop_existing(ui_port):
            return 2
    world = None
    if args.demo:
        from mcc import sim
        if not args.data and data_dir.exists():
            shutil.rmtree(data_dir, ignore_errors=True)  # every demo starts from a clean slate
        data_dir.mkdir(parents=True, exist_ok=True)
        (data_dir / "blocklist.txt").write_text(DEMO_BLOCKLIST, encoding="utf-8")
        world = sim.World(speed=args.speed).start()
        router = sim.serve(sim.make_router(world))
        switch = sim.serve(sim.make_swos(world))
        cfg = Config(data_dir)
        cfg.update({"collectors": {"bind": "127.0.0.1", "flow_port": 0, "syslog_port": 0},
                    "blocklist_file": str(data_dir / "blocklist.txt"),
                    "lan_networks": ["192.168.88.0/24"], "wan": {"down_mbps": 500, "up_mbps": 100}})
    else:
        cfg = Config(data_dir)

    bind = args.bind or cfg.get("ui.bind") or "127.0.0.1"
    port = args.port if args.port is not None else int(cfg.get("ui.port") or 8840)
    hub = Hub(cfg, data_dir)
    if args.demo and not hub.geo.db:
        hub.geo.demo = sim.demo_geo  # the simulated Internet's addresses aren't in any real database
    hub.start(fallback_ports=args.demo)
    for c in (hub.flow_col, hub.syslog_col):
        if c.last_error:
            print("  ! " + c.last_error, file=sys.stderr)

    try:
        httpd, token = make_server(hub, bind, port, os.environ.get("MCC_TOKEN"))
    except OSError as e:
        if os.environ.get("INVOCATION_ID"):  # running as a systemd service
            print("Cannot listen on {}:{} -- {}. Another program holds the port -- often a copy of MCC started "
                  "by hand. Find it with:  sudo ss -ltnp 'sport = :{}'   then stop it, or re-run "
                  "deploy/install-debian.sh (it stops a stray MCC for you).".format(bind, port, e, port),
                  file=sys.stderr)
        else:
            print("Cannot listen on {}:{} -- {}. MCC is probably already running: restart it with\n"
                  "  python mcc.py --replace   (or pick another --port)".format(bind, port, e), file=sys.stderr)
        hub.stop()
        return 2
    url = "http://{}:{}/".format("127.0.0.1" if bind in ("0.0.0.0", "::") else bind, httpd.server_address[1])
    # lets a later `mcc.py --replace` ask this copy to shut down cleanly
    hub.admin_secret = write_run_file(httpd.server_address[1])
    hub.shutdown_hook = lambda: threading.Thread(target=httpd.shutdown, daemon=True).start()
    if token:
        url += "?token=" + token

    if args.demo:
        hub.connect_router("127.0.0.1", "admin", "demo", scheme="http", port=router.server_address[1])
        hub.connect_switch("127.0.0.1:{}".format(switch.server_address[1]), "admin", "")
    else:
        auto_connect(hub, cfg)

    print("Mikrotik Command Center {}{}".format(__version__, "  (DEMO: simulated network)" if args.demo else ""))
    print("  console   {}".format(url))
    print("  flows     UDP {}   syslog UDP {}".format(hub.flow_col.port, hub.syslog_col.port))
    print("  data      {}".format(data_dir))
    if token:
        print("  ! the console is reachable from the network; the token in the URL is required")
    print("  Ctrl+C to stop · restart with: python mcc.py --replace{}".format(" --demo" if args.demo else ""))
    headless = sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    if not args.no_browser and not headless:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    # systemd (and kill) stop a service with SIGTERM: shut down like Ctrl+C, releasing the ports
    try:
        signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=httpd.shutdown, daemon=True).start())
    except (ValueError, OSError):
        pass
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        remove_run_file(httpd.server_address[1])
        httpd.server_close()
        hub.stop()
        if world:
            world.stop()
    return 0


def auto_connect(hub: Hub, cfg: Config) -> None:
    """Unattended start (a service after a reboot): reconnect with passwords from the environment
    (MCC_ROUTER_PASSWORD / MCC_SWITCH_PASSWORD, kept by the admin in a root-only file) and the
    host/user saved from Setup. MCC itself never writes a password anywhere. Keeps retrying in the
    background while the router is unreachable (the VM may boot before the network is up)."""
    jobs = []
    rpw = os.environ.get("MCC_ROUTER_PASSWORD")
    r = cfg.get("router") or {}
    host = os.environ.get("MCC_ROUTER_HOST") or r.get("host")
    user = os.environ.get("MCC_ROUTER_USER") or r.get("user")
    if rpw is not None and host and user:
        def router() -> None:
            hub.connect_router(host, user, rpw, os.environ.get("MCC_ROUTER_SCHEME") or r.get("scheme") or "https",
                               int(os.environ.get("MCC_ROUTER_PORT") or r.get("port") or 0),
                               bool(r.get("verify_tls")), pin=True)
        jobs.append(("router " + host, router))
    elif rpw is not None:
        print("  ! MCC_ROUTER_PASSWORD is set but no router address/user is known yet: connect once from Setup "
              "(or set MCC_ROUTER_HOST and MCC_ROUTER_USER)", file=sys.stderr)
    spw = os.environ.get("MCC_SWITCH_PASSWORD")
    sw = cfg.get("switch") or {}
    shost = os.environ.get("MCC_SWITCH_HOST") or sw.get("host")
    if spw is not None and shost:
        def switch() -> None:
            hub.connect_switch(shost, os.environ.get("MCC_SWITCH_USER") or sw.get("user") or "admin", spw,
                               sw.get("scheme") or "http", sw.get("kind") or "auto")
        jobs.append(("switch " + shost, switch))

    def run() -> None:
        pending = list(jobs)
        delay = 5.0
        while pending:
            for item in list(pending):
                name, fn = item
                try:
                    fn()
                    print("  connected to the {}".format(name))
                    pending.remove(item)
                except (RouterOSError, SwOSError, OSError) as e:
                    print("  ! {}: {} -- retrying in {:.0f}s".format(name, e, delay), file=sys.stderr)
                    if getattr(e, "status", 0) == 401 or "refused the user" in str(e):
                        pending.remove(item)  # a wrong password won't fix itself; don't lock the account out
            if pending:
                time.sleep(delay)
                delay = min(delay * 2, 120.0)
    if jobs:
        threading.Thread(target=run, name="mcc-autoconnect", daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
