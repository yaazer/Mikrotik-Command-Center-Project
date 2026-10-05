"""End-to-end UI check: starts a private demo (simulated router + switch), drives the console in
headless Chrome/Edge in real time, and asserts on what a person would see and do.

    python tools/ui_check.py              all scenarios
    python tools/ui_check.py setup respond
    SHOTS=out/ python tools/ui_check.py   also save screenshots
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from cdp import Browser, find_browser  # noqa: E402
from mcc import sim  # noqa: E402
from mcc.config import Config  # noqa: E402
from mcc.hub import Hub  # noqa: E402
from mcc.server import make_server  # noqa: E402

SHOTS = os.environ.get("SHOTS", "")


class Demo:
    def __enter__(self) -> "Demo":
        self.dir = Path(tempfile.mkdtemp(prefix="mcc-ui-"))
        (self.dir / "blocklist.txt").write_text("192.0.2.66\n", encoding="utf-8")
        self.world = sim.World(speed=4).start()
        self.router = sim.serve(sim.make_router(self.world))
        self.switch = sim.serve(sim.make_swos(self.world))
        cfg = Config(self.dir)
        cfg.update({"collectors": {"bind": "127.0.0.1", "flow_port": 0, "syslog_port": 0},
                    "blocklist_file": str(self.dir / "blocklist.txt"), "lan_networks": ["192.168.88.0/24"],
                    "wan": {"down_mbps": 500, "up_mbps": 100}})
        self.hub = Hub(cfg, self.dir)
        self.hub.geo.demo = sim.demo_geo
        self.hub.start()
        self.httpd, _ = make_server(self.hub, "127.0.0.1", 0)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.hub.connect_router("127.0.0.1", "admin", "demo", scheme="http", port=self.router.server_address[1])
        self.hub.connect_switch("127.0.0.1:{}".format(self.switch.server_address[1]), "admin", "")
        self.url = "http://127.0.0.1:{}/".format(self.httpd.server_address[1])
        return self

    def __exit__(self, *a) -> None:
        self.httpd.shutdown()
        self.hub.stop()
        self.world.stop()
        shutil.rmtree(self.dir, ignore_errors=True)


class Check:
    def __init__(self, name: str):
        self.name, self.ok, self.fails = name, 0, []

    def __call__(self, cond, label: str) -> bool:
        if cond:
            self.ok += 1
        else:
            self.fails.append(label)
        return bool(cond)


def shot(b: Browser, name: str) -> None:
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        b.shot(str(Path(SHOTS) / (name + ".png")))


def click(b: Browser, sel: str) -> bool:
    return bool(b.eval("(() => { const e = document.querySelector(%r); if (!e) return false; e.click(); return true; })()" % sel))


# ------------------------------------------------------------------------------------------
def sc_pages(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/overview")
        c(b.until("document.querySelectorAll('.kpi').length === 7", 10), "overview shows 7 KPIs")
        c(b.until("!!document.querySelector('#live canvas') && document.querySelectorAll('#talkers tr[data-ip]').length > 3", 15),
          "live traffic canvas and top talkers render")
        c(b.eval("document.querySelector('#router-id').innerText.includes('core-router')"), "header names the router")
        c(b.eval("[...document.querySelectorAll('.chip')].map(x=>x.innerText).join()").count(",") == 3, "4 status chips")
        c(b.until("document.querySelectorAll('#ports .port').length === 9", 10), "switch shows 9 ports")
        c(b.until("document.querySelector('#feed') && document.querySelector('#feed').children.length > 0", 5),
          "threat feed is never blank (cards or 'All quiet')")
        shot(b, "overview")
        for page, probe in (("traffic", "document.querySelectorAll('#pairs tr[data-ip]').length > 3"),
                            ("threats", "document.querySelector('#tlist') !== null"),
                            ("actions", "document.querySelector('#history') !== null"),
                            ("devices", "document.querySelectorAll('#devs tr[data-ip]').length >= 9"),
                            ("interfaces", "document.querySelectorAll('#ifs tr[data-if]').length >= 7"),
                            ("logs", "document.querySelectorAll('#ll .logline').length > 0"),
                            ("setup", "!!(document.querySelector('#f-router') && document.querySelector('#collectors table'))")):
            b.nav(d.url + "#/" + page)
            c(b.until(probe, 10), "{} page renders".format(page))
            shot(b, page)
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_setup(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/setup")
        c(b.until("!!document.querySelector('#plan-load')", 10), "setup offers the plan")
        click(b, "#plan-load")
        c(b.until("document.querySelectorAll('.plan-item').length === 4", 10), "plan lists 4 items")
        c(b.eval("document.querySelector('#plan').innerText.includes('/ip traffic-flow target add')"),
          "plan shows the exact terminal command")
        c(b.eval("document.querySelectorAll('[data-item]:checked').length === 4"), "missing items pre-selected")
        c(not d.world.flows_on(), "router untouched before approval")
        shot(b, "setup-plan")
        click(b, "#plan-apply")
        c(b.until("document.querySelector('#plan-again') !== null", 15), "apply reports results")
        c(b.eval("!document.querySelector('#plan').innerText.includes('✗')"), "every step succeeded")
        c(d.world.flows_on() and d.world.log_rules(), "router now exports flows and logs attempts")
        c(b.until("document.querySelector('.chip[title*=\"records/s\"]') !== null", 25), "Flows chip goes live")
        click(b, "#plan-again")
        c(b.until("document.querySelectorAll('.plan-item .pill.green').length === 4", 10), "re-review shows all installed")
        # removal is planned and approved the same way
        b.nav(d.url + "#/overview")
        b.nav(d.url + "#/setup")
        b.until("!!document.querySelector('#plan-remove')", 10)
        click(b, "#plan-remove")
        c(b.until("document.querySelector('#plan').innerText.includes('/ip firewall raw remove')", 10),
          "removal plan lists MCC's rules")
        click(b, "#plan-apply")
        c(b.until("document.querySelector('#plan-again') !== null", 15), "removal applied")
        c(not d.world.flows_on() or not d.world.tables["/ip/traffic-flow/target"], "flow target removed")
        c(not [r for r in d.world.tables["/ip/firewall/filter"] if str(r.get("comment", "")).startswith("mcc:")],
          "MCC's filter rules removed")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_respond(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/threats")
        ok = b.until("document.querySelector('[data-respond]') !== null", 60)
        c(ok, "a threat with suggested responses appears")
        if not ok:
            return
        click(b, "[data-respond]")
        if b.until("document.querySelector('.modal [data-i]') !== null", 3):
            click(b, ".modal [data-i]")
        c(b.until("document.querySelector('.modal [data-confirm]') !== null", 10), "proposal modal opens")
        c(b.eval("document.querySelectorAll('.modal .change pre').length >= 1"), "proposal shows exact changes")
        c(b.eval("document.querySelector('.modal').innerText.includes('Nothing has changed yet')"), "says nothing changed")
        before = len(d.world.tables["/ip/firewall/address-list"])
        shot(b, "proposal")
        click(b, ".modal [data-confirm]")
        c(b.until("document.querySelector('.modal') && /applied/i.test(document.querySelector('.modal').innerText)", 10),
          "result modal confirms")
        title = b.eval("document.querySelector('.modal h2').innerText")
        changed = len(d.world.tables["/ip/firewall/address-list"]) != before or "connections" in (title or "")
        c(changed, "the router actually changed ({})".format(title))
        has_undo = b.eval("document.querySelector('.modal [data-undo]') !== null")
        if has_undo:
            click(b, ".modal [data-undo]")
            c(b.until("document.querySelector('.modal [data-go]') !== null", 5), "undo asks first")
            click(b, ".modal [data-go]")
            c(b.until("[...document.querySelectorAll('.toast')].some(t => t.innerText.startsWith('Undone'))", 10), "undo toast")
            c(len(d.world.tables["/ip/firewall/address-list"]) == before, "undo removed the entry")
        b.nav(d.url + "#/actions")
        c(b.until("document.querySelectorAll('#history tr[data-detail]').length >= 1", 10), "action is in history")
        # a protected address is refused, not proposed
        b.eval("respond('block_ip', {ip: '192.168.88.1'}, 'test')")
        c(b.until("[...document.querySelectorAll('.toast')].some(t => t.innerText.includes(\"router's own\"))", 5),
          "blocking the router itself is refused")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_ignore(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/threats")
        ok = b.until("document.querySelector('#tlist [data-ignore]') !== null", 60)
        c(ok, "threats offer Ignore")
        if not ok:
            return
        tid = b.eval("document.querySelector('#tlist [data-ignore]').dataset.ignore")
        click(b, "#tlist [data-ignore]")
        c(b.until("document.querySelectorAll('.modal input[name=iscope]').length >= 1", 5), "ignore dialog with scopes")
        c(b.eval("document.querySelector('.modal input[name=iscope]:checked').value") == "exact", "narrowest scope by default")
        b.eval("document.querySelector('#idur [data-d=\"7d\"]').click()")
        b.eval("document.querySelector('#inote').value = 'confirmed with the owner'")
        shot(b, "ignore-dialog")
        click(b, ".modal [data-go]")
        c(b.until("!document.querySelector('#modal').classList.contains('open')", 5), "dialog closes")
        c(b.until("!document.querySelector('#th-%s')" % tid, 5), "the threat leaves the Active list")
        c(d.hub.detector.threats[tid]["status"] == "ignored", "server marks it ignored")
        b.eval("document.querySelector('#tf [data-f=ignored]').click()")
        c(b.until("document.querySelector('#th-%s') && document.querySelector('#th-%s').innerText.includes('confirmed with the owner')" % (tid, tid), 5),
          "Ignored tab shows it with the reason")
        b.eval("document.querySelector('#tf [data-f=rules]').click()")
        c(b.until("document.querySelectorAll('#tlist [data-unignore]').length === 1", 5), "Ignore list shows the rule")
        c(b.eval("document.querySelector('#tlist').innerText.includes('left')"), "with its expiry")
        shot(b, "ignore-list")
        b.eval("(() => { document.querySelector('#ig-sub').value = '192.168.88.10'; document.querySelector('#ig-rule').value = 'exfil'; })()")
        b.eval("document.querySelector('#f-ign button[type=submit]').click()")
        c(b.until("document.querySelectorAll('#tlist [data-unignore]').length === 2", 5), "a rule can be added by hand")
        click(b, "#tlist [data-unignore]")
        c(b.until("document.querySelectorAll('#tlist [data-unignore]').length === 1", 5), "and removed")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def drag(b: Browser, x0: float, y0: float, x1: float, y1: float) -> None:
    b.call("Input.dispatchMouseEvent", type="mouseMoved", x=x0, y=y0)
    b.call("Input.dispatchMouseEvent", type="mousePressed", x=x0, y=y0, button="left", clickCount=1)
    for i in range(1, 9):
        b.call("Input.dispatchMouseEvent", type="mouseMoved", x=x0 + (x1 - x0) * i / 8, y=y0 + (y1 - y0) * i / 8,
               button="left", buttons=1)
    b.call("Input.dispatchMouseEvent", type="mouseReleased", x=x1, y=y1, button="left", clickCount=1)


def sc_layout(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/overview")
        c(b.until("document.querySelectorAll('#main .panel > .rz-e').length >= 7", 10), "every panel has resize handles")
        r = b.eval("(() => { const r = document.querySelector('[data-pid=\"overview:live\"]').getBoundingClientRect(); "
                   "return [r.right, r.top + r.height / 2, r.bottom, r.left + r.width / 2, r.height]; })()")
        drag(b, r[0] + 1, r[1], r[0] - 260, r[1])
        spans = b.eval("[...document.querySelectorAll('#main .grid > .panel')].slice(0, 2).map(p => p.style.getPropertyValue('--span'))")
        c(spans and spans[0] and int(spans[0]) < 8, "dragging the right edge narrows the panel ({})".format(spans))
        c(spans and spans[1] and int(spans[0]) + int(spans[1]) == 12, "its neighbour takes the space, row stays full")
        drag(b, r[3], r[2] + 1, r[3], r[2] + 180)
        h = b.eval("document.querySelector('[data-pid=\"overview:live\"]').getBoundingClientRect().height")
        c(h and h > r[4] + 120, "dragging the bottom edge makes it taller ({:.0f} -> {:.0f})".format(r[4], h or 0))
        b.wait(0.6)
        ch = b.eval("document.querySelector('#live canvas').getBoundingClientRect().height")
        c(ch and ch > 500, "the globe grows with its panel ({:.0f}px)".format(ch or 0))
        shot(b, "layout-resized")
        b.nav(d.url + "#/traffic")
        b.nav(d.url + "#/overview")
        c(b.until("document.querySelector('[data-pid=\"overview:live\"]')?.style.getPropertyValue('--span') === '%s'" % spans[0], 8),
          "layout survives navigation and reload")
        click(b, "#layout-btn")
        c(b.until("document.querySelector('[data-pid=\"overview:live\"]')?.classList.contains('sized') === false", 3), "reset restores the page")
        # globe / flow map switch
        c(b.until("document.querySelector('#live.globe-wrap canvas') !== null", 5), "overview shows the globe")
        c(b.until("/peers located/.test(document.querySelector('#map-src').innerText)", 8), "says how many peers are located")
        # particles must survive the 1 s data refreshes and finish their trips (they used to restart)
        b.until("VIEWS.overview.map.stats && VIEWS.overview.map.stats().parts > 5", 10)
        oldest, end = 0.0, time.time() + 5
        while time.time() < end:
            oldest = max(oldest, b.eval("VIEWS.overview.map.stats().oldest") or 0)
            time.sleep(0.1)
        c(oldest > 0.8, "globe particles fly through data refreshes (furthest trip {:.0%})".format(oldest))
        click(b, '#live-kind [data-k="map"]')
        c(b.until("document.querySelector('#live.map-wrap canvas') !== null", 3), "switches to the flow map")
        click(b, '#live-kind [data-k="globe"]')
        c(b.until("document.querySelector('#live.globe-wrap canvas') !== null", 3), "and back to the globe")
        b.nav(d.url + "#/traffic")
        c(b.until("document.querySelector('#globe canvas') && document.querySelectorAll('#countries tr').length > 2", 10),
          "traffic page has the globe and a countries table")
        shot(b, "traffic-globe")
        # drawer resizes too
        b.until("document.querySelectorAll('#peers tr[data-ip]').length > 0", 8)
        click(b, "#peers tr[data-ip]")
        c(b.until("document.querySelector('#drawer.open h4') && [...document.querySelectorAll('#drawer h4')].some(h => h.innerText.match(/location/i))", 8),
          "peer drawer shows its location")
        w0 = b.eval("document.querySelector('#drawer').getBoundingClientRect().width")
        x = b.eval("document.querySelector('#drawer').getBoundingClientRect().left")
        drag(b, x + 1, 400, x - 200, 400)
        w1 = b.eval("document.querySelector('#drawer').getBoundingClientRect().width")
        c(w1 > w0 + 150, "drawer resizes ({:.0f} -> {:.0f})".format(w0, w1))
        b.nav(d.url + "#/setup")
        c(b.until("document.querySelector('#geo-panel [data-dl=\"city\"]') !== null", 8), "Setup offers the database download")
        b.eval("(() => { document.querySelector('#h-lat').value = '51.5'; document.querySelector('#h-lon').value = '-0.12'; "
               "document.querySelector('#h-label').value = 'London'; })()")
        b.eval("document.querySelector('#f-home button[type=submit]').click()")
        c(b.until("document.querySelector('#geo-panel').innerText.includes('London')", 5), "home location can be set")
        c(d.hub.geo.home([])["label"] == "London", "server uses it")
        click(b, "#h-clear")
        c(b.until("document.querySelector('#geo-panel').innerText.includes('Dallas')", 5), "and cleared back to the router's address")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


GLOBE_FADE_JS = r"""
(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const div = document.createElement('div');
  div.className = 'globe-wrap';
  div.style.cssText = 'position:fixed;left:0;top:0;width:500px;height:360px;z-index:99';
  document.body.appendChild(div);
  const g = Globe.create(div, { fadeS: 2 });
  const peer = (ip, lat, lon) => ({ ip, name: '', up: 1e6, down: 5e6, conns: 1, hosts: ['192.168.88.10'], ports: [443],
    blocked: false, threat: '', geo: { lat, lon, cc: 'XX', country: 'X', city: 'C' + ip, precision: 'city' } });
  const snap = (peers) => ({ router: { identity: 'r' }, traffic: { peers },
    geo: { home: { lat: 32.8, lon: -96.8, label: 'Home' }, source: 'demo', countries: [] } });
  const NY = peer('1.1.1.1', 40.7, -74), LON = peer('2.2.2.2', 51.5, -0.1), PAR = peer('3.3.3.3', 48.9, 2.35);
  const st = (key) => g.stats().list.find((n) => n.key === key);
  const out = {};
  g.update(snap([NY, LON, PAR]));
  await sleep(700);
  g.update(snap([NY]));                        // London and Paris go quiet
  await sleep(500);
  out.early = st('51.5,-0.1');                 // just gone: still clearly visible
  g.update(snap([NY]));                        // a data refresh must not restart the fade
  await sleep(500);
  out.mid = st('51.5,-0.1');
  g.update(snap([NY, PAR]));                   // Paris comes back before it faded out
  await sleep(700);
  out.paris = st('48.9,2.4') || st('48.9,2.3');
  await sleep(600);
  out.late = st('51.5,-0.1');                  // past fadeS: gone (or invisible while its last pips land)
  await sleep(6000);
  out.after = st('51.5,-0.1') || null;
  out.places = g.stats().places;
  g.destroy(); div.remove();
  return out;
})()
"""


def sc_globe_fade(d: Demo, c: Check) -> None:
    with Browser(1200, 800) as b:
        b.nav(d.url + "#/overview")
        b.until("typeof Globe !== 'undefined' && !!document.querySelector('#kpis .kpi')", 10)
        r = b.eval(GLOBE_FADE_JS) or {}
        early, mid, late, paris = r.get("early") or {}, r.get("mid") or {}, r.get("late") or {}, r.get("paris") or {}
        c(early.get("gone") and early.get("alpha", 0) > 0.6, "a place that goes quiet stays, still bright at first ({})".format(early))
        c(mid.get("gone") and 0.05 < mid.get("alpha", 0) < early.get("alpha", 0),
          "it fades gradually, and refreshes don't restart the fade ({} -> {})".format(early.get("alpha"), mid.get("alpha")))
        c(not late or late.get("alpha", 1) == 0, "fully faded after the fade time ({})".format(late))
        c(r.get("after") is None, "then dropped from the globe")
        c(paris and not paris.get("gone") and paris.get("alpha", 0) > 0.5, "a place whose traffic resumes comes back ({})".format(paris))
        c(r.get("places") == 2, "the live places remain ({} places)".format(r.get("places")))
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_drawer(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/overview")
        b.until("document.querySelectorAll('#talkers tr[data-ip]').length > 2", 15)
        click(b, "#talkers tr[data-ip]")
        c(b.until("document.querySelector('#drawer.open h2') && !document.querySelector('#drawer h2').innerText.includes('Loading')", 8),
          "host drawer opens")
        c(b.until("document.querySelectorAll('#drawer tr[data-ip]').length > 0", 8), "drawer lists conversations")
        c(b.eval("document.querySelector('#drawer [data-act=block_ip]') !== null"), "drawer offers Block")
        shot(b, "drawer")
        b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
        c(b.until("!document.querySelector('#drawer').classList.contains('open')", 3), "Esc closes the drawer")
        b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'k', ctrlKey: true}))")
        c(b.until("document.querySelector('#cmdk.open input') !== null", 3), "Ctrl+K opens the palette")
        b.eval("(() => { const i = document.querySelector('#cmdk input'); i.value = '192.168.88.10'; i.dispatchEvent(new Event('input')); })()")
        c(b.until("document.querySelector('#cmdk li.on') && document.querySelector('#cmdk li.on').innerText.includes('Inspect')", 3),
          "typing an IP offers to inspect it")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_phone(d: Demo, c: Check) -> None:
    with Browser(390, 844, mobile=True) as b:
        for page in ("overview", "threats", "setup"):
            b.nav(d.url + "#/" + page)
            b.wait(2.5)
            over = b.eval("document.documentElement.scrollWidth - window.innerWidth")
            c(over is not None and over <= 1, "{} @390px: no sideways scroll ({}px)".format(page, over))
            shot(b, "phone-" + page)
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_light(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/overview")
        b.until("document.querySelectorAll('.kpi').length === 7", 10)
        click(b, "#theme-btn")
        c(b.eval("document.documentElement.dataset.theme") == "light", "theme toggles to light")
        bg = b.eval("getComputedStyle(document.body).backgroundColor")
        c(bg and "oklch(0.96" in bg or "rgb(2" in (bg or ""), "light background applied ({})".format(bg))
        b.wait(2)
        shot(b, "light")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


SCENARIOS = {"pages": sc_pages, "setup": sc_setup, "respond": sc_respond, "ignore": sc_ignore, "layout": sc_layout, "globe-fade": sc_globe_fade, "drawer": sc_drawer, "phone": sc_phone,
             "light": sc_light}


def main(argv) -> int:
    if not find_browser():
        print("SKIP: no Chrome/Edge found (set MCC_BROWSER)")
        return 0
    names = argv or list(SCENARIOS)
    failed = 0
    t0 = time.time()
    with Demo() as d:
        for name in names:
            c = Check(name)
            t = time.time()
            try:
                SCENARIOS[name](d, c)
            except Exception as e:
                c.fails.append("crashed: {}: {}".format(type(e).__name__, e))
            status = "PASS" if not c.fails else "FAIL"
            failed += bool(c.fails)
            print("[{}] {}  ({} checks, {:.0f}s)".format(status, name, c.ok + len(c.fails), time.time() - t))
            for f in c.fails:
                print("    x " + f)
    print("{} scenario(s), {} failed, {:.0f}s".format(len(names), failed, time.time() - t0))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
