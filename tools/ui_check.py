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
    return bool(b.eval("(() => { const e = document.querySelector(%r); if (!e) return false; e.scrollIntoView({block: 'nearest'}); e.click(); return true; })()" % sel))


def see(b: Browser, sel: str) -> None:
    """Scroll to a panel, as a person would: live tables off screen wait until they're scrolled to."""
    # (again until it stays in view: tables above it can fill in as they come into view and push it down)
    b.until("(() => { const e = document.querySelector(%r); if (!e) return false; e.scrollIntoView({block: 'nearest'});"
            " const r = e.getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0; })()" % sel, 10)
    b.wait(0.2)
    b.until("(() => { const e = document.querySelector(%r); e.scrollIntoView({block: 'nearest'});"
            " const r = e.getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0; })()" % sel, 10)


# ------------------------------------------------------------------------------------------
def sc_pages(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/overview")
        c(b.until("document.querySelectorAll('.kpi').length === 7", 10), "overview shows 7 KPIs")
        see(b, "#talkers")
        c(b.until("!!document.querySelector('#live canvas') && document.querySelectorAll('#talkers tr[data-ip]').length > 3", 15),
          "live traffic canvas and top talkers render")
        c(b.eval("document.querySelector('#router-id').innerText.includes('core-router')"), "header names the router")
        c(b.eval("[...document.querySelectorAll('.chip')].map(x=>x.innerText).join()").count(",") == 3, "4 status chips")
        c(b.until("document.querySelectorAll('#ports .port').length === 9", 10), "switch shows 9 ports")
        c(b.until("document.querySelector('#feed') && document.querySelector('#feed').children.length > 0", 5),
          "threat feed is never blank (cards or 'All quiet')")
        shot(b, "overview")
        for page, probe in (("traffic", "document.querySelectorAll('#pairs tr[data-ip]').length > 3"),
                            ("lan", "document.querySelectorAll('#lan-ports tr').length > 3"),
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
        c(b.until("document.querySelectorAll('.plan-item').length >= 5", 10), "plan lists the telemetry items and the LAN options")
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
        c(b.until("['flows','syslog','logrules','droprules'].every(i => { const e = document.querySelector('[data-item=' + i + ']'); return !e || "
          "e.closest('.plan-item').querySelector('.pill.green'); })", 10), "re-review shows all installed")
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


def sc_update(d: Demo, c: Check) -> None:
    """A tab left open across a restart onto new code must reload itself (it kept old JS before)."""
    with Browser(1400, 900) as b:
        b.nav(d.url + "#/traffic")
        b.until("!!S.build && !!document.querySelector('#pairs')", 10)
        build = b.eval("S.build")
        c(build and len(build) == 16, "the console knows which build it runs ({})".format(build))
        b.eval("window.__marker = 1")
        c(b.eval("onBuild(S.build)") is False, "same build on reconnect: no reload")
        b.wait(1.0)
        c(b.eval("window.__marker") == 1, "page kept")
        b.eval("onBuild('0000000000000000')")  # what a reconnect to an updated MCC delivers
        c(b.until("window.__marker === undefined && !!document.querySelector('#pairs')", 10),
          "different build: the tab reloads itself onto the new code, same page")
        c(b.eval("location.hash") == "#/traffic", "and stays on the page you were on")
        # a dropped live feed reconnects without rebuilding the page: the globe and its particles survive
        b.nav(d.url + "#/overview")
        b.until("VIEWS.overview.map && VIEWS.overview.map.stats && VIEWS.overview.map.stats().parts > 0", 10)
        b.eval("VIEWS.overview.map.__marker = 42")
        b.eval("es.close(); connectStream()")
        c(b.until("S.reconnects >= 1", 10), "the live feed reconnected")
        b.wait(1.0)
        c(b.eval("VIEWS.overview.map.__marker") == 42, "same globe after a reconnect (page not rebuilt)")
        c(b.eval("VIEWS.overview.map.stats().parts") > 0, "its particles kept flying")
        b.nav(d.url + "#/traffic")
        b.until("!!document.querySelector('#pairs')", 8)
        # an MCC whose files were updated but which wasn't restarted says so, instead of looking broken
        c(not b.eval("!!document.querySelector('#update-bar')"), "no update bar when the server runs the current files")
        b.eval("checkSkew({ build: S.build, build_disk: 'ffffffffffffffff' })")
        c(b.eval("!!document.querySelector('#update-bar') && /restart-mcc\\.cmd/.test(document.querySelector('#update-bar').innerText)"),
          "files changed since start: the bar asks for a restart")
        b.eval("checkSkew(null)")
        c(b.eval("/traffic types/.test(document.querySelector('#update-bar').innerText)"),
          "a server too old to report its build: same bar, and it says what stays empty")
        b.eval("checkSkew({ build: S.build, build_disk: S.build })")
        c(not b.eval("!!document.querySelector('#update-bar')"), "the bar goes once they match")
        b.eval("Theme.set({ motion: 'off' })")
        b.nav(d.url + "#/overview")
        b.until("!!document.querySelector('#live canvas')", 8)
        b.wait(1.0)
        shot(b, "motion-off-note")
        b.eval("Theme.set({ motion: 'full' })")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_types(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/overview")
        c(b.until("document.querySelectorAll('#types .trow').length >= 5", 20), "Overview lists traffic types")
        c(b.eval("!!document.querySelector('#types .tbar.big')"), "with a breakdown bar")
        c(b.until("document.querySelectorAll('#live .type-legend .tl').length >= 5", 5), "the live view's legend shows the types")
        click(b, '#live-kind [data-k="map"]')
        c(b.until("document.querySelectorAll('#live .type-legend .tl').length >= 5", 5), "the flow map has the same legend")
        click(b, '.color-by [data-by="direction"]')
        c(b.eval("Types.by") == "direction" and "download" in b.eval("document.querySelector('#live .type-legend').innerText"),
          "Direction mode switches back to download/upload colours")
        click(b, '.color-by [data-by="type"]')
        click(b, '#live-kind [data-k="globe"]')
        b.until("!!document.querySelector('#live.globe-wrap canvas')", 5)
        first = b.eval("document.querySelector('#live .type-legend .tl').dataset.type")
        click(b, "#live .type-legend .tl")
        c(b.eval("Types.focus") == first, "clicking a legend entry focuses that type ({})".format(first))
        see(b, "#types")
        c(b.until("!!document.querySelector('#types .trow.on[data-type=\"%s\"]')" % first, 3), "the types panel marks it")
        c(b.until("VIEWS.overview.map.stats().parts > 0", 8), "globe keeps drawing while focused")
        b.nav(d.url + "#/traffic")
        see(b, "#pairs")
        c(b.until("document.querySelectorAll('#pairs tbody tr').length > 0", 10), "Traffic page conversations")
        cats = b.eval("[...new Set([...document.querySelectorAll('#pairs .tchip')].map(x => x.innerText.trim()))]")
        c(cats == [b.eval("Types.label(Types.focus)")], "conversations filtered to the focused type ({})".format(cats))
        click(b, "#pairs [data-type-filter]")
        c(b.until("Types.focus === null && new Set([...document.querySelectorAll('#pairs .tchip')].map(x => x.innerText.trim())).size > 2", 5),
          "'Show all types' clears the filter")
        c(b.eval("document.querySelectorAll('#hosts .tdot').length") > 3, "host rows carry a type dot")
        b.until("!!document.querySelector('#hosts tr[data-ip]')", 5)
        click(b, "#hosts tr[data-ip]")
        c(b.until("[...document.querySelectorAll('#drawer h4')].some(h => /traffic types/i.test(h.innerText)) && !!document.querySelector('#drawer .tbar')", 8),
          "the host drawer breaks its traffic down by type")
        b.eval("closeDrawer()")
        b.eval("location.reload()")
        b.wait(1.0)
        b.until("typeof Types !== 'undefined'", 8)
        c(b.eval("Types.by") == "type", "colour mode persists")
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
        b.until("!!document.querySelector('#studio [data-th=\"glacier\"]')", 5)
        click(b, '#studio [data-th="glacier"]')
        click(b, "#studio [data-close]")
        c(b.eval("document.documentElement.dataset.theme") == "light", "a light theme switches the console to light")
        bg = b.eval("getComputedStyle(document.body).backgroundColor")
        c(bg and ("oklch(0.96" in bg or "rgb(2" in bg), "light background applied ({})".format(bg))
        b.wait(2)
        shot(b, "light")
        b.eval("Theme.set({ theme: 'noc' })")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def css(b: Browser, name: str) -> str:
    return b.eval("getComputedStyle(document.documentElement).getPropertyValue(%r).trim()" % name) or ""


def sc_theme(d: Demo, c: Check) -> None:
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/overview")
        b.until("document.querySelectorAll('.kpi').length === 7 && document.querySelector('#live canvas')", 10)
        c(b.eval("!!document.querySelector('#fx-aurora')"), "aurora layer behind the console")
        click(b, "#theme-btn")
        c(b.until("document.querySelectorAll('#studio .swatch').length === 8", 5), "Theme Studio opens with 8 themes")
        shot(b, "theme-studio")
        accents = {}
        for tid in ("noc", "aurora", "nebula", "solar", "phosphor", "graphite", "glacier", "daylight"):
            click(b, '#studio [data-th="%s"]' % tid)
            accents[tid] = (css(b, "--accent"), b.eval("document.documentElement.dataset.theme"))
        c(len({a for a, _ in accents.values()}) == 8, "every theme has its own accent")
        c(accents["glacier"][1] == "light" and accents["nebula"][1] == "dark", "light and dark themes set the mode")
        c(b.eval("document.querySelector('#studio .swatch.on').dataset.th") == "daylight", "picked theme is marked")
        click(b, '#studio [data-th="aurora"]')
        before = css(b, "--accent")
        b.eval("(() => { const r = document.querySelector('#studio [data-in=shift]'); r.value = 90; r.dispatchEvent(new Event('input')); })()")
        c(css(b, "--accent") != before and "+90" in b.eval("document.querySelector('#v-shift').innerText"), "hue shift recolours live")
        b.eval("(() => { const r = document.querySelector('#studio [data-in=glow]'); r.value = 0; r.dispatchEvent(new Event('input')); })()")
        c(b.eval("getComputedStyle(document.querySelector('#fx-aurora')).opacity") == "0", "glow 0 hides the aurora")
        click(b, '#studio [data-seg="motion"] [data-k="off"]')
        c(b.eval("document.body.dataset.motion") == "off", "motion off")
        c(b.until("VIEWS.overview.map.stats && VIEWS.overview.map.stats().parts === 0", 12), "motion off stops the globe's particles")
        click(b, '#studio [data-seg="motion"] [data-k="full"]')
        c(b.until("VIEWS.overview.map.stats().parts > 0", 8), "and full brings them back")
        click(b, '#studio [data-seg="quality"] [data-k="lite"]')
        c(b.eval("document.body.dataset.fx") == "lite" and b.eval("getComputedStyle(document.querySelector('#fx-aurora')).display") == "none",
          "Lite rendering drops the aurora")
        click(b, '#studio [data-seg="density"] [data-k="compact"]')
        c(b.eval("document.body.dataset.density") == "compact", "compact density")
        pad = b.eval("parseFloat(getComputedStyle(document.querySelector('.panel > header')).paddingTop)")
        c(pad is not None and pad <= 8, "compact tightens panels ({}px)".format(pad))
        b.eval("location.reload()")
        b.wait(1.0)
        b.until("!!document.querySelector('.kpi') && typeof Theme !== 'undefined'", 10)
        c(b.eval("Theme.prefs.theme") == "aurora" and b.eval("Theme.prefs.shift") == 90 and b.eval("document.body.dataset.density") == "compact",
          "choices persist across reloads")
        c(not b.eval("!!document.querySelector('#studio')"), "studio starts closed after a reload")
        click(b, "#theme-btn")
        b.until("!!document.querySelector('#studio [data-reset]')", 5)
        click(b, "#studio [data-reset]")
        c(b.eval("Theme.prefs.theme") == "noc" and b.eval("Theme.prefs.shift") == 0 and b.eval("document.body.dataset.density") == "comfortable",
          "reset restores the defaults")
        b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
        c(b.until("!document.querySelector('#studio')", 3), "Esc closes the studio")
        b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'k', ctrlKey: true}))")
        b.eval("(() => { const i = document.querySelector('#cmdk input'); i.value = 'nebula'; i.dispatchEvent(new Event('input')); })()")
        c(b.until("document.querySelector('#cmdk li.on') && document.querySelector('#cmdk li.on').innerText.includes('Nebula')", 3),
          "Ctrl+K finds themes")
        b.eval("document.querySelector('#cmdk li.on').click()")
        c(b.eval("Theme.prefs.theme") == "nebula", "and switches to them")
        b.eval("Theme.set({ theme: 'noc' })")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_offscreen(d: Demo, c: Check) -> None:
    """The Traffic page runs a flow map and a globe: whatever is scrolled out of view must stop costing frames."""
    with Browser(1600, 520) as b:  # short window: the globe starts below the fold
        b.nav(d.url + "#/traffic")
        b.until("!!document.querySelector('#globe canvas') && S.snap && document.querySelectorAll('#pairs tr').length > 0", 15)
        b.wait(1.0)
        c(b.eval("document.getElementById('globe').getBoundingClientRect().top") > b.eval("innerHeight"), "(the globe is below the fold)")
        t0 = b.eval("VIEWS.traffic.globe.stats().oldest")
        b.wait(1.0)
        c(b.eval("VIEWS.traffic.globe.stats().oldest") == t0, "the globe doesn't animate while out of view")
        b.eval("document.getElementById('globe').scrollIntoView()")
        c(b.until("VIEWS.traffic.globe.stats().parts > 0 && VIEWS.traffic.globe.stats().oldest !== %r" % t0, 5),
          "and starts once scrolled to")
        # off screen, a table refresh waits; scrolled to, it lands at once
        c(b.until("document.getElementById('countries')._pending != null", 5), "an off-screen table's refresh waits")
        b.eval("document.getElementById('countries').scrollIntoView()")
        c(b.until("document.getElementById('countries')._pending == null && document.querySelectorAll('#countries tr').length > 2", 3),
          "a waiting table refresh lands as soon as it is visible")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_single_out(d: Demo, c: Check) -> None:
    """Click a device on the flow map: only it and its paths remain, details in the drawer. Pin it."""
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/traffic")
        b.until("!!document.querySelector('#map canvas') && VIEWS.traffic.map.stats().nodes.filter(n => n.kind === 'host').length > 3", 15)
        b.wait(2.0)  # let the nodes settle into place
        n = b.eval("(() => { const n = VIEWS.traffic.map.stats().nodes.filter(n => n.kind === 'host')[0]; const r = document.querySelector('#map canvas').getBoundingClientRect(); return {ip: n.ip, x: r.left + n.x, y: r.top + n.y}; })()")
        for t in ("mouseMoved", "mousePressed", "mouseReleased"):
            b.call("Input.dispatchMouseEvent", type=t, x=n["x"], y=n["y"], button="left", clickCount=1)
        c(b.until("Select.ip === %r && !!Select.data" % n["ip"], 5), "clicking a device on the map singles it out ({})".format(n["ip"]))
        c(b.until("document.querySelector('#drawer.open') && document.querySelectorAll('#drawer table.paths tbody tr').length > 0", 5),
          "its drawer lists its traffic paths")
        npaths = b.eval("Select.paths().length")
        c(b.until("(() => { const ns = VIEWS.traffic.map.stats().nodes; return ns.filter(x => x.sel).length === 1 && ns.length === 1 + Math.min(%d, 30) || ns.length <= 1 + %d; })()" % (npaths, npaths), 5),
          "the map shows just it and the devices it talks to")
        others = b.eval("VIEWS.traffic.map.stats().nodes.filter(x => !x.sel).map(x => x.ip)")
        paths = b.eval("Select.paths().map(x => x.ip)")
        c(all(ip in paths for ip in others), "every other device on the map is one of its paths")
        c(not b.eval("document.querySelector('#map .sel-banner').classList.contains('hidden')"), "a strip over the map says what is singled out")
        c(b.until("VIEWS.traffic.globe.stats().list.some(p => !p.gone)", 5), "the globe keeps only its destinations")
        shot(b, "single-out")
        click(b, "#drawer [data-pin]")
        c(b.until("Pins.has(%r) && S.snap.traffic.hosts[0].ip === %r" % (n["ip"], n["ip"]), 5), "pinning puts it first in the lists")
        b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
        c(b.until("Select.ip === null && document.querySelector('#map .sel-banner').classList.contains('hidden')", 3), "Esc shows everything again")
        c(b.until("VIEWS.traffic.map.stats().nodes.some(x => x.ip === %r && x.pinned)" % n["ip"], 5), "the map marks it as pinned")
        see(b, "#hosts")
        c(b.until("document.querySelector('#hosts tr[data-ip]').dataset.ip === %r && document.querySelector('#hosts tr.pinned .pin-btn.on') !== null" % n["ip"], 5),
          "LAN hosts table: pinned row first, with its pin lit")
        click(b, "#hosts tr.pinned .pin-btn")
        c(b.until("!Pins.has(%r)" % n["ip"], 5), "the row's pin button unpins")
        c(not b.eval("!!document.querySelector('#drawer.open')"), "(the pin button doesn't open the row)")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_globe_fit(d: Demo, c: Check) -> None:
    """Singling out a device snaps the globe to show all its connection points, and holds it still."""
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/overview")
        b.until("!!document.querySelector('#live canvas') && VIEWS.overview.map && VIEWS.overview.map.stats && VIEWS.overview.map.stats().places > 3", 15)
        b.eval("VIEWS.overview.mountLive('globe')")
        b.wait(2.0)
        z0 = b.eval("VIEWS.overview.map.stats().view.zoom")
        lon0 = b.eval("VIEWS.overview.map.stats().view.lon")
        b.wait(1.0)
        c(b.eval("VIEWS.overview.map.stats().view.lon") != lon0, "(the globe orbits before anything is singled out)")
        # a host whose destinations fit on one side of the globe (the torrent box's swarm spans the world)
        host = b.eval("S.snap.traffic.hosts.find(h => h.peers >= 2 && h.cat !== 'p2p').ip")
        b.eval("openHost(%r)" % host)
        c(b.until("Select.data && Select.data.ip === %r && !VIEWS.overview.map.stats().view.settling" % host, 8),
          "singling out a host snaps the globe to a new view ({})".format(host))
        b.wait(0.5)
        inview = b.eval("""(() => { const cv = document.querySelector('#live canvas'), w = cv.clientWidth, h = cv.clientHeight;
          const live = VIEWS.overview.map.stats().list.filter(p => !p.gone);
          return {n: live.length, ok: live.filter(p => p.screen && p.screen[0] >= 0 && p.screen[0] <= w && p.screen[1] >= 0 && p.screen[1] <= h).length}; })()""")
        c(inview["n"] > 0 and inview["ok"] == inview["n"], "every one of its connection points is in view ({ok}/{n})".format(**inview))
        swarm = b.eval("(S.snap.traffic.hosts.find(h => h.cat === 'p2p') || {}).ip")
        if swarm:
            b.eval("openHost(%r)" % swarm)
            b.until("Select.data && Select.data.ip === %r && !VIEWS.overview.map.stats().view.settling" % swarm, 8)
            b.wait(0.5)
            iv = b.eval("""(() => { const cv = document.querySelector('#live canvas'), w = cv.clientWidth, h = cv.clientHeight;
              const live = VIEWS.overview.map.stats().list.filter(p => !p.gone);
              return {n: live.length, ok: live.filter(p => p.screen && p.screen[0] >= 0 && p.screen[0] <= w && p.screen[1] >= 0 && p.screen[1] <= h).length}; })()""")
            c(iv["ok"] >= 0.6 * iv["n"], "a worldwide swarm: the side with most of it is shown ({ok}/{n})".format(**iv))
            b.eval("openHost(%r)" % host)
            b.until("Select.data && Select.data.ip === %r && !VIEWS.overview.map.stats().view.settling" % host, 8)
        v1 = b.eval("VIEWS.overview.map.stats().view")
        b.wait(4.5)  # two drawer refreshes: its paths change, the view holds
        v2 = b.eval("VIEWS.overview.map.stats().view")
        c(abs(v1["lon"] - v2["lon"]) < 0.01 and abs(v1["lat"] - v2["lat"]) < 0.01, "and stops orbiting")
        peer = b.eval("S.snap.traffic.peers.find(p => p.geo).ip")
        b.eval("openHost(%r)" % peer)
        c(b.until("Select.data && Select.data.ip === %r && !VIEWS.overview.map.stats().view.settling" % peer, 8), "picking an Internet host re-frames it")
        g = b.eval("S.snap.traffic.peers.find(p => p.ip === %r).geo" % peer)
        v = b.eval("VIEWS.overview.map.stats().view")
        c(v["zoom"] > 1.0, "a single destination is zoomed in on (zoom {:.2f})".format(v["zoom"]))
        shot(b, "globe-fit")
        b.eval("closeDrawer()")
        c(b.until("Math.abs(VIEWS.overview.map.stats().view.zoom - %r) < 0.01" % z0, 6), "Show all goes back to the earlier zoom")
        lon1 = b.eval("VIEWS.overview.map.stats().view.lon")
        b.wait(1.0)
        c(b.eval("VIEWS.overview.map.stats().view.lon") != lon1, "and orbiting resumes")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_vpn(d: Demo, c: Check) -> None:
    """The VPN page: the tunnel, only its traffic on the map, devices, and requiring the VPN."""
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/vpn")
        c(b.until("S.snap && S.snap.traffic.vpn && S.snap.traffic.vpn.pairs.length > 0", 25), "VPN traffic arrives")
        c(b.until("document.querySelectorAll('#vpn-kpis .kpi').length === 6", 5), "six VPN KPIs")
        c(b.until("/WireGuard/.test(document.querySelector('#vpn-tunnels').innerText) && !!document.querySelector('#vpn-tunnels .tunnel.up')", 8),
          "the tunnel card: WireGuard, up")
        c("Zurich" in b.eval("document.querySelector('#vpn-tunnels').innerText"), "with its server's location")
        c(b.until("VIEWS.vpn.map.stats().nodes.filter(n => n.kind === 'host').length === 2", 10), "the map shows the two VPN devices")
        hosts = b.eval("VIEWS.vpn.map.stats().nodes.filter(n => n.kind === 'host').map(n => n.ip).sort()")
        c(hosts == ["192.168.88.21", "192.168.88.22"], "and only them ({})".format(hosts))
        c(b.eval("VIEWS.vpn.map.stats().nodes.filter(n => n.kind === 'peer').every(n => S.snap.traffic.vpn.peers.some(p => p.ip === n.ip))"),
          "its destinations are the ones reached through the tunnel")
        see(b, "#vpn-hosts")
        c(b.until("document.querySelectorAll('#vpn-hosts tr[data-ip]').length === 2", 5), "devices on the VPN")
        click(b, '#vpn-hosts [data-req="192.168.88.21"]')
        c(b.until("(S.config.vpn.required || []).includes('192.168.88.21')", 5), "Require puts it on the must-use-the-VPN list")
        c(not b.eval("!!document.querySelector('#drawer.open')"), "(the button doesn't open the row)")
        c(b.until("!!document.querySelector('#vpn-hosts [data-req=\"192.168.88.21\"].on')", 5), "the row shows it")
        click(b, '#vpn-hosts [data-req="192.168.88.21"]')
        c(b.until("!(S.config.vpn.required || []).includes('192.168.88.21')", 5), "and again takes it off")
        see(b, "#vpn-pairs")
        c(b.until("document.querySelectorAll('#vpn-pairs tbody tr').length > 0", 5), "conversations through the VPN")
        shot(b, "vpn")
        b.nav(d.url + "#/traffic")
        see(b, "#pairs")
        c(b.until("document.querySelectorAll('#pairs .pill.vpn').length > 0", 10), "Traffic › Conversations marks what went through the tunnel")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_identify(d: Demo, c: Check) -> None:
    """Devices says what each device is (and why); the drawer, Setup and Ctrl+K do too."""
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/devices")
        c(b.until("document.querySelectorAll('#devs .ident').length >= 9", 15), "Devices has an 'Identified as' column")
        row = "[...document.querySelectorAll('#devs tr[data-ip]')].find(r => r.dataset.ip === %r)"
        c(b.until("(%s || {innerText: ''}).innerText.includes('Brother printer')" % (row % "192.168.88.60"), 10),
          "the printer is identified from its MAC vendor and name")
        c(b.until("(%s || {innerText: ''}).innerText.includes('Synology NAS')" % (row % "192.168.88.10"), 10),
          "the NAS is identified")
        c(b.until("(%s || {innerText: ''}).innerText.includes('CRS309')" % (row % "192.168.88.2"), 10),
          "the switch is identified from neighbor discovery")
        b.eval("(() => { const i = document.querySelector('#dq'); i.value = 'camera'; i.dispatchEvent(new Event('input')); })()")
        c(b.until("document.querySelectorAll('#devs tr[data-ip]').length === 1", 5), "filtering by kind finds the camera")
        shot(b, "devices-identified")
        click(b, "#devs tr[data-ip]")
        c(b.until("document.querySelector('#drawer.open .ident-hero') && document.querySelectorAll('#drawer .clues li').length >= 2", 8),
          "the drawer explains what the device is and why")
        shot(b, "drawer-identity")
        b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
        b.until("!document.querySelector('#drawer').classList.contains('open')", 3)
        b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'k', ctrlKey: true}))")
        b.until("document.querySelector('#cmdk.open input') !== null", 3)
        b.eval("(() => { const i = document.querySelector('#cmdk input'); i.value = '3c:22:fb:00:00:22'; i.dispatchEvent(new Event('input')); })()")
        c(b.until("document.querySelector('#cmdk li.on') && document.querySelector('#cmdk li.on').innerText.includes('What is')", 3),
          "pasting a MAC into Ctrl+K offers to identify it")
        b.eval("document.querySelector('#cmdk input').dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter'}))")
        c(b.until("document.querySelector('#modal.open h2') && document.querySelector('#modal h2').innerText === 'Apple'", 5),
          "the lookup names the vendor")
        c(b.eval("document.querySelector('#modal').innerText.includes('iPhone')"), "and the device it is")
        b.eval("document.querySelector('#modal [data-x]').click()")
        b.nav(d.url + "#/setup")
        see(b, "#ident-panel")
        c(b.until("document.querySelector('#ident-panel .callout.good') && /prefixes/.test(document.querySelector('#ident-panel').innerText)", 8),
          "Setup shows the MAC vendor registry")
        shot(b, "setup-identification")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


def sc_lan(d: Demo, c: Check) -> None:
    """The LAN page: routed traffic at once; same-network traffic once the router is set to show it."""
    with Browser(1600, 1000) as b:
        b.nav(d.url + "#/lan")
        c(b.until("S.snap.lan && S.snap.lan.pairs.some(p => p.service === 'MQTT 1883' && p.routed)", 20),
          "traffic routed between networks (IoT VLAN -> Home Assistant) shows at once")
        c(b.until("!!document.querySelector('#lan-vis .callout.warn')", 5), "and the page says same-network traffic isn't visible yet")
        c(b.until("VIEWS.lan.map.stats().nodes.some(n => n.kind === 'peer' && n.ip === '192.168.88.70')", 10),
          "the map shows Home Assistant serving the IoT devices")
        c(b.until("document.querySelectorAll('#lan-ports tr').length >= 6 && /switch chip/.test(document.querySelector('#lan-ports').innerText)", 8),
          "LAN ports say the switch chip forwards between them")
        shot(b, "lan-routed")
        # approve only the two LAN items (leave the telemetry items for the setup scenario)
        b.nav(d.url + "#/setup")
        b.until("!!document.querySelector('#plan-load')", 10)
        click(b, "#plan-load")
        c(b.until("!!document.querySelector('[data-item=lanfw]') && !!document.querySelector('[data-item=lanhw]')", 10),
          "Setup offers both LAN items")
        c(b.eval("!document.querySelector('[data-item=lanfw]').checked && !document.querySelector('[data-item=lanhw]').checked"),
          "unticked: they cost router CPU")
        b.eval("document.querySelectorAll('[data-item]').forEach(i => { i.checked = i.dataset.item === 'lanfw' || i.dataset.item === 'lanhw'; })")
        click(b, "#plan-apply")
        c(b.until("document.querySelector('#plan-again') !== null && !document.querySelector('#plan').innerText.includes('✗')", 15),
          "applied")
        c(d.world.single["/interface/bridge/settings"]["use-ip-firewall"] == "true" and not d.world.hw_offloaded("ether2"),
          "the router now sends bridged traffic through the firewall, in software")
        b.nav(d.url + "#/lan")
        c(b.until("S.snap.lan.pairs.some(p => p.service === 'Plex 32400' && !p.routed)", 20), "same-network conversations appear (TV -> NAS Plex)")
        c(b.until("[...document.querySelectorAll('#lan-pairs tr')].some(r => /SMB 445/.test(r.innerText))", 8), "listed as conversations")
        c(b.until("!!document.querySelector('#lan-vis .callout.good')", 5), "the page says it can see them")
        c(not b.eval("S.snap.lan.pairs.some(p => p.client === '192.168.88.20' && p.server === '192.168.88.10')"),
          "but never what stays inside the switch (workstation -> NAS)")
        c(b.until("[...document.querySelectorAll('#lan-devices tr[data-ip]')].some(r => r.dataset.ip === '192.168.88.10' && /server/.test(r.innerText))", 8),
          "the NAS is listed as a server")
        shot(b, "lan-visible")
        click(b, "#lan-devices tr[data-ip]")
        c(b.until("document.querySelector('#drawer.open') && /only/.test(document.querySelector('#lan-src').innerText)", 8),
          "opening a device narrows the map to its conversations")
        b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape'}))")
        c(b.until("!/only/.test(document.querySelector('#lan-src').innerText)", 5), "Esc shows everything again")
        c(not b.errors, "no console errors: {}".format(b.errors[:3]))


SCENARIOS = {"pages": sc_pages, "identify": sc_identify, "setup": sc_setup, "respond": sc_respond, "ignore": sc_ignore, "layout": sc_layout, "globe-fade": sc_globe_fade, "theme": sc_theme, "update": sc_update, "types": sc_types, "drawer": sc_drawer, "phone": sc_phone,
             "light": sc_light, "offscreen": sc_offscreen,
             "single-out": sc_single_out, "globe-fit": sc_globe_fit,
             "vpn": sc_vpn, "lan": sc_lan}


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
