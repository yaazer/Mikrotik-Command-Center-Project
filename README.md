# Mikrotik Command Center

A self-contained NOC console for a MikroTik network: a **RouterOS 7** router and a **SwOS** switch.

- **Live telemetry**: throughput, CPU, memory, temperature, every interface and switch port.
- **A live traffic map**: who on your LAN is talking to whom on the Internet, at what rate, animated as it happens.
- **Threat detection**: port scans, brute force, router login guessing, floods, worm-like spreading, blocklisted addresses, unusual uploads, new devices, link failures.
- **Interactive responses**: block an address, quarantine a host, drop its connections, disable a port. Each one is shown as the exact router change, applied only when you confirm, logged, and undoable.

It's one Python program with no dependencies (standard library only) and a plain-JavaScript web console. There are no CDNs, no cloud and no accounts, and it never makes outbound calls except to your own router and switch.

```
python mcc.py --demo     # try it now: a simulated router, switch and network with scripted incidents
python mcc.py            # the real thing: then connect your router from Setup
```

The console opens at <http://127.0.0.1:8840/>. It needs Python 3.8+ and a current Chrome, Edge, Firefox or Safari.

---

## Running it on a Debian VM (a service)

On Debian 12/13 or Ubuntu, as a user with sudo:

```
git clone -b main https://github.com/yaazer/Mikrotik-Command-Center-Project.git
cd Mikrotik-Command-Center-Project
sudo ./deploy/install-debian.sh
```

It prints the console URL, `http://<vm-ip>:8840/?token=…`. Open it from your desktop; the token sets a cookie, so bookmark the URL once.

| What | Where |
|---|---|
| Program | `/opt/mcc`: root-owned, read-only to the service |
| Data | `/var/lib/mcc`: config, threats, actions, ignore rules, geolocation DB |
| Settings | `/etc/mcc/mcc.env` (root-only): bind address, port, access token, optional passwords |
| Service | `systemctl status mcc` · `journalctl -u mcc -f` · runs as the unprivileged user `mcc`, sandboxed by systemd |
| Update | `git pull && sudo ./deploy/install-debian.sh`: code replaced, data and settings kept |

**Ports to allow** if the VM has a firewall: 8840/tcp (console) from your desktop, and 2055/udp (flows) and 5514/udp (syslog) from the router. The installer opens these automatically when `ufw` is active.

**Reconnecting after a reboot.** MCC keeps passwords in memory only, so after a restart you'd enter them again in Setup. To have the service reconnect on its own:
1. Connect once from Setup; that saves the address and user.
2. Put the password in `/etc/mcc/mcc.env` (`MCC_ROUTER_PASSWORD=…`, `MCC_SWITCH_PASSWORD=…`). The file is root-only.
3. Run `systemctl restart mcc`.

MCC itself still never writes a password. Use a dedicated, limited RouterOS user for this. A wrong password is tried once, not retried, so the account doesn't get locked.

**Moving from a PC to the VM.**
- **Data:** copy the PC's `data` folder next to `mcc.py` before running the installer, and the first install imports it (threat history, ignore rules, known devices, geolocation database).
- **Telemetry:** in the VM's console open **Setup › Telemetry** and approve the plan again. That points flow export and syslog at the VM, and offers (unticked) to remove the router's old flow export to the PC.
- **The PC:** stop the copy running there.

## The demo

`--demo` starts a simulated RB5009 and CRS309 with a small LAN:
- a NAS, a workstation, a TV, a gaming PC, cameras, a homelab with an SSH port forward;
- a repeating script of incidents: SSH brute force, router login guessing, a port scan, a camera that starts spreading like a worm, a beacon to a blocklisted server, a new device, a link flap, a large upload, and an IRC connection.

The simulated router behaves like the real one:
- **Your responses take effect:** a blocked attacker stops, a quarantined host goes quiet, a disabled port drops.
- **Telemetry only flows after you approve it:** the router sends flow and syslog data only once you've approved the setup plan.

`--speed 3` runs the incident script faster. Demo data goes to `data/demo/` and is wiped on each run.

## Connecting your network

### 1. Give MCC its own RouterOS user (recommended)

```
/user group add name=mcc policy=read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!password,!sniff,!sensitive,!romon
/user add name=mcc group=mcc password="<long random>" address=<this PC's IP>/32
/ip service set www-ssl disabled=no
```

The REST API needs the `www-ssl` service (HTTPS, with a certificate) or `www` (HTTP; use it only on a LAN you trust). Locking the user to this PC's address limits the damage if the password leaks.

### 2. Connect from Setup

Enter the router's address, user and password.
- **Credentials stay in memory only.** They are never written to disk, so after a restart you enter the password again.
- **The certificate is pinned on first connect** (trust on first use). From then on, MCC refuses to talk to the router if its certificate changes. Compare the fingerprint with `/certificate print` on the router.

The switch is optional. Enter its address and SwOS user. (Its default user is `admin` with an empty password.)

### 3. Approve telemetry (optional, recommended)

Even with no router changes, MCC works from the REST API alone:
- live per-connection traffic from the connection table;
- the router's in-memory log, for login failures;
- interfaces, health and devices.

**Setup › Review the router changes MCC needs** reads the router and shows the exact commands for four optional additions. Each is shown as a terminal command and as the REST call:

| Item | What it adds | Why |
|---|---|---|
| Traffic Flow export | `/ip traffic-flow set enabled=yes …` + a target pointing at this PC (IPFIX, UDP 2055) | Full per-flow accounting; catches scans of closed ports |
| Syslog to MCC | a `remote` logging action + rules for `firewall`, `critical`, `interface` (UDP 5514) | Real-time scan, login and link events |
| Log inbound attempts | two non-blocking `action=log` filter rules (`MCC-IN`, `MCC-FWD`), rate-limited | See every attempt from the Internet, whatever your later rules do |
| Drop rules | raw `drop` for `mcc-blocked`, forward `drop` for `mcc-quarantine` | Makes MCC's lists work; both start empty |

Choose the items you want and approve. MCC applies the plan you looked at, never a fresh one, and refuses a plan older than 10 minutes. Everything it adds carries an `mcc:` comment or the `mcc` name.

**Plan removal of everything MCC added** works the same way: it shows the exact removals and runs only after you approve.

## How responses work

1. **A threat suggests responses.** For example, *Block 203.0.113.9 for 24 h*. You can also start one from any host (click it on the map or in a table) or from the command palette (`Ctrl+K`, then type an IP).
2. **MCC prepares a proposal.** It reads the router and shows exactly what will change, for example:
   ```
   /ip firewall address-list add list=mcc-blocked address=203.0.113.9 timeout=1d comment="mcc: Port scan … (A0007)"
   ```
   It also shows any one-time prerequisites and warnings. **Nothing has changed yet.**
3. **Confirm** runs those calls in order. **Don't do it** discards the proposal.
4. **Undo** is available on the result screen and in **Actions**. A dropped connection can't be restored; the proposal tells you that up front.

Every proposal, confirmation, failure, undo and dismissal is appended to `data/actions.jsonl`.

### Safety rails

MCC refuses to block or quarantine:
- the router's own addresses;
- your Internet gateway;
- the machine MCC runs on;
- anything in **Settings › Never block** (put your VPN, DNS servers and so on there).

Disabling the WAN interface warns that the whole network goes offline. Disabling the interface MCC reaches the router through requires an extra acknowledgement.

Blocks and quarantines also drop the address's open connections. Without that, connections that are already fast-tracked would keep going.

### Detection rules

| Rule | Fires when (defaults, all adjustable in Settings) | Suggested response |
|---|---|---|
| Port scan | one outside address probes ≥ 15 ports in 60 s | block |
| Network sweep | one address probes ≥ 10 of your hosts on one port | block |
| Service brute force | ≥ 20 new connections to SSH/RDP/Winbox/SMB/… in 60 s | block (or quarantine a LAN source) |
| Router login failures | ≥ 5 failed router logins in 5 min | block |
| Flood | ≥ 5000 pps in a flow, or ≥ 300 logged packets/min | block |
| Blocklisted address | traffic to/from `data/blocklist.txt` | block, quarantine the LAN host, drop connections |
| Host fan-out | a LAN host contacts ≥ 150 Internet addresses/min | quarantine, drop connections |
| Worm-like spreading | ≥ 30 destinations/min on 23/25/445/2323/3389 | quarantine |
| Suspicious outbound port | a LAN host connects out on 23, 4444, 6667, 9001, … | block peer / quarantine |
| Unusual upload | ≥ 50 Mb/s and ≥ 4× the host's normal rate, for 2 min | drop connections / quarantine |
| VPN leak | a firewall rule logged with the `VPN-LEAK` prefix (your VPN kill switch) catches a device; prefixes in Settings | drop connections / quarantine |
| New device | a MAC never seen before (the first run is the baseline) | quarantine, or mark known |
| Link down | a router or switch port that was up loses link | — |
| Router CPU / temperature | ≥ 90 % for 30 s / ≥ 75 °C | — |

**VPN leaks.** Give your kill-switch rule a log prefix, and every hit becomes a *VPN leak* threat for the device it caught, with the interface it tried to use:

```
/ip firewall filter set [find comment="Kill-switch: .42 must never use Bell"] log=yes log-prefix=VPN-LEAK
```

MCC sees the hit through syslog (approve *Syslog to MCC* in Setup) or the router's own log. Other prefixes can be added in **Settings › Detection thresholds › VPN leak log prefixes**.

A threat is keyed by rule and subject, so a ten-minute scan is one threat whose count and evidence grow, not a thousand alerts.

A threat's status moves through `open`, `acknowledged`, `mitigated`, `quiet` (no activity for 10 min) and `resolved`.

If a mitigated threat shows activity again **after a two-minute grace period**, it reopens marked *came back after mitigation*. The grace period covers flow records that describe traffic from before the block, which arrive up to a minute late.

### Acknowledging and ignoring

- **Acknowledge** means "I've seen it". The threat stays in the Active list and keeps counting, but it no longer raises the threat level.
- **Ignore…** is for a *confirmed false positive*. You choose how far the ignore reaches:
  - **just this alert**: the same rule and the same case, for example *this host on port 6667*;
  - **this rule for this address or network**: any port, any target;
  - **every rule for this address**: only for hosts you fully trust.

  You also choose how long (24 hours, 7 days, 30 days or forever) and give a reason.
- **After you ignore something:** matching events still increment the rule's *silenced* counter, but they raise no threat, toast or threat level, and don't mark the host on the map.
- **Threats › Ignore list:** shows every rule with its reason, what it has silenced and its expiry. Rules can also be added there by hand. *Remove* makes MCC alert again the next time it happens.
- **Storage:** rules are kept in `data/ignore.json`. Every addition, removal and expiry is appended to `data/ignore.log.jsonl`.
- **Ignoring never changes the router.**

**Blocklist:** put a list you trust in `data/blocklist.txt`, one IP or CIDR per line, with `#` or `;` comments. Spamhaus DROP and FireHOL level1 both work. The file is re-read whenever it changes.

## Where traffic goes: the globe

The Overview's live traffic panel switches between **Globe** and **Flow map**. The Traffic page shows both, plus a table by country.

On the globe:
- **Arcs:** each located Internet peer is joined to your router's location by a great-circle arc.
- **Particles** flow along each arc at the live rate: toward home for downloads, away for uploads, red for threats. Dashed arcs are blocked peers.
- **Merged places:** peers at the same place are merged; click one to list them, or to open the host when there's only one.
- **Controls:** drag to spin, scroll to zoom, double-click (or ⌂) to centre on home.

Locations come from a **local** MaxMind-format (`.mmdb`) database. Your traffic's addresses are never sent anywhere.
- **Download from Setup:** **Setup › Geolocation** can download the free **DB-IP Lite** database (CC BY 4.0, no account). That button is the only time MCC contacts anything but your router.
  - **Country Lite** (≈4 MB) places peers at the middle of their country.
  - **City Lite** (≈60 MB) places them at the city.

  DB-IP updates both monthly; download again to refresh.
- **Bring your own:** any other `.mmdb` works too (MaxMind GeoLite2, IPinfo). Drop it in `data/geo/` or give its path.
- **Home** (where arcs start) is found by looking up the router's public address. If you're behind CGNAT, or want it exact, set latitude and longitude in Setup.

The globe's coastlines and land come from Natural Earth (public domain), bundled in `mcc/web/world.js` (43 KB). To regenerate it, run `tools/build_world.py`.

## Traffic types

Every conversation is classified into one of these types:
- video & music streaming;
- BitTorrent/P2P;
- gaming;
- voice & video calls;
- social & messaging;
- cloud storage & backup;
- software updates;
- smart home/IoT;
- VPN & remote access;
- email;
- web;
- DNS & time;
- other.

**Where you see them:**
- **Colour by type:** the globe and the flow map colour links, places and particles by type. The **Type / Direction** switch on each live panel changes that back to download/upload colours.
- **Focus a type:** click a type in the legend or the **Traffic types** panel. It's highlighted everywhere, and the Conversations table shows only that type.
- **Per row:** Conversations gets a Type column (hover it to see why a row was classified that way), host and peer rows get a type dot, and the host drawer breaks a host's traffic down by type.

**How a type is decided** (`mcc/classify.py`):
1. **The name your device looked up**, from the router's DNS cache. For example, `*.nflxvideo.net` and `*.googlevideo.com` are streaming, and `*.steamcontent.com` is gaming. A name must be the listed domain or a subdomain of it, so a lookalike such as `netflix.com.evil.example` doesn't count.
2. **Well-known ports:**
   - 6881–6999 and 51413: BitTorrent;
   - 3074: Xbox Live;
   - 8801: Zoom;
   - 993: IMAPS;
   - 51820: WireGuard;
   - and so on.
3. **A pattern:** a LAN host talking to many unnamed peers on random high ports is running P2P. BitTorrent picks random ports, so ports alone miss most of it.
4. **Fallback:** anything else on 80/443 is web, and the rest is "other".

This is an informed guess from names and ports, not deep packet inspection. A CDN that serves several services shows as whatever its name says, and encrypted traffic to an unrecognised name is "web". Each type keeps the same colour in every theme.

## Singling out a device, and pinning

**Single out a device:** click it on the flow map (or a place on the globe, or a row in any list).
- The flow map shows only that device and every device it talks to, with its traffic paths running through the router.
- The globe shows only where its traffic goes. It stops orbiting and snaps to a view of all its connection points and your home location.
  - **Worldwide traffic:** if they span more than one side of the globe (a torrent swarm, say), it faces the side with the most of them.
  - **Holds still:** it re-frames only when a new connection lands outside the view.
  - **Your view wins:** drag or zoom and it leaves the view to you. Show all returns to your earlier zoom, and orbiting resumes.
- The drawer shows everything MCC knows about it: rates, traffic types, location, the device record, threats, actions, and its **traffic paths**. Each path lists who it talks to, where they are, the type and services, connections and rates.
- Click a path to single out that device instead. Press Esc, click **Show all**, or click empty space or the router to see everything again.

**Pin a device:** use **Pin** in its drawer, the pin in the strip over the map, or the pin that appears when you hover a row in Traffic, Overview or Devices.
- A pinned device is always on the flow map, at the top of its column with a pin marker, even when it's quiet ("pinned · idle").
- It comes first in every list: LAN hosts, Internet peers, top talkers, Devices. Its conversations come first too.
- Pins are kept by MCC in `data/pins.json`, so every browser sees the same ones. A LAN device is remembered by its MAC as well, so its pin follows it when DHCP gives it a new address.

## Arranging the console

Every panel on every page is resizable:
- **Width:** drag a panel's right edge. Widths snap to a 12-column grid, and the panel beside it gives or takes the space, so rows stay full.
- **Height:** drag the bottom edge, or the corner for both. Charts, the globe and the flow map redraw to fit.
- **Drawer:** the host detail drawer resizes from its left edge.
- **Reset:** double-click a handle to reset that panel. The layout button in the header resets the whole page (also in `Ctrl+K`).

Layouts are saved in your browser, per page. On a phone, panels stack full-width.

### Theme Studio

The palette button in the header (or `Ctrl+K`, then type a theme name) opens the Theme Studio. It's the same one as in the VCF Automation Import tool, and changes apply live.

- **Themes:** NOC (the default cyan and amber), Aurora, Nebula, Solar Flare, Phosphor, Graphite, Glacier (light) and Daylight (light).
  - Palettes are generated in OKLCH from a few hues, so every theme stays legible.
  - Severity colours (critical, high, medium, low, ok) keep their meaning in every theme.
  - Download and upload take each theme's two main hues.
- **Hue shift** rotates a whole theme. **Glow** sets the aurora behind the panels and the glow around them; 0 turns the aurora off.
- **Reactive ambience:** the aurora tints with the threat level, hazard red under attack and amber when elevated.
- **Motion:**
  - **Full**: everything moves.
  - **Calm**: thinner traffic particles and a slower globe. This is the default when your OS asks for reduced motion.
  - **Off**: no particles, spin, pulses or aurora. The data is still drawn.
- **Rendering:**
  - **Lite** drops the aurora, frosted glass and glow, and draws the map and globe at normal resolution. It's much faster on a VM or remote desktop without GPU acceleration.
  - **Auto** detects that from the browser, or from slow frames.
- **Density:** **Compact** tightens tables, panels, logs and the threat feed.

Choices are saved per browser.

## The switch (RouterOS or SwOS)

CRS switches can boot either RouterOS or SwOS. In Setup, the switch type defaults to **Auto-detect**. It works this out from how the switch refuses an unauthenticated request: RouterOS's REST API answers with JSON, and SwOS asks for a digest login. Either way, MCC **only reads the switch**.

- **RouterOS:** MCC uses the same REST API as the router: per-port counters, link state, link rate (`/interface/ethernet/monitor`), model, version and temperature.
  - Enable the `www` or `www-ssl` service.
  - A user with `read` and `rest-api` policies is enough.
- **SwOS:** SwOS has no API, so MCC reads the status files the switch's own web page loads (`link.b`, `stats.b`, `sys.b`) over HTTP digest auth.
  - Those files are undocumented, and their field names vary a little between SwOS releases.
  - If a column reads "—", **Setup › Switch probe** shows the raw data, and `switch.fields` in `data/config.json` can remap a field.

If you force a type that doesn't match the switch, MCC says so rather than showing an empty port list.

To act on a switch port, disable the router port facing it, or quarantine the hosts behind it.

## Security of MCC itself

- **Binding:** the console binds to `127.0.0.1` by default. With `--bind 0.0.0.0`, it generates an access token at startup and prints a URL containing it; the token is then required, held in an `HttpOnly`, `SameSite=Strict` cookie.
- **Request checks:**
  - The Host header must name MCC, which defeats DNS rebinding.
  - Every state-changing request needs an `X-MCC` header and a same-origin `Origin`.
  - A strict Content-Security-Policy allows no inline scripts.
- **Telemetry senders:** the flow and syslog listeners accept packets only from the router. Anything else is counted and shown in Setup with an *Accept from* button, so another LAN host can't feed MCC fake events to steer you into blocking someone.
- **Credentials:** they stay in memory only. `data/config.json` never contains a password.

## Files

```
mcc.py               entry point (--demo, --bind, --port, --speed, --data)
mcc/routeros.py      RouterOS 7 REST client, certificate pinning, CLI rendering
mcc/swos.py          read-only SwOS reader
mcc/collectors.py    IPFIX / NetFlow v9 / v5 and syslog listeners + RouterOS log parsing
mcc/traffic.py       traffic model (connection table + flows -> hosts, peers, conversations)
mcc/detect.py        threat rules, blocklist
mcc/actions.py       propose / confirm / undo engine with safety rails and audit log
mcc/setup_plan.py    telemetry setup and removal plans
mcc/hub.py           pollers, collectors, history, live event fan-out
mcc/server.py        HTTP API, server-sent events, static console
mcc/web/             the console (no frameworks); theme.js = Theme Studio, layout.js = resizable panels
mcc/pins.py          pinned devices (follow a LAN device's MAC)
mcc/names.py         remembered device / DNS names (survive restarts and DNS-cache expiry)
mcc/geo.py           .mmdb reader (stdlib), locator, home location, opt-in DB-IP download
mcc/geodata.py       country label points (Natural Earth) for country-level databases
mcc/sim.py           simulated router, switch and network (demo + tests)
data/                config.json, actions.jsonl, threats.jsonl, devices.json, setup_state.json, blocklist.txt,
                     ignore.json + ignore.log.jsonl, pins.json, names.json, geo/*.mmdb
```

## Tests

```
python tests/run_tests.py          # unit + integration against the simulator (~70 s)
python tools/ui_check.py           # drives the real console in headless Chrome/Edge
SHOTS=out python tools/ui_check.py # ...and saves screenshots
```

## Known limits

- **IPv6:** blocking and quarantine work for IPv6 addresses, but the traffic view and flow detection are IPv4-first.
- **Geolocation is approximate:** IP geolocation places a server at its registered or data-centre location, not exactly where the content comes from. Anycast services (Cloudflare, Google DNS) show one location for many places. Country-level databases put every peer at the middle of its country.
- **Names need the router:** device and host names come from the router's DHCP leases, ARP comments and DNS cache. After a restart MCC uses the names it remembers (`data/names.json`) until you reconnect the router in Setup, or set `MCC_ROUTER_PASSWORD` so it reconnects by itself. Devices it has never seen show as addresses until then.
- **Flow lag:** flow records arrive in batches, so the live map's rates come from the connection table.
- **Validation:** the SwOS field mapping is best effort (see above). Developed against RouterOS 7.x REST and SwOS 2.x behaviour, using the bundled simulator.
