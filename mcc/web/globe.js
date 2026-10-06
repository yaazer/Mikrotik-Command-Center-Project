/* 3D globe of where traffic goes. Canvas 2D, orthographic projection, no libraries.
   Home (the router's location) is joined to every located Internet peer by a great-circle arc
   raised above the surface; particles flow along it at the live rate -- in the "in" colour toward
   home (download), the "out" colour away from it (upload). Peers at the same place are merged.
   Drag to spin, wheel to zoom, hover for details, click a place to single out its host. */
"use strict";

const Globe = (() => {
  const D2R = Math.PI / 180;
  let LAND = null, COAST = null;

  function unpack(b64) {
    const bin = atob(b64);
    const buf = new ArrayBuffer(bin.length);
    const u8 = new Uint8Array(buf);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return new Int16Array(buf);
  }
  const W = (lat, lon) => {
    const a = lat * D2R, b = lon * D2R;
    return [Math.cos(a) * Math.sin(b), Math.sin(a), Math.cos(a) * Math.cos(b)];
  };
  function geography() {
    if (LAND || !window.WORLD) return;
    const d = unpack(WORLD.dots);
    LAND = new Float32Array((d.length / 2) * 3);
    for (let i = 0, j = 0; i < d.length; i += 2, j += 3) {
      const v = W(d[i] / 100, d[i + 1] / 100);
      LAND[j] = v[0]; LAND[j + 1] = v[1]; LAND[j + 2] = v[2];
    }
    const c = unpack(WORLD.coast);
    COAST = [];
    let ring = [];
    for (let i = 0; i < c.length; i += 2) {
      if (c[i] === 32767) { if (ring.length) COAST.push(ring); ring = []; continue; }
      ring.push(W(c[i] / 100, c[i + 1] / 100));
    }
    if (ring.length) COAST.push(ring);
  }

  function create(wrap, opts) {
    // fadeS: how long a place that went quiet stays on the globe, fading out, before it's dropped
    opts = Object.assign({ fadeS: 30 }, opts || {});
    geography();
    const cv = document.createElement("canvas");
    wrap.appendChild(cv);
    wrap.insertAdjacentHTML("beforeend", `
      <div class="globe-ui"><button class="icon-btn" data-g="home" title="Centre on home">⌂</button>
        <button class="icon-btn" data-g="spin" title="Auto-rotate">⟳</button>
        <button class="icon-btn" data-g="in" title="Zoom in">+</button><button class="icon-btn" data-g="out" title="Zoom out">−</button></div>
      <div class="globe-countries"></div>
      <div class="map-legend type-legend"></div>
      <div class="globe-attrib"></div>
      <div class="globe-note hidden"></div>
      <div class="sel-banner hidden"></div>`);
    const ctx = cv.getContext("2d");
    // Theme Studio: Motion (full / calm / off) and Rendering (Lite draws at 1x resolution)
    const motion = () => (window.Theme ? Theme.motion()
      : (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches ? "off" : "full"));
    const lite = () => !!(window.Theme && Theme.isLite());
    let w = 0, h = 0, dpr = 1, colors = {}, raf = 0, last = 0, alive = true, snap = null;
    let clat = 25, clon = -40, target = null, zoom = 1, vlon = 0, vlat = 0, dragging = false, lastTouch = 0;
    let spin = motion() !== "off";
    try { const s = localStorage.getItem("mcc-globe-spin"); if (s !== null) spin = s === "1"; } catch (e) { /* */ }
    let home = null, homeV = null, nodes = [], parts = [], hover = null, centred = false;

    function readColors() {
      // (fonts too: getComputedStyle per label per frame is a style recalculation every time)
      const cs = getComputedStyle(document.documentElement);
      const g = (n) => cs.getPropertyValue(n).trim();
      colors = { in: g("--in"), out: g("--out"), crit: g("--crit"), med: g("--med"), text: g("--text"), muted: g("--muted"),
        faint: g("--faint"), line: g("--line"), soft: g("--line-soft"), accent: g("--accent"), bg: g("--bg"),
        panel: g("--panel-hi"), mono: g("--mono"), light: document.documentElement.dataset.theme === "light",
        oceanA: g("--globe-ocean-a"), oceanB: g("--globe-ocean-b"), land: g("--globe-land"),
        sans: getComputedStyle(document.body).fontFamily };
    }
    readColors();
    on("theme", () => { if (alive) { readColors(); resize(); } });
    function resize() {
      dpr = Math.min(lite() ? 1 : 2, window.devicePixelRatio || 1);
      w = wrap.clientWidth; h = wrap.clientHeight;
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    }
    const ro = new ResizeObserver(resize);
    ro.observe(wrap);
    let onScreen = true;
    const io = new IntersectionObserver((e) => { onScreen = e[e.length - 1].isIntersecting; });
    io.observe(wrap);
    resize();

    const R = () => Math.min(w, h) * 0.42 * zoom;
    const byType = () => Types.by === "type";
    const focusOK = (n) => !Types.focus || !byType() || !!(n.cats && n.cats[Types.focus]);
    const rate = (n) => n.up + n.down;
    // a device is singled out: places it doesn't talk to step right back
    const selDim = (n) => (Select.ip && n.gone ? 0.12 : 1);
    let selShown = null;
    on("select", () => { if (alive && snap) update(snap); });

    /* the peers to put on the globe: everything, or only the singled-out device's paths */
    function peerList(s) {
      const ip = Select.ip;
      if (!ip) return s.traffic.peers;
      const h = Select.data && Select.data.ip === ip ? Select.data : null;
      const live = new Map(s.traffic.peers.map((p) => [p.ip, p]));
      if (!h) return s.traffic.peers.filter((p) => p.ip === ip || (p.hosts || []).includes(ip));  // still loading
      const paths = Select.paths();
      if (!h.lan) {  // an Internet host: just its own place
        const sum = (k) => paths.reduce((a, x) => a + x[k], 0);
        const cats = {};
        paths.forEach((x) => { for (const k in x.cats) cats[k] = (cats[k] || 0) + x.cats[k]; });
        return h.geo ? [Object.assign({ ip, name: h.name, up: sum("up"), down: sum("down"), cats }, live.get(ip) || {}, { geo: h.geo })] : [];
      }
      return paths.filter((x) => x.geo && !x.lan).map((x) => {
        const l = live.get(x.ip) || {};
        return Object.assign({}, x, { threat: l.threat || "", blocked: !!l.blocked });
      });
    }

    /* -------- data -------- */
    function update(s) {
      snap = s;
      const geo = s.geo || {};
      home = geo.home || null;
      homeV = home ? W(home.lat, home.lon) : null;
      if (home && !centred) { clat = Math.max(-60, Math.min(60, home.lat * 0.6)); clon = home.lon + 25; centred = true; }
      // Places are long-lived objects, updated in place: particles hold a reference to their place,
      // so replacing the objects on every refresh would cut every particle off mid-flight.
      const hk = homeKey();
      const seen = new Set();
      const list = peerList(s);
      const wrapB = $(".sel-banner", wrap);
      wrapB.innerHTML = Select.banner();
      wrapB.classList.toggle("hidden", !Select.ip);
      if (Select.ip !== selShown) {
        selShown = Select.ip;
        // singling out an Internet host: turn the globe to it
        const g = Select.ip && list.length === 1 && list[0].ip === Select.ip ? list[0].geo : null;
        if (g) { target = { lat: Math.max(-60, Math.min(60, g.lat)), lon: g.lon }; vlon = vlat = 0; }
        else if (Select.ip) selShown = Select.data && Select.data.ip === Select.ip ? Select.ip : null;  // retry once loaded
      }
      for (const p of list) {
        if (!p.geo) continue;
        const key = p.geo.lat.toFixed(1) + "," + p.geo.lon.toFixed(1);
        let n = places.get(key);
        if (!n) {
          n = { key, lat: p.geo.lat, lon: p.geo.lon, v: W(p.geo.lat, p.geo.lon), acc: { in: 0, out: 0 }, arc: null,
            homeKey: null, alpha: 0 };
          places.set(key, n);
        }
        if (!seen.has(key)) {
          seen.add(key);
          Object.assign(n, { city: p.geo.city, country: p.geo.country, cc: p.geo.cc, precision: p.geo.precision,
            peers: [], up: 0, down: 0, threat: "", blocked: 0, gone: false, talpha: 1, cats: {} });
        }
        n.peers.push(p);
        n.up += p.up; n.down += p.down;
        if (p.blocked) n.blocked++;
        for (const k in p.cats || {}) n.cats[k] = (n.cats[k] || 0) + p.cats[k];
        if (p.threat && (TrafficMap.SEV_RANK[p.threat] || 0) > (TrafficMap.SEV_RANK[n.threat] || -1)) n.threat = p.threat;
      }
      for (const n of places.values()) {
        if (!seen.has(n.key) && !n.gone) {
          // Gone quiet: keep it on the globe for opts.fadeS seconds, fading out gradually (see frame()).
          // It stops spawning particles; those already in flight finish their trip. Its last peers,
          // direction and threat are kept so the fading point still says what it was.
          Object.assign(n, { gone: true, goneAt: performance.now(), goneAlpha: Math.max(n.alpha, 0.05),
            wasDown: n.down >= n.up, lastRate: rate(n), up: 0, down: 0 });
        }
        if (n.homeKey !== hk) {
          n.arc = homeV ? arcPoints(homeV, n.v) : null;
          n.homeKey = hk;
        }
        n.peers.sort((a, b) => rate(b) - rate(a));
        n.cat = Object.entries(n.cats || {}).sort((a, b) => b[1] - a[1]).map((e) => e[0])[0] || "other";
      }
      nodes = [...places.values()].sort((a, b) => (a.gone - b.gone) || rate(b) - rate(a));
      overlays(geo);
    }
    const places = new Map();
    const homeKey = () => (home ? home.lat + "," + home.lon : "");

    function arcPoints(a, b) {
      const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
      const om = Math.acos(dot);
      if (om < 0.01) return null;
      const so = Math.sin(om), lift = 0.04 + 0.32 * (om / Math.PI);
      const n = Math.max(16, Math.round(om * 40)), pts = [];
      for (let i = 0; i <= n; i++) {
        const t = i / n, k1 = Math.sin((1 - t) * om) / so, k2 = Math.sin(t * om) / so, alt = 1 + lift * Math.sin(Math.PI * t);
        pts.push([(k1 * a[0] + k2 * b[0]) * alt, (k1 * a[1] + k2 * b[1]) * alt, (k1 * a[2] + k2 * b[2]) * alt]);
      }
      return pts;
    }

    function overlays(geo) {
      const cl = $(".globe-countries", wrap);
      const list = (geo.countries || []).slice(0, 6);
      const max = Math.max(1, ...list.map((c) => c.up + c.down));
      cl.innerHTML = list.length ? `<div class="gc-h">Top countries</div>` + list.map((c) => `<div class="gc" title="${esc(c.country)}: ${c.peers} peer${c.peers === 1 ? "" : "s"}">
        <span class="cc ${c.threat ? "bad" : ""}">${esc(c.cc || "?")}</span><span class="bar"><i style="width:${(((c.up + c.down) / max) * 100).toFixed(0)}%"></i></span><span class="num">${fmt.bps(c.up + c.down)}</span></div>`).join("") : "";
      const at = $(".globe-attrib", wrap);
      at.innerHTML = geo.dbip ? 'IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a>' :
        geo.source === "demo" ? "simulated locations" : "";
      const note = $(".globe-note", wrap);
      let msg = "";
      if (geo.source === "none") msg = 'No geolocation database yet — add one in <a href="#/setup">Setup › Geolocation</a>. Lookups stay on this machine.';
      else if (!home) msg = 'Where is home? Set your location in <a href="#/setup">Setup › Geolocation</a> so arcs start at your router.';
      note.innerHTML = msg;
      note.classList.toggle("hidden", !msg);
    }

    /* -------- projection -------- */
    let cy0, sy0, cx0, sx0;
    function setView() {
      const a = clat * D2R, b = clon * D2R;
      cy0 = Math.cos(a); sy0 = Math.sin(a); cx0 = Math.cos(b); sx0 = Math.sin(b);
    }
    // world vector -> [screen x, screen y, depth z, |xy|^2]
    function proj(v) {
      const x1 = v[0] * cx0 - v[2] * sx0;
      const z1 = v[0] * sx0 + v[2] * cx0;
      const y2 = v[1] * cy0 - z1 * sy0;
      const z2 = v[1] * sy0 + z1 * cy0;
      return [x1, y2, z2];
    }
    const visible = (p) => p[2] >= 0 || p[0] * p[0] + p[1] * p[1] > 1;

    /* -------- animation -------- */
    function frame(now) {
      if (!alive) return;
      if (!wrap.isConnected) { destroy(); return; }
      raf = requestAnimationFrame(frame);
      if (!onScreen) { last = 0; return; }  // scrolled out of view: draw nothing (the Traffic page has two of these)
      if (last && now - last < 15) return;  // ~60 fps cap (high-refresh screens would draw 2x for nothing)
      const dt = Math.min(0.1, last ? (now - last) / 1000 : 0.016);
      last = now;
      if (!dragging) {
        if (target) {
          const k = 1 - Math.pow(0.02, dt);
          let dl = ((target.lon - clon + 540) % 360) - 180;
          clon += dl * k; clat += (target.lat - clat) * k;
          if (Math.abs(dl) < 0.05 && Math.abs(target.lat - clat) < 0.05) target = null;
        } else {
          clon += vlon * dt; clat = Math.max(-80, Math.min(80, clat + vlat * dt));
          vlon *= Math.pow(0.05, dt); vlat *= Math.pow(0.05, dt);
          const m = motion();
          if (spin && m !== "off" && Math.abs(vlon) < 1 && now - lastTouch > 2500) clon += (m === "calm" ? 1.5 : 4) * dt;
        }
      }
      let expired = false;
      for (const n of nodes) {
        if (n.gone) {
          // cosine ease: holds near full brightness at first, then fades away smoothly to nothing
          const e = (now - n.goneAt) / 1000 / opts.fadeS;
          n.alpha = e >= 1 ? 0 : n.goneAlpha * 0.5 * (1 + Math.cos(Math.PI * e));
          if (e >= 1) expired = true;
        } else {
          n.alpha += (1 - n.alpha) * Math.min(1, dt * 3);
        }
      }
      if (expired) {
        const keep = (n) => !(n.gone && n.alpha === 0 && !parts.some((p) => p.n === n));
        nodes = nodes.filter(keep);
        for (const [k, n] of places) if (!keep(n)) places.delete(k);
      }
      spawn(dt);
      setView();
      draw(now / 1000);
    }

    function spawn(dt) {
      if (!homeV) { parts = []; return; }
      const m = motion();
      const density = m === "off" ? 0 : m === "calm" ? 0.4 : 1;
      for (const n of nodes) {
        if (!n.arc || n.blocked === n.peers.length) continue;
        for (const dir of ["in", "out"]) {
          const bps = dir === "in" ? n.down : n.up;
          if (bps < 400) continue;
          n.acc[dir] += Math.min(12, Math.log10(1 + bps / 1e3) * 2) * density * dt;
          while (n.acc[dir] >= 1) {
            n.acc[dir] -= 1;
            parts.push({ n, dir, t: 0, v: 0.22 + Math.random() * 0.12, s: 1.2 + Math.min(2, Math.log10(1 + bps / 1e5)),
              cat: Types.pick(n.cats) });
          }
        }
      }
      for (const p of parts) p.t += p.v * dt;
      parts = parts.filter((p) => p.t < 1 && places.get(p.n.key) === p.n);
      if (parts.length > 1500) parts.splice(0, parts.length - 1500);
    }

    function draw(t) {
      const r = R(), cx = w / 2, cy = h / 2 + 6;
      const S = (p) => [cx + p[0] * r, cy - p[1] * r];
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      // atmosphere
      const atm = ctx.createRadialGradient(cx, cy, r * 0.96, cx, cy, r * 1.22);
      atm.addColorStop(0, alphaC(colors.accent, colors.light ? 0.25 : 0.32));
      atm.addColorStop(1, alphaC(colors.accent, 0));
      ctx.fillStyle = atm;
      ctx.beginPath(); ctx.arc(cx, cy, r * 1.22, 0, Math.PI * 2); ctx.fill();
      // ocean
      const oc = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.4, r * 0.1, cx, cy, r);
      oc.addColorStop(0, colors.oceanA || (colors.light ? "oklch(0.97 0.02 230)" : "oklch(0.30 0.05 245)"));
      oc.addColorStop(1, colors.oceanB || (colors.light ? "oklch(0.88 0.03 235)" : "oklch(0.15 0.03 255)"));
      ctx.fillStyle = oc;
      ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.fill();
      // graticule
      ctx.strokeStyle = alphaC(colors.accent, colors.light ? 0.12 : 0.09);
      ctx.lineWidth = 1;
      for (let lat = -60; lat <= 60; lat += 30) polyline(lineOfLat(lat), S, false);
      for (let lon = -180; lon < 180; lon += 30) polyline(lineOfLon(lon), S, false);
      // land
      if (LAND) {
        const ds = Math.max(0.9, Math.min(2.4, r / 230));
        ctx.fillStyle = colors.land || (colors.light ? "oklch(0.55 0.06 240)" : "oklch(0.80 0.08 215)");
        // limb darkening in 6 brightness bands: one path and one fill per band instead of an alpha
        // change and a fill per dot (5,400 dots, every frame)
        const BANDS = 6;
        for (let b = 0; b < BANDS; b++) bands[b].length = 0;
        for (let i = 0; i < LAND.length; i += 3) {
          const x1 = LAND[i] * cx0 - LAND[i + 2] * sx0;
          const z1 = LAND[i] * sx0 + LAND[i + 2] * cx0;
          const z2 = LAND[i + 1] * sy0 + z1 * cy0;
          if (z2 <= 0.02) continue;
          const y2 = LAND[i + 1] * cy0 - z1 * sy0;
          bands[Math.min(BANDS - 1, (z2 * BANDS) | 0)].push(cx + x1 * r - ds / 2, cy - y2 * r - ds / 2);
        }
        for (let b = 0; b < BANDS; b++) {
          const pts = bands[b];
          if (!pts.length) continue;
          ctx.globalAlpha = 0.18 + 0.55 * ((b + 0.5) / BANDS);
          ctx.beginPath();
          for (let k = 0; k < pts.length; k += 2) ctx.rect(pts[k], pts[k + 1], ds, ds);
          ctx.fill();
        }
        ctx.globalAlpha = 1;
      }
      if (COAST) {
        ctx.strokeStyle = alphaC(colors.accent, colors.light ? 0.35 : 0.28);
        ctx.lineWidth = 0.8;
        for (const ring of COAST) polyline(ring, S, true);
      }
      // arcs
      const live = hover && hover !== "home" ? hover : null;
      for (const n of nodes) {
        if (!n.arc) continue;
        const rel = (!live || live === n) && focusOK(n);
        const col = n.threat ? colors.crit : n.blocked === n.peers.length ? colors.faint : byType() ? Types.color(n.cat)
          : (n.gone ? n.wasDown : n.down >= n.up) ? colors.in : colors.out;
        ctx.strokeStyle = col;
        ctx.globalAlpha = n.alpha * selDim(n) * (rel ? (live ? 0.95 : Select.ip ? 0.85 : 0.55) : 0.12);
        ctx.lineWidth = 0.8 + Math.min(3, Math.log10(1 + rate(n) / 2e4));
        ctx.setLineDash(n.blocked === n.peers.length ? [3, 4] : []);
        polyline(n.arc, S, true);
      }
      ctx.setLineDash([]);
      // particles
      ctx.globalCompositeOperation = colors.light ? "source-over" : "lighter";
      for (const p of parts) {
        const a = p.n.arc;
        if (!a) continue;
        const pos = p.dir === "in" ? 1 - p.t : p.t;
        const f = pos * (a.length - 1), i = Math.floor(f), k = f - i;
        const q = a[Math.min(i + 1, a.length - 1)], o = a[i];
        const v = proj([o[0] + (q[0] - o[0]) * k, o[1] + (q[1] - o[1]) * k, o[2] + (q[2] - o[2]) * k]);
        if (!visible(v)) continue;
        const [x, y] = S(v);
        const pon = (!live || live === p.n) && (!Types.focus || !byType() || p.cat === Types.focus);
        ctx.globalAlpha = p.n.alpha * selDim(p.n) * Math.min(1, p.t * 6, (1 - p.t) * 6) * (pon ? 0.95 : 0.1);
        ctx.fillStyle = byType() ? Types.color(p.cat) : p.n.threat ? colors.crit : p.dir === "in" ? colors.in : colors.out;
        ctx.beginPath(); ctx.arc(x, y, p.s, 0, Math.PI * 2); ctx.fill();
      }
      ctx.globalCompositeOperation = "source-over";
      // places
      const labels = [];
      nodes.forEach((n, idx) => {
        const v = proj(n.v);
        n.screen = null;
        if (v[2] < 0) return;
        const [x, y] = S(v);
        const rad = 2.5 + Math.min(7, Math.log10(1 + rate(n) / 2e3) * 1.8);
        n.screen = [x, y, rad];
        const col = n.threat ? colors.crit : byType() ? Types.color(n.cat) : n.precision === "country" ? colors.med : colors.accent;
        ctx.globalAlpha = n.alpha * selDim(n) * ((!live || live === n) && focusOK(n) ? 1 : 0.35) * (0.4 + 0.6 * v[2]);
        if (n.threat && motion() !== "off" && !n.gone) {
          const ph = (t * 1.1 + idx * 0.13) % 1;
          ctx.strokeStyle = colors.crit;
          ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(x, y, rad + 2 + ph * 14, 0, Math.PI * 2); ctx.stroke();
        }
        ctx.fillStyle = col;
        ctx.beginPath(); ctx.arc(x, y, rad, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = colors.bg;
        ctx.lineWidth = 1;
        ctx.stroke();
        if (idx < 8 || n === live || n.threat) labels.push([n, x, y, rad, v[2]]);
      });
      // labels: home's first, then places in rate order, each on the right or left of its dot
      // wherever it doesn't collide with one already drawn (otherwise it waits for hover)
      const placed = [];
      const free = (bx) => !placed.some((p) => bx[0] < p[0] + p[2] && bx[0] + bx[2] > p[0] && bx[1] < p[1] + p[3] && bx[1] + bx[3] > p[1]);
      const font = colors.sans;
      let homeLabel = null;
      if (homeV) {
        const v = proj(homeV);
        if (v[2] >= 0) {
          const [x, y] = S(v);
          ctx.font = "700 12px " + font;
          const text = ((snap && snap.router && snap.router.identity) || "home") + " · " + (home.label || "");
          const tw = ctx.measureText(text).width;
          homeLabel = [text, x + 10, y - 14];
          placed.push([x + 8, y - 22, tw + 4, 16], [x - 7, y - 7, 14, 14]);
        }
      }
      ctx.font = "600 11.5px " + font;
      ctx.textBaseline = "middle";
      for (const [n, x, y, rad, z] of labels) {
        const text = n.city || n.country || n.cc;
        const tw = ctx.measureText(text).width;
        const right = [x + rad + 3, y - 8, tw + 4, 16], left = [x - rad - 7 - tw, y - 8, tw + 4, 16];
        let at = free(right) ? right : free(left) ? left : n === live ? right : null;
        if (!at) continue;
        placed.push(at);
        ctx.globalAlpha = n.alpha * selDim(n) * Math.min(1, z * 3);
        ctx.textAlign = "left";
        ctx.lineWidth = 3;
        ctx.strokeStyle = alphaC(colors.bg, 0.8);
        ctx.strokeText(text, at[0] + 1, y);
        ctx.fillStyle = n.threat ? colors.crit : colors.text;
        ctx.fillText(text, at[0] + 1, y);
      }
      ctx.globalAlpha = 1;
      // home
      if (homeV) {
        const v = proj(homeV);
        if (v[2] >= 0) {
          const [x, y] = S(v);
          const ph = motion() === "off" ? 0.5 : (t * 0.8) % 1;
          ctx.strokeStyle = colors.accent;
          ctx.globalAlpha = 1 - ph;
          ctx.lineWidth = 2;
          ctx.beginPath(); ctx.arc(x, y, 6 + ph * 18, 0, Math.PI * 2); ctx.stroke();
          ctx.globalAlpha = 1;
          ctx.fillStyle = colors.accent;
          ctx.beginPath(); ctx.arc(x, y, 5, 0, Math.PI * 2); ctx.fill();
          ctx.strokeStyle = colors.bg;
          ctx.lineWidth = 1.5;
          ctx.stroke();
          if (homeLabel) {
            ctx.font = "700 12px " + font;
            ctx.textAlign = "left";
            ctx.lineWidth = 3;
            ctx.strokeStyle = alphaC(colors.bg, 0.8);
            ctx.strokeText(homeLabel[0], homeLabel[1], homeLabel[2]);
            ctx.fillStyle = colors.text;
            ctx.fillText(homeLabel[0], homeLabel[1], homeLabel[2]);
          }
          homeScreen = [x, y];
        } else homeScreen = null;
      }
      if (motion() === "off") motionOffNote(ctx, w / 2, h - 14, colors);
    }
    let homeScreen = null;

    function polyline(pts, S, isWorld) {
      let open = false;
      ctx.beginPath();
      for (const p0 of pts) {
        const p = proj(p0);
        const vis = isWorld ? visible(p) && (p[2] >= -0.02 || p[0] * p[0] + p[1] * p[1] > 1) : p[2] >= 0;
        if (!vis) { open = false; continue; }
        const [x, y] = S(p);
        if (open) ctx.lineTo(x, y); else { ctx.moveTo(x, y); open = true; }
      }
      ctx.stroke();
    }
    const latCache = {}, lonCache = {};
    const bands = [[], [], [], [], [], []];  // reused land-dot buckets (see draw)
    function lineOfLat(lat) {
      if (!latCache[lat]) { latCache[lat] = []; for (let lon = -180; lon <= 180; lon += 4) latCache[lat].push(W(lat, lon)); }
      return latCache[lat];
    }
    function lineOfLon(lon) {
      if (!lonCache[lon]) { lonCache[lon] = []; for (let lat = -85; lat <= 85; lat += 4) lonCache[lon].push(W(lat, lon)); }
      return lonCache[lon];
    }
    function alphaC(c, a) {
      if (!c) return `rgba(128,128,128,${a})`;
      if (c.startsWith("oklch(") && !c.includes("/")) return c.replace(/\)\s*$/, ` / ${a})`);
      return c;
    }

    /* -------- interaction -------- */
    function hit(mx, my) {
      if (homeScreen && Math.hypot(mx - homeScreen[0], my - homeScreen[1]) < 9) return "home";
      let best = null, bd = 1e9;
      for (const n of nodes) {
        if (!n.screen || n.alpha < 0.08) continue;
        const d = Math.hypot(mx - n.screen[0], my - n.screen[1]);
        if (d < n.screen[2] + 7 && d < bd) { best = n; bd = d; }
      }
      return best;
    }
    let down = null;
    cv.addEventListener("pointerdown", (e) => {
      down = { x: e.clientX, y: e.clientY, lon: clon, lat: clat, t: performance.now(), moved: false };
      dragging = true; target = null; lastTouch = performance.now();
      cv.setPointerCapture(e.pointerId);
    });
    cv.addEventListener("pointermove", (e) => {
      const rect = cv.getBoundingClientRect();
      if (down) {
        const r = R();
        const dx = e.clientX - down.x, dy = e.clientY - down.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) down.moved = true;
        const nlon = down.lon - (dx / r) * (180 / Math.PI), nlat = Math.max(-80, Math.min(80, down.lat + (dy / r) * (180 / Math.PI)));
        const dtm = Math.max(1, performance.now() - (down.lt || down.t)) / 1000;
        vlon = (nlon - clon) / dtm * 0.5; vlat = (nlat - clat) / dtm * 0.5;
        down.lt = performance.now();
        clon = nlon; clat = nlat;
        lastTouch = performance.now();
        tip.hide();
        return;
      }
      hover = hit(e.clientX - rect.left, e.clientY - rect.top);
      cv.style.cursor = hover ? "pointer" : "grab";
      if (!hover) return tip.hide();
      if (hover === "home") return tip.show(`<b>${esc((snap.router && snap.router.identity) || "Router")}</b>${esc(home.label || "")}<br><span class="muted">${esc(home.source || "")}</span>`, e.clientX, e.clientY);
      const n = hover;
      const where = [n.city, n.country].filter(Boolean).join(", ") || n.cc;
      const quiet = n.gone ? Math.round((performance.now() - n.goneAt) / 1000) : 0;
      tip.show(`<b>${esc(where)}</b>${n.precision === "country" ? '<span class="muted">country-level location</span><br>' : ""}
        ${n.gone ? `<span class="muted">No traffic now · quiet for ${quiet}s · fading out (was ${fmt.bps(n.lastRate)})</span><div class="faint" style="font-size:11px">last seen talking:</div>`
          : `<span class="in">↓ ${fmt.bps(n.down)}</span> · <span class="out">↑ ${fmt.bps(n.up)}</span>`}
        ${n.peers.slice(0, 6).map((p) => `<div class="mono" style="font-size:11.5px">${esc(p.name || p.ip)} <span class="muted">${fmt.bps(p.up + p.down)}</span>${p.threat ? ' <span style="color:var(--crit)">⚠</span>' : ""}</div>`).join("")}
        ${n.peers.length > 6 ? `<span class="muted">+${n.peers.length - 6} more</span>` : ""}
        ${Types.mixHtml(n.cats)}
        ${n.threat ? `<br><span style="color:var(--crit)">⚠ ${esc(n.threat)} threat</span>` : ""}`, e.clientX, e.clientY);
    });
    const release = (e) => {
      if (!down) return;
      const clicked = !down.moved;
      down = null; dragging = false;
      if (clicked) {
        const rect = cv.getBoundingClientRect();
        const n = hit(e.clientX - rect.left, e.clientY - rect.top);
        if (n && n !== "home") { tip.hide(); openPlace(n); }
        else if (!n && Select.ip) closeDrawer();  // empty space: back to everything
      }
    };
    cv.addEventListener("pointerup", release);
    cv.addEventListener("pointercancel", release);
    cv.addEventListener("mouseleave", () => { hover = null; tip.hide(); });
    cv.addEventListener("wheel", (e) => {
      e.preventDefault();
      zoom = Math.max(0.6, Math.min(4, zoom * Math.exp(-e.deltaY * 0.0015)));
    }, { passive: false });
    cv.addEventListener("dblclick", () => goHome());
    $(".globe-ui", wrap).addEventListener("click", (e) => {
      const b = e.target.closest("[data-g]");
      if (!b) return;
      const k = b.dataset.g;
      if (k === "home") goHome();
      if (k === "spin") { spin = !spin; b.classList.toggle("on", spin); try { localStorage.setItem("mcc-globe-spin", spin ? "1" : "0"); } catch (err) { /* */ } }
      if (k === "in") zoom = Math.min(4, zoom * 1.25);
      if (k === "out") zoom = Math.max(0.6, zoom / 1.25);
    });
    $('.globe-ui [data-g="spin"]', wrap).classList.toggle("on", spin);
    function goHome() { if (home) { target = { lat: Math.max(-60, Math.min(60, home.lat * 0.6)), lon: home.lon + 25 }; zoom = 1; } }

    function openPlace(n) {
      if (n.peers.length === 1) return openHost(n.peers[0].ip);
      const where = [n.city, n.country].filter(Boolean).join(", ") || n.cc;
      openModal(`<header><div class="grow"><div class="faint" style="font-size:12px;letter-spacing:.1em;text-transform:uppercase">${n.peers.length} peers</div><h2>${esc(where)}</h2></div>
          <button class="icon-btn" data-x aria-label="Close">${ICON.x}</button></header>
        <div class="mbody">${n.precision === "country" ? '<div class="note">Country-level location: these are placed at the middle of the country.</div>' : ""}
          <table class="t"><thead><tr><th>Remote</th><th>LAN hosts</th><th class="r">↓</th><th class="r">↑</th></tr></thead><tbody>
          ${n.peers.map((p) => `<tr class="click" data-ip="${esc(p.ip)}"><td><div class="who"><b>${esc(p.name || p.ip)}</b>${p.name ? `<span>${esc(p.ip)}</span>` : ""}</div></td>
            <td class="mono" style="font-size:12px">${esc((p.hosts || []).join(", "))}</td><td class="r num in">${fmt.bps(p.down)}</td><td class="r num out">${fmt.bps(p.up)}</td></tr>`).join("")}
          </tbody></table></div>
        <footer><span class="grow"></span><button class="btn primary" data-x>Close</button></footer>`,
      (m) => {
        $$("[data-x]", m).forEach((b) => (b.onclick = closeModal));
        $$("tr[data-ip]", m).forEach((tr) => (tr.onclick = () => { closeModal(); openHost(tr.dataset.ip); }));
      });
    }

    function destroy() {
      alive = false;
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
    }
    raf = requestAnimationFrame(frame);
    // for the UI checks: how far the oldest particle has travelled (0..1) and how many there are
    const stats = () => ({ parts: parts.length, oldest: parts.reduce((m, p) => Math.max(m, p.t), 0), places: places.size,
      list: [...places.values()].map((n) => ({ key: n.key, gone: !!n.gone, alpha: n.alpha })) });
    return { update, destroy, stats };
  }
  return { create };
})();
window.Globe = Globe;
