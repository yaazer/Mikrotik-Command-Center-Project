/* Live traffic map: Internet peers (left) <-> router (centre) <-> LAN hosts (right).
   Particles flow along each link; their density follows the live rate. Download is drawn in the
   "in" colour, upload in the "out" colour. Threat subjects pulse red; blocked peers are greyed and
   their link dashed. Hover for details; click a device to single it out (just it and its traffic
   paths, with its details in the drawer). Pinned devices are always shown, at the top.
   Options: captions (left, right), singleOut (false: the page filters what it feeds the map itself),
   centerTip(router, snap) and tipExtra(node) for other uses (the VPN and LAN pages). */
"use strict";

/* Shared by the flow map and the globe: say why nothing is moving, rather than look frozen. */
function motionOffNote(ctx, x, y, colors) {
  ctx.save();
  ctx.globalAlpha = 1;
  ctx.font = "600 11.5px " + (colors.sans || getComputedStyle(document.body).fontFamily);
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  const text = "Motion is off: traffic particles paused · Theme Studio › Motion";
  const tw = ctx.measureText(text).width;
  ctx.fillStyle = colors.bg || "#000";
  ctx.globalAlpha = 0.8;
  ctx.fillRect(x - tw / 2 - 10, y - 11, tw + 20, 22);
  ctx.globalAlpha = 1;
  ctx.fillStyle = colors.muted || "#999";
  ctx.fillText(text, x, y);
  ctx.restore();
}

const TrafficMap = (() => {
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0, "": -1 };

  // cool -> hot for the heat overlay: v is how big a node's smoothed rate is (0..1, absolute scale,
  // not relative to whatever else is on screen, so a quiet network doesn't make everything glow)
  function heatColor(v) {
    v = Math.max(0, Math.min(1, v || 0));
    const light = document.documentElement.dataset.theme === "light";
    const hue = 245 - v * 215, c = 0.1 + v * 0.13;
    const l = light ? 0.52 - v * 0.08 : 0.58 + v * 0.14;
    return `oklch(${l} ${c} ${hue})`;
  }

  function create(wrap, opts) {
    opts = Object.assign({ peers: 14, hosts: 12, captions: ["INTERNET", "LAN"], singleOut: true }, opts || {});
    const cv = document.createElement("canvas");
    wrap.appendChild(cv);
    const banner = document.createElement("div");
    banner.className = "sel-banner hidden";
    wrap.appendChild(banner);
    const ctx = cv.getContext("2d");
    // Theme Studio: Motion (full / calm / off) and Rendering (Lite draws at 1x resolution)
    const motion = () => (window.Theme ? Theme.motion()
      : (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches ? "off" : "full"));
    const lite = () => !!(window.Theme && Theme.isLite());
    const nodes = new Map();
    // smoothed rate + "how long has this been busy" per candidate (kind:ip), kept for everything the
    // server reports -- not just what's currently drawn -- so a device's heat survives it scrolling
    // off the top-N and back, and so ranking for the top-N itself is based on settled numbers
    const hist = new Map();
    let lastSnap = null, lastIngestT = 0;
    let parts = [];
    let VW = 0, W = 0, H = 0, dpr = 1, colors = {}, hover = null, snap = null, raf = 0, last = 0, alive = true;
    const router = { id: "router", kind: "router", x: 0, y: 0, r: 26, alpha: 1, label: "router" };

    function readColors() {
      // (fonts too: getComputedStyle per label per frame is a style recalculation every time)
      const cs = getComputedStyle(document.documentElement);
      const g = (n) => cs.getPropertyValue(n).trim();
      colors = { in: g("--in"), out: g("--out"), crit: g("--crit"), high: g("--high"), med: g("--med"), text: g("--text"),
        muted: g("--muted"), faint: g("--faint"), line: g("--line"), soft: g("--line-soft"), panel: g("--panel-hi"),
        bg: g("--bg"), accent: g("--accent"), mono: g("--mono"), sans: getComputedStyle(document.body).fontFamily };
    }
    function resize() {
      dpr = Math.min(lite() ? 1 : 2, window.devicePixelRatio || 1);
      W = wrap.clientWidth; H = wrap.clientHeight;
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
      layout(true);
    }
    const ro = new ResizeObserver(resize);
    ro.observe(wrap);
    let onScreen = true;
    const io = new IntersectionObserver((e) => { onScreen = e[e.length - 1].isIntersecting; });
    io.observe(wrap);
    readColors();
    on("theme", () => { if (alive) { readColors(); resize(); } });
    on("select", () => { if (alive && snap) update(snap); });

    const narrow = () => W < 640;  // phones: nodes hug the edges, labels point inward
    const rate = (n) => (n.up || 0) + (n.down || 0);
    const srate = (n) => (n.sup || 0) + (n.sdown || 0);  // smoothed rate, for layout/sort stability
    const radius = (bps) => 4 + Math.min(14, Math.log10(1 + bps / 2e3) * 3.2);
    // absolute 0..1 scale for the heat colour: fixed thresholds, not "biggest thing on screen right
    // now", so the map doesn't look hot just because the network is quiet everywhere else. The top of
    // the scale sits around 30 Mb/s -- a single connection pushing a serious chunk of a home/office
    // link -- so ordinary browsing reads cool and only real downloads/streaming climb toward hot.
    const intensityOf = (bps) => Math.max(0, Math.min(1, Math.log10(1 + bps / 1500) / Math.log10(1 + 3e7 / 1500)));

    function histFor(kind, ip) {
      const key = kind + ":" + ip;
      let h = hist.get(key);
      if (!h) { h = { up: null, down: null, active: 0, idle: 0, duration: 0, lastSeen: 0 }; hist.set(key, h); }
      return h;
    }
    // runs once per real server tick (never per redraw/filter-change call): eases each candidate's
    // rate and tracks how long it's stayed above the floor, so a single noisy sample can't make a
    // link's width, particle count or on-screen rank jump, and heat reflects sustained use, not a blip.
    // "duration" is wall-clock time this map instance has watched the link stay busy -- it has no
    // server-side connection-age to draw on, so it resets on reload and starts over, never longer.
    function ingest(tr, now) {
      const dt = lastIngestT ? Math.min(5, Math.max(0.1, (now - lastIngestT) / 1000)) : 1;
      lastIngestT = now;
      const seen = new Set(), floor = 1500, a = 1 - Math.exp(-dt / 2.5);
      const step = (kind, x) => {
        const key = kind + ":" + x.ip;
        seen.add(key);
        const h = histFor(kind, x.ip);
        if (h.up == null) { h.up = x.up || 0; h.down = x.down || 0; }  // seed from the first sample, don't ramp up from 0
        else { h.up += ((x.up || 0) - h.up) * a; h.down += ((x.down || 0) - h.down) * a; }
        if (h.up + h.down > floor) { if (!h.active) h.active = now; h.idle = 0; }
        else { if (!h.idle) h.idle = now; if (now - h.idle > 5000) h.active = 0; }
        h.duration = h.active ? (now - h.active) / 1000 : 0;
        h.lastSeen = now;
      };
      tr.peers.forEach((x) => step("peer", x));
      tr.hosts.forEach((x) => step("host", x));
      for (const [key, h] of hist) if (!seen.has(key) && now - h.lastSeen > 30000) hist.delete(key);
    }

    function update(s) {
      snap = s;
      const tr = s.traffic;
      const now = performance.now();
      if (s !== lastSnap) { ingest(tr, now); lastSnap = s; }
      const seen = new Set();
      // top-N by smoothed rate, pinned first (the server already orders its lists that way; keep it
      // through the re-sort), with a margin for whatever's already shown: a newcomer has to beat the
      // weakest incumbent by >25%, not just edge past it for one noisy tick, so the map doesn't
      // shuffle its layout every second over rates that are effectively tied
      const pick = (list, kind, n) => {
        const shown = new Set();
        for (const nd of nodes.values()) if (nd.kind === kind && !nd.dead) shown.add(nd.ip);
        const scored = list.map((x) => {
          const h = histFor(kind, x.ip);
          return { x, rate: (h.up || 0) + (h.down || 0), was: shown.has(x.ip), pin: !!x.pinned || Pins.has(x.ip) };
        });
        scored.sort((a, b) => (b.pin - a.pin) || (b.rate * (b.was ? 1 : 0.8)) - (a.rate * (a.was ? 1 : 0.8)));
        const top = scored.slice(0, n).map((e) => e.x);
        const topIps = new Set(top.map((x) => x.ip));
        // anything under suspicion is always on the map, even if it's quiet
        scored.forEach((e) => { if (e.x.threat && !topIps.has(e.x.ip) && top.length < n + 2) { top.push(e.x); topIps.add(e.x.ip); } });
        return top;
      };
      const fit = Math.max(4, Math.floor((H - 90) / 30) + 1);  // two-line labels need ~30px each
      // singled out, "peers"/"hosts" are per-pair path aggregates, not the devices hist tracks totals
      // for -- so that mode eases off the raw per-tick numbers instead (still smoothed frame to frame
      // by r/lw easing, just without the multi-tick history or a meaningful "how long has this been busy")
      const rawRates = Select.ip && opts.singleOut;
      let peers, hosts, shown = null;
      if (Select.ip && opts.singleOut) {
        // singled out: only this device, on its own side, and everything it talks to on the other
        const ip = Select.ip, h = Select.data && Select.data.ip === ip ? Select.data : null;
        const lan = h ? h.lan : tr.hosts.some((x) => x.ip === ip);
        const paths = Select.paths();
        const live = (lan ? tr.hosts : tr.peers).find((x) => x.ip === ip);
        const sum = (k) => paths.reduce((a, x) => a + x[k], 0);
        const cats = {};
        paths.forEach((x) => { for (const k in x.cats) cats[k] = (cats[k] || 0) + x.cats[k]; });
        const me = Object.assign({ ip, name: (h && h.name) || "", up: sum("up"), down: sum("down"), conns: sum("conns"), cats,
          cat: Object.entries(cats).sort((a, b) => b[1] - a[1]).map((e) => e[0])[0] || "other" }, live || {});
        const n = Math.min(paths.length, Math.max(opts.peers, opts.hosts, fit));
        const others = paths.slice(0, n).map((x) => Object.assign({}, x, lan ? { hosts: [ip] } : {}));
        if (lan) { hosts = [me]; peers = others; } else { peers = [Object.assign({}, me, { hosts: paths.map((x) => x.ip) })]; hosts = others; }
        shown = n;
      } else {
        peers = pick(tr.peers, "peer", Math.min(opts.peers, fit)); hosts = pick(tr.hosts, "host", Math.min(opts.hosts, fit));
      }
      banner.innerHTML = opts.singleOut ? Select.banner(shown) : "";
      banner.classList.toggle("hidden", !Select.ip || !opts.singleOut);
      const add = (kind, x) => {
        const id = kind + ":" + x.ip;
        seen.add(id);
        let n = nodes.get(id);
        if (!n) {
          n = { id, kind, ip: x.ip, x: router.x, y: router.y, alpha: 0, r: 4, lw: 0.6, acc: { in: 0, out: 0 } };
          nodes.set(id, n);
        }
        const h = histFor(kind, x.ip);
        Object.assign(n, { label: x.name || x.ip, name: x.name, up: x.up, down: x.down, conns: x.conns, threat: x.threat || "",
          blocked: !!x.blocked, peers: x.peers, hosts: x.hosts, ports: x.ports, talpha: 1, dead: false,
          cats: x.cats || {}, cat: x.cat || "other", pinned: !!x.pinned || Pins.has(x.ip), sel: x.ip === Select.ip, idle: !!x.idle,
          sup: rawRates ? (x.up || 0) : (h.up || 0), sdown: rawRates ? (x.down || 0) : (h.down || 0),
          duration: rawRates ? 0 : h.duration });
        const sr = srate(n);
        n.tr = radius(sr);
        n.tlw = 0.6 + Math.min(4, Math.log10(1 + sr / 1e4));
        n.intensity = intensityOf(sr);
        // "how long has this been busy" -> halo size, log-scaled so it keeps differentiating minutes
        // in, not just the first half-minute
        n.glow = Math.max(0, Math.min(1, Math.log10(1 + n.duration / 30) / Math.log10(21)));
      };
      peers.forEach((p) => add("peer", p));
      hosts.forEach((h) => add("host", h));
      for (const [id, n] of nodes) if (!seen.has(id)) { n.talpha = 0; n.dead = true; }
      router.down = tr.in_bps; router.up = tr.out_bps;
      router.label = (s.router && s.router.identity) || "router";
      layout(false);
    }

    // the device drawer slides over the right of the page: lay the map out in the part still visible
    function visibleWidth() {
      const d = document.getElementById("drawer");
      if (!d || !d.classList.contains("open") || narrow()) return W;
      const r = cv.getBoundingClientRect();
      const left = window.innerWidth - d.offsetWidth;
      return r.right > left ? Math.max(Math.min(W, 420), left - r.left) : W;
    }
    function layout(snapNow) {
      VW = visibleWidth();
      router.x = VW / 2; router.y = H / 2;
      // evenly spaced columns that bow toward the router, leaving room for the labels outside
      const R = narrow() ? W / 2 - 24 : Math.max(110, Math.min(VW * 0.36, VW / 2 - 185));
      const place = (kind, side) => {
        // pinned devices at the top of their column, then the busiest -- by smoothed rate, so two
        // nodes with near-identical traffic don't keep swapping slots tick to tick (the pick() margin
        // above keeps membership itself from churning, which is what used to cause a reflow here)
        const list = [...nodes.values()].filter((n) => n.kind === kind && !n.dead)
          .sort((a, b) => (b.pinned - a.pinned) || srate(b) - srate(a));
        const n = list.length;
        const gap = n > 1 ? Math.min(48, (H - 90) / (n - 1)) : 0;
        const y0 = H / 2 - (gap * (n - 1)) / 2;
        list.forEach((node, i) => {
          node.ty = y0 + i * gap;
          const rel = (node.ty - H / 2) / (H / 2);
          node.tx = router.x + side * R * (1 - 0.3 * rel * rel);
          if (snapNow || node.alpha === 0) { node.x = node.tx; node.y = node.ty; }
        });
      };
      place("peer", -1);
      place("host", 1);
    }

    // a link's curve: from the node to the router, bowing horizontally
    function curve(n, lane) {
      const ax = n.x, ay = n.y, bx = router.x + (n.kind === "peer" ? -router.r : router.r), by = router.y;
      const cx = (ax + bx) / 2, cy = ay;
      const off = lane * 3;
      return [ax, ay + off, cx, cy + off, bx, by + off * 0.4];
    }
    function at(c, t) {
      const u = 1 - t;
      return [u * u * c[0] + 2 * u * t * c[2] + t * t * c[4], u * u * c[1] + 2 * u * t * c[3] + t * t * c[5]];
    }

    function frame(now) {
      if (!alive) return;
      if (!wrap.isConnected) { destroy(); return; }
      raf = requestAnimationFrame(frame);
      if (!onScreen) { last = 0; return; }  // scrolled out of view: draw nothing (the Traffic page has two of these)
      if (last && now - last < 15) return;  // ~60 fps cap (high-refresh screens would draw 2x for nothing)
      const dt = Math.min(0.1, last ? (now - last) / 1000 : 0.016);
      last = now;
      // ease nodes. Time constants close to the ~1s tick interval, not a fraction of it: the old
      // 1-0.002^dt covered ~95% of the distance in half a second, so everything sprinted to its new
      // target and then sat still for the rest of each tick -- a lurch-and-hold rhythm that reads as
      // stutter even though the motion itself was eased. Staying mid-motion through the whole tick looks smoother.
      const kPos = 1 - Math.exp(-dt / 0.9), kFast = 1 - Math.exp(-dt / 0.5);
      for (const [id, n] of nodes) {
        n.x += (n.tx - n.x) * kPos; n.y += (n.ty - n.y) * kPos;
        n.r += (n.tr - n.r) * kFast; n.alpha += (n.talpha - n.alpha) * kFast;
        n.lw += ((n.tlw == null ? n.lw : n.tlw) - n.lw) * kFast;
        if (n.dead && n.alpha < 0.02) nodes.delete(id);
      }
      spawn(dt);
      draw(now / 1000, dt);
    }

    function spawn(dt) {
      const m = motion();
      const density = m === "off" ? 0 : m === "calm" ? 0.45 : 1;
      for (const n of nodes.values()) {
        if (n.dead || n.blocked) continue;
        for (const dir of ["in", "out"]) {
          // smoothed, not the raw per-tick sample: otherwise particle bursts/droughts follow every
          // noisy reading instead of the underlying flow
          const bps = dir === "in" ? n.sdown : n.sup;
          if (!bps || bps < 400) continue;
          const per = Math.min(16, Math.log10(1 + bps / 1e3) * 2.4) * density;
          n.acc[dir] += per * dt;
          while (n.acc[dir] >= 1) {
            n.acc[dir] -= 1;
            // toward the router for peer downloads and host uploads; away from it otherwise
            const toward = (n.kind === "peer") === (dir === "in");
            parts.push({ n, dir, toward, t: 0, v: 0.38 + Math.random() * 0.22, s: 1.3 + Math.min(2.2, Math.log10(1 + bps / 1e5)),
              cat: Types.pick(n.cats) });
          }
        }
      }
      for (const p of parts) p.t += p.v * dt;
      parts = parts.filter((p) => p.t < 1 && nodes.has(p.n.id) && !p.n.blocked);
      if (parts.length > 2500) parts.splice(0, parts.length - 2500);
    }

    // a type is focused (legend click): everything that doesn't carry it steps back
    const focusOK = (n) => !Types.focus || Types.by !== "type" || !!(n.cats && n.cats[Types.focus]);
    const byType = () => Types.by === "type";

    function related(n) {
      if (!hover || hover === router) return true;
      if (n === hover) return true;
      if (hover.kind === "peer" && n.kind === "host") return (hover.hosts || []).includes(n.ip);
      if (hover.kind === "host" && n.kind === "peer") return (n.hosts || []).includes(hover.ip);
      return false;
    }

    function draw(t) {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      // zone captions
      ctx.font = "600 10.5px " + colors.mono;
      ctx.fillStyle = colors.faint;
      ctx.textAlign = "left";
      ctx.fillText(opts.captions[0], 14, 20);
      ctx.textAlign = "right";
      ctx.fillText(opts.captions[1], (VW || W) - 14, 20);
      // faint dot grid
      ctx.fillStyle = colors.soft;
      for (let x = 20; x < W; x += 28) for (let y = 34; y < H; y += 28) ctx.fillRect(x, y, 1, 1);

      // links
      const heatOn = Types.by === "heat";
      for (const n of nodes.values()) {
        const rel = related(n);
        const c = curve(n, 0);
        const w = n.lw;
        const baseAlpha = n.alpha * (rel && focusOK(n) ? (hover && hover !== router ? 0.75 : byType() ? 0.42 : 0.32) : 0.08);
        if (heatOn && !lite() && !n.blocked && n.glow > 0.04) {
          // a soft halo under the line, not a per-frame shadowBlur: its width/opacity track how long
          // this link has stayed busy (duration), so a flow that's been steady for a while visibly
          // glows while a brief spike -- same instantaneous colour -- doesn't
          ctx.globalAlpha = baseAlpha * n.glow * 0.5;
          ctx.strokeStyle = heatColor(n.intensity);
          ctx.lineWidth = w + 2 + n.glow * 9;
          ctx.setLineDash([]);
          ctx.beginPath(); ctx.moveTo(c[0], c[1]); ctx.quadraticCurveTo(c[2], c[3], c[4], c[5]); ctx.stroke();
        }
        ctx.globalAlpha = baseAlpha;
        ctx.strokeStyle = n.threat ? colors.crit : n.blocked ? colors.faint
          : heatOn ? heatColor(n.intensity) : byType() ? Types.color(n.cat) : colors.line;
        ctx.lineWidth = w;
        ctx.setLineDash(n.blocked ? [4, 5] : []);
        ctx.beginPath(); ctx.moveTo(c[0], c[1]); ctx.quadraticCurveTo(c[2], c[3], c[4], c[5]); ctx.stroke();
      }
      ctx.setLineDash([]);

      // particles
      ctx.globalCompositeOperation = document.documentElement.dataset.theme === "light" ? "source-over" : "lighter";
      for (const p of parts) {
        const n = p.n;
        const c = curve(n, p.dir === "in" ? -1 : 1);
        const tt = p.toward ? p.t : 1 - p.t;
        const [x, y] = at(c, tt);
        const fade = Math.min(1, p.t * 6, (1 - p.t) * 6);
        const on = related(n) && (!Types.focus || !byType() || p.cat === Types.focus);
        ctx.globalAlpha = n.alpha * fade * (on ? 0.95 : 0.1);
        ctx.fillStyle = byType() ? Types.color(p.cat)
          : n.threat && p.dir === "out" && n.kind === "host" ? colors.crit : p.dir === "in" ? colors.in : colors.out;
        ctx.beginPath(); ctx.arc(x, y, p.s, 0, Math.PI * 2); ctx.fill();
      }
      ctx.globalCompositeOperation = "source-over";

      // nodes
      for (const n of nodes.values()) {
        const rel = related(n) && focusOK(n);
        ctx.globalAlpha = n.alpha * (rel ? 1 : 0.3);
        const col = n.threat ? (n.threat === "critical" || n.threat === "high" ? colors.crit : colors.med)
          : n.blocked ? colors.faint : byType() ? Types.color(n.cat)
          : heatOn ? heatColor(n.intensity) : n.kind === "peer" ? colors.in : colors.accent;
        if (heatOn && !lite() && !n.blocked && n.glow > 0.04) {
          ctx.strokeStyle = heatColor(n.intensity);
          ctx.globalAlpha = n.alpha * n.glow * 0.5;
          ctx.lineWidth = 3 + n.glow * 6;
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 4 + n.glow * 5, 0, Math.PI * 2); ctx.stroke();
          ctx.globalAlpha = n.alpha * (rel ? 1 : 0.3);
        }
        if (n.threat && motion() !== "off") {
          const ph = (t * 1.2) % 1;
          ctx.strokeStyle = colors.crit;
          ctx.globalAlpha = n.alpha * (1 - ph) * 0.8;
          ctx.lineWidth = 2;
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 3 + ph * 16, 0, Math.PI * 2); ctx.stroke();
          ctx.globalAlpha = n.alpha * (rel ? 1 : 0.3);
        }
        if (n.sel) {  // the singled-out device
          ctx.strokeStyle = colors.accent;
          ctx.lineWidth = 2;
          ctx.globalAlpha = n.alpha * (0.55 + 0.35 * Math.sin(t * 3));
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 7, 0, Math.PI * 2); ctx.stroke();
          ctx.globalAlpha = n.alpha * (rel ? 1 : 0.3);
        }
        ctx.fillStyle = colors.panel;
        ctx.strokeStyle = col;
        ctx.lineWidth = n === hover || n.sel ? 3 : 1.8;
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
        if (n.blocked) {
          ctx.beginPath(); ctx.moveTo(n.x - n.r * 0.6, n.y - n.r * 0.6); ctx.lineTo(n.x + n.r * 0.6, n.y + n.r * 0.6); ctx.stroke();
        } else {
          ctx.fillStyle = col;
          ctx.globalAlpha *= 0.35;
          ctx.beginPath(); ctx.arc(n.x, n.y, Math.max(1.5, n.r - 3), 0, Math.PI * 2); ctx.fill();
          ctx.globalAlpha = n.alpha * (rel ? 1 : 0.3);
        }
        // label
        const left = (n.kind === "peer") !== narrow();
        let lx = n.x + (left ? -(n.r + 7) : n.r + 7);
        if (n.pinned) { pinGlyph(left ? lx - 5 : lx + 5, n.y - 5); lx += left ? -14 : 14; }
        ctx.textAlign = left ? "right" : "left";
        ctx.textBaseline = "alphabetic";
        ctx.font = "600 12px " + colors.sans;
        ctx.fillStyle = n.threat ? colors.crit : colors.text;
        const max = narrow() ? 13 : 26;
        const lbl = n.label.length > max ? n.label.slice(0, max - 1) + "…" : n.label;
        ctx.fillText(lbl, lx, n.y - 1);
        ctx.font = "11px " + colors.mono;
        ctx.fillStyle = colors.muted;
        ctx.fillText(n.idle ? "pinned · idle" : narrow() ? fmt.bps(rate(n)) : `↓${fmt.bps(n.down)} ↑${fmt.bps(n.up)}`, lx, n.y + 12);
      }
      ctx.globalAlpha = 1;

      // router
      const rr = router.r;
      ctx.fillStyle = colors.panel;
      ctx.strokeStyle = colors.accent;
      ctx.lineWidth = 2;
      const rx = router.x - rr, ry = router.y - rr;
      ctx.beginPath();
      if (ctx.roundRect) ctx.roundRect(rx, ry, rr * 2, rr * 2, 10); else ctx.rect(rx, ry, rr * 2, rr * 2);
      ctx.fill(); ctx.stroke();
      ctx.fillStyle = colors.accent;
      for (let i = 0; i < 4; i++) ctx.fillRect(router.x - 13 + i * 8, router.y + 6, 5, 4);
      ctx.strokeStyle = colors.accent;
      ctx.lineWidth = 1.8;
      ctx.beginPath(); ctx.moveTo(router.x - 10, router.y - 2); ctx.lineTo(router.x - 3, router.y - 10); ctx.lineTo(router.x + 3, router.y - 4); ctx.lineTo(router.x + 10, router.y - 12); ctx.stroke();
      ctx.textAlign = "center";
      ctx.font = "600 12px " + colors.sans;
      ctx.fillStyle = colors.text;
      ctx.fillText(router.label, router.x, router.y + rr + 16);
      ctx.font = "11px " + colors.mono;
      ctx.fillStyle = colors.in;
      const sep = narrow() ? 0 : 44, dy = narrow() ? 13 : 0;
      ctx.fillText("↓ " + fmt.bps(router.down || 0), router.x - sep, router.y + rr + 31);
      ctx.fillStyle = colors.out;
      ctx.fillText("↑ " + fmt.bps(router.up || 0), router.x + sep, router.y + rr + 31 + dy);
      if (motion() === "off") motionOffNote(ctx, W / 2, H - 14, colors);
    }

    // a small map pin: head and needle, in the accent colour
    function pinGlyph(x, y) {
      ctx.save();
      ctx.fillStyle = colors.accent; ctx.strokeStyle = colors.accent; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(x, y - 1.5, 3.4, 0, Math.PI * 2); ctx.fill();
      ctx.beginPath(); ctx.moveTo(x, y + 1.5); ctx.lineTo(x, y + 7); ctx.stroke();
      ctx.restore();
    }

    function hit(x, y) {
      if (Math.abs(x - router.x) < router.r && Math.abs(y - router.y) < router.r) return router;
      let best = null, bd = 1e9;
      for (const n of nodes.values()) {
        if (n.dead) continue;
        const d = Math.hypot(n.x - x, n.y - y);
        if (d < n.r + 8 && d < bd) { best = n; bd = d; }
      }
      return best;
    }
    cv.addEventListener("mousemove", (e) => {
      const r = cv.getBoundingClientRect();
      hover = hit(e.clientX - r.left, e.clientY - r.top);
      cv.style.cursor = hover && hover !== router ? "pointer" : "default";
      if (!hover) return tip.hide();
      if (hover === router) {
        if (opts.centerTip) return tip.show(opts.centerTip(router, snap), e.clientX, e.clientY);
        return tip.show(`<b>${esc(router.label)}</b>Internet ↓ ${fmt.bps(router.down)} · ↑ ${fmt.bps(router.up)}<br><span class="muted">${snap ? snap.traffic.conns : 0} connections · source: ${snap ? snap.traffic.source : "—"}</span>`, e.clientX, e.clientY);
      }
      const n = hover;
      const extra = opts.tipExtra ? opts.tipExtra(n) : n.kind === "peer"
        ? `talking to ${(n.hosts || []).length} LAN host${(n.hosts || []).length === 1 ? "" : "s"}${n.ports && n.ports.length ? " · ports " + n.ports.join(", ") : ""}`
        : `${n.peers || 0} Internet peer${n.peers === 1 ? "" : "s"} · ${n.conns || 0} conns`;
      tip.show(`<b>${esc(n.label)}</b>${n.name ? `<span class="mono muted">${esc(n.ip)}</span><br>` : ""}<span class="in">↓ ${fmt.bps(n.down)}</span> · <span class="out">↑ ${fmt.bps(n.up)}</span><br><span class="muted">${esc(extra)}</span>` +
        (n.duration > 4 ? `<br><span class="muted">busy ${fmt.dur(n.duration)} this session</span>` : "") +
        Types.mixHtml(n.cats) +
        (n.threat ? `<br><span style="color:var(--crit)">⚠ ${esc(n.threat)} threat</span>` : "") + (n.blocked ? '<br><span class="muted">blocked by MCC</span>' : "") +
        (n.pinned ? '<br><span class="muted">pinned</span>' : "") + `<br><span class="faint">${!opts.singleOut ? "click for details" : n.sel ? "singled out" : "click to single it out"}</span>`, e.clientX, e.clientY);
    });
    cv.addEventListener("mouseleave", () => { hover = null; tip.hide(); });
    cv.addEventListener("click", () => {
      tip.hide();
      if (hover && hover !== router) openHost(hover.ip);  // single it out
      else if (Select.ip) closeDrawer();                 // the router or empty space: back to everything
    });

    function destroy() {
      alive = false;
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
    }
    raf = requestAnimationFrame(frame);
    // for the UI checks: where each device is drawn, and what is pinned / singled out
    const stats = () => ({ parts: parts.length, nodes: [...nodes.values()].filter((n) => !n.dead)
      .map((n) => ({ ip: n.ip, kind: n.kind, x: n.x, y: n.y, sel: !!n.sel, pinned: !!n.pinned,
        intensity: n.intensity || 0, busyFor: n.duration || 0 })) });
    return { update, destroy, stats };
  }
  return { create, SEV_RANK };
})();
window.TrafficMap = TrafficMap;
