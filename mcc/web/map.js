/* Live traffic map: Internet peers (left) <-> router (centre) <-> LAN hosts (right).
   Particles flow along each link; their density follows the live rate. Download is drawn in the
   "in" colour, upload in the "out" colour. Threat subjects pulse red; blocked peers are greyed and
   their link dashed. Hover for details, click to open the host. */
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

  function create(wrap, opts) {
    opts = Object.assign({ peers: 14, hosts: 12 }, opts || {});
    const cv = document.createElement("canvas");
    wrap.appendChild(cv);
    const ctx = cv.getContext("2d");
    // Theme Studio: Motion (full / calm / off) and Rendering (Lite draws at 1x resolution)
    const motion = () => (window.Theme ? Theme.motion()
      : (window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches ? "off" : "full"));
    const lite = () => !!(window.Theme && Theme.isLite());
    const nodes = new Map();
    let parts = [];
    let W = 0, H = 0, dpr = 1, colors = {}, hover = null, snap = null, raf = 0, last = 0, alive = true;
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
    readColors();
    on("theme", () => { if (alive) { readColors(); resize(); } });

    const narrow = () => W < 640;  // phones: nodes hug the edges, labels point inward
    const rate = (n) => (n.up || 0) + (n.down || 0);
    const radius = (bps) => 4 + Math.min(14, Math.log10(1 + bps / 2e3) * 3.2);

    function update(s) {
      snap = s;
      const tr = s.traffic;
      const seen = new Set();
      const pick = (list, n) => {
        const top = list.slice(0, n);
        // anything under suspicion is always on the map, even if it's quiet
        list.slice(n).forEach((x) => { if (x.threat && top.length < n + 2) top.push(x); });
        return top;
      };
      const fit = Math.max(4, Math.floor((H - 90) / 30) + 1);  // two-line labels need ~30px each
      const peers = pick(tr.peers, Math.min(opts.peers, fit)), hosts = pick(tr.hosts, Math.min(opts.hosts, fit));
      const add = (kind, x) => {
        const id = kind + ":" + x.ip;
        seen.add(id);
        let n = nodes.get(id);
        if (!n) {
          n = { id, kind, ip: x.ip, x: router.x, y: router.y, alpha: 0, r: 4, acc: { in: 0, out: 0 } };
          nodes.set(id, n);
        }
        Object.assign(n, { label: x.name || x.ip, name: x.name, up: x.up, down: x.down, conns: x.conns, threat: x.threat || "",
          blocked: !!x.blocked, peers: x.peers, hosts: x.hosts, ports: x.ports, talpha: 1, dead: false,
          cats: x.cats || {}, cat: x.cat || "other" });
        n.tr = radius(rate(n));
      };
      peers.forEach((p) => add("peer", p));
      hosts.forEach((h) => add("host", h));
      for (const [id, n] of nodes) if (!seen.has(id)) { n.talpha = 0; n.dead = true; }
      router.down = tr.in_bps; router.up = tr.out_bps;
      router.label = (s.router && s.router.identity) || "router";
      layout(false);
    }

    function layout(snapNow) {
      router.x = W / 2; router.y = H / 2;
      // evenly spaced columns that bow toward the router, leaving room for the labels outside
      const R = narrow() ? W / 2 - 24 : Math.max(110, Math.min(W * 0.36, W / 2 - 185));
      const place = (kind, side) => {
        const list = [...nodes.values()].filter((n) => n.kind === kind && !n.dead).sort((a, b) => rate(b) - rate(a));
        const n = list.length;
        const gap = n > 1 ? Math.min(48, (H - 90) / (n - 1)) : 0;
        const y0 = H / 2 - (gap * (n - 1)) / 2;
        list.forEach((node, i) => {
          node.ty = y0 + i * gap;
          const rel = (node.ty - H / 2) / (H / 2);
          node.tx = W / 2 + side * R * (1 - 0.3 * rel * rel);
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
      if (last && now - last < 15) return;  // ~60 fps cap (high-refresh screens would draw 2x for nothing)
      const dt = Math.min(0.1, last ? (now - last) / 1000 : 0.016);
      last = now;
      // ease nodes
      const k = 1 - Math.pow(0.002, dt);
      for (const [id, n] of nodes) {
        n.x += (n.tx - n.x) * k; n.y += (n.ty - n.y) * k;
        n.r += (n.tr - n.r) * k; n.alpha += (n.talpha - n.alpha) * k;
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
          const bps = dir === "in" ? n.down : n.up;
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
      ctx.fillText("INTERNET", 14, 20);
      ctx.textAlign = "right";
      ctx.fillText("LAN", W - 14, 20);
      // faint dot grid
      ctx.fillStyle = colors.soft;
      for (let x = 20; x < W; x += 28) for (let y = 34; y < H; y += 28) ctx.fillRect(x, y, 1, 1);

      // links
      for (const n of nodes.values()) {
        const rel = related(n);
        const c = curve(n, 0);
        const w = 0.6 + Math.min(4, Math.log10(1 + rate(n) / 1e4));
        ctx.globalAlpha = n.alpha * (rel && focusOK(n) ? (hover && hover !== router ? 0.75 : byType() ? 0.42 : 0.32) : 0.08);
        ctx.strokeStyle = n.threat ? colors.crit : n.blocked ? colors.faint : byType() ? Types.color(n.cat) : colors.line;
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
          : n.blocked ? colors.faint : byType() ? Types.color(n.cat) : n.kind === "peer" ? colors.in : colors.accent;
        if (n.threat && motion() !== "off") {
          const ph = (t * 1.2) % 1;
          ctx.strokeStyle = colors.crit;
          ctx.globalAlpha = n.alpha * (1 - ph) * 0.8;
          ctx.lineWidth = 2;
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 3 + ph * 16, 0, Math.PI * 2); ctx.stroke();
          ctx.globalAlpha = n.alpha * (rel ? 1 : 0.3);
        }
        ctx.fillStyle = colors.panel;
        ctx.strokeStyle = col;
        ctx.lineWidth = n === hover ? 3 : 1.8;
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
        const lx = n.x + (left ? -(n.r + 7) : n.r + 7);
        ctx.textAlign = left ? "right" : "left";
        ctx.textBaseline = "alphabetic";
        ctx.font = "600 12px " + colors.sans;
        ctx.fillStyle = n.threat ? colors.crit : colors.text;
        const max = narrow() ? 13 : 26;
        const lbl = n.label.length > max ? n.label.slice(0, max - 1) + "…" : n.label;
        ctx.fillText(lbl, lx, n.y - 1);
        ctx.font = "11px " + colors.mono;
        ctx.fillStyle = colors.muted;
        ctx.fillText(narrow() ? fmt.bps(rate(n)) : `↓${fmt.bps(n.down)} ↑${fmt.bps(n.up)}`, lx, n.y + 12);
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
        return tip.show(`<b>${esc(router.label)}</b>Internet ↓ ${fmt.bps(router.down)} · ↑ ${fmt.bps(router.up)}<br><span class="muted">${snap ? snap.traffic.conns : 0} connections · source: ${snap ? snap.traffic.source : "—"}</span>`, e.clientX, e.clientY);
      }
      const n = hover;
      const extra = n.kind === "peer"
        ? `talking to ${(n.hosts || []).length} LAN host${(n.hosts || []).length === 1 ? "" : "s"}${n.ports && n.ports.length ? " · ports " + n.ports.join(", ") : ""}`
        : `${n.peers || 0} Internet peer${n.peers === 1 ? "" : "s"} · ${n.conns || 0} conns`;
      tip.show(`<b>${esc(n.label)}</b>${n.name ? `<span class="mono muted">${esc(n.ip)}</span><br>` : ""}<span class="in">↓ ${fmt.bps(n.down)}</span> · <span class="out">↑ ${fmt.bps(n.up)}</span><br><span class="muted">${esc(extra)}</span>` +
        Types.mixHtml(n.cats) +
        (n.threat ? `<br><span style="color:var(--crit)">⚠ ${esc(n.threat)} threat</span>` : "") + (n.blocked ? '<br><span class="muted">blocked by MCC</span>' : ""), e.clientX, e.clientY);
    });
    cv.addEventListener("mouseleave", () => { hover = null; tip.hide(); });
    cv.addEventListener("click", () => { if (hover && hover !== router) { tip.hide(); openHost(hover.ip); } });

    function destroy() {
      alive = false;
      cancelAnimationFrame(raf);
      ro.disconnect();
    }
    raf = requestAnimationFrame(frame);
    return { update, destroy };
  }
  return { create, SEV_RANK };
})();
window.TrafficMap = TrafficMap;
