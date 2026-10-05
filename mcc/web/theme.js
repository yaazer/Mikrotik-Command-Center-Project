/* Theme Studio -- ported from the VCF Automation Import tool's fx.js.
 *
 *   Theme engine   palettes generated live in OKLCH from a few hues, so any preset or hue shift
 *                  stays legible. Severity colours (critical / high / medium / low / ok) keep their
 *                  meaning in every theme; download/upload take the theme's two main hues.
 *   Ambience       a slow aurora behind the panels. Reactive: it tints with the threat level --
 *                  hazard red under attack, amber when elevated.
 *   Motion         Full / Calm / Off. Calm thins the map and globe particles and slows the globe;
 *                  Off stops particles, spin and pulses (the data is still drawn).
 *   Rendering      Full / Lite / Auto. Lite drops the aurora, frosted glass and glow -- for a VM
 *                  or remote desktop without GPU acceleration. Auto detects that.
 *   Density        Comfortable / Compact.
 * Prefs are per browser (localStorage). Everything fails soft: the console works without it. */
"use strict";

const Theme = (() => {
  const THEMES = [
    { id: "noc", label: "NOC", tag: "cyan and amber on deep navy", mode: "dark", h1: 215, h2: 70, h3: 300, hb: 255, c: 1 },
    { id: "aurora", label: "Aurora", tag: "teal and violet on deep ink", mode: "dark", h1: 190, h2: 285, h3: 155, hb: 255, c: 1 },
    { id: "nebula", label: "Nebula", tag: "magenta and indigo", mode: "dark", h1: 335, h2: 280, h3: 215, hb: 292, c: 1.05 },
    { id: "solar", label: "Solar Flare", tag: "amber and coral", mode: "dark", h1: 68, h2: 28, h3: 345, hb: 38, c: 1 },
    { id: "phosphor", label: "Phosphor", tag: "terminal green", mode: "dark", h1: 148, h2: 170, h3: 125, hb: 165, c: 0.95 },
    { id: "graphite", label: "Graphite", tag: "quiet monochrome", mode: "dark", h1: 250, h2: 250, h3: 250, hb: 250, c: 0.16 },
    { id: "glacier", label: "Glacier", tag: "ice blue, light", mode: "light", h1: 238, h2: 200, h3: 285, hb: 235, c: 1 },
    { id: "daylight", label: "Daylight", tag: "warm paper, light", mode: "light", h1: 268, h2: 22, h3: 172, hb: 75, c: 0.9 },
  ];
  const KEY = "mcc-fx";
  const DEFAULTS = { theme: "noc", shift: 0, glow: 100, motion: null, reactive: true, density: "comfortable", quality: "auto" };
  const P = Object.assign({}, DEFAULTS, read());
  const osReduce = () => !!(window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches);
  if (!P.motion) P.motion = osReduce() ? "calm" : "full";
  if (!THEMES.some((t) => t.id === P.theme)) P.theme = "noc";

  function read() {
    try {
      const p = JSON.parse(localStorage.getItem(KEY) || "null");
      if (p) return p;
      if (localStorage.getItem("mcc-theme") === "light") return { theme: "glacier" };  // the old light/dark toggle
    } catch (e) { /* private mode */ }
    return {};
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(P)); } catch (e) { /* private mode */ } }
  const theme = () => THEMES.find((t) => t.id === P.theme) || THEMES[0];
  const wrap = (h) => ((h % 360) + 360) % 360;
  const ok = (l, c, h, a) => "oklch(" + l + " " + (+c).toFixed(3) + " " + wrap(h).toFixed(1) + (a === undefined ? "" : " / " + a) + ")";
  const H = { h1: 215, h2: 70, h3: 300, hb: 255, mode: "dark" };

  function palette(t) {
    const s = +P.shift || 0, c = t.c, g = P.glow / 100;
    const h1 = t.h1 + s, h2 = t.h2 + s, h3 = t.h3 + s, hb = t.hb + s * 0.6;
    Object.assign(H, { h1, h2, h3, hb, mode: t.mode });
    const v = { "--h1": wrap(h1).toFixed(1), "--h2": wrap(h2).toFixed(1), "--hb": wrap(hb).toFixed(1), "--glowk": g.toFixed(2) };
    if (t.mode === "dark") {
      const ac = Math.max(0.03, 0.13 * c);
      Object.assign(v, {
        "--bg": ok(0.155, 0.02 * c, hb), "--bg2": ok(0.185, 0.024 * c, hb),
        "--panel": ok(0.205, 0.026 * c, hb, 0.92), "--panel-hi": ok(0.24, 0.03 * c, hb),
        "--line": ok(0.31, 0.03 * c, hb), "--line-soft": ok(0.27, 0.025 * c, hb),
        "--text": ok(0.94, 0.01, hb), "--muted": ok(0.7, 0.02 * c, hb), "--faint": ok(0.55, 0.02 * c, hb),
        "--accent": ok(t.id === "graphite" ? 0.88 : 0.8, ac, h1),
        "--in": ok(0.8, Math.max(0.06, 0.13 * c), h1), "--out": ok(0.8, Math.max(0.07, 0.15 * c), t.id === "graphite" ? 70 : h2),
        "--ok": ok(0.78, 0.16, 150), "--crit": ok(0.66, 0.23, 25), "--high": ok(0.73, 0.18, 48), "--med": ok(0.84, 0.15, 90),
        "--low": ok(0.76, 0.11, 240), "--info": ok(0.7, 0.03, hb),
        "--glow": "0 0 0 1px " + ok(0.8, 0.13 * c, h1, (0.1 * g).toFixed(3)) + ", 0 8px 30px " + ok(0.05, 0.02, hb, 0.55),
        "--amb-a": ok(0.3, 0.07 * c, h1, (0.25 * g).toFixed(3)), "--amb-b": ok(0.3, 0.07 * c, h2, (0.15 * g).toFixed(3)),
        "--mark-glow": "0 0 18px " + ok(0.8, 0.13 * c, h1, (0.35 * g).toFixed(3)),
        "--globe-ocean-a": ok(0.3, 0.05 * Math.max(c, 0.3), hb), "--globe-ocean-b": ok(0.15, 0.03 * Math.max(c, 0.3), hb),
        "--globe-land": ok(0.8, 0.08 * Math.max(c, 0.3), h1),
      });
    } else {
      const ac = Math.max(0.04, 0.14 * c);
      Object.assign(v, {
        "--bg": ok(0.965, 0.008 * c, hb), "--bg2": ok(0.94, 0.01 * c, hb),
        "--panel": ok(0.995, 0.003, hb, 0.95), "--panel-hi": ok(0.97, 0.008 * c, hb),
        "--line": ok(0.86, 0.014 * c, hb), "--line-soft": ok(0.91, 0.012 * c, hb),
        "--text": ok(0.22, 0.02, hb), "--muted": ok(0.45, 0.02 * c, hb), "--faint": ok(0.6, 0.02 * c, hb),
        "--accent": ok(0.55, ac, h1),
        "--in": ok(0.58, Math.max(0.06, 0.14 * c), h1), "--out": ok(0.62, Math.max(0.07, 0.16 * c), h2),
        "--ok": ok(0.58, 0.15, 150), "--crit": ok(0.56, 0.22, 25), "--high": ok(0.62, 0.18, 45), "--med": ok(0.7, 0.15, 85),
        "--low": ok(0.56, 0.12, 245), "--info": ok(0.55, 0.02, hb),
        "--glow": "0 1px 2px " + ok(0.3, 0.02, hb, 0.08) + ", 0 6px 20px " + ok(0.3, 0.02, hb, 0.08),
        "--amb-a": ok(0.85, 0.06 * c, h1, (0.35 * g).toFixed(3)), "--amb-b": ok(0.88, 0.05 * c, h2, (0.25 * g).toFixed(3)),
        "--mark-glow": "0 0 14px " + ok(0.6, 0.12 * c, h1, (0.25 * g).toFixed(3)),
        "--globe-ocean-a": ok(0.97, 0.02 * Math.max(c, 0.3), h1), "--globe-ocean-b": ok(0.88, 0.03 * Math.max(c, 0.3), hb),
        "--globe-land": ok(0.55, 0.06 * Math.max(c, 0.3), h1),
      });
    }
    return v;
  }

  /* ------------------------------------------------------------ rendering quality */
  /* Frosted glass and full-screen effects are nearly free on a GPU and very expensive in software
   * compositing (a VM or RDP session without GPU acceleration). Auto picks Lite when the browser
   * has no hardware acceleration, or when frames are measured to be slow. */
  const RQ = { soft: false, why: "", checked: false };
  try { Object.assign(RQ, JSON.parse(sessionStorage.getItem("mcc-rq") || "{}")); } catch (e) { /* none */ }
  function detectRendering() {
    if (RQ.checked) return;
    let soft = false, why = "";
    try {
      const c = document.createElement("canvas");
      const gl = c.getContext("webgl", { failIfMajorPerformanceCaveat: true }) || c.getContext("experimental-webgl", { failIfMajorPerformanceCaveat: true });
      if (!gl) { soft = true; why = "no hardware acceleration"; }
      else {
        const ext = gl.getExtension("WEBGL_debug_renderer_info");
        why = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "") : "";
        if (/swiftshader|llvmpipe|softpipe|software|basic render|\bwarp\b/i.test(why)) soft = true;
        const lose = gl.getExtension("WEBGL_lose_context");
        if (lose) lose.loseContext();
      }
    } catch (e) { soft = false; why = ""; }
    Object.assign(RQ, { soft, why: soft ? (why || "software rendering") : why, checked: true });
    try { sessionStorage.setItem("mcc-rq", JSON.stringify(RQ)); } catch (e) { /* private mode */ }
  }
  const quality = () => (P.quality === "full" || P.quality === "lite" ? P.quality : (RQ.soft ? "lite" : "full"));
  const isLite = () => quality() === "lite";
  const motion = () => P.motion || "full";
  // a second opinion for Auto: frames well above 16 ms twice in a row -> Lite for the session
  const FW = { strikes: 0, running: false };
  function frameWatch() {
    if (P.quality !== "auto" || isLite() || motion() === "off" || FW.running || document.hidden) return;
    FW.running = true;
    const gaps = [];
    let last = 0;
    const t0 = performance.now();
    const step = (t) => {
      if (last) gaps.push(t - last);
      last = t;
      if (t - t0 < 900) { requestAnimationFrame(step); return; }
      FW.running = false;
      if (gaps.length < 5) return;
      gaps.sort((a, b) => a - b);
      const med = gaps[Math.floor(gaps.length / 2)];
      FW.strikes = med > 45 ? FW.strikes + 1 : 0;
      if (FW.strikes >= 2) {
        Object.assign(RQ, { soft: true, why: "slow frames (" + Math.round(med) + " ms each)", checked: true });
        try { sessionStorage.setItem("mcc-rq", JSON.stringify(RQ)); } catch (e) { /* */ }
        apply();
        if (typeof toast === "function") toast("Switched to Lite rendering", "This machine draws the console slowly (no GPU acceleration). Theme Studio › Rendering changes it.", { ms: 8000 });
      }
    };
    requestAnimationFrame(step);
  }

  /* ------------------------------------------------------------------ apply */
  function apply() {
    const t = theme();
    const root = document.documentElement;
    const vars = palette(t);
    for (const k in vars) root.style.setProperty(k, vars[k]);
    root.style.colorScheme = t.mode;
    root.dataset.theme = t.mode;
    if (document.body) {
      document.body.dataset.motion = motion();
      document.body.dataset.density = P.density === "compact" ? "compact" : "comfortable";
      document.body.dataset.fx = quality();
    }
    mood();
    if (typeof emit === "function") emit("theme");
    kick();
  }

  /* ------------------------------------------------------------ ambience */
  const M = { level: "calm", hue: null, strength: 0 };
  function onLevel(level) {
    if (level === M.level) return;
    M.level = level;
    mood();
  }
  function mood() {
    let hue = H.h1, strength = 0;
    if (P.reactive) {
      if (M.level === "critical") { hue = 25; strength = 0.95; }
      else if (M.level === "high") { hue = 30; strength = 0.7; }
      else if (M.level === "elevated") { hue = 80; strength = 0.5; }
      else if (M.level === "watch") { hue = 240; strength = 0.25; }
    }
    M.hue = hue; M.strength = strength;
  }
  const AU = { canvas: null, ctx: null, w: 0, h: 0, timer: 0, queued: false };
  const BLOBS = [
    { hk: "h1", ax: 0.22, ay: 0.18, r: 0.55, sx: 0.045, sy: 0.06, ph: 0 },
    { hk: "h2", ax: 0.78, ay: 0.26, r: 0.5, sx: 0.035, sy: 0.05, ph: 2.1 },
    { hk: "h3", ax: 0.58, ay: 0.82, r: 0.58, sx: 0.05, sy: 0.04, ph: 4.2 },
    { hk: "mood", ax: 0.12, ay: 0.78, r: 0.46, sx: 0.06, sy: 0.045, ph: 1.3 },
  ];
  function sizeAurora() {
    if (!AU.canvas) return;
    // drawn small and scaled up: the blur is free and the cost is tiny
    AU.w = AU.canvas.width = Math.max(64, Math.round((innerWidth * 1.2) / 6));
    AU.h = AU.canvas.height = Math.max(48, Math.round((innerHeight * 1.2) / 6));
  }
  function drawAurora(t) {
    const { ctx, w, h } = AU;
    if (!ctx) return;
    const dark = H.mode === "dark";
    const time = (t / 1000) * (motion() === "calm" ? 0.35 : 1) * (M.strength > 0.6 ? 1.8 : 1);
    ctx.clearRect(0, 0, w, h);
    ctx.globalCompositeOperation = dark ? "lighter" : "source-over";
    for (const b of BLOBS) {
      const hue = b.hk === "mood" ? (M.strength > 0 ? M.hue : H.h2) : H[b.hk];
      const x = (b.ax + Math.sin(time * b.sx * 6 + b.ph) * 0.12) * w;
      const y = (b.ay + Math.cos(time * b.sy * 6 + b.ph * 1.3) * 0.1) * h;
      const r = b.r * Math.max(w, h) * (b.hk === "mood" ? 0.6 + M.strength * 0.6 : 1);
      const a = b.hk === "mood" ? (dark ? 0.25 + M.strength * 0.55 : 0.12 + M.strength * 0.22) : (dark ? 0.5 : 0.38);
      const g = ctx.createRadialGradient(x, y, 0, x, y, r);
      g.addColorStop(0, ok(dark ? 0.62 : 0.84, dark ? 0.2 * Math.max(theme().c, 0.25) : 0.12, hue, a));
      g.addColorStop(1, ok(dark ? 0.62 : 0.84, dark ? 0.2 : 0.12, hue, 0));
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, w, h);
    }
    ctx.globalCompositeOperation = "source-over";
  }
  function loop(t) {
    AU.queued = false;
    if (!AU.ctx || isLite() || document.hidden || P.glow === 0) return;
    drawAurora(t);
    // Off: one still frame. Otherwise a gentle ~20 fps is plenty for something this slow.
    if (motion() !== "off") AU.timer = setTimeout(() => { AU.timer = 0; kick(); }, 50);
  }
  function kick() {
    if (AU.timer) { clearTimeout(AU.timer); AU.timer = 0; }
    if (AU.ctx && !AU.queued) { AU.queued = true; requestAnimationFrame(loop); }
  }

  /* -------------------------------------------------------------- studio */
  function swatch(t) {
    const bg = t.mode === "dark" ? ok(0.16, 0.03 * t.c, t.hb) : ok(0.97, 0.012 * t.c, t.hb);
    const fg = t.mode === "dark" ? ok(0.96, 0.01, t.hb) : ok(0.25, 0.03, t.hb);
    const L = t.mode === "dark" ? 0.66 : 0.8, C = (t.mode === "dark" ? 0.2 : 0.13) * Math.max(t.c, 0.2);
    const bgi = "radial-gradient(circle at 20% 20%, " + ok(L, C, t.h1, 0.9) + ", transparent 55%), radial-gradient(circle at 85% 30%, " +
      ok(L, C, t.h2, 0.85) + ", transparent 50%), radial-gradient(circle at 60% 110%, " + ok(L, C, t.h3, 0.8) + ", transparent 55%), " + bg;
    const cc = 0.16 * Math.max(t.c, 0.2);
    return `<button class="swatch ${P.theme === t.id ? "on" : ""}" data-th="${t.id}" style="background:${bgi};color:${fg}" aria-pressed="${P.theme === t.id}">
      <span class="dots"><i style="background:${ok(t.mode === "dark" ? 0.78 : 0.56, cc, t.h1)}"></i><i style="background:${ok(0.72, 0.19 * Math.max(t.c, 0.2), t.h2)}"></i><i style="background:${ok(0.8, cc, t.h3)}"></i></span>
      <b>${esc(t.label)}</b><small>${esc(t.tag)}</small></button>`;
  }
  const seg = (key, opts) => `<div class="seg" data-seg="${key}">${opts.map(([k, l]) => `<button type="button" data-k="${k}" class="${(P[key] || "") === k ? "on" : ""}">${l}</button>`).join("")}</div>`;

  function open() {
    const root = $("#studio-root");
    root.innerHTML = `<div class="studio-ov" data-close></div><aside class="studio" role="dialog" aria-label="Theme Studio" id="studio"></aside>`;
    $(".studio-ov", root).onclick = close;
    render();
  }
  function close() { const r = $("#studio-root"); if (r) r.innerHTML = ""; }
  function isOpen() { return !!$("#studio"); }
  function render() {
    const el = $("#studio");
    if (!el) return;
    const scroll = $(".studio-b", el) ? $(".studio-b", el).scrollTop : 0;
    el.innerHTML = `<div class="studio-h"><div class="grow"><h2>Theme Studio</h2><div class="note">Live: changes apply as you move</div></div>
        <button class="icon-btn" data-close aria-label="Close">${ICON.x}</button></div>
      <div class="studio-b">
        <div><div class="studio-sec">Theme</div><div class="swatches">${THEMES.map(swatch).join("")}</div></div>
        <label class="sfield"><span>Hue shift <b class="num" id="v-shift">${P.shift > 0 ? "+" : ""}${P.shift}°</b></span>
          <div class="hue-track"></div><input type="range" min="-180" max="180" step="5" value="${P.shift}" data-in="shift"></label>
        <label class="sfield"><span>Glow <b class="num" id="v-glow">${P.glow}%</b></span>
          <input type="range" min="0" max="160" step="5" value="${P.glow}" data-in="glow">
          <small>The aurora behind the panels and the glow around them. 0 turns the aurora off.</small></label>
        <div class="sfield"><span>Motion</span>${seg("motion", [["full", "Full"], ["calm", "Calm"], ["off", "Off"]])}
          <small>Calm thins the traffic particles and slows the globe. Off stops particles, spin, pulses and the aurora; the data is still drawn. Your OS "reduce motion" setting picks Calm by default (here the particles are data, so they stay).</small></div>
        <div class="sfield"><span>Rendering</span>${seg("quality", [["auto", "Auto"], ["full", "Full"], ["lite", "Lite"]])}
          <small>${(P.quality || "auto") === "auto" ? `Auto is using <b>${quality() === "lite" ? "Lite" : "Full"}</b>${RQ.soft ? " — " + esc(RQ.why) : ""}. ` : ""}Lite drops the aurora, frosted glass and glow, and draws the map and globe at normal resolution: much faster on a VM or remote desktop without GPU acceleration. Colours and layout stay the same.</small></div>
        <div class="sfield"><span>Density</span>${seg("density", [["comfortable", "Comfortable"], ["compact", "Compact"]])}
          <small>Compact fits more rows on a screen: tables, cards, logs and the threat feed tighten up.</small></div>
        <div class="opt-row"><div><b>Reactive ambience</b><div class="d">The aurora tints with the threat level: hazard red under attack, amber when elevated.</div></div>
          <button class="switch ${P.reactive ? "on" : ""}" data-toggle="reactive" role="switch" aria-checked="${P.reactive}" aria-label="Reactive ambience"></button></div>
        <div class="btnrow"><button class="btn sm" data-reset>Reset to defaults</button><span class="grow"></span>
          <span class="note"><span class="kbd">Ctrl</span> <span class="kbd">K</span> switches themes too</span></div>
      </div>`;
    $(".studio-b", el).scrollTop = scroll;
    $$("[data-close]", el).forEach((b) => (b.onclick = close));
    $$("[data-th]", el).forEach((b) => (b.onclick = () => set({ theme: b.dataset.th })));
    $$("[data-seg]", el).forEach((s) => (s.onclick = (e) => { const b = e.target.closest("[data-k]"); if (b) set({ [s.dataset.seg]: b.dataset.k }); }));
    $("[data-toggle=reactive]", el).onclick = () => set({ reactive: !P.reactive });
    $("[data-reset]", el).onclick = () => set(Object.assign({}, DEFAULTS, { motion: osReduce() ? "calm" : "full" }));
    $$("[data-in]", el).forEach((r) => (r.oninput = () => {
      P[r.dataset.in] = +r.value;
      save();
      apply();
      $("#v-shift").textContent = (P.shift > 0 ? "+" : "") + P.shift + "°";
      $("#v-glow").textContent = P.glow + "%";
    }));
  }
  function set(changes) {
    Object.assign(P, changes);
    save();
    apply();
    render();
  }

  function init() {
    detectRendering();
    AU.canvas = document.createElement("canvas");
    AU.canvas.id = "fx-aurora";
    AU.canvas.setAttribute("aria-hidden", "true");
    document.body.prepend(AU.canvas);
    AU.ctx = AU.canvas.getContext("2d");
    sizeAurora();
    addEventListener("resize", () => { sizeAurora(); kick(); }, { passive: true });
    document.addEventListener("visibilitychange", kick);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && isOpen()) { e.stopImmediatePropagation(); close(); } }, true);
    apply();
  }

  return {
    THEMES, prefs: P, init, apply, set, open, close, isOpen, onLevel, frameWatch,
    motion, isLite, quality, theme, rendering: () => Object.assign({ quality: quality() }, RQ),
  };
})();
window.Theme = Theme;
