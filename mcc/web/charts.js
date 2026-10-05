/* Canvas charts: time-series lines (optionally mirrored: download up, upload down), sparklines, ring gauges. */
"use strict";

const Charts = (() => {
  function size(cv) {
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const w = cv.clientWidth, h = cv.clientHeight;
    if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
      cv.width = Math.round(w * dpr);
      cv.height = Math.round(h * dpr);
    }
    const ctx = cv.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, w, h };
  }
  function nice(v) {
    if (v <= 0) return 1;
    const e = Math.pow(10, Math.floor(Math.log10(v)));
    const m = v / e;
    return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10) * e;
  }
  function alpha(color, a) {
    if (!color) return `rgba(128,128,128,${a})`;
    if (color.startsWith("oklch(")) return color.replace(/\)\s*$/, ` / ${a})`).replace(/\/\s*[\d.]+\s*\/ /, "/ ");
    return color;
  }
  function css(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }

  /* series: [{data: [[t, v], ...], color, fill, label}]  opts: {window (s), yfmt, mirror, min} */
  function line(cv, series, opts) {
    opts = opts || {};
    cv._chart = { series, opts };
    if (!cv._hooked) {
      cv._hooked = true;
      new ResizeObserver(() => { if (cv._chart && cv.isConnected) draw(cv); }).observe(cv.parentElement);
      cv.addEventListener("mousemove", (e) => {
        const r = cv.getBoundingClientRect();
        cv._hover = e.clientX - r.left;
        draw(cv, e.clientX, e.clientY);
      });
      cv.addEventListener("mouseleave", () => { cv._hover = null; draw(cv); if (window.tip) tip.hide(); });
    }
    draw(cv);
  }

  function draw(cv, mx, my) {
    const { series, opts } = cv._chart;
    const { ctx, w, h } = size(cv);
    if (!w || !h) return;
    ctx.clearRect(0, 0, w, h);
    const win = opts.window || 1800;
    let tmax = 0;
    for (const s of series) if (s.data.length) tmax = Math.max(tmax, s.data[s.data.length - 1][0]);
    if (!tmax) tmax = Date.now() / 1000;
    const tmin = tmax - win;
    const mirror = !!opts.mirror && series.length === 2;
    let vmax = opts.min || 0;
    series.forEach((s) => s.data.forEach(([t, v]) => { if (t >= tmin && v > vmax) vmax = v; }));
    vmax = nice(vmax * 1.08 || 1);
    const yfmt = opts.yfmt || ((v) => v.toFixed(0));
    ctx.font = "11px " + css("--mono");
    const labelW = Math.max(...[1, 0.75, 0.5, 0.25].map((f) => ctx.measureText(yfmt(f * vmax)).width));
    const padL = Math.ceil(labelW) + 12, padR = 8, padT = 8, padB = 20;
    const pw = w - padL - padR, ph = h - padT - padB;
    const zeroY = mirror ? padT + ph / 2 : padT + ph;
    const scaleY = mirror ? (ph / 2) / vmax : ph / vmax;
    const X = (t) => padL + ((t - tmin) / win) * pw;
    const grid = css("--line-soft"), txt = css("--faint");
    ctx.font = "11px " + css("--mono");
    ctx.textBaseline = "middle";
    ctx.fillStyle = txt;
    ctx.strokeStyle = grid;
    ctx.lineWidth = 1;
    const ticks = mirror ? [-1, -0.5, 0, 0.5, 1] : [0, 0.25, 0.5, 0.75, 1];
    ticks.forEach((f) => {
      const y = Math.round(zeroY - f * (mirror ? ph / 2 : ph)) + 0.5;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(w - padR, y); ctx.stroke();
      ctx.textAlign = "right";
      ctx.fillText(yfmt(Math.abs(f) * vmax), padL - 6, y);
    });
    // time labels
    ctx.textAlign = "center";
    ctx.textBaseline = "alphabetic";
    const step = win <= 600 ? 120 : win <= 1800 ? 300 : 900;
    for (let t = Math.ceil(tmin / step) * step; t <= tmax; t += step) {
      const x = X(t);
      if (x < padL + 20 || x > w - 20) continue;
      const d = new Date(t * 1000);
      ctx.fillText(d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false }), x, h - 5);
    }
    series.forEach((s, si) => {
      const pts = s.data.filter(([t]) => t >= tmin - 5);
      if (pts.length < 2) return;
      const sign = mirror && si === 1 ? -1 : 1;
      ctx.beginPath();
      pts.forEach(([t, v], i) => {
        const x = X(t), y = zeroY - sign * Math.min(v, vmax) * scaleY;
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      });
      if (s.fill) {
        ctx.save();
        ctx.lineTo(X(pts[pts.length - 1][0]), zeroY);
        ctx.lineTo(X(pts[0][0]), zeroY);
        ctx.closePath();
        const g = ctx.createLinearGradient(0, zeroY - sign * ph * (mirror ? 0.5 : 1), 0, zeroY);
        g.addColorStop(0, alpha(s.color, 0.35));
        g.addColorStop(1, alpha(s.color, 0.02));
        ctx.fillStyle = g;
        ctx.fill();
        ctx.restore();
        ctx.beginPath();
        pts.forEach(([t, v], i) => { const x = X(t), y = zeroY - sign * Math.min(v, vmax) * scaleY; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      }
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 1.6;
      ctx.lineJoin = "round";
      ctx.stroke();
    });
    if (mirror) {
      ctx.strokeStyle = css("--line");
      ctx.beginPath(); ctx.moveTo(padL, zeroY + 0.5); ctx.lineTo(w - padR, zeroY + 0.5); ctx.stroke();
    }
    // hover
    const hx = cv._hover;
    if (hx != null && hx >= padL && hx <= w - padR) {
      const t = tmin + ((hx - padL) / pw) * win;
      ctx.strokeStyle = css("--muted");
      ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.moveTo(hx + 0.5, padT); ctx.lineTo(hx + 0.5, padT + ph); ctx.stroke();
      ctx.setLineDash([]);
      const rows = series.map((s) => {
        let best = null;
        for (const p of s.data) if (!best || Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p;
        return best ? `<div><span style="color:${s.color}">●</span> ${s.label || ""} ${yfmt(best[1])}</div>` : "";
      }).join("");
      if (mx != null && window.tip) tip.show(`<b>${new Date(t * 1000).toLocaleTimeString([], { hour12: false })}</b>${rows}`, mx, my);
    }
  }

  function spark(cv, values, color, opts) {
    opts = opts || {};
    const { ctx, w, h } = size(cv);
    ctx.clearRect(0, 0, w, h);
    if (!values || values.length < 2) return;
    let max = opts.max || 0;
    if (!opts.max) values.forEach((v) => { if (v > max) max = v; });
    max = max || 1;
    const X = (i) => (i / (values.length - 1)) * w;
    const Y = (v) => h - 2 - (Math.min(v, max) / max) * (h - 6);
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(X(i), Y(v)) : ctx.moveTo(X(i), Y(v))));
    ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, alpha(color, 0.28));
    g.addColorStop(1, alpha(color, 0));
    ctx.fillStyle = g;
    ctx.fill();
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(X(i), Y(v)) : ctx.moveTo(X(i), Y(v))));
    ctx.strokeStyle = alpha(color, 0.9);
    ctx.lineWidth = 1.4;
    ctx.stroke();
  }

  function gauge(pct, color) {
    const r = 22, c = 2 * Math.PI * r;
    const v = Math.max(0, Math.min(100, pct || 0));
    return `<svg class="gauge" viewBox="0 0 54 54" aria-hidden="true"><circle class="track" cx="27" cy="27" r="${r}"/>
      <circle class="val" cx="27" cy="27" r="${r}" stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${(c * (1 - v / 100)).toFixed(1)}" style="stroke:${color}"/></svg>`;
  }

  window.addEventListener("resize", () => {
    document.querySelectorAll("canvas").forEach((cv) => { if (cv._chart) draw(cv); });
  });
  return { line, spark, gauge, redraw: draw };
})();
window.Charts = Charts;
