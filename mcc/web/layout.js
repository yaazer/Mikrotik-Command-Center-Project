/* Resizable layout. Every panel on every page gets handles:
     right edge  -> width, snapped to the 12-column grid (a neighbour in the same row gives/takes space)
     bottom edge -> height
     corner      -> both
   Double-click a handle to reset that panel. Layouts are saved per browser (localStorage) per page;
   the header's layout button resets the current page. The detail drawer's left edge resizes it too. */
"use strict";

const Layout = (() => {
  const KEY = "mcc-layout-v1";
  const COLS = 12, MIN_SPAN = 2, MIN_H = 140;
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch (e) { saved = {}; }
  const persist = () => { try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (e) { /* private mode */ } };
  const page = () => (typeof parseHash === "function" ? parseHash().page : "page");
  const narrow = () => window.matchMedia("(max-width: 720px)").matches;

  function panelsOf(root) {
    return Array.from(root.querySelectorAll(":scope > .grid > .panel, :scope > .panel"));
  }
  function spanOf(p) {
    const st = p.style.getPropertyValue("--span");
    if (st) return +st;
    const m = p.className.match(/\bs(\d+)\b/);
    return m ? +m[1] : COLS;
  }
  function setSpan(p, n) {
    p.style.setProperty("--span", n);
    p.classList.add("spanned");
  }
  function setHeight(p, h) {
    p.style.setProperty("--ph", h + "px");
    p.classList.add("sized");
  }

  function apply(root) {
    root = root || $("#main");
    if (!root) return;
    const pg = page();
    panelsOf(root).forEach((p, i) => {
      if (!p.dataset.pid) p.dataset.pid = pg + ":" + i;
      const s = saved[p.dataset.pid];
      if (s && s.span && p.parentElement.classList.contains("grid")) setSpan(p, s.span);
      if (s && s.h) setHeight(p, s.h);
      if (p.querySelector(":scope > .rz")) return;
      const inGrid = p.parentElement.classList.contains("grid");
      p.insertAdjacentHTML("beforeend", (inGrid ? '<div class="rz rz-e" title="Drag to resize · double-click to reset"></div>' : "") +
        '<div class="rz rz-s" title="Drag to resize · double-click to reset"></div>' +
        (inGrid ? '<div class="rz rz-se" title="Drag to resize · double-click to reset"></div>' : ""));
      p.querySelectorAll(":scope > .rz").forEach((h) => {
        h.addEventListener("pointerdown", (e) => start(e, p, h));
        h.addEventListener("dblclick", () => resetPanel(p));
      });
    });
  }

  function start(e, p, handle) {
    if (narrow() || e.button !== 0) return;
    e.preventDefault();
    handle.setPointerCapture(e.pointerId);
    const grid = p.parentElement;
    const inGrid = grid.classList.contains("grid");
    const doW = handle.classList.contains("rz-e") || handle.classList.contains("rz-se");
    const doH = handle.classList.contains("rz-s") || handle.classList.contains("rz-se");
    const gs = getComputedStyle(grid);
    const gap = parseFloat(gs.columnGap) || 14;
    const colW = (grid.clientWidth - gap * (COLS - 1)) / COLS;
    const rect = p.getBoundingClientRect();
    const span0 = spanOf(p);
    // the neighbour sharing this row, if any, trades columns with us so the row stays full
    let nb = p.nextElementSibling;
    while (nb && !nb.classList.contains("panel")) nb = nb.nextElementSibling;
    if (nb && Math.abs(nb.getBoundingClientRect().top - rect.top) > 4) nb = null;
    const pair = nb ? span0 + spanOf(nb) : 0;
    const badge = document.createElement("div");
    badge.className = "rz-badge";
    p.appendChild(badge);
    p.classList.add("resizing");
    document.body.classList.add("rz-active");
    let span = span0, h = rect.height;

    const move = (ev) => {
      if (doW && inGrid) {
        const w = ev.clientX - rect.left;
        span = Math.max(MIN_SPAN, Math.min(nb ? pair - MIN_SPAN : COLS, Math.round((w + gap) / (colW + gap))));
        setSpan(p, span);
        if (nb) setSpan(nb, pair - span);
      }
      if (doH) {
        h = Math.max(MIN_H, Math.min(2400, Math.round(ev.clientY - rect.top)));
        setHeight(p, h);
      }
      badge.textContent = (inGrid ? `${span}/${COLS} cols` : "") + (inGrid && doH ? " · " : "") + (doH ? `${h}px` : "");
    };
    const end = () => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", end);
      handle.removeEventListener("pointercancel", end);
      badge.remove();
      p.classList.remove("resizing");
      document.body.classList.remove("rz-active");
      const s = saved[p.dataset.pid] = saved[p.dataset.pid] || {};
      if (doW && inGrid) {
        s.span = span;
        if (nb) (saved[nb.dataset.pid] = saved[nb.dataset.pid] || {}).span = pair - span;
      }
      if (doH) s.h = h;
      persist();
      window.dispatchEvent(new Event("resize"));
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", end);
    handle.addEventListener("pointercancel", end);
    move(e);
  }

  function resetPanel(p) {
    delete saved[p.dataset.pid];
    persist();
    p.style.removeProperty("--span");
    p.style.removeProperty("--ph");
    p.classList.remove("spanned", "sized");
    window.dispatchEvent(new Event("resize"));
  }
  function resetPage() {
    const pg = page() + ":";
    Object.keys(saved).forEach((k) => { if (k.startsWith(pg)) delete saved[k]; });
    persist();
    $$(".panel[data-pid]").forEach((p) => {
      p.style.removeProperty("--span");
      p.style.removeProperty("--ph");
      p.classList.remove("spanned", "sized");
    });
    window.dispatchEvent(new Event("resize"));
  }

  /* the drawer */
  function drawer() {
    const d = $("#drawer");
    try { const w = +localStorage.getItem("mcc-drawer-w"); if (w) d.style.width = w + "px"; } catch (e) { /* */ }
    const h = document.createElement("div");
    h.className = "rz rz-w";
    h.title = "Drag to resize · double-click to reset";
    d.appendChild(h);
    h.addEventListener("pointerdown", (e) => {
      if (narrow()) return;
      e.preventDefault();
      h.setPointerCapture(e.pointerId);
      document.body.classList.add("rz-active");
      const move = (ev) => { d.style.width = Math.max(360, Math.min(window.innerWidth - 80, window.innerWidth - ev.clientX)) + "px"; };
      const end = () => {
        h.removeEventListener("pointermove", move);
        h.removeEventListener("pointerup", end);
        document.body.classList.remove("rz-active");
        try { localStorage.setItem("mcc-drawer-w", parseInt(d.style.width, 10)); } catch (e) { /* */ }
        window.dispatchEvent(new Event("resize"));
      };
      h.addEventListener("pointermove", move);
      h.addEventListener("pointerup", end);
    });
    h.addEventListener("dblclick", () => { d.style.width = ""; try { localStorage.removeItem("mcc-drawer-w"); } catch (e) { /* */ } });
    // the drawer rewrites its content on every refresh; keep the handle attached
    new MutationObserver(() => { if (h.parentElement !== d) d.appendChild(h); }).observe(d, { childList: true });
  }

  document.addEventListener("DOMContentLoaded", () => {
    // pages (re)render by replacing #main's children; re-apply the layout whenever that happens
    new MutationObserver(() => apply($("#main"))).observe($("#main"), { childList: true });
    drawer();
  });
  return { apply, resetPage, resetPanel };
})();
window.Layout = Layout;
