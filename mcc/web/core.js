/* Mikrotik Command Center -- core: state, live stream, API, formatting, shared UI (modal, drawer,
   toasts, command palette). Pages live in views.js, the traffic map in map.js, charts in charts.js. */
"use strict";

const $ = (s, el) => (el || document).querySelector(s);
const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ---------------- formatting ---------------- */
const fmt = {
  bps(v) {
    if (v == null || isNaN(v)) return "—";
    const u = ["b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"];
    let i = 0;
    while (Math.abs(v) >= 1000 && i < u.length - 1) { v /= 1000; i++; }
    return (i === 0 ? v.toFixed(0) : v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + " " + u[i];
  },
  bpsParts(v) {
    const s = fmt.bps(v).split(" ");
    return [s[0], s[1] || ""];
  },
  bytes(v) {
    if (v == null || isNaN(v)) return "—";
    const u = ["B", "KB", "MB", "GB", "TB", "PB"];
    let i = 0;
    while (Math.abs(v) >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + u[i];
  },
  pct(v) { return v == null || isNaN(v) ? "—" : Math.round(v) + "%"; },
  ago(ts) {
    if (!ts) return "—";
    const t = typeof ts === "number" ? ts * 1000 : Date.parse(ts);
    const s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 5) return "just now";
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m ago";
    return Math.floor(s / 86400) + "d ago";
  },
  dur(s) {
    s = Math.max(0, Math.floor(s || 0));
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return d + "d " + h + "h";
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + (s % 60) + "s";
    return s + "s";
  },
  time(ts) {
    const d = typeof ts === "number" ? new Date(ts * 1000) : new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  },
};

/* ---------------- icons ---------------- */
const ICON = {
  shield: '<svg viewBox="0 0 24 24"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>',
  block: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/></svg>',
  cut: '<svg viewBox="0 0 24 24"><path d="M4 12h5M15 12h5M10 8l4 8"/></svg>',
  quarantine: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 12h6"/></svg>',
  undo: '<svg viewBox="0 0 24 24"><path d="M9 14L4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 0 12h-3"/></svg>',
  check: '<svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  x: '<svg viewBox="0 0 24 24"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  power: '<svg viewBox="0 0 24 24"><path d="M12 3v8"/><path d="M6.3 7.5a8 8 0 1 0 11.4 0"/></svg>',
  eye: '<svg viewBox="0 0 24 24"><path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  host: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
  globe: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/></svg>',
  bolt: '<svg viewBox="0 0 24 24"><path d="M13 2L4 14h7l-1 8 9-12h-7z"/></svg>',
  page: '<svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></svg>',
  alert: '<svg viewBox="0 0 24 24"><path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17.5v.01"/></svg>',
};

/* ---------------- API ---------------- */
const api = {
  async get(path) {
    const r = await fetch(path, { headers: { Accept: "application/json" } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || r.statusText);
    return j;
  },
  async post(path, body) {
    const r = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-MCC": "1" },
      body: JSON.stringify(body || {}),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || r.statusText);
    return j;
  },
};

/* ---------------- state + events ---------------- */
const S = {
  snap: null, hist: { ifaces: {}, health: [], switch: {} }, threats: new Map(), actions: new Map(), logs: [],
  entries: [], config: {}, rules: {}, ignore: [], connected: false, lastTick: 0, seenThreats: new Set(),
};
const HIST_MAX = 1800;
const bus = {};
function on(ev, fn) { (bus[ev] = bus[ev] || []).push(fn); }
function emit(ev, data) { (bus[ev] || []).forEach((fn) => { try { fn(data); } catch (e) { console.error(e); } }); }

function pushHist(arr, row) {
  arr.push(row);
  if (arr.length > HIST_MAX) arr.splice(0, arr.length - HIST_MAX);
}

let es = null;
function connectStream() {
  if (es) es.close();
  es = new EventSource("/api/stream");
  es.addEventListener("state", (e) => {
    const st = JSON.parse(e.data);
    S.snap = st.snapshot;
    S.hist = st.history || { ifaces: {}, health: [], switch: {} };
    S.threats = new Map(st.threats.map((t) => [t.id, t]));
    st.threats.forEach((t) => S.seenThreats.add(t.id + ":" + t.first_seen));
    S.actions = new Map(st.actions.map((a) => [a.id, a]));
    S.logs = st.logs || [];
    S.entries = st.entries || [];
    S.config = st.config || {};
    S.rules = st.rules || {};
    S.ignore = st.ignore || [];
    S.connected = true;
    setReconnect(false);
    emit("state");
    emit("tick");
  });
  es.addEventListener("tick", (e) => {
    const snap = JSON.parse(e.data);
    S.snap = snap;
    S.lastTick = Date.now();
    const t = snap.t;
    for (const i of snap.ifaces) pushHist(S.hist.ifaces[i.name] = S.hist.ifaces[i.name] || [], [t, i.rx_bps, i.tx_bps]);
    if (snap.router && snap.router.cpu != null) {
      const mem = snap.router.mem_total ? snap.router.mem_used * 100 / snap.router.mem_total : 0;
      pushHist(S.hist.health, [t, snap.router.cpu, mem]);
    }
    for (const p of (snap.switch && snap.switch.ports) || []) {
      if (p.rx_bps != null) pushHist(S.hist.switch[p.n] = S.hist.switch[p.n] || [], [t, p.rx_bps, p.tx_bps || 0]);
    }
    emit("tick");
  });
  es.addEventListener("threat", (e) => {
    const t = JSON.parse(e.data);
    S.threats.set(t.id, t);
    const key = t.id + ":" + t.first_seen;
    if (!S.seenThreats.has(key)) {
      S.seenThreats.add(key);
      if (t.status === "open") threatToast(t);
    }
    emit("threats", t);
  });
  es.addEventListener("action", (e) => {
    const a = JSON.parse(e.data);
    S.actions.set(a.id, a);
    emit("actions", a);
  });
  es.addEventListener("logs", (e) => {
    const rows = JSON.parse(e.data);
    S.logs.push(...rows);
    if (S.logs.length > 3000) S.logs.splice(0, S.logs.length - 3000);
    emit("logs", rows);
  });
  es.addEventListener("status", () => {});
  es.addEventListener("ignore", (e) => { S.ignore = JSON.parse(e.data); emit("ignore"); });
  es.addEventListener("setup", (e) => emit("setup", JSON.parse(e.data)));
  es.addEventListener("resync", () => { es.close(); setTimeout(connectStream, 300); });
  es.onerror = () => { setReconnect(true); };
}
let reconnectEl = null;
function setReconnect(on) {
  if (on && !reconnectEl) {
    reconnectEl = document.createElement("div");
    reconnectEl.className = "reconnect";
    reconnectEl.textContent = "Lost the live feed — reconnecting…";
    document.body.appendChild(reconnectEl);
  } else if (!on && reconnectEl) { reconnectEl.remove(); reconnectEl = null; }
}

/* ---------------- header ---------------- */
function chip(label, cls, title, href) {
  const tag = href ? "a" : "span";
  return `<${tag} class="chip ${cls}" title="${esc(title)}"${href ? ` href="${href}"` : ""}><i></i>${esc(label)}</${tag}>`;
}
function renderHeader() {
  const s = S.snap;
  if (!s) return;
  const st = s.status, r = s.router || {};
  const rid = $("#router-id");
  if (st.router.state === "ok" || r.identity) {
    rid.innerHTML = `<b>${esc(r.identity || "router")}</b> · ${esc(r.board || "")} · RouterOS ${esc((r.version || "").split(" ")[0])}` +
      (r.uptime ? ` · up ${esc(fmt.dur(r.uptime_s))}` : "");
  } else rid.innerHTML = '<span class="muted">not connected</span>';
  const rs = st.router.state;
  const chips = [
    chip("Router", rs === "ok" && !st.router.stale ? "ok" : rs === "disconnected" ? "" : "bad",
      rs === "ok" ? "REST API polling OK" : (st.router.error || rs), "#/setup"),
    chip("Flows", st.flows.live ? "ok" : st.flows.packets ? "warn" : "",
      st.flows.live ? `${st.flows.rate.toFixed(1)} records/s on UDP ${st.flows.port}` : "No IPFIX/NetFlow arriving — see Setup", "#/setup"),
    chip("Syslog", st.syslog.live ? "ok" : st.syslog.packets ? "warn" : "",
      st.syslog.live ? `receiving on UDP ${st.syslog.port}` : "No syslog arriving — MCC reads the router's memory log instead", "#/setup"),
    chip("Switch", st.switch.state === "ok" ? "ok" : st.switch.state === "off" ? "" : "bad",
      st.switch.state === "ok" ? "SwOS polling OK" : (st.switch.error || "no switch connected"), "#/interfaces"),
  ];
  $("#chips").innerHTML = chips.join("");
  const lvl = s.level || "calm";
  const lb = $("#level");
  lb.className = "level " + lvl;
  lb.textContent = lvl.toUpperCase();
  $("#frame").className = "frame lvl-" + lvl;
  const nOpen = s.counts.threats_open;
  $("#nb-threats").textContent = nOpen || "";
  $("#nb-actions").textContent = s.counts.actions_pending || "";
  $("#nb-actions").className = "badge info";
  const needSetup = st.router.state === "ok" && !st.flows.live && !st.syslog.live;
  $("#nb-setup").textContent = st.router.state !== "ok" ? "!" : needSetup ? "1" : "";
  document.title = (nOpen ? `(${nOpen}) ` : "") + "Mikrotik Command Center";
}
function tickClock() {
  const d = new Date();
  $("#clock").innerHTML = `${d.toLocaleTimeString([], { hour12: false })}<br>${d.toISOString().slice(11, 19)} UTC`;
}

/* ---------------- toasts ---------------- */
function toast(title, body, opts) {
  opts = opts || {};
  const el = document.createElement("div");
  el.className = "toast";
  if (opts.sev) el.style.setProperty("--sv", `var(--${{ critical: "crit", high: "high", medium: "med", low: "low" }[opts.sev] || "info"})`);
  if (opts.bad) el.style.setProperty("--sv", "var(--crit)");
  if (opts.good) el.style.setProperty("--sv", "var(--ok)");
  el.innerHTML = `<b>${esc(title)}</b>${body ? `<span class="muted">${esc(body)}</span>` : ""}`;
  el.onclick = () => { el.remove(); if (opts.onclick) opts.onclick(); };
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), opts.ms || 6000);
  while ($("#toasts").children.length > 5) $("#toasts").firstChild.remove();
}
function threatToast(t) {
  if (!["critical", "high", "medium"].includes(t.severity)) return;
  toast(t.title, t.summary, { sev: t.severity, ms: t.severity === "critical" ? 12000 : 7000, onclick: () => go("threats", { id: t.id }) });
}

/* ---------------- tooltip ---------------- */
const tip = {
  show(html, x, y) {
    const el = $("#tip");
    el.innerHTML = html;
    el.style.display = "block";
    const w = el.offsetWidth, h = el.offsetHeight;
    el.style.left = Math.min(window.innerWidth - w - 8, x + 14) + "px";
    el.style.top = Math.min(window.innerHeight - h - 8, y + 14) + "px";
  },
  hide() { $("#tip").style.display = "none"; },
};

/* ---------------- modal ---------------- */
function openModal(html, onMount) {
  const wrap = $("#modal");
  wrap.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${html}</div>`;
  wrap.classList.add("open");
  wrap.setAttribute("aria-hidden", "false");
  wrap.onclick = (e) => { if (e.target === wrap) closeModal(); };
  if (onMount) onMount($(".modal", wrap));
  const f = $("[autofocus]", wrap) || $(".btn", wrap);
  if (f) f.focus();
}
function closeModal() {
  const wrap = $("#modal");
  wrap.classList.remove("open");
  wrap.setAttribute("aria-hidden", "true");
  wrap.innerHTML = "";
  if (closeModal.after) { const f = closeModal.after; closeModal.after = null; f(); }
}

function changesHtml(changes) {
  if (!changes || !changes.length) return '<div class="note">No changes needed.</div>';
  return `<div class="changes">${changes.map((c) => `
    <div class="change">
      <div class="note-line"><span class="method ${esc(c.method)}">${esc(c.method === "KILL" ? "DELETE ×n" : c.method)}</span>
        <span class="grow">${esc(c.note || "")}</span>${c.keep ? '<span class="pill" title="Stays in place after undo; Setup › Remove takes it out">one-time</span>' : ""}</div>
      <pre>${esc(c.cli)}</pre>
      ${c.method !== "KILL" ? `<pre class="rest">${esc(c.method)} /rest${esc(c.path)}${c.body && Object.keys(c.body).length ? "  " + esc(JSON.stringify(c.body)) : ""}</pre>` : ""}
    </div>`).join("")}</div>`;
}
function stepsHtml(steps) {
  return `<div class="steps">${(steps || []).map((s) => `<div><span class="${s.ok ? "okk" : "bad"}">${s.ok ? "✓" : "✗"}</span><span>${esc(s.cli || "")} <span class="faint">→ ${esc(s.result || "")}</span></span></div>`).join("")}</div>`;
}

/* ---------------- responses: propose -> review -> confirm ---------------- */
const TIMEOUT_LABEL = { "15m": "15 min", "1h": "1 hour", "24h": "24 hours", "7d": "7 days", "0": "permanent" };

async function respond(kind, params, reason, threatId) {
  let rec;
  try {
    rec = await api.post("/api/actions/propose", { kind, params, reason: reason || "", threat_id: threatId || "" });
  } catch (e) {
    toast("Can't prepare that", e.message, { bad: true, ms: 9000 });
    return;
  }
  showProposal(rec);
}

function showProposal(rec) {
  const needsAck = rec.params && rec.params.acknowledge_risk === false;
  const hasTimeout = rec.kind === "block_ip" || rec.kind === "quarantine_host";
  openModal(`
    <header><div class="grow"><div class="faint" style="font-size:12px;letter-spacing:.1em;text-transform:uppercase">Proposed response · ${esc(rec.id)}</div>
      <h2>${esc(rec.title)}</h2></div><button class="icon-btn" data-x aria-label="Close">${ICON.x}</button></header>
    <div class="mbody">
      <div>${esc(rec.summary)}</div>
      ${hasTimeout ? `<div class="btnrow"><span class="muted">Duration</span><div class="seg" id="dur">${Object.keys(TIMEOUT_LABEL).map((k) => `<button data-t="${k}" class="${String(rec.params.timeout) === k ? "on" : ""}">${TIMEOUT_LABEL[k]}</button>`).join("")}</div></div>` : ""}
      ${(rec.warnings || []).map((w) => `<div class="callout ${/DANGER/.test(w) ? "bad" : "warn"}">${esc(w)}</div>`).join("")}
      <div><h4 style="margin:4px 0 8px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)">Exactly what will change on the router</h4>${changesHtml(rec.changes)}</div>
      <div class="note">${rec.undo && rec.undo.possible ? `Undo: ${esc(rec.undo.why)}.` : `Can't be undone: ${esc((rec.undo || {}).why || "")}.`} Logged as ${esc(rec.id)}.</div>
      ${needsAck ? `<label class="check"><input type="checkbox" id="ack"> I understand this can cut MCC off from the router.</label>` : ""}
    </div>
    <footer><span class="grow faint">Nothing has changed yet.</span>
      <button class="btn" data-dismiss>Don't do it</button>
      <button class="btn danger" data-confirm ${needsAck ? "disabled" : ""} autofocus>${ICON.check} Confirm — apply now</button></footer>`,
  (m) => {
    $("[data-x]", m).onclick = () => { dismiss(rec.id); closeModal(); };
    $("[data-dismiss]", m).onclick = () => { dismiss(rec.id); closeModal(); };
    const ack = $("#ack", m);
    if (ack) ack.onchange = () => { $("[data-confirm]", m).disabled = !ack.checked; };
    const dur = $("#dur", m);
    if (dur) dur.onclick = async (e) => {
      const b = e.target.closest("button[data-t]");
      if (!b || b.classList.contains("on")) return;
      await dismiss(rec.id);
      closeModal();
      respond(rec.kind, Object.assign({}, rec.params, { timeout: b.dataset.t }), rec.reason, rec.threat_id);
    };
    $("[data-confirm]", m).onclick = async (e) => {
      e.target.disabled = true;
      e.target.textContent = "Applying…";
      try {
        const done = await api.post(`/api/actions/${rec.id}/confirm`, { confirm: true, acknowledge_risk: ack ? ack.checked : false });
        showResult(done);
      } catch (err) {
        toast("Not applied", err.message, { bad: true, ms: 10000 });
        closeModal();
      }
    };
  });
}
async function dismiss(id) { try { await api.post(`/api/actions/${id}/dismiss`, {}); } catch (e) { /* already gone */ } }

function showResult(rec) {
  const ok = rec.status === "done";
  openModal(`
    <header><div class="grow"><div class="faint" style="font-size:12px;letter-spacing:.1em;text-transform:uppercase">${esc(rec.id)} · ${ok ? "applied" : "failed"}</div>
      <h2>${ok ? "✓ " : "✗ "}${esc(rec.title)}</h2></div><button class="icon-btn" data-x aria-label="Close">${ICON.x}</button></header>
    <div class="mbody">
      ${ok ? "" : `<div class="callout bad">${esc(rec.error || "")}</div>`}
      ${stepsHtml(rec.steps)}
      ${rec.undo && rec.undo.possible ? `<div class="note">You can undo this any time from Actions.</div>` : ""}
    </div>
    <footer><span class="grow"></span>
      ${rec.undo && rec.undo.possible ? `<button class="btn" data-undo>${ICON.undo} Undo now</button>` : ""}
      <button class="btn primary" data-x autofocus>Close</button></footer>`,
  (m) => {
    $$("[data-x]", m).forEach((b) => (b.onclick = closeModal));
    const u = $("[data-undo]", m);
    if (u) u.onclick = () => askUndo(rec);
  });
  toast(ok ? `${rec.title} — done` : `${rec.title} — failed`, ok ? rec.summary : rec.error, ok ? { good: true } : { bad: true });
}

function askUndo(rec) {
  const created = (rec.created_ids || []).filter((c) => !c.keep && c.id);
  openModal(`
    <header><h2>Undo ${esc(rec.id)}: ${esc(rec.title)}?</h2><button class="icon-btn" data-x aria-label="Close">${ICON.x}</button></header>
    <div class="mbody"><div>${esc(rec.undo.why)}.</div>
      ${created.length ? `<div class="changes">${created.map((c) => `<div class="change"><pre>${esc(cliRemove(c))}</pre></div>`).join("")}</div>` : ""}
    </div>
    <footer><span class="grow"></span><button class="btn" data-x>Cancel</button><button class="btn danger" data-go autofocus>${ICON.undo} Undo</button></footer>`,
  (m) => {
    $$("[data-x]", m).forEach((b) => (b.onclick = closeModal));
    $("[data-go]", m).onclick = async (e) => {
      e.target.disabled = true;
      try {
        const r = await api.post(`/api/actions/${rec.id}/undo`, { confirm: true });
        closeModal();
        toast(r.status === "undone" ? `Undone: ${r.title}` : "Undo failed", r.undo_error || "", r.status === "undone" ? { good: true } : { bad: true });
      } catch (err) { toast("Undo failed", err.message, { bad: true }); closeModal(); }
    };
  });
}
function cliRemove(c) {
  const p = c.path.split("/").filter(Boolean).join(" ");
  return `/${p} remove [find .id=${c.id}]`;
}

/* ---------------- host / peer drawer ---------------- */
let drawerIp = null, drawerTimer = null, drawerChart = null;
function openHost(ip) {
  if (!ip) return;
  drawerIp = ip;
  const d = $("#drawer");
  d.classList.add("open");
  d.setAttribute("aria-hidden", "false");
  d.innerHTML = `<header><div class="grow"><div class="faint">${esc(ip)}</div><h2>Loading…</h2></div><button class="icon-btn" data-x aria-label="Close">${ICON.x}</button></header>`;
  $("[data-x]", d).onclick = closeDrawer;
  loadHost();
  clearInterval(drawerTimer);
  drawerTimer = setInterval(loadHost, 3000);
}
function closeDrawer() {
  drawerIp = null;
  clearInterval(drawerTimer);
  const d = $("#drawer");
  d.classList.remove("open");
  d.setAttribute("aria-hidden", "true");
  drawerChart = null;
}
async function loadHost() {
  const ip = drawerIp;
  if (!ip) return;
  let h;
  try { h = await api.get("/api/host?ip=" + encodeURIComponent(ip)); } catch (e) { return; }
  if (ip !== drawerIp) return;
  const d = $("#drawer");
  const peer = !h.lan;
  const dev = h.device || {};
  const blocked = h.entries.some((e) => e.list === "mcc-blocked");
  const quarantined = h.entries.some((e) => e.list === "mcc-quarantine");
  const now = h.history.length ? h.history[h.history.length - 1] : null;
  const scrollTop = $(".dbody", d) ? $(".dbody", d).scrollTop : 0;
  const badges = [
    `<span class="pill ${peer ? "blue" : "green"}">${peer ? "Internet" : "LAN"}</span>`,
    h.blocklisted ? '<span class="pill red">on blocklist</span>' : "",
    blocked ? '<span class="pill red">blocked</span>' : "",
    quarantined ? '<span class="pill amber">quarantined</span>' : "",
    h.protected ? `<span class="pill" title="${esc(h.protected)}">protected</span>` : "",
  ].join(" ");
  const acts = [];
  if (!h.protected) {
    if (blocked) acts.push(`<button class="btn sm" data-act="remove_entry" data-list="mcc-blocked">${ICON.undo} Unblock</button>`);
    else acts.push(`<button class="btn sm danger" data-act="block_ip">${ICON.block} Block</button>`);
    if (!peer) {
      if (quarantined) acts.push(`<button class="btn sm" data-act="remove_entry" data-list="mcc-quarantine">${ICON.undo} Release</button>`);
      else acts.push(`<button class="btn sm" data-act="quarantine_host">${ICON.quarantine} Quarantine</button>`);
    }
    if (h.pairs.length) acts.push(`<button class="btn sm" data-act="kill_connections">${ICON.cut} Drop connections</button>`);
  }
  d.innerHTML = `
    <header><div class="grow"><div class="faint mono">${esc(ip)}</div><h2>${esc(h.name || dev.name || dev.hostname || (peer ? "Internet host" : "LAN host"))}</h2>
      <div style="margin-top:6px">${badges}</div></div><button class="icon-btn" data-x aria-label="Close">${ICON.x}</button></header>
    <div class="dbody">
      ${h.protected ? `<div class="callout">MCC won't block or cut off this address: ${esc(h.protected)}.</div>` : ""}
      <div class="btnrow">${acts.join("")}</div>
      <div class="kpis" style="grid-template-columns:repeat(3,1fr);margin:0">
        <div class="panel kpi"><div class="k in">↓ ${peer ? "to LAN" : "download"}</div><div class="v">${fmt.bps(now ? now[1] : 0)}</div></div>
        <div class="panel kpi"><div class="k out">↑ ${peer ? "from LAN" : "upload"}</div><div class="v">${fmt.bps(now ? now[2] : 0)}</div></div>
        <div class="panel kpi"><div class="k">Conversations</div><div class="v">${h.pairs.length}</div></div>
      </div>
      ${!peer ? `<div class="panel"><div class="body" style="padding:8px"><div class="chart short"><canvas id="hchart"></canvas></div></div></div>` : ""}
      ${h.geo ? `<div><h4>Location</h4><dl class="kv"><dt>Where</dt><dd>${esc([h.geo.city, h.geo.region, h.geo.country].filter(Boolean).join(", "))}</dd>
        <dt>Coordinates</dt><dd>${h.geo.lat}, ${h.geo.lon}${h.geo.precision === "country" ? " (country centre)" : ""}</dd></dl></div>` : ""}
      ${h.device ? `<div><h4>Device</h4><dl class="kv"><dt>MAC</dt><dd>${esc(dev.mac)}</dd><dt>Hostname</dt><dd>${esc(dev.hostname || "—")}</dd>
        <dt>Port</dt><dd>${esc(dev.port || dev.iface || "—")}</dd><dt>DHCP</dt><dd>${dev.dhcp ? esc(dev.status || "yes") : "no (ARP only)"}</dd></dl></div>` : ""}
      <div><h4>Conversations now</h4>${h.pairs.length ? `<table class="t"><thead><tr><th>${peer ? "LAN host" : "Remote"}</th><th>Service</th><th class="r">↓</th><th class="r">↑</th></tr></thead><tbody>
        ${h.pairs.slice(0, 40).map((p) => { const other = p.local === ip ? p.remote : p.local; const nm = p.local === ip ? p.remote_name : p.local_name;
          return `<tr class="click" data-ip="${esc(other)}"><td><div class="who"><b>${esc(nm || other)}</b>${nm ? `<span>${esc(other)}</span>` : ""}</div></td><td>${esc(p.service)}</td><td class="r num in">${fmt.bps(p.down)}</td><td class="r num out">${fmt.bps(p.up)}</td></tr>`; }).join("")}
        </tbody></table>` : '<div class="note">No traffic right now.</div>'}</div>
      ${h.threats.length ? `<div><h4>Threats</h4>${h.threats.map((t) => `<div class="tcard ${t.status !== "open" ? "dim" : ""}" style="--sv:var(--${sevVar(t.severity)});border:1px solid var(--line-soft);border-radius:8px;margin-bottom:6px" data-tid="${esc(t.id)}">
        <div class="row1"><span class="sev sv-${esc(t.severity)}">${esc(t.severity)}</span><span class="grow"></span><span class="pill">${esc(t.status)}</span></div><h3>${esc(t.title)}</h3><p>${esc(t.summary)}</p></div>`).join("")}</div>` : ""}
      ${h.actions.length ? `<div><h4>Actions</h4>${h.actions.map((a) => `<div class="btnrow" style="justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--line-soft)"><span><b>${esc(a.id)}</b> ${esc(a.title)}</span><span class="pill ${a.status === "done" ? "green" : a.status === "failed" ? "red" : ""}">${esc(a.status)}</span></div>`).join("")}</div>` : ""}
    </div>`;
  $(".dbody", d).scrollTop = scrollTop;
  $("[data-x]", d).onclick = closeDrawer;
  $$("[data-act]", d).forEach((b) => {
    b.onclick = () => {
      const k = b.dataset.act;
      const params = { ip };
      if (k === "remove_entry") params.list = b.dataset.list;
      respond(k, params, "from the console");
    };
  });
  $$("tr[data-ip]", d).forEach((tr) => (tr.onclick = () => openHost(tr.dataset.ip)));
  $$("[data-tid]", d).forEach((c) => (c.onclick = () => { closeDrawer(); go("threats", { id: c.dataset.tid }); }));
  const cv = $("#hchart", d);
  if (cv && window.Charts) {
    Charts.line(cv, [
      { data: h.history.map((r) => [r[0], r[1]]), color: cssVar("--in"), fill: true, label: "↓" },
      { data: h.history.map((r) => [r[0], r[2]]), color: cssVar("--out"), fill: true, label: "↑" },
    ], { window: 600, yfmt: fmt.bps });
  }
}
function sevVar(s) { return { critical: "crit", high: "high", medium: "med", low: "low" }[s] || "info"; }
function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }

/* ---------------- routing ---------------- */
const VIEWS = {};
let current = null;
function parseHash() {
  const h = location.hash.replace(/^#\/?/, "");
  const [page, qs] = h.split("?");
  const params = {};
  new URLSearchParams(qs || "").forEach((v, k) => (params[k] = v));
  return { page: VIEWS[page] ? page : "overview", params };
}
function go(page, params) {
  const qs = params ? new URLSearchParams(params).toString() : "";
  const target = "#/" + page + (qs ? "?" + qs : "");
  if (location.hash === target) route(); else location.hash = target;
}
function route() {
  const { page, params } = parseHash();
  if (current && current.view.leave) current.view.leave();
  $$("#tabs a").forEach((a) => a.classList.toggle("on", a.dataset.page === page));
  const main = $("#main");
  main.innerHTML = "";
  current = { name: page, view: VIEWS[page], params };
  if (S.snap) current.view.render(main, params); else main.innerHTML = '<div class="empty"><b>Connecting to MCC…</b></div>';
}
on("state", () => { if (current) { const m = $("#main"); m.innerHTML = ""; current.view.render(m, current.params); } });
on("tick", () => {
  renderHeader();
  if (current && current.view.tick && S.snap) current.view.tick();
});
on("threats", (t) => { if (current && current.view.onThreat) current.view.onThreat(t); });
on("actions", (a) => { if (current && current.view.onAction) current.view.onAction(a); });
on("logs", (rows) => { if (current && current.view.onLogs) current.view.onLogs(rows); });
on("ignore", () => { if (current && current.view.onIgnore) current.view.onIgnore(); });

/* ---------------- command palette ---------------- */
const cmdk = {
  items: [], sel: 0,
  open() {
    const w = $("#cmdk");
    w.innerHTML = `<div class="cmdk"><input type="text" placeholder="Jump to a page, host, IP or threat… (type an IP to act on it)" aria-label="Search"><ul></ul>
      <div class="foot">↑↓ to move · Enter to open · Esc to close</div></div>`;
    w.classList.add("open");
    w.setAttribute("aria-hidden", "false");
    const inp = $("input", w);
    inp.oninput = () => { cmdk.sel = 0; cmdk.search(inp.value); };
    inp.onkeydown = (e) => {
      if (e.key === "ArrowDown") { cmdk.sel = Math.min(cmdk.items.length - 1, cmdk.sel + 1); cmdk.draw(); e.preventDefault(); }
      else if (e.key === "ArrowUp") { cmdk.sel = Math.max(0, cmdk.sel - 1); cmdk.draw(); e.preventDefault(); }
      else if (e.key === "Enter") { const it = cmdk.items[cmdk.sel]; if (it) { cmdk.close(); it.run(); } }
      else if (e.key === "Escape") cmdk.close();
    };
    w.onclick = (e) => { if (e.target === w) cmdk.close(); };
    cmdk.search("");
    inp.focus();
  },
  close() { const w = $("#cmdk"); w.classList.remove("open"); w.setAttribute("aria-hidden", "true"); w.innerHTML = ""; },
  search(q) {
    q = q.trim().toLowerCase();
    const out = [];
    const pages = ["overview", "traffic", "threats", "actions", "devices", "interfaces", "logs", "setup"];
    pages.forEach((p) => out.push({ kind: "page", label: p[0].toUpperCase() + p.slice(1), run: () => go(p) }));
    out.push({ kind: "layout", label: "Reset this page's layout", run: () => Layout.resetPage() });
    const snap = S.snap || { traffic: { hosts: [], peers: [] } };
    snap.traffic.hosts.forEach((h) => out.push({ kind: "LAN host", label: `${h.name || h.ip}  ${h.name ? h.ip : ""}`, key: h.ip, run: () => openHost(h.ip) }));
    snap.traffic.peers.forEach((p) => out.push({ kind: "Internet", label: `${p.name || p.ip}  ${p.name ? p.ip : ""}`, key: p.ip, run: () => openHost(p.ip) }));
    for (const t of S.threats.values()) if (t.status === "open" || t.status === "acknowledged") out.push({ kind: "threat", label: t.title, run: () => go("threats", { id: t.id }) });
    let res = q ? out.filter((i) => fuzzy(q, i.label.toLowerCase()) || (i.key || "").startsWith(q)) : out.slice(0, 12);
    if (/^[0-9a-f.:]{3,}$/i.test(q) && /^\d{1,3}(\.\d{1,3}){3}$|:/.test(q)) {
      res = [{ kind: "inspect", label: `Inspect ${q}`, run: () => openHost(q) },
        { kind: "respond", label: `Block ${q}…`, run: () => respond("block_ip", { ip: q }, "from the command palette") }].concat(res);
    }
    cmdk.items = res.slice(0, 40);
    cmdk.draw();
  },
  draw() {
    const ul = $("#cmdk ul");
    if (!ul) return;
    ul.innerHTML = cmdk.items.map((it, i) => `<li class="${i === cmdk.sel ? "on" : ""}" data-i="${i}"><span class="grow">${esc(it.label)}</span><span class="kind">${esc(it.kind)}</span></li>`).join("") ||
      '<li class="muted">Nothing matches</li>';
    $$("li[data-i]", ul).forEach((li) => (li.onclick = () => { const it = cmdk.items[+li.dataset.i]; cmdk.close(); it.run(); }));
    const on = $("li.on", ul);
    if (on) on.scrollIntoView({ block: "nearest" });
  },
};
function fuzzy(q, s) {
  let i = 0;
  for (const c of s) if (c === q[i]) i++;
  return i === q.length && (s.includes(q.slice(0, 2)));
}

/* ---------------- theme ---------------- */
function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } return null; }
function applyTheme(t) { document.documentElement.dataset.theme = t; store("mcc-theme", t); emit("theme"); }

/* ---------------- boot ---------------- */
document.addEventListener("DOMContentLoaded", () => {
  applyTheme(store("mcc-theme") || "dark");
  $("#theme-btn").onclick = () => applyTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light");
  $("#cmdk-btn").onclick = () => cmdk.open();
  $("#layout-btn").onclick = () => { Layout.resetPage(); toast("Layout reset", "Drag a panel's right or bottom edge to resize it; double-click an edge to reset one panel.", { good: true }); };
  $("#level").onclick = () => go("threats");
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); cmdk.open(); }
    else if (e.key === "Escape") {
      if ($("#cmdk").classList.contains("open")) cmdk.close();
      else if ($("#modal").classList.contains("open")) { const d = $("[data-dismiss]", $("#modal")); if (d) d.click(); else closeModal(); }
      else if (drawerIp) closeDrawer();
    }
  });
  window.addEventListener("hashchange", route);
  tickClock();
  setInterval(tickClock, 1000);
  setInterval(() => { if (S.lastTick && Date.now() - S.lastTick > 6000) setReconnect(true); }, 2000);
  route();
  connectStream();
});
