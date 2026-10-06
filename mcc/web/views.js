/* Pages. Each view: render(main, params), optional tick(), onThreat(), onAction(), onLogs(), leave(). */
"use strict";

/* ---------------- shared bits ---------------- */
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const STATUS_PILL = { open: "red", acknowledged: "amber", mitigated: "green", quiet: "", resolved: "", ignored: "blue" };
const IGNORE_FOR = { "24h": "24 hours", "7d": "7 days", "30d": "30 days", "0": "Forever" };

function switchKindLabel() {
  const k = S.snap && S.snap.status.switch.kind;
  return k === "routeros" ? "RouterOS" : k === "swos" ? "SwOS" : "switch";
}

function connected() { return S.snap && S.snap.status.router.state === "ok"; }

function connectBanner() {
  if (!S.snap) return "";
  const r = S.snap.status.router;
  if (r.state === "ok") return "";
  return `<div class="callout ${r.state === "error" ? "bad" : ""}" style="margin-bottom:14px">
    <b>${r.state === "error" ? "Lost the router" : "No router connected"}.</b> ${r.error ? esc(r.error) + ". " : ""}
    <a href="#/setup">Connect it in Setup</a> — passwords stay in memory only.</div>`;
}
function telemetryNudge() {
  if (!connected()) return "";
  const st = S.snap.status;
  if (st.flows.live || st.syslog.live) return "";
  return `<div class="callout warn" style="margin-bottom:14px"><b>Running on the router's REST API only.</b>
    Live connections and the memory log work now; flow export and syslog give MCC complete traffic accounting and
    real-time scan detection. <a href="#/setup">Review the exact router changes</a> — nothing is applied until you approve.</div>`;
}

function whoCell(name, ip) {
  return `<div class="who"><b>${esc(name || ip)}</b>${name ? `<span>${esc(ip)}</span>` : ""}</div>`;
}
function rateBars(down, up, max) {
  max = max || 1;
  const w = (v) => Math.max(1, Math.round(Math.sqrt(v / max) * 100));
  return `<div class="ratebar"><div style="width:${w(down)}%"></div><div class="u" style="width:${w(up)}%"></div></div>`;
}
function hostsTable(list, kind, limit) {
  if (!list.length) return `<div class="empty"><b>No traffic yet</b>${connected() ? "Waiting for the first connection-table read…" : "Connect a router to see traffic."}</div>`;
  const max = Math.max(...list.map((h) => Math.max(h.down, h.up)), 1);
  return `<table class="t"><thead><tr><th>${kind === "peer" ? "Remote" : "Host"}</th><th class="r">↓</th><th class="r">↑</th><th></th></tr></thead><tbody>
    ${list.slice(0, limit || 12).map((h) => `<tr class="click" data-ip="${esc(h.ip)}">
      <td><div class="who-row">${typeDot(h.cat)}${whoCell(h.name, h.ip + (h.geo ? " · " + (h.geo.city ? h.geo.city + ", " : "") + h.geo.cc : ""))}</div>${h.threat ? ` <span class="sev sv-${esc(h.threat)}"></span>` : ""}${h.blocked ? ' <span class="pill red">blocked</span>' : ""}</td>
      <td class="r num in">${fmt.bps(h.down)}</td><td class="r num out">${fmt.bps(h.up)}</td><td style="width:90px">${rateBars(h.down, h.up, max)}</td></tr>`).join("")}
  </tbody></table>`;
}
function servicesHtml(list) {
  if (!list.length) return '<div class="empty">No services yet.</div>';
  const max = Math.max(...list.map((s) => s.bps), 1);
  return list.slice(0, 10).map((s) => `<div class="svc"><span>${esc(s.label)} <span class="faint">· ${s.conns}</span></span><span class="num r" style="text-align:right">${fmt.bps(s.bps)}</span>
    <div class="bar"><i style="width:${Math.max(1, (s.bps / max) * 100).toFixed(1)}%"></i></div></div>`).join("");
}
/* ---- traffic types (mcc/classify.py): panel, legend, colour-mode switch ---- */
function typesHtml(types) {
  const list = (types || []).filter((t) => t.bps > 0);
  if (!list.length) return '<div class="empty">No classified traffic yet.</div>';
  const total = list.reduce((a, t) => a + t.bps, 0) || 1;
  return `<div class="tbar big">${list.map((t) => `<i style="width:${((t.bps / total) * 100).toFixed(2)}%;background:${Types.color(t.id)}" title="${esc(t.label)}"></i>`).join("")}</div>
    <div class="types">${list.map((t) => `<div class="trow ${Types.focus === t.id ? "on" : ""} ${Types.focus && Types.focus !== t.id ? "dim" : ""}" data-type="${esc(t.id)}" title="Click to highlight ${esc(t.label)} in the map, globe and conversations">
      <i class="tdot" style="background:${Types.color(t.id)}"></i><span class="tl-name">${esc(t.label)}</span>
      <span class="num faint">${Math.round((t.bps / total) * 100)}%</span><span class="num in">${fmt.bps(t.down)}</span><span class="num out">${fmt.bps(t.up)}</span>
      <span class="faint tl-sub">${t.hosts} host${t.hosts === 1 ? "" : "s"} · ${t.peers} peer${t.peers === 1 ? "" : "s"}</span></div>`).join("")}</div>`;
}
function typeDot(cat) {
  return cat ? `<i class="tdot" style="background:${Types.color(cat)}" title="${esc(Types.label(cat))}"></i>` : "";
}
/* every live panel: legend over the map/globe and the Type/Direction switch */
function refreshTypeUI() {
  const types = S.snap && S.snap.traffic.types;
  $$(".type-legend").forEach((el) => { el.innerHTML = Types.legend(types); });
  $$(".color-by button").forEach((b) => b.classList.toggle("on", b.dataset.by === Types.by));
}
document.addEventListener("click", (e) => {
  const t = e.target.closest(".type-legend [data-type], .types [data-type], [data-type-filter]");
  if (t) { Types.toggleFocus(t.dataset.type || t.dataset.typeFilter); return; }
  const b = e.target.closest(".color-by [data-by]");
  if (b) Types.setBy(b.dataset.by);
});
on("types", () => {
  refreshTypeUI();
  if (current && current.view.onTypes) current.view.onTypes();
});

function bindRows(root) {
  $$("tr[data-ip]", root).forEach((tr) => (tr.onclick = () => openHost(tr.dataset.ip)));
}

/* Per-second panel refreshes without stutter. Rewriting a few thousand table cells every second costs
   one long frame, and the globe and flow map visibly hitch on it. So a refresh
   - is dropped when the HTML hasn't changed,
   - waits while its panel is scrolled out of view (it's applied the moment the panel comes back),
   - and is applied a few panels per animation frame, never all in one. */
const Live = (() => {
  const queue = new Map();  // element -> after() callback
  let raf = 0;
  const seen = new IntersectionObserver((entries) => entries.forEach((e) => {
    e.target._onScreen = e.isIntersecting;
    if (e.isIntersecting && e.target._pending != null) queue.set(e.target, e.target._after), kick();
  }), { rootMargin: "200px" });
  function kick() { if (!raf) raf = requestAnimationFrame(flush); }
  function flush() {
    raf = 0;
    const t0 = performance.now();
    for (const [el, after] of queue) {
      queue.delete(el);
      if (el.isConnected && el._pending != null) {
        el.innerHTML = el._html = el._pending;
        el._pending = null;
        if (after) after(el);
      }
      if (performance.now() - t0 > 4) break;  // the rest next frame
    }
    if (queue.size) kick();
  }
  /* set(el, html, after): after(el) runs once the HTML is in (e.g. to bind row clicks) */
  function set(el, html, after) {
    if (!el) return;
    if (!el._watched) { el._watched = true; el._onScreen = true; seen.observe(el); }
    if (html === el._html) { el._pending = null; return; }
    el._pending = html; el._after = after;
    if (el._onScreen) { queue.set(el, after); kick(); }
  }
  return { set };
})();

function portsHtml(ports) {
  if (!ports || !ports.length) {
    const sw = S.snap.status.switch;
    const title = sw.state === "error" ? "Switch unreachable" : sw.state === "ok" ? "Switch connected — waiting for port data" : "No switch connected";
    return `<div class="empty"><b>${title}</b>${sw.error ? esc(sw.error) : sw.state === "ok" ? 'If this doesn\'t fill in, open <a href="#/setup">Setup › Switch probe</a>.' : 'Add your switch in <a href="#/setup">Setup</a> (RouterOS or SwOS, read-only).'}</div>`;
  }
  const cap = (sp) => ({ "10G": 1e10, "1G": 1e9, "2.5G": 2.5e9, "5G": 5e9, "100M": 1e8, "10M": 1e7, "25G": 2.5e10 }[sp] || 1e9);
  const threats = [...S.threats.values()].filter((t) => t.rule === "link_down" && t.status === "open" && t.role === "switch").map((t) => t.target);
  return `<div class="ports">${ports.map((p) => {
    const util = p.rx_bps != null ? Math.min(100, ((p.rx_bps + (p.tx_bps || 0)) / cap(p.speed)) * 100) : 0;
    const cls = p.enabled === false ? "disabled" : p.link ? "up" : "down";
    return `<div class="port ${cls} ${threats.includes(p.name) ? "alert" : ""}" data-port="${p.n}" title="${esc(p.name)} — ${p.link ? "link up" : "no link"}${p.speed ? " · " + esc(p.speed) : ""}">
      <div class="pn"><span>${esc(p.name)}</span><span class="led"></span></div>
      <div class="sp">${p.link ? esc(p.speed || "up") : "—"}</div>
      <div class="rates"><span class="in">↓${p.tx_bps != null ? fmt.bps(p.tx_bps) : "—"}</span><br><span class="out">↑${p.rx_bps != null ? fmt.bps(p.rx_bps) : "—"}</span></div>
      <div class="util"><i style="width:${util.toFixed(1)}%"></i></div></div>`;
  }).join("")}</div>`;
}

function wanSeries() {
  const names = (S.snap && S.snap.wan.names) || [];
  if (!names.length) return [[], []];
  const base = S.hist.ifaces[names[0]] || [];
  if (names.length === 1) return [base.map((r) => [r[0], r[1]]), base.map((r) => [r[0], r[2]])];
  const others = names.slice(1).map((n) => S.hist.ifaces[n] || []);
  const rx = [], tx = [];
  base.forEach((r, i) => {
    let a = r[1], b = r[2];
    others.forEach((o) => { const q = o[o.length - base.length + i]; if (q) { a += q[1]; b += q[2]; } });
    rx.push([r[0], a]); tx.push([r[0], b]);
  });
  return [rx, tx];
}

/* ---------------- threats ---------------- */
function sortedThreats(filter) {
  const list = [...S.threats.values()].filter(filter || (() => true));
  const live = (t) => (t.status === "open" ? 2 : t.status === "acknowledged" ? 1 : 0);
  return list.sort((a, b) => live(b) - live(a) || SEV_ORDER[b.severity] - SEV_ORDER[a.severity] || b.last_ts - a.last_ts);
}
function threatCard(t, full) {
  const rule = S.rules[t.rule] || {};
  const props = t.proposals || [];
  const live = t.status === "open" || t.status === "acknowledged";
  const acts = [];
  if (live && props.length) acts.push(`<button class="btn sm danger" data-respond="${esc(t.id)}">${ICON.shield} Respond…</button>`);
  if (t.status === "open") acts.push(`<button class="btn sm" data-status="acknowledged" data-tid="${esc(t.id)}">${ICON.check} Acknowledge</button>`);
  if (live && full) acts.push(`<button class="btn sm ghost" data-status="resolved" data-tid="${esc(t.id)}">Resolve</button>`);
  if (!live && full) acts.push(`<button class="btn sm ghost" data-status="open" data-tid="${esc(t.id)}">Reopen</button>`);
  if (t.subject) acts.push(`<button class="btn sm ghost" data-host="${esc(t.subject)}">${ICON.eye} ${esc(t.subject)}</button>`);
  if (t.rule === "new_device" && live) acts.push(`<button class="btn sm" data-known="${esc(t.target)}">Mark as known</button>`);
  const sup = t.status === "ignored" ? S.ignore.find((x) => x.id === t.ignored_by) : null;
  if (t.status !== "ignored") acts.push(`<button class="btn sm ghost" data-ignore="${esc(t.id)}" title="Confirmed false positive: stop alerting on it">${ICON.x} Ignore…</button>`);
  else if (sup) acts.push(`<button class="btn sm" data-unignore="${esc(sup.id)}">${ICON.undo} Stop ignoring</button>`);
  const ignoredLine = t.status === "ignored"
    ? `<div class="why" style="border-left-color:var(--accent)">False positive${sup ? ` · ${esc(sup.id)} · ${esc(ignoreScopeText(sup))}${sup.note ? ` — “${esc(sup.note)}”` : ""} · ${sup.hits} silenced since` : " · ignore rule since removed"}</div>` : "";
  return `<div class="tcard ${live ? "" : "dim"}" id="th-${esc(t.id)}" data-tid="${esc(t.id)}" style="--sv:var(--${sevVar(t.severity)})">
    <div class="row1"><span class="sev sv-${esc(t.severity)}">${esc(t.severity)}</span><span class="faint" style="font-size:12px">${esc(t.rule_name || rule.name || t.rule)}</span>
      <span class="grow"></span>${t.status !== "open" ? `<span class="pill ${STATUS_PILL[t.status] || ""}">${esc(t.status)}</span>` : ""}<span class="faint" style="font-size:12px">${fmt.ago(t.last_ts)}</span></div>
    <h3>${esc(t.title)}</h3><p>${esc(t.summary)}</p>
    <div class="meta"><span>×${t.count}</span><span>first ${fmt.ago(t.first_ts)}</span>${t.target && t.target !== t.subject ? `<span>target ${esc(t.target)}</span>` : ""}
      ${t.reopened ? `<span class="pill amber">came back after mitigation</span>` : ""}${(t.mitigated_by || []).length ? `<span>by ${t.mitigated_by.map(esc).join(", ")}</span>` : ""}</div>
    ${ignoredLine}
    ${full ? `<div class="why">${esc(rule.why || "")}</div>${(t.evidence || []).length ? `<div class="evidence">${t.evidence.slice().reverse().map((e) => esc(fmt.time(e.ts) + "  " + e.text)).join("\n")}</div>` : ""}` : ""}
    <div class="acts">${acts.join("")}</div></div>`;
}
function bindThreatCards(root, onOpen) {
  $$("[data-respond]", root).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); chooseResponse(S.threats.get(b.dataset.respond)); }));
  $$("[data-status]", root).forEach((b) => (b.onclick = async (e) => {
    e.stopPropagation();
    try { const t = await api.post(`/api/threats/${b.dataset.tid}/status`, { status: b.dataset.status }); S.threats.set(t.id, t); emit("threats", t); }
    catch (err) { toast("Couldn't update", err.message, { bad: true }); }
  }));
  $$("[data-host]", root).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); openHost(b.dataset.host); }));
  $$("[data-known]", root).forEach((b) => (b.onclick = async (e) => {
    e.stopPropagation();
    try { await api.post("/api/devices/known", { mac: b.dataset.known }); toast("Marked as known", b.dataset.known, { good: true }); }
    catch (err) { toast("Couldn't update", err.message, { bad: true }); }
  }));
  $$("[data-ignore]", root).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); ignoreThreat(S.threats.get(b.dataset.ignore)); }));
  $$("[data-unignore]", root).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); stopIgnoring(b.dataset.unignore); }));
  if (onOpen) $$(".tcard[data-tid]", root).forEach((c) => (c.onclick = () => onOpen(c.dataset.tid)));
}

/* ---------------- false positives: ignore rules ---------------- */
function ignoreScopeText(x) {
  if (x.scope === "exact") return `${x.rule_name}, this exact case (${x.key})`;
  if (x.scope === "subject") return `${x.rule_name} for ${x.subject}`;
  return `every rule for ${x.subject}`;
}
function ignoreThreat(t) {
  if (!t) return;
  const rn = t.rule_name || t.rule;
  const scopes = [["exact", `Just this alert`, `${esc(rn)} for <span class="mono">${esc(t.key)}</span>. Anything else from the same address still alerts.`]];
  if (t.subject) {
    scopes.push(["subject", `${esc(rn)} for anything involving ${esc(t.subject)}`, "Any port, any target — this rule stays quiet for this address."]);
    scopes.push(["subject_any", `Every rule for ${esc(t.subject)}`, `<span style="color:var(--high)">MCC won't alert on anything this address does.</span> Only for hosts you fully trust.`]);
  }
  openModal(`<header><div class="grow"><div class="faint" style="font-size:12px;letter-spacing:.1em;text-transform:uppercase">Mark ${esc(t.id)} as a false positive</div><h2>${esc(t.title)}</h2></div>
      <button class="icon-btn" data-x aria-label="Close">${ICON.x}</button></header>
    <div class="mbody">
      <div class="muted">${esc(t.summary)}</div>
      <div><h4 style="margin:0 0 8px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)">Stop alerting on</h4>
        ${scopes.map(([k, label, hint], i) => `<label class="check" style="align-items:flex-start;margin:0 0 10px"><input type="radio" name="iscope" value="${k}" ${i === 0 ? "checked" : ""} style="margin-top:3px">
          <span><b>${label}</b><br><span class="note">${hint}</span></span></label>`).join("")}</div>
      <div class="btnrow"><span class="muted">For</span><div class="seg" id="idur">${Object.entries(IGNORE_FOR).map(([k, l]) => `<button type="button" data-d="${k}" class="${k === "0" ? "on" : ""}">${l}</button>`).join("")}</div></div>
      <div><label class="muted" for="inote" style="font-size:13px">Why is it a false positive?</label>
        <textarea id="inote" rows="2" placeholder="e.g. the NAS's nightly offsite backup to S3" style="margin-top:6px"></textarea></div>
      <div class="note">Matching events are still counted against the ignore rule, so you can see what it silences, but they no longer raise threats, toasts or the threat level. Review or remove it any time in Threats › Ignore list. The router is not changed.</div>
    </div>
    <footer><span class="grow"></span><button class="btn" data-x>Cancel</button><button class="btn primary" data-go autofocus>${ICON.check} Ignore</button></footer>`,
  (m) => {
    $$("[data-x]", m).forEach((b) => (b.onclick = closeModal));
    let dur = "0";
    $("#idur", m).onclick = (e) => { const b = e.target.closest("[data-d]"); if (!b) return; dur = b.dataset.d; $$("#idur button", m).forEach((x) => x.classList.toggle("on", x === b)); };
    $("[data-go]", m).onclick = async (e) => {
      e.target.disabled = true;
      const scope = $("input[name=iscope]:checked", m).value;
      try {
        const r = await api.post(`/api/threats/${t.id}/ignore`, { scope, duration: dur, note: $("#inote", m).value });
        S.threats.set(r.threat.id, r.threat);
        closeModal();
        toast(`Ignoring: ${ignoreScopeText(r.ignore)}`, dur === "0" ? "Until you remove it." : `For ${IGNORE_FOR[dur]}.`, { good: true });
        emit("threats", r.threat);
      } catch (err) { e.target.disabled = false; toast("Couldn't ignore", err.message, { bad: true, ms: 9000 }); }
    };
  });
}
async function stopIgnoring(id) {
  try {
    const r = await api.post(`/api/ignore/${id}/remove`, {});
    toast(`Stopped ignoring (${r.id})`, "It alerts again if it recurs.", { good: true });
  } catch (err) { toast("Couldn't remove", err.message, { bad: true }); }
}
function chooseResponse(t) {
  if (!t) return;
  const props = t.proposals || [];
  if (props.length === 1) return respond(props[0].kind, props[0].params, t.title, t.id);
  openModal(`<header><div class="grow"><div class="faint" style="font-size:12px;letter-spacing:.1em;text-transform:uppercase">Respond to ${esc(t.id)}</div><h2>${esc(t.title)}</h2></div>
      <button class="icon-btn" data-x aria-label="Close">${ICON.x}</button></header>
    <div class="mbody"><div class="muted">${esc(t.summary)}</div><div class="note">Pick a response. You'll see exactly what it changes on the router before anything happens.</div>
      <div class="changes">${props.map((p, i) => `<button class="btn" style="justify-content:flex-start;padding:10px 12px" data-i="${i}">${ICON[{ block_ip: "block", quarantine_host: "quarantine", kill_connections: "cut" }[p.kind] || "shield"]} ${esc(p.label)}</button>`).join("")}</div></div>
    <footer><span class="grow"></span><button class="btn" data-x>Cancel</button></footer>`,
  (m) => {
    $$("[data-x]", m).forEach((b) => (b.onclick = closeModal));
    $$("[data-i]", m).forEach((b) => (b.onclick = () => { const p = props[+b.dataset.i]; closeModal(); respond(p.kind, p.params, t.title, t.id); }));
  });
}

/* ================= Overview ================= */
VIEWS.overview = {
  render(m) {
    m.innerHTML = `${connectBanner()}${telemetryNudge()}
      <div class="kpis" id="kpis"></div>
      <div class="grid">
        <section class="panel s8" data-pid="overview:live"><header><h2>Live traffic</h2><span class="grow"></span><span class="hint" id="map-src"></span>
          <div class="seg color-by" title="Colour the traffic by type or by direction"><button data-by="type">Type</button><button data-by="direction">Direction</button></div>
          <div class="seg" id="live-kind"><button data-k="globe">Globe</button><button data-k="map">Flow map</button></div></header>
          <div id="live" class="globe-wrap"></div></section>
        <section class="panel s4"><header><h2>Threat feed</h2><span class="grow"></span><a class="hint" href="#/threats">all threats →</a></header><div class="feed" id="feed" style="height:470px"></div></section>
        <section class="panel s7"><header><h2>Internet throughput</h2><span class="grow"></span><span class="legend"><span><i style="background:var(--in)"></i>download</span><span><i style="background:var(--out)"></i>upload</span></span></header>
          <div class="body"><div class="chart"><canvas id="wan-chart"></canvas></div></div></section>
        <section class="panel s5"><header><h2>Switch</h2><span class="grow"></span><span class="hint" id="sw-id"></span></header><div class="body" id="ports"></div></section>
        <section class="panel s4"><header><h2>Top LAN talkers</h2><span class="grow"></span><a class="hint" href="#/traffic">traffic →</a></header><div class="body flush scroll" style="max-height:340px" id="talkers"></div></section>
        <section class="panel s4"><header><h2>Top destinations</h2></header><div class="body flush scroll" style="max-height:340px" id="dests"></div></section>
        <section class="panel s4" data-pid="overview:types"><header><h2>Traffic types</h2><span class="grow"></span><a class="hint" href="#/traffic">by conversation →</a></header>
          <div class="body scroll" style="max-height:340px" id="types"></div></section>
      </div>`;
    this.mountLive(liveKind());
    $("#live-kind", m).onclick = (e) => { const b = e.target.closest("[data-k]"); if (b) this.mountLive(b.dataset.k); };
    this.feedKey = null;
    this.n = 0;
    this.tick();
  },
  tick() {
    const s = S.snap, r = s.router || {}, tr = s.traffic;
    const [rx, tx] = wanSeries();
    const spark = (arr) => arr.slice(-90).map((p) => p[1]);
    const capD = s.wan.down_mbps ? s.wan.down_mbps * 1e6 : 0, capU = s.wan.up_mbps ? s.wan.up_mbps * 1e6 : 0;
    const memPct = r.mem_total ? (r.mem_used * 100) / r.mem_total : null;
    const [dv, du] = fmt.bpsParts(s.wan.rx_bps), [uv, uu] = fmt.bpsParts(s.wan.tx_bps);
    const usage = (bps, cap, mbps) => { const pct = Math.round((bps / cap) * 100); return `<span style="color:${pct >= 90 ? "var(--crit)" : "inherit"}">${pct}% of ${mbps} Mb/s</span>`; };
    const pctColor = (v) => (v >= 90 ? "var(--crit)" : v >= 70 ? "var(--high)" : "var(--accent)");
    $("#kpis").innerHTML = `
      <div class="panel kpi"><div class="k in">↓ Download</div><div class="v">${dv}<small>${du}</small></div>
        <div class="sub">${capD ? usage(s.wan.rx_bps, capD, s.wan.down_mbps) : esc(s.wan.names.join(", ") || "WAN")}</div><canvas class="spark" id="sp-d"></canvas></div>
      <div class="panel kpi"><div class="k out">↑ Upload</div><div class="v">${uv}<small>${uu}</small></div>
        <div class="sub">${capU ? usage(s.wan.tx_bps, capU, s.wan.up_mbps) : esc(s.wan.names.join(", ") || "WAN")}</div><canvas class="spark" id="sp-u"></canvas></div>
      <div class="panel kpi"><div class="k">CPU</div><div class="v">${fmt.pct(r.cpu)}</div><div class="sub">${r.cpu_count || "?"} cores · ${esc(r.arch || "")}</div>${Charts.gauge(r.cpu, pctColor(r.cpu || 0))}</div>
      <div class="panel kpi"><div class="k">Memory</div><div class="v">${fmt.pct(memPct)}</div><div class="sub">${fmt.bytes(r.mem_used)} of ${fmt.bytes(r.mem_total)}</div>${Charts.gauge(memPct, pctColor(memPct || 0))}</div>
      <div class="panel kpi"><div class="k">Temperature</div><div class="v">${r.temp != null ? Math.round(r.temp) + "<small>°C</small>" : "—"}</div><div class="sub">${r.voltage ? r.voltage + " V" : "router health"}</div></div>
      <div class="panel kpi clickable" data-go="traffic"><div class="k">Connections</div><div class="v">${tr.conns.toLocaleString()}</div><div class="sub">${tr.host_count} hosts · ${tr.peer_count} peers</div></div>
      <div class="panel kpi clickable" data-go="threats"><div class="k">Open threats</div><div class="v" style="color:${s.counts.threats_open ? "var(--crit)" : "var(--ok)"}">${s.counts.threats_open}</div>
        <div class="sub">${s.counts.blocked} blocked · ${s.counts.actions_pending} pending</div></div>`;
    $$("[data-go]", $("#kpis")).forEach((k) => (k.onclick = () => go(k.dataset.go)));
    Charts.spark($("#sp-d"), spark(rx), cssVar("--in"));
    Charts.spark($("#sp-u"), spark(tx), cssVar("--out"));
    this.map.update(s);
    $("#map-src").textContent = geoHint(s);
    if (this.kind === "map") $("#map-src").textContent = { conntrack: "live · connection table", flows: "flow records (IPFIX)", none: "no data yet" }[tr.source];
    Charts.line($("#wan-chart"), [{ data: rx, color: cssVar("--in"), fill: true, label: "↓" }, { data: tx, color: cssVar("--out"), fill: true, label: "↑" }],
      { window: 1800, yfmt: fmt.bps, mirror: true });
    Live.set($("#ports"), portsHtml(s.switch.ports),
      (el) => $$("[data-port]", el).forEach((p) => (p.onclick = () => go("interfaces", { port: p.dataset.port }))));
    const sys = s.switch.sys || {};
    $("#sw-id").textContent = [sys.identity, sys.model, sys.version && (sys.os === "routeros" ? sys.version : "SwOS " + sys.version)].filter(Boolean).join(" · ");
    Live.set($("#talkers"), hostsTable(tr.hosts, "host", 10), bindRows);
    Live.set($("#dests"), hostsTable(tr.peers, "peer", 10), bindRows);
    Live.set($("#types"), typesHtml(tr.types));
    refreshTypeUI();
    if (++this.n % 10 === 0) this.feedKey = null;
    this.drawFeed();
  },
  drawFeed() {
    const cutoff = Date.now() / 1000 - 3600;
    const list = sortedThreats((t) => t.status === "open" || t.status === "acknowledged" || (t.last_ts > cutoff && t.status === "mitigated")).slice(0, 30);
    const key = list.map((t) => t.id + t.status + t.count + t.severity).join("|");
    if (key === this.feedKey) return;
    const fresh = new Set(list.filter((t) => !(this.feedKey || "").includes(t.id)).map((t) => t.id));
    const first = !this.feedKey;
    this.feedKey = key;
    const feed = $("#feed");
    feed.innerHTML = list.length ? list.map((t) => threatCard(t, false)).join("") :
      `<div class="empty" style="margin:auto"><b style="color:var(--ok)">All quiet</b>No open threats. MCC is watching ${connected() ? "your network" : "— once a router is connected"}.</div>`;
    if (!first) fresh.forEach((id) => { const c = $("#th-" + id, feed); if (c) c.classList.add("fresh"); });
    bindThreatCards(feed, (id) => go("threats", { id }));
  },
  onThreat() { this.drawFeed(); },
  onTypes() { const el = $("#types"); if (el && S.snap) Live.set(el, typesHtml(S.snap.traffic.types)); },
  mountLive(kind) {
    if (this.map) this.map.destroy();
    this.kind = kind;
    try { localStorage.setItem("mcc-live-view", kind); } catch (e) { /* */ }
    $$("#live-kind button").forEach((b) => b.classList.toggle("on", b.dataset.k === kind));
    const host = $("#live");
    host.className = kind === "globe" ? "globe-wrap" : "map-wrap";
    host.innerHTML = kind === "map" ? '<div class="map-legend type-legend"></div>' : "";
    this.map = kind === "globe" ? Globe.create(host) : TrafficMap.create(host);
    if (S.snap) this.map.update(S.snap);
    refreshTypeUI();
  },
  leave() { if (this.map) this.map.destroy(); },
};

function liveKind() {
  try { return localStorage.getItem("mcc-live-view") || "globe"; } catch (e) { return "globe"; }
}
function geoHint(s) {
  const g = s.geo || {};
  if (g.source === "none") return "no geolocation database";
  return `${g.located}/${g.peers} peers located${g.source === "demo" ? " · simulated" : ""}`;
}
function countriesTable(list) {
  if (!list || !list.length) return '<div class="empty">No located traffic yet.</div>';
  const max = Math.max(...list.map((c) => Math.max(c.down, c.up)), 1);
  return `<table class="t"><thead><tr><th>Country</th><th class="r">Peers</th><th class="r">↓</th><th class="r">↑</th><th></th></tr></thead><tbody>
    ${list.map((c) => `<tr><td><b class="mono" style="${c.threat ? "color:var(--crit)" : ""}">${esc(c.cc || "?")}</b> ${esc(c.country || "")}</td><td class="r num">${c.peers}</td>
      <td class="r num in">${fmt.bps(c.down)}</td><td class="r num out">${fmt.bps(c.up)}</td><td style="width:90px">${rateBars(c.down, c.up, max)}</td></tr>`).join("")}
  </tbody></table>`;
}

/* ================= Traffic ================= */
VIEWS.traffic = {
  render(m) {
    this.q = "";
    m.innerHTML = `${connectBanner()}${telemetryNudge()}
      <div class="grid">
        <section class="panel s12"><header><h2>Traffic map</h2><span class="grow"></span><span class="hint" id="t-src"></span><div class="seg color-by" title="Colour the traffic by type or by direction"><button data-by="type">Type</button><button data-by="direction">Direction</button></div></header>
          <div class="map-wrap tall" id="map"><div class="map-legend type-legend"></div></div></section>
        <section class="panel s8" data-pid="traffic:globe"><header><h2>Where it goes</h2><span class="grow"></span><span class="hint" id="g-src"></span></header>
          <div class="globe-wrap" id="globe"></div></section>
        <section class="panel s4" data-pid="traffic:types"><header><h2>Traffic types</h2><span class="grow"></span><span class="hint">click one to highlight it</span></header>
          <div class="body scroll" style="max-height:470px" id="types"></div></section>
        <section class="panel s12"><header><h2>Conversations</h2><span class="grow"></span><input type="text" id="t-q" placeholder="Filter by host, IP or service" style="max-width:280px"></header>
          <div class="body flush scroll" style="max-height:440px" id="pairs"></div></section>
        <section class="panel s3"><header><h2>LAN hosts</h2></header><div class="body flush scroll" style="max-height:420px" id="hosts"></div></section>
        <section class="panel s3"><header><h2>Internet peers</h2></header><div class="body flush scroll" style="max-height:420px" id="peers"></div></section>
        <section class="panel s3"><header><h2>Services</h2></header><div class="body flush services scroll" style="max-height:420px;padding:6px 0" id="svcs"></div></section>
        <section class="panel s3" data-pid="traffic:countries"><header><h2>Countries</h2></header><div class="body flush scroll" style="max-height:420px" id="countries"></div></section>
      </div>`;
    this.map = TrafficMap.create($("#map", m), { peers: 18, hosts: 16 });
    this.globe = Globe.create($("#globe", m));
    $("#t-q", m).oninput = (e) => { this.q = e.target.value.toLowerCase(); this.tick(); };
    this.tick();
  },
  tick() {
    const tr = S.snap.traffic;
    this.map.update(S.snap);
    this.globe.update(S.snap);
    $("#g-src").textContent = geoHint(S.snap);
    Live.set($("#countries"), countriesTable((S.snap.geo || {}).countries));
    $("#t-src").textContent = `${tr.conns.toLocaleString()} connections · source: ${tr.source}`;
    const names = {};
    tr.hosts.forEach((h) => (names[h.ip] = h.name));
    tr.peers.forEach((p) => (names[p.ip] = p.name));
    const q = this.q;
    const focus = Types.focus;
    const rows = tr.pairs.filter((p) => (!focus || p.cat === focus) &&
      (!q || [p.local, p.remote, names[p.local], names[p.remote], p.service, Types.label(p.cat)].some((v) => (v || "").toLowerCase().includes(q))));
    const max = Math.max(...rows.map((p) => Math.max(p.down, p.up)), 1);
    Live.set($("#types"), typesHtml(tr.types));
    refreshTypeUI();
    const note = focus ? `<div class="focus-note"><i class="tdot" style="background:${Types.color(focus)}"></i>Showing only <b>${esc(Types.label(focus))}</b>
      <button class="btn sm ghost" data-type-filter="${esc(focus)}">${ICON.x} Show all types</button></div>` : "";
    Live.set($("#pairs"), note + (rows.length ? `<table class="t"><thead><tr><th>LAN host</th><th></th><th>Remote</th><th>Type</th><th>Service</th><th class="r">Conns</th><th class="r">↓</th><th class="r">↑</th><th></th></tr></thead><tbody>
      ${rows.map((p) => `<tr class="click" data-ip="${esc(p.dir === "lan" ? p.local : p.remote)}"><td>${whoCell(names[p.local], p.local)}</td><td class="faint">${p.dir === "in" ? "⇠" : p.dir === "lan" ? "⇄" : "⇢"}</td>
        <td>${whoCell(names[p.remote], p.remote)}</td><td><span class="tchip" title="${esc(p.cat_why || "")}">${typeDot(p.cat)}${esc(Types.label(p.cat))}</span></td>
        <td>${esc(p.service)}</td><td class="r num">${p.conns}</td><td class="r num in">${fmt.bps(p.down)}</td><td class="r num out">${fmt.bps(p.up)}</td><td style="width:100px">${rateBars(p.down, p.up, max)}</td></tr>`).join("")}
      </tbody></table>` : '<div class="empty">No conversations match.</div>'), bindRows);
    Live.set($("#hosts"), hostsTable(tr.hosts, "host", 60), bindRows);
    Live.set($("#peers"), hostsTable(tr.peers, "peer", 80), bindRows);
    Live.set($("#svcs"), servicesHtml(tr.services));
  },
  onTypes() { if (S.snap && $("#pairs")) this.tick(); },
  leave() { if (this.map) this.map.destroy(); if (this.globe) this.globe.destroy(); },
};

/* ================= Threats ================= */
VIEWS.threats = {
  render(m, params) {
    this.filter = this.filter || "active";
    this.q = "";
    this.focus = params.id || "";
    m.innerHTML = `<div class="toolbar"><div class="seg" id="tf">${[["active", "Active"], ["mitigated", "Mitigated"], ["quiet", "Quiet / resolved"], ["ignored", "Ignored"], ["all", "All"], ["rules", "Ignore list"]]
      .map(([k, l]) => `<button data-f="${k}" class="${this.filter === k ? "on" : ""}">${l}${k === "rules" ? ' <b class="badge info" id="nb-ign"></b>' : ""}</button>`).join("")}</div>
      <input type="text" id="tq" placeholder="Search threats, IPs…"><span class="grow"></span>
      <span class="note">MCC suggests responses; nothing changes on the router until you confirm one.</span></div>
      <div class="panel"><div class="feed" id="tlist"></div></div>`;
    $("#tf", m).onclick = (e) => { const b = e.target.closest("[data-f]"); if (!b) return; this.filter = b.dataset.f; $$("#tf button").forEach((x) => x.classList.toggle("on", x === b)); this.draw(); };
    $("#tq", m).oninput = (e) => { this.q = e.target.value.toLowerCase(); this.draw(); };
    this.draw();
    if (this.focus) {
      const t = S.threats.get(this.focus);
      if (t && !this.match(t)) { this.filter = "all"; $$("#tf button").forEach((x) => x.classList.toggle("on", x.dataset.f === "all")); this.draw(); }
      const el = $("#th-" + this.focus);
      if (el) { el.scrollIntoView({ block: "center" }); el.classList.add("fresh"); }
    }
  },
  match(t) {
    const f = this.filter;
    if (f === "active" && !(t.status === "open" || t.status === "acknowledged")) return false;
    if (f === "mitigated" && t.status !== "mitigated") return false;
    if (f === "quiet" && !(t.status === "quiet" || t.status === "resolved")) return false;
    if (f === "ignored" && t.status !== "ignored") return false;
    if (this.q && ![t.title, t.summary, t.subject, t.target, t.rule_name].some((v) => (v || "").toLowerCase().includes(this.q))) return false;
    return true;
  },
  draw() {
    const el = $("#tlist");
    if (!el) return;
    $("#nb-ign").textContent = S.ignore.length || "";
    if (this.filter === "rules") return this.drawRules(el);
    const list = sortedThreats((t) => this.match(t));
    const top = el.scrollTop;
    const nIgn = [...S.threats.values()].filter((t) => t.status === "ignored").length;
    el.innerHTML = list.length ? list.map((t) => threatCard(t, true)).join("") :
      `<div class="empty"><b>${this.filter === "active" ? "Nothing active" : "Nothing here"}</b>${this.filter === "active" ? "No open threats right now." + (nIgn ? ` ${nIgn} ignored as false positives.` : "") : ""}</div>`;
    el.scrollTop = top;
    bindThreatCards(el);
  },
  drawRules(el) {
    const now = Date.now() / 1000;
    const ruleOpts = Object.entries(S.rules).map(([k, r]) => `<option value="${esc(k)}">${esc(r.name)}</option>`).join("");
    el.innerHTML = `<div class="body">
      <div class="note" style="margin-bottom:12px">Confirmed false positives. Events that match are counted here but never raise a threat. Removing a rule makes MCC alert again the next time it happens.</div>
      ${S.ignore.length ? `<table class="t"><thead><tr><th>ID</th><th>Ignoring</th><th>Why</th><th class="r">Silenced</th><th>Until</th><th></th></tr></thead><tbody>
        ${S.ignore.map((x) => `<tr><td class="mono">${esc(x.id)}</td>
          <td><b>${esc(ignoreScopeText(x))}</b>${x.title ? `<div class="muted" style="font-size:12px">from: ${esc(x.title)}${x.threat_id ? " (" + esc(x.threat_id) + ")" : ""}</div>` : ""}
            ${x.scope === "subject_any" ? '<div style="font-size:12px;color:var(--high)">covers every rule</div>' : ""}</td>
          <td class="muted">${esc(x.note || "—")}</td>
          <td class="r num">${x.hits}<div class="faint" style="font-size:12px">${x.last_hit ? "last " + fmt.ago(x.last_hit) : "none yet"}</div></td>
          <td class="num">${x.expires ? fmt.dur(x.expires - now) + " left" : "forever"}<div class="faint" style="font-size:12px">added ${fmt.ago(x.created_ts)}</div></td>
          <td class="r"><button class="btn sm" data-unignore="${esc(x.id)}">${ICON.undo} Remove</button></td></tr>`).join("")}</tbody></table>`
        : '<div class="empty"><b>No ignore rules</b>Use <b>Ignore…</b> on a threat you have confirmed is a false positive.</div>'}
      <h4 style="margin:22px 0 10px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)">Add one by hand</h4>
      <form class="form" id="f-ign">
        <label for="ig-sub">Address or network</label><input type="text" id="ig-sub" placeholder="e.g. 192.168.88.10 or 203.0.113.0/24" required>
        <label for="ig-rule">Rule</label><select id="ig-rule"><option value="*">All rules (trust this address completely)</option>${ruleOpts}</select>
        <label for="ig-dur">For</label><select id="ig-dur">${Object.entries(IGNORE_FOR).map(([k, l]) => `<option value="${k}" ${k === "0" ? "selected" : ""}>${l}</option>`).join("")}</select>
        <label for="ig-note">Why</label><input type="text" id="ig-note" placeholder="e.g. vulnerability scanner we run on purpose">
        <span></span><div><button class="btn primary" type="submit">Add ignore rule</button></div>
      </form></div>`;
    $$("[data-unignore]", el).forEach((b) => (b.onclick = () => stopIgnoring(b.dataset.unignore)));
    $("#f-ign", el).onsubmit = async (e) => {
      e.preventDefault();
      const rule = $("#ig-rule").value;
      try {
        const x = await api.post("/api/ignore", { subject: $("#ig-sub").value.trim(), rule, scope: rule === "*" ? "subject_any" : "subject",
          duration: $("#ig-dur").value, note: $("#ig-note").value });
        toast(`Ignoring: ${ignoreScopeText(x)}`, "", { good: true });
      } catch (err) { toast("Not added", err.message, { bad: true, ms: 9000 }); }
    };
  },
  onThreat() { if (this.filter !== "rules") { clearTimeout(this.t); this.t = setTimeout(() => this.draw(), 250); } },
  onIgnore() {
    // don't wipe a half-typed form on the hit-counter refreshes
    const f = $("#f-ign");
    if (f && f.contains(document.activeElement)) return;
    this.draw();
  },
};

/* ================= Actions ================= */
VIEWS.actions = {
  render(m) {
    m.innerHTML = `<div class="grid">
      <section class="panel s12" id="pend-panel"><header><h2>Waiting for your confirmation</h2></header><div class="body" id="pending"></div></section>
      <section class="panel s12"><header><h2>In force on the router</h2><span class="grow"></span><button class="btn sm" id="refresh-entries">Refresh</button></header><div class="body flush" id="entries"></div></section>
      <section class="panel s12"><header><h2>History</h2><span class="grow"></span><span class="hint">every proposal, confirmation and undo is logged to data/actions.jsonl</span></header><div class="body flush scroll" style="max-height:560px" id="history"></div></section>
    </div>`;
    $("#refresh-entries", m).onclick = () => this.loadEntries();
    this.draw();
    this.loadEntries();
  },
  async loadEntries() {
    try { const r = await api.get("/api/entries"); S.entries = r.entries; } catch (e) { /* not connected */ }
    this.drawEntries();
  },
  drawEntries() {
    const el = $("#entries");
    if (!el) return;
    el.innerHTML = S.entries.length ? `<table class="t"><thead><tr><th>Address</th><th>List</th><th>Time left</th><th>Comment</th><th></th></tr></thead><tbody>
      ${S.entries.map((e) => `<tr><td class="mono"><span class="ipl" data-host="${esc(e.ip)}">${esc(e.ip)}</span></td><td><span class="pill ${e.list === "mcc-blocked" ? "red" : "amber"}">${esc(e.list)}</span></td>
        <td class="num">${e.timeout ? esc(e.timeout) : "permanent"}</td><td class="muted">${esc(e.comment)}</td>
        <td class="r"><button class="btn sm" data-rm="${esc(e.ip)}" data-list="${esc(e.list)}">${ICON.undo} ${e.list === "mcc-blocked" ? "Unblock" : "Release"}</button></td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">${connected() ? "Nothing blocked or quarantined by MCC." : "Connect the router to see what's in force."}</div>`;
    $$("[data-rm]", el).forEach((b) => (b.onclick = () => respond("remove_entry", { ip: b.dataset.rm, list: b.dataset.list }, "from the console")));
    $$("[data-host]", el).forEach((b) => (b.onclick = () => openHost(b.dataset.host)));
  },
  draw() {
    const all = [...S.actions.values()].sort((a, b) => (b.created || "").localeCompare(a.created || ""));
    const pend = all.filter((a) => a.status === "pending");
    $("#pending").innerHTML = pend.length ? pend.map((a) => `<div class="plan-item"><div class="head"><span class="pill blue">${esc(a.id)}</span><h3>${esc(a.title)}</h3>
        <button class="btn sm" data-dis="${esc(a.id)}">Dismiss</button><button class="btn sm danger" data-rev="${esc(a.id)}">Review &amp; confirm…</button></div><p>${esc(a.summary)}</p></div>`).join("")
      : '<div class="note">Nothing pending. Responses you start from a threat, a host or the command palette wait here until you confirm or dismiss them.</div>';
    $$("[data-rev]").forEach((b) => (b.onclick = () => showProposal(S.actions.get(b.dataset.rev))));
    $$("[data-dis]").forEach((b) => (b.onclick = () => dismiss(b.dataset.dis)));
    const hist = all.filter((a) => a.status !== "pending");
    const pill = { done: "green", failed: "red", undone: "", dismissed: "", expired: "" };
    $("#history").innerHTML = hist.length ? `<table class="t"><thead><tr><th>ID</th><th>When</th><th>Action</th><th>Status</th><th></th></tr></thead><tbody>
      ${hist.map((a) => `<tr class="click" data-detail="${esc(a.id)}"><td class="mono">${esc(a.id)}</td><td class="num muted">${esc(fmt.ago(a.executed_at || a.created))}</td>
        <td><b>${esc(a.title)}</b><div class="muted" style="font-size:12px">${esc(a.reason || "")}</div></td><td><span class="pill ${pill[a.status] || ""}">${esc(a.status)}</span></td>
        <td class="r">${(a.status === "done" || a.status === "failed") && a.undo && a.undo.possible ? `<button class="btn sm" data-undo="${esc(a.id)}">${ICON.undo} Undo</button>` : ""}</td></tr>`).join("")}</tbody></table>`
      : '<div class="empty">No actions yet.</div>';
    $$("[data-undo]").forEach((b) => (b.onclick = (e) => { e.stopPropagation(); askUndo(S.actions.get(b.dataset.undo)); }));
    $$("[data-detail]").forEach((tr) => (tr.onclick = () => this.detail(S.actions.get(tr.dataset.detail))));
  },
  detail(a) {
    openModal(`<header><div class="grow"><div class="faint" style="font-size:12px">${esc(a.id)} · ${esc(a.status)}</div><h2>${esc(a.title)}</h2></div><button class="icon-btn" data-x>${ICON.x}</button></header>
      <div class="mbody"><div>${esc(a.summary)}</div>${a.error ? `<div class="callout bad">${esc(a.error)}</div>` : ""}
        <h4 style="margin:0;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)">Planned changes</h4>${changesHtml(a.changes)}
        ${(a.steps || []).length ? `<h4 style="margin:0;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)">What ran</h4>${stepsHtml(a.steps)}` : ""}
        ${(a.undo_steps || []).length ? `<h4 style="margin:0;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)">Undo</h4>${stepsHtml(a.undo_steps)}` : ""}
        <div class="steps faint">${(a.history || []).map((h) => `<div>${esc(h.at)} ${esc(h.event)}</div>`).join("")}</div></div>
      <footer><span class="grow"></span><button class="btn primary" data-x>Close</button></footer>`,
    (mm) => $$("[data-x]", mm).forEach((b) => (b.onclick = closeModal)));
  },
  onAction() { this.draw(); clearTimeout(this.t); this.t = setTimeout(() => this.loadEntries(), 600); },
};

/* ================= Devices ================= */
VIEWS.devices = {
  render(m) {
    this.q = "";
    m.innerHTML = `${connectBanner()}<div class="toolbar"><input type="text" id="dq" placeholder="Filter by name, IP, MAC, port"><span class="grow"></span>
      <span class="note">From DHCP leases, ARP and the bridge host table. New MACs raise a "New device" threat.</span></div>
      <div class="panel"><div class="body flush scroll" id="devs"><div class="empty">Loading…</div></div></div>`;
    $("#dq", m).oninput = (e) => { this.q = e.target.value.toLowerCase(); this.draw(); };
    this.load();
    this.timer = setInterval(() => this.load(), 5000);
  },
  async load() {
    try { this.devs = (await api.get("/api/devices")).devices; } catch (e) { this.devs = []; }
    this.draw();
  },
  draw() {
    const el = $("#devs");
    if (!el || !this.devs) return;
    const q = this.q;
    const list = this.devs.filter((d) => !q || [d.name, d.hostname, d.ip, d.mac, d.port, d.iface].some((v) => (v || "").toLowerCase().includes(q)));
    el.innerHTML = list.length ? `<table class="t"><thead><tr><th></th><th>Device</th><th>MAC</th><th>Port</th><th>Lease</th><th class="r">↓</th><th class="r">↑</th><th></th></tr></thead><tbody>
      ${list.map((d) => `<tr class="click" data-ip="${esc(d.ip)}"><td style="width:28px">${!d.known ? '<span class="pill yellow">new</span>' : d.threat ? `<span class="sev sv-${esc(d.threat)}"></span>` : ""}</td>
        <td>${whoCell(d.name || d.hostname, d.ip)}</td><td class="mono muted">${esc(d.mac)}</td><td>${esc(d.port || d.iface || "—")}</td>
        <td class="muted">${d.dhcp ? esc(d.status || "") + (d.static ? " · static" : "") : "ARP only"}</td>
        <td class="r num in">${d.down ? fmt.bps(d.down) : ""}</td><td class="r num out">${d.up ? fmt.bps(d.up) : ""}</td>
        <td class="r" style="white-space:nowrap">${!d.known ? `<button class="btn sm" data-known="${esc(d.mac)}">Mark known</button> ` : ""}${d.quarantined
          ? `<button class="btn sm" data-rel="${esc(d.ip)}">Release</button>` : d.ip ? `<button class="btn sm" data-q="${esc(d.ip)}">${ICON.quarantine} Quarantine</button>` : ""}</td></tr>`).join("")}
      </tbody></table>` : `<div class="empty">${connected() ? "No devices match." : "Connect a router to list devices."}</div>`;
    bindRows(el);
    $$("[data-known]", el).forEach((b) => (b.onclick = async (e) => { e.stopPropagation(); try { await api.post("/api/devices/known", { mac: b.dataset.known }); this.load(); } catch (err) { toast("Couldn't update", err.message, { bad: true }); } }));
    $$("[data-q]", el).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); respond("quarantine_host", { ip: b.dataset.q }, "from Devices"); }));
    $$("[data-rel]", el).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); respond("remove_entry", { ip: b.dataset.rel, list: "mcc-quarantine" }, "from Devices"); }));
  },
  leave() { clearInterval(this.timer); },
};

/* ================= Interfaces ================= */
VIEWS.interfaces = {
  render(m, params) {
    this.sel = params.port ? "sw:" + params.port : this.sel || "";
    m.innerHTML = `${connectBanner()}<div class="grid">
      <section class="panel s12"><header><h2 id="ch-title">Select an interface</h2><span class="grow"></span><span class="legend"><span><i style="background:var(--in)"></i>in</span><span><i style="background:var(--out)"></i>out</span></span></header>
        <div class="body"><div class="chart"><canvas id="if-chart"></canvas></div></div></section>
      <section class="panel s7"><header><h2>Router interfaces</h2></header><div class="body flush scroll" id="ifs"></div></section>
      <section class="panel s5"><header><h2>Switch ports</h2><span class="grow"></span><span class="hint">${switchKindLabel()} · read-only</span></header><div class="body" id="ports"></div>
        <div class="body note" style="padding-top:0">MCC watches the switch but doesn't change it. To act on a switch port, disable the router port facing it, or quarantine the hosts behind it.</div></section>
    </div>`;
    this.tick();
  },
  tick() {
    const s = S.snap;
    const el = $("#ifs");
    const wan = new Set(s.wan.names);
    el.innerHTML = s.ifaces.length ? `<table class="t"><thead><tr><th>Interface</th><th>State</th><th class="r">In</th><th class="r">Out</th><th class="r">Errors</th><th>30 min</th><th></th></tr></thead><tbody>
      ${s.ifaces.map((i) => `<tr class="click ${this.sel === "if:" + i.name ? "sel" : ""}" data-if="${esc(i.name)}"><td><div class="who"><b>${esc(i.name)} ${wan.has(i.name) ? '<span class="pill blue">WAN</span>' : ""}</b><span>${esc(i.comment || i.type)}</span></div></td>
        <td>${i.disabled ? '<span class="pill">disabled</span>' : i.running ? '<span class="pill green">up</span>' : '<span class="pill red">down</span>'}</td>
        <td class="r num in">${fmt.bps(i.rx_bps)}</td><td class="r num out">${fmt.bps(i.tx_bps)}</td><td class="r num ${i.rx_err + i.tx_err ? "" : "faint"}">${(i.rx_err + i.tx_err).toLocaleString()}</td>
        <td style="width:120px"><canvas class="ifspark" data-sp="${esc(i.name)}" style="width:110px;height:26px;display:block"></canvas></td>
        <td class="r">${i.type === "bridge" ? "" : i.disabled ? `<button class="btn sm" data-en="${esc(i.name)}">${ICON.power} Enable</button>` : `<button class="btn sm" data-dis="${esc(i.name)}">${ICON.power} Disable</button>`}</td></tr>`).join("")}
      </tbody></table>` : '<div class="empty">No interfaces yet.</div>';
    $$("[data-sp]", el).forEach((cv) => {
      const h = S.hist.ifaces[cv.dataset.sp] || [];
      Charts.spark(cv, h.slice(-180).map((r) => r[1] + r[2]), cssVar("--accent"));
    });
    $$("tr[data-if]", el).forEach((tr) => (tr.onclick = () => { this.sel = "if:" + tr.dataset.if; this.chart(); }));
    $$("[data-dis]", el).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); respond("disable_interface", { name: b.dataset.dis }, "from Interfaces"); }));
    $$("[data-en]", el).forEach((b) => (b.onclick = (e) => { e.stopPropagation(); respond("enable_interface", { name: b.dataset.en }, "from Interfaces"); }));
    $("#ports").innerHTML = portsHtml(s.switch.ports);
    $$("[data-port]", $("#ports")).forEach((p) => (p.onclick = () => { this.sel = "sw:" + p.dataset.port; this.chart(); }));
    if (!this.sel && s.wan.names.length) this.sel = "if:" + s.wan.names[0];
    this.chart();
  },
  chart() {
    const [kind, name] = (this.sel || ":").split(/:(.*)/);
    let data = [], title = "Select an interface";
    if (kind === "if") { data = S.hist.ifaces[name] || []; title = "Router · " + name; }
    if (kind === "sw") {
      data = (S.hist.switch[name] || []).map((r) => [r[0], r[1], r[2]]);
      const p = (S.snap.switch.ports || []).find((x) => String(x.n) === name);
      title = "Switch · " + (p ? p.name : "port " + name);
    }
    $("#ch-title").textContent = title;
    Charts.line($("#if-chart"), [{ data: data.map((r) => [r[0], r[1]]), color: cssVar("--in"), fill: true, label: "in" },
      { data: data.map((r) => [r[0], r[2]]), color: cssVar("--out"), fill: true, label: "out" }], { window: 1800, yfmt: fmt.bps, mirror: true });
  },
};

/* ================= Logs ================= */
VIEWS.logs = {
  render(m) {
    this.q = ""; this.lvl = "all"; this.paused = false;
    m.innerHTML = `<div class="toolbar"><input type="text" id="lq" placeholder="Filter text or IP"><div class="seg" id="lv">
      ${[["all", "All"], ["fw", "Firewall"], ["login", "Logins"], ["warn", "Warnings+"]].map(([k, l]) => `<button data-l="${k}" class="${k === "all" ? "on" : ""}">${l}</button>`).join("")}</div>
      <span class="grow"></span><span class="note" id="lsrc"></span><button class="btn sm" id="lp">Pause</button></div>
      <div class="panel"><div class="loglist" id="ll"></div></div>`;
    $("#lq", m).oninput = (e) => { this.q = e.target.value.toLowerCase(); this.draw(); };
    $("#lv", m).onclick = (e) => { const b = e.target.closest("[data-l]"); if (!b) return; this.lvl = b.dataset.l; $$("#lv button").forEach((x) => x.classList.toggle("on", x === b)); this.draw(); };
    $("#lp", m).onclick = (e) => { this.paused = !this.paused; e.target.textContent = this.paused ? "Resume" : "Pause"; if (!this.paused) this.draw(); };
    this.draw();
  },
  match(l) {
    if (this.lvl === "fw" && l.kind !== "fw") return false;
    if (this.lvl === "login" && !/^login/.test(l.kind)) return false;
    if (this.lvl === "warn" && !["warn", "error", "crit"].includes(l.level)) return false;
    if (this.q && !(l.msg.toLowerCase().includes(this.q) || (l.topics || "").includes(this.q))) return false;
    return true;
  },
  draw() {
    const el = $("#ll");
    if (!el) return;
    const rows = S.logs.filter((l) => this.match(l)).slice(-600).reverse();
    const ipre = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;
    el.innerHTML = rows.length ? rows.map((l) => `<div class="logline l-${esc(l.level)}"><span class="lt">${esc(l.time || fmt.time(l.ts))}</span><span class="ls">${esc(l.source)}</span>
      <span class="lp">${esc(l.topics)}</span><span class="lm">${esc(l.msg).replace(ipre, '<span class="ipl" data-host="$1">$1</span>')}</span></div>`).join("")
      : '<div class="empty">No log lines match.</div>';
    $$("[data-host]", el).forEach((s) => (s.onclick = () => openHost(s.dataset.host)));
    const st = S.snap && S.snap.status;
    if (st) $("#lsrc").textContent = st.syslog.live ? "live via syslog + router log" : "router memory log (polled)";
  },
  onLogs() { if (!this.paused) { clearTimeout(this.t); this.t = setTimeout(() => this.draw(), 400); } },
};

/* ================= Setup ================= */
VIEWS.setup = {
  render(m) {
    const c = S.config || {}, r = c.router || {}, sw = c.switch || {};
    const st = S.snap.status;
    m.innerHTML = `<div class="grid">
      <section class="panel s6"><header><h2>Router</h2><span class="grow"></span>${this.stateChip(st.router.state)}</header><div class="body">
        <form class="form" id="f-router" autocomplete="off">
          <label for="r-host">Address</label><input type="text" id="r-host" value="${esc(r.host || "")}" placeholder="192.168.88.1" required>
          <label for="r-scheme">Protocol</label><div class="btnrow"><select id="r-scheme" style="width:auto"><option value="https" ${r.scheme !== "http" ? "selected" : ""}>HTTPS (www-ssl)</option><option value="http" ${r.scheme === "http" ? "selected" : ""}>HTTP (www)</option></select>
            <input type="number" id="r-port" value="${r.port || ""}" placeholder="port" style="width:90px"></div>
          <label for="r-user">User</label><input type="text" id="r-user" value="${esc(r.user || "")}" placeholder="mcc" required>
          <label for="r-pass">Password</label><input type="password" id="r-pass" placeholder="kept in memory only">
          <span></span><label class="check"><input type="checkbox" id="r-pin" checked> Pin the router's certificate (refuse if it changes)</label>
          ${r.pinned_sha256 ? `<span class="faint" style="font-size:12px">Pinned</span><span class="mono faint" style="font-size:11px;word-break:break-all">${esc(r.pinned_sha256)} <label class="check" style="font-size:12px"><input type="checkbox" id="r-repin"> re-pin</label></span>` : ""}
          <span></span><div class="btnrow"><button class="btn primary" type="submit">Connect</button>${st.router.state === "ok" ? '<button class="btn" type="button" id="r-off">Disconnect</button>' : ""}</div>
        </form>
        ${st.router.error ? `<div class="callout bad" style="margin-top:12px">${esc(st.router.error)}</div>` : ""}
        ${Object.keys(st.router.tasks || {}).length ? `<div class="callout warn" style="margin-top:12px">${Object.entries(st.router.tasks).map(([k, v]) => `<div><b>${esc(k)}</b>: ${esc(v)}</div>`).join("")}</div>` : ""}
        <details class="note" style="margin-top:12px"><summary>Recommended: a dedicated RouterOS user for MCC</summary><pre class="evidence">/user group add name=mcc policy=read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!password,!sniff,!sensitive,!romon
/user add name=mcc group=mcc password="&lt;long random&gt;" address=&lt;this PC's IP&gt;/32
/ip service set www-ssl disabled=no          # needs a certificate; or use www (HTTP) on a trusted LAN only</pre>
          It can read everything and change firewall/interface settings — what MCC needs to act — but can't log in interactively, reboot or manage users. Restricting it to this PC's address limits damage if the password leaks.</details>
      </div></section>
      <section class="panel s6"><header><h2>Switch${st.switch.kind ? " (" + switchKindLabel() + ")" : ""}</h2><span class="grow"></span>${this.stateChip(st.switch.state === "off" ? "disconnected" : st.switch.state)}</header><div class="body">
        <form class="form" id="f-switch" autocomplete="off">
          <label for="s-host">Address</label><input type="text" id="s-host" value="${esc(sw.host || "")}" placeholder="192.168.88.2" required>
          <label for="s-kind">Runs</label><select id="s-kind">${[["auto", "Auto-detect"], ["routeros", "RouterOS (REST API)"], ["swos", "SwOS"]]
            .map(([k, l]) => `<option value="${k}" ${(sw.kind || "auto") === k ? "selected" : ""}>${l}</option>`).join("")}</select>
          <label for="s-scheme">Protocol</label><select id="s-scheme"><option value="http" ${sw.scheme !== "https" ? "selected" : ""}>HTTP</option><option value="https" ${sw.scheme === "https" ? "selected" : ""}>HTTPS (RouterOS www-ssl)</option></select>
          <label for="s-user">User</label><input type="text" id="s-user" value="${esc(sw.user || "admin")}">
          <label for="s-pass">Password</label><input type="password" id="s-pass" placeholder="kept in memory only">
          <span></span><div class="btnrow"><button class="btn primary" type="submit">Connect</button>${st.switch.state === "ok" ? '<button class="btn" type="button" id="s-off">Disconnect</button>' : ""}<button class="btn ghost" type="button" id="s-probe">Switch probe</button></div>
        </form>
        ${st.switch.error ? `<div class="callout bad" style="margin-top:12px">${esc(st.switch.error)}</div>` : ""}
        <div class="note" style="margin-top:12px">CRS switches can run RouterOS or SwOS; Auto-detect works out which. On RouterOS MCC uses the REST API (enable the <span class="mono">www</span> or <span class="mono">www-ssl</span> service; a read-only user is enough). SwOS has no API, so MCC reads the status files its web page uses. Either way MCC only reads. If a column shows "—", open <b>Switch probe</b> to see the raw data.</div>
        <pre class="evidence hidden" id="probe"></pre>
      </div></section>

      <section class="panel s12"><header><h2>Telemetry from the router</h2><span class="grow"></span><span class="hint">nothing changes until you approve</span></header><div class="body" id="plan">
        ${connected() ? '<div class="btnrow"><button class="btn primary" id="plan-load">Review the router changes MCC needs</button><button class="btn ghost" id="plan-remove">Plan removal of everything MCC added…</button></div>' : '<div class="note">Connect the router first.</div>'}
      </div></section>

      <section class="panel s6"><header><h2>Collectors</h2></header><div class="body" id="collectors"></div></section>
      <section class="panel s6"><header><h2>Settings</h2></header><div class="body">${this.settingsForm(c)}</div></section>
      <section class="panel s12" data-pid="setup:geo"><header><h2>Geolocation</h2><span class="grow"></span><span class="hint">for the globe · lookups stay on this machine</span></header>
        <div class="body" id="geo-panel"><div class="note">Loading…</div></div></section>
    </div>`;
    this.bind(m);
    this.drawCollectors();
    this.drawGeo();
  },
  stateChip(s) {
    const cls = s === "ok" ? "green" : s === "error" ? "red" : s === "connecting" ? "amber" : "";
    return `<span class="pill ${cls}">${esc(s === "ok" ? "connected" : s)}</span>`;
  },
  settingsForm(c) {
    const d = c.detect || {};
    const num = (k, label) => `<label for="d-${k}">${label}</label><input type="number" id="d-${k}" data-detect="${k}" value="${esc(d[k])}">`;
    return `<form class="form" id="f-settings">
      <label for="x-lan">LAN networks</label><textarea id="x-lan" rows="3">${esc((c.lan_networks || []).join("\n"))}</textarea>
      <label for="x-never">Never block</label><textarea id="x-never" rows="3" placeholder="one IP or network per line — e.g. your VPN provider, work VPN, DNS">${esc((c.never_block || []).join("\n"))}</textarea>
      <label for="x-wan">WAN interfaces</label><input type="text" id="x-wan" value="${esc(((c.wan || {}).interfaces || []).join(", "))}" placeholder="auto: WAN list / default route">
      <label for="x-down">Plan speed (Mb/s)</label><div class="btnrow"><input type="number" id="x-down" value="${esc((c.wan || {}).down_mbps || "")}" placeholder="down" style="width:110px"><input type="number" id="x-up" value="${esc((c.wan || {}).up_mbps || "")}" placeholder="up" style="width:110px"></div>
      <label for="x-block">Default block</label><select id="x-block">${["15m", "1h", "24h", "7d", "0"].map((v) => `<option value="${v}" ${(c.actions || {}).default_block === v ? "selected" : ""}>${TIMEOUT_LABEL[v]}</option>`).join("")}</select>
      <label for="x-adv">Send telemetry to</label><input type="text" id="x-adv" value="${esc((c.collectors || {}).advertise_ip || "")}" placeholder="auto: this PC's address toward the router">
      <div class="full"><details><summary class="muted">Detection thresholds</summary><div class="form" style="margin-top:10px">
        ${num("scan_ports", "Scan: ports / window")}${num("scan_hosts", "Sweep: hosts / window")}${num("scan_window_s", "Scan window (s)")}
        ${num("login_failures", "Login failures")}${num("login_window_s", "Login window (s)")}${num("service_conns", "Brute force: conns")}
        ${num("fanout_peers", "Fan-out: peers / min")}${num("worm_dsts", "Worm: dsts / min")}${num("exfil_mbps", "Upload alert (Mb/s)")}
        ${num("exfil_s", "Sustained for (s)")}${num("cpu_pct", "CPU alert (%)")}${num("temp_c", "Temperature alert (°C)")}${num("quiet_s", "Quiet after (s)")}
      </div></details></div>
      <span></span><div class="btnrow"><button class="btn primary" type="submit">Save settings</button></div></form>`;
  },
  bind(m) {
    $("#f-router", m).onsubmit = async (e) => {
      e.preventDefault();
      const btn = $("button[type=submit]", e.target);
      btn.disabled = true; btn.textContent = "Connecting…";
      try {
        const res = await api.post("/api/connect", { router: { host: $("#r-host").value, user: $("#r-user").value, password: $("#r-pass").value,
          scheme: $("#r-scheme").value, port: +$("#r-port").value || 0, pin: $("#r-pin").checked, repin: $("#r-repin") ? $("#r-repin").checked : false } });
        $("#r-pass").value = "";
        toast(`Connected to ${res.identity || "router"}`, `${res.board} · RouterOS ${res.version}${res.newly_pinned ? " · certificate pinned" : ""}`, { good: true });
        if (res.newly_pinned) toast("Certificate pinned", res.newly_pinned + " — compare with /certificate print on the router.", { ms: 15000 });
        S.config = (await api.get("/api/state")).config;
        setTimeout(() => this.render($("#main")), 400);
      } catch (err) { toast("Couldn't connect", err.message, { bad: true, ms: 12000 }); btn.disabled = false; btn.textContent = "Connect"; }
    };
    const off = $("#r-off", m);
    if (off) off.onclick = async () => { await api.post("/api/disconnect", { what: "router" }); setTimeout(() => this.render($("#main")), 300); };
    $("#f-switch", m).onsubmit = async (e) => {
      e.preventDefault();
      try {
        const res = await api.post("/api/connect/switch", { switch: { host: $("#s-host").value, user: $("#s-user").value, password: $("#s-pass").value,
          kind: $("#s-kind").value, scheme: $("#s-scheme").value } });
        $("#s-pass").value = "";
        toast("Switch connected", `${res.kind === "routeros" ? "RouterOS" : "SwOS"} · ${res.sys.model || ""} · ${res.ports} ports`, { good: true });
        S.config = (await api.get("/api/state")).config;
        setTimeout(() => this.render($("#main")), 300);
      } catch (err) { toast("Couldn't reach the switch", err.message, { bad: true, ms: 12000 }); }
    };
    const soff = $("#s-off", m);
    if (soff) soff.onclick = async () => { await api.post("/api/disconnect", { what: "switch" }); setTimeout(() => this.render($("#main")), 300); };
    $("#s-probe", m).onclick = async () => {
      const pre = $("#probe");
      try { pre.textContent = JSON.stringify(await api.get("/api/switch/probe"), null, 1); } catch (err) { pre.textContent = err.message; }
      pre.classList.remove("hidden");
    };
    const pl = $("#plan-load", m);
    if (pl) pl.onclick = () => this.loadPlan("/api/setup/plan");
    const pr = $("#plan-remove", m);
    if (pr) pr.onclick = () => this.loadPlan("/api/setup/removal");
    $("#f-settings", m).onsubmit = async (e) => {
      e.preventDefault();
      const lines = (id) => $(id).value.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
      const detect = {};
      $$("[data-detect]").forEach((i) => { if (i.value !== "") detect[i.dataset.detect] = +i.value; });
      try {
        S.config = await api.post("/api/settings", { lan_networks: lines("#x-lan"), never_block: lines("#x-never"),
          wan: { interfaces: lines("#x-wan"), down_mbps: +$("#x-down").value || 0, up_mbps: +$("#x-up").value || 0 },
          actions: { default_block: $("#x-block").value }, collectors: { advertise_ip: $("#x-adv").value.trim() }, detect });
        toast("Settings saved", "", { good: true });
      } catch (err) { toast("Not saved", err.message, { bad: true, ms: 10000 }); }
    };
  },
  async loadPlan(url, lists) {
    const el = $("#plan");
    el.innerHTML = '<div class="note">Reading the router…</div>';
    let plan;
    try { plan = await api.get(url + (lists ? "?lists=1" : "")); } catch (err) { el.innerHTML = `<div class="callout bad">${esc(err.message)}</div>`; return; }
    const removal = plan.kind === "remove";
    const sl = { installed: "green", partial: "amber", missing: "red", unavailable: "", present: "amber", clean: "green", optional: "blue" };
    el.innerHTML = `${removal ? `<label class="check" style="margin-bottom:10px"><input type="checkbox" id="rm-lists" ${lists ? "checked" : ""}> Also empty MCC's block and quarantine lists</label>` :
      `<div class="note" style="margin-bottom:10px">MCC listens on UDP <b>${plan.flow_port}</b> (flows) and <b>${plan.syslog_port}</b> (syslog) at <b>${esc(plan.mcc_ip)}</b>. Each item below shows the exact commands; tick the ones you want.</div>`}
      ${plan.items.map((it) => `<div class="plan-item"><div class="head">${it.changes.length ? `<input type="checkbox" data-item="${esc(it.id)}" ${it.status !== "installed" && it.status !== "optional" ? "checked" : ""} aria-label="include">` : ""}
        <h3>${esc(it.title)}</h3><span class="pill ${sl[it.status] || ""}">${esc(it.status)}</span></div><p>${esc(it.why)}</p>
        ${it.detail ? `<div class="note" style="margin-bottom:8px">${esc(it.detail)}</div>` : ""}${it.changes.length ? changesHtml(it.changes) : '<div class="note">Nothing to change.</div>'}</div>`).join("")}
      <div class="btnrow"><button class="btn ${removal ? "danger" : "primary"}" id="plan-apply">${removal ? "Approve removal" : "Approve & apply selected"}</button><button class="btn ghost" id="plan-cancel">Cancel</button>
        <span class="note">This plan is valid for 10 minutes; MCC applies exactly what is shown.</span></div>`;
    const rl = $("#rm-lists");
    if (rl) rl.onchange = () => this.loadPlan("/api/setup/removal", rl.checked);
    $("#plan-cancel").onclick = () => this.render($("#main"));
    $("#plan-apply").onclick = async (e) => {
      const items = $$("[data-item]", el).filter((c) => c.checked).map((c) => c.dataset.item);
      if (!items.length) return toast("Nothing selected", "", {});
      const n = plan.items.filter((i) => items.includes(i.id)).reduce((a, i) => a + i.changes.length, 0);
      e.target.disabled = true;
      e.target.textContent = `Applying ${n} change${n === 1 ? "" : "s"}…`;
      try {
        const res = await api.post("/api/setup/apply", { plan_id: plan.id, items, approve: true });
        el.innerHTML = res.results.map((r) => `<div class="plan-item"><div class="head"><h3>${r.ok ? "✓" : "✗"} ${esc(r.title)}</h3></div>${stepsHtml(r.steps)}</div>`).join("") +
          '<div class="btnrow"><button class="btn" id="plan-again">Review again</button></div>';
        $("#plan-again").onclick = () => this.loadPlan("/api/setup/plan");
        const ok = res.results.every((r) => r.ok);
        toast(ok ? "Router configured" : "Some changes failed", ok ? "Telemetry should start arriving within a minute." : "See the steps for details.", ok ? { good: true } : { bad: true });
      } catch (err) { toast("Not applied", err.message, { bad: true, ms: 10000 }); this.loadPlan(url); }
    };
  },
  drawCollectors() {
    const st = S.snap.status, el = $("#collectors");
    if (!el) return;
    const row = (name, c) => `<tr><td><b>${name}</b></td><td class="num">UDP ${c.port}</td><td>${c.live ? '<span class="pill green">receiving</span>' : c.listening ? '<span class="pill">idle</span>' : '<span class="pill red">not listening</span>'}</td>
      <td class="num r">${c.packets.toLocaleString()}</td><td class="muted">${c.last_at ? fmt.ago(c.last_at) : "never"}</td></tr>`;
    const rej = Object.entries(Object.assign({}, st.flows.rejected, st.syslog.rejected));
    el.innerHTML = `<table class="t"><thead><tr><th></th><th>Port</th><th>State</th><th class="r">Packets</th><th>Last</th></tr></thead><tbody>${row("Flows", st.flows)}${row("Syslog", st.syslog)}</tbody></table>
      ${st.flows.last_error || st.syslog.last_error ? `<div class="callout bad" style="margin-top:10px">${esc(st.flows.last_error || st.syslog.last_error)}</div>` : ""}
      ${rej.length ? `<div class="callout warn" style="margin-top:10px"><b>Ignored packets from other senders.</b> MCC only accepts telemetry from the router. If one of these is your router's other address, accept it:
        ${rej.map(([ip, n]) => `<div class="btnrow" style="margin-top:6px"><span class="mono">${esc(ip)}</span><span class="faint">${n} packets</span><button class="btn sm" data-accept="${esc(ip)}">Accept from ${esc(ip)}</button></div>`).join("")}</div>` : ""}
      ${st.server ? `<div class="note" style="margin-top:10px">Server load: each update takes <b>${st.server.tick_ms} ms</b> of its 1 s budget${st.server.tick_ms > 600 ? ' — <b style="color:var(--high)">this machine is struggling; give the VM more CPU</b>' : ""} ·
        ${st.server.clients} open console${st.server.clients === 1 ? "" : "s"}${st.server.ticks_skipped ? ` · ${st.server.ticks_skipped} updates skipped for slow consoles` : ""}${st.server.resyncs ? ` · ${st.server.resyncs} resyncs` : ""}</div>` : ""}
      <div class="note" style="margin-top:10px">Telemetry source: <b>${esc(st.traffic_source)}</b>. Flow records arrive in batches (active flows every minute); live rates come from the connection table.</div>`;
    $$("[data-accept]", el).forEach((b) => (b.onclick = async () => {
      const cur = ((S.config.collectors || {}).accept_from || []).concat([b.dataset.accept]);
      try { S.config = await api.post("/api/settings", { collectors: { accept_from: cur } }); toast("Accepted", b.dataset.accept, { good: true }); } catch (err) { toast("Not saved", err.message, { bad: true }); }
    }));
  },
  async drawGeo() {
    const el = $("#geo-panel");
    if (!el) return;
    let g;
    try { g = await api.get("/api/geo"); } catch (err) { el.innerHTML = `<div class="callout bad">${esc(err.message)}</div>`; return; }
    if (!$("#geo-panel")) return;
    const c = S.config.geo || {}, hm = c.home || {};
    const dl = g.download || {};
    const pct = dl.total ? Math.round((dl.bytes / dl.total) * 100) : 0;
    const running = dl.state === "running" || dl.state === "unpacking";
    el.innerHTML = `
      <div class="grid" style="gap:18px">
        <div class="s6">
          ${g.source === "database" ? `<div class="callout good"><b>${esc(g.type || g.file)}</b> · ${esc(g.file)}${g.built ? " · built " + esc(g.built) : ""}<br>
              <span class="note">${/city/i.test((g.type || "") + g.file) ? "City-level locations." : "Country-level: peers are placed at the middle of their country. The City edition is more precise."}</span></div>`
            : g.source === "demo" ? '<div class="callout">Demo: simulated locations. Add a database to locate real addresses.</div>'
            : '<div class="callout warn"><b>No geolocation database.</b> The globe needs one to place Internet addresses.</div>'}
          ${g.error ? `<div class="callout bad" style="margin-top:8px">${esc(g.error)}</div>` : ""}
          <p class="note" style="margin:12px 0 8px">Download the free <b>DB-IP Lite</b> database (CC BY 4.0, no account). This is the one time MCC contacts anything but your router: a single download from <span class="mono">download.db-ip.com</span>. Lookups afterwards are local. DB-IP updates it monthly; download again to refresh.</p>
          <div class="btnrow">
            <button class="btn" data-dl="country" ${running ? "disabled" : ""}>Country Lite <span class="faint">≈4 MB</span></button>
            <button class="btn primary" data-dl="city" ${running ? "disabled" : ""}>City Lite <span style="opacity:.75">≈60 MB</span></button>
          </div>
          ${running ? `<div class="kpi" style="padding:10px 0 0"><div class="note">${dl.state === "unpacking" ? "Unpacking…" : `Downloading ${esc(dl.url)} — ${fmt.bytes(dl.bytes)}${dl.total ? " of " + fmt.bytes(dl.total) : ""}`}</div><div class="bar"><i style="width:${dl.state === "unpacking" ? 100 : pct}%"></i></div></div>` : ""}
          ${dl.state === "error" ? `<div class="callout bad" style="margin-top:10px">Download failed: ${esc(dl.error)}</div>` : ""}
          ${dl.state === "done" ? `<div class="callout good" style="margin-top:10px">Installed ${esc(dl.file)}.</div>` : ""}
          <p class="note" style="margin:14px 0 6px">Or use your own <span class="mono">.mmdb</span> (MaxMind GeoLite2, IPinfo…): put it in <span class="mono">data/geo/</span>, or give its path:</p>
          <div class="btnrow"><input type="text" id="geo-db" value="${esc(c.db || "")}" placeholder="blank = newest .mmdb in data/geo" style="max-width:420px"><button class="btn" id="geo-db-save">Use</button></div>
        </div>
        <div class="s6">
          <h4 style="margin:0 0 8px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)">Home (where arcs start)</h4>
          <div class="note" style="margin-bottom:10px">Now: ${g.home ? `<b>${esc(g.home.label || "")}</b> ${(+g.home.lat).toFixed(2)}, ${(+g.home.lon).toFixed(2)} <span class="faint">(${esc(g.home.source || "")})</span>` : "<b>unknown</b>"}.
            Leave blank to locate the router's public address. If you're behind CGNAT, or want it exact, set it here.</div>
          <form class="form" id="f-home">
            <label for="h-lat">Latitude</label><input type="number" step="any" id="h-lat" value="${esc(hm.lat)}" placeholder="e.g. 32.78">
            <label for="h-lon">Longitude</label><input type="number" step="any" id="h-lon" value="${esc(hm.lon)}" placeholder="e.g. -96.80">
            <label for="h-label">Label</label><input type="text" id="h-label" value="${esc(hm.label)}" placeholder="Home">
            <span></span><div class="btnrow"><button class="btn primary" type="submit">Save home</button><button class="btn ghost" type="button" id="h-clear">Use router's address</button></div>
          </form>
        </div>
      </div>`;
    $$("[data-dl]", el).forEach((b) => (b.onclick = async () => {
      try {
        await api.post("/api/geo/download", { edition: b.dataset.dl, confirm: true });
        this.geoPoll();
      } catch (err) { toast("Download not started", err.message, { bad: true }); }
    }));
    const saveGeo = async (geo, msg) => {
      try { S.config = await api.post("/api/settings", { geo }); toast(msg, "", { good: true }); this.drawGeo(); }
      catch (err) { toast("Not saved", err.message, { bad: true, ms: 9000 }); }
    };
    $("#geo-db-save", el).onclick = () => saveGeo({ db: $("#geo-db").value.trim() }, "Geolocation database set");
    $("#f-home", el).onsubmit = (e) => { e.preventDefault(); saveGeo({ home: { lat: $("#h-lat").value, lon: $("#h-lon").value, label: $("#h-label").value } }, "Home saved"); };
    $("#h-clear", el).onclick = () => saveGeo({ home: { lat: "", lon: "", label: "" } }, "Home follows the router's public address");
    if (running) this.geoPoll();
  },
  geoPoll() {
    clearTimeout(this.geoT);
    this.geoT = setTimeout(() => this.drawGeo(), 800);
  },
  leave() { clearTimeout(this.geoT); },
  tick() { if (++this.n % 3 === 0) this.drawCollectors(); },
  n: 0,
};
