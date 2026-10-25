"use strict";
/* ExactusWAF Console — SPA (vanilla JS, tanpa dependensi). */

/* ---------------- Ikon (SVG tepercaya, bukan data API) ---------------- */
const I = {
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v5.5c0 4.4 3 8.3 7 9.5 4-1.2 7-5.1 7-9.5V6z"/><path d="m9 12 2.2 2.2L15.5 10"/></svg>',
  search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.2-3.2"/></svg>',
  sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5 19 19M19 5l-1.5 1.5M6.5 17.5 5 19"/></svg>',
  moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/></svg>',
  user: '<svg class="av" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c.8-3.6 4-5.5 8-5.5s7.2 1.9 8 5.5"/></svg>',
  logout: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 17l5-5-5-5M20 12H9M11 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h5"/></svg>',
  menu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h16"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>',
  dash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>',
  acl: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v5.5c0 4.4 3 8.3 7 9.5 4-1.2 7-5.1 7-9.5V6z"/></svg>',
  sig: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M4 12h10M4 17h7"/></svg>',
  ipset: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"/></svg>',
  log: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3v5h5"/><path d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8z"/><path d="M8 13h8M8 17h5"/></svg>',
  ban: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/></svg>',
  settings: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.3l2-1.5-2-3.4-2.3 1a7 7 0 0 0-2.2-1.3L14 2h-4l-.4 2.5a7 7 0 0 0-2.2 1.3l-2.3-1-2 3.4 2 1.5A7 7 0 0 0 5 12a7 7 0 0 0 .1 1.3l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 2.2 1.3L10 22h4l.4-2.5a7 7 0 0 0 2.2-1.3l2.3 1 2-3.4-2-1.5A7 7 0 0 0 19 12z"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13"/></svg>',
  play: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>',
  edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 7.5v5M12 16.5h.01"/></svg>',
  info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 11v5.5M12 7.5h.01"/></svg>',
  warn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
  okc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m8 12 2.5 2.5L16 9"/></svg>',
  empty: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 14h8"/></svg>',
};

/* ---------------- DOM helper ---------------- */
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) for (const k in props) {
    const v = props[k];
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k === "html") e.innerHTML = v; // hanya untuk konstanta ikon tepercaya
    else if (k === "dataset") Object.assign(e.dataset, v);
    else if (k.startsWith("on") && typeof v === "function") e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, "");
    else e.setAttribute(k, v);
  }
  for (const kid of kids.flat(3)) {
    if (kid == null || kid === false) continue;
    e.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return e;
}
const ico = (name, cls) => h("span", { class: cls, html: I[name] });
// mount menambahkan beberapa node ke parent sambil melewati null/false (agar
// nilai kondisional tidak berubah menjadi teks "null").
function mount(parent) {
  for (let i = 1; i < arguments.length; i++) {
    const k = arguments[i];
    if (k == null || k === false) continue;
    parent.append(k.nodeType ? k : document.createTextNode(String(k)));
  }
}

/* ---------------- Util format ---------------- */
const nf = new Intl.NumberFormat("en-US");
const num = (n) => nf.format(n || 0);
function timeHMS(ms) { const d = new Date(ms); return d.toLocaleTimeString("en-US", { hour12: false }); }
const MON = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
function dateStr(s) { const d = new Date(s); if (isNaN(d)) return "-"; return d.getDate() + " " + MON[d.getMonth()] + " " + d.getFullYear(); }
function dateTimeStr(s) { const d = new Date(s); if (isNaN(d)) return "-"; return dateStr(s) + " " + d.toLocaleTimeString("en-US", { hour12: false }); }
function fmtUptime(s) { const d=Math.floor(s/86400), h2=Math.floor(s%86400/3600), m=Math.floor(s%3600/60);
  if (d>0) return d+"d "+h2+"h"; if (h2>0) return h2+"h "+m+"m"; if (m>0) return m+"m"; return (s||0)+"s"; }
function fmtDur(sec) { sec=Math.max(0,sec|0); const m=Math.floor(sec/60), s=sec%60; return m>0?(m+"m "+s+"s"):(s+"s"); }

/* ---------------- API ---------------- */
async function api(path, opts) {
  let r;
  try { r = await fetch(path, { credentials: "same-origin", headers: { "Content-Type": "application/json" }, ...opts }); }
  catch (e) { throw new Error("Cannot reach the server."); }
  if (r.status === 401) { location.replace("/login?expired"); throw new Error("401"); }
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : null;
  if (!r.ok) throw new Error((data && data.error) || ("Failed (HTTP " + r.status + ")"));
  return data;
}
const API = {
  get: (p) => api(p),
  post: (p, b) => api(p, { method: "POST", body: JSON.stringify(b || {}) }),
  put: (p, b) => api(p, { method: "PUT", body: JSON.stringify(b || {}) }),
  del: (p) => api(p, { method: "DELETE", body: "{}" }),
};

/* ---------------- State global ---------------- */
const State = { meta: null, theme: "light", navOpen: false };

function loadTheme() {
  try { const t = localStorage.getItem("exw-theme"); if (t === "dark" || t === "light") State.theme = t; } catch (e) {}
  document.documentElement.setAttribute("data-theme", State.theme);
}
function setTheme(t) {
  State.theme = t; document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem("exw-theme", t); } catch (e) {}
  const btn = document.getElementById("themeBtn");
  if (btn) btn.innerHTML = t === "dark" ? I.sun : I.moon;
}

/* ---------------- Polling ---------------- */
let pageTimer = null;
function poll(fn, ms) {
  stopPoll();
  pageTimer = setInterval(() => { if (!document.hidden) fn(); }, ms);
}
function stopPoll() { if (pageTimer) { clearInterval(pageTimer); pageTimer = null; } }

/* ---------------- Flashbar ---------------- */
let flashQueue = []; // flash yang harus bertahan melewati satu navigasi
function flashNode(kind, msg) {
  const iconName = kind === "success" ? "okc" : kind === "error" ? "alert" : kind === "warning" ? "warn" : "info";
  const node = h("div", { class: "flash " + kind, role: kind === "error" ? "alert" : "status" },
    ico(iconName, "fi"), h("span", { text: msg }),
    h("button", { class: "fx", "aria-label": "Close", onclick: () => node.remove(), html: I.x }));
  if (kind === "success") setTimeout(() => node.remove(), 6000);
  return node;
}
function flash(kind, msg) {
  const bar = document.getElementById("flashbar");
  if (!bar) { flashQueue.push({ kind, msg }); return; }
  bar.append(flashNode(kind, msg));
}
// flashAfter menampilkan pesan SETELAH navigasi/route berikutnya (agar tidak
// langsung terhapus saat halaman dibangun ulang).
function flashAfter(kind, msg) { flashQueue.push({ kind, msg }); }
function drainFlash(bar) { const q = flashQueue; flashQueue = []; for (const f of q) bar.append(flashNode(f.kind, f.msg)); }
function clearFlash() { const b = document.getElementById("flashbar"); if (b) b.textContent = ""; }

/* ---------------- Komponen umum ---------------- */
function sevBadge(sev) {
  const label = { critical: "Critical", high: "High", medium: "Medium", low: "Low" }[sev] || sev || "-";
  return h("span", { class: "badge sev-" + (sev || "low"), text: label });
}
function actionBadge(action) {
  if (action === "count") return h("span", { class: "badge act-count", text: "Count" });
  return h("span", { class: "badge act-block", text: "Block" });
}
function statusEl(kind, text) {
  const m = { ok: "okc", err: "alert", warn: "warn", info: "info", muted: "info" };
  return h("span", { class: "status " + kind }, ico(m[kind] || "info"), h("span", { text }));
}
function emptyState(msg) { return h("div", { class: "empty" }, ico("empty"), h("div", { text: msg })); }

function container(opts, body) {
  const head = h("div", { class: "c-head" },
    h("div", { class: "c-title" },
      h("h2", {}, opts.title, opts.count != null ? h("span", { class: "count", text: " (" + opts.count + ")" }) : null),
      opts.desc ? h("div", { class: "c-desc", text: opts.desc }) : null),
    opts.actions ? h("div", { class: "c-actions" }, opts.actions) : null);
  return h("div", { class: "container" }, opts.title ? head : null, h("div", { class: "c-body" + (opts.flush ? " flush" : "") }, body));
}

function table(cols, rows, opts) {
  opts = opts || {};
  if (!rows || rows.length === 0) return emptyState(opts.empty || "No data yet.");
  const thead = h("tr", {}, cols.map((c) => h("th", { class: c.num ? "num" : null, text: c.label })));
  const tbody = rows.map((r) => h("tr", opts.rowClick ? { onclick: () => opts.rowClick(r), style: "cursor:pointer" } : null,
    cols.map((c) => {
      const cell = c.render ? c.render(r) : r[c.key];
      const td = h("td", { class: (c.mono ? "mono " : "") + (c.num ? "num" : "") || null });
      if (cell && cell.nodeType) td.append(cell); else td.textContent = cell == null ? "-" : String(cell);
      return td;
    })));
  return h("div", { class: "table-wrap" }, h("table", { class: "tbl" }, h("thead", {}, thead), h("tbody", {}, tbody)));
}

/* ---------------- Modal ---------------- */
let lastFocus = null;
function modal(title, bodyNode, footNode) {
  lastFocus = document.activeElement;
  const ov = h("div", { class: "overlay" });
  const box = h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title },
    h("div", { class: "m-head", text: title }),
    h("div", { class: "m-body" }, bodyNode),
    h("div", { class: "m-foot" }, footNode));
  ov.append(box);
  function close() { ov.remove(); document.removeEventListener("keydown", onKey); if (lastFocus) lastFocus.focus(); }
  const focusable = () => box.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  function onKey(e) {
    if (e.key === "Escape") { close(); return; }
    if (e.key !== "Tab") return;
    // Jebak fokus di dalam modal agar tidak lari ke belakang overlay.
    const items = focusable(); if (!items.length) return;
    const first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
  ov.addEventListener("mousedown", (e) => { if (e.target === ov) close(); });
  document.addEventListener("keydown", onKey);
  document.body.append(ov);
  const f = box.querySelector("button, input, a"); if (f) f.focus();
  return close;
}
function confirmModal(title, message, confirmLabel, danger, onConfirm) {
  let close;
  const btn = h("button", { class: "btn " + (danger ? "danger" : "primary"), text: confirmLabel, onclick: async () => {
    btn.disabled = true; btn.textContent = "Processing…";
    try { await onConfirm(); close(); } catch (e) { btn.disabled = false; btn.textContent = confirmLabel; flash("error", e.message); }
  } });
  close = modal(title, h("p", { text: message }),
    [h("button", { class: "btn link", text: "Cancel", onclick: () => close() }), btn]);
}

/* ---------------- Grafik garis (SVG) ---------------- */
function lineChart(points) {
  const W = 760, H = 230, padL = 46, padR = 14, padT = 14, padB = 26;
  const series = [
    { key: "allowed", name: "Allowed", color: "#2ea597" },
    { key: "blocked", name: "Blocked", color: "#c33d69" },
    { key: "counted", name: "Counted", color: "#8456ce" },
  ];
  const off = {};
  const wrap = h("div", { class: "chart chart-box" });
  if (!points || points.length === 0) { wrap.append(emptyState("No traffic data yet.")); return wrap; }
  let maxV = 1;
  for (const p of points) maxV = Math.max(maxV, p.allowed, p.blocked, p.counted);
  const niceMax = Math.max(4, Math.ceil(maxV / 4) * 4);
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const xAt = (i) => padL + (points.length === 1 ? plotW / 2 : (i / (points.length - 1)) * plotW);
  const yAt = (v) => padT + plotH - (v / niceMax) * plotH;

  function draw() {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "Per-minute traffic chart");
    const mk = (t, a) => { const e = document.createElementNS(ns, t); for (const k in a) e.setAttribute(k, a[k]); return e; };
    // gridlines + y labels
    for (let g = 0; g <= 4; g++) {
      const v = (niceMax / 4) * g, y = yAt(v);
      svg.append(mk("line", { x1: padL, y1: y, x2: W - padR, y2: y, stroke: "var(--c-grid)", "stroke-width": 1 }));
      const tx = mk("text", { x: padL - 8, y: y + 4, "text-anchor": "end", "font-size": 11, fill: "var(--text-sec)" });
      tx.textContent = num(Math.round(v)); svg.append(tx);
    }
    // x labels tiap 10 minutes
    for (let i = 0; i < points.length; i += 10) {
      const tx = mk("text", { x: xAt(i), y: H - 8, "text-anchor": "middle", "font-size": 11, fill: "var(--text-sec)" });
      tx.textContent = timeHMS(points[i].t).slice(0, 5); svg.append(tx);
    }
    // lines
    for (const s of series) {
      if (off[s.key]) continue;
      let d = "";
      points.forEach((p, i) => { d += (i === 0 ? "M" : "L") + xAt(i).toFixed(1) + " " + yAt(p[s.key]).toFixed(1); });
      svg.append(mk("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round" }));
    }
    // hover
    const cross = mk("line", { x1: 0, y1: padT, x2: 0, y2: padT + plotH, stroke: "var(--text-sec)", "stroke-width": 1, opacity: 0 });
    svg.append(cross);
    const tip = h("div", { class: "ctip" }); tip.style.display = "none";
    const overlay = mk("rect", { x: padL, y: padT, width: plotW, height: plotH, fill: "transparent" });
    svg.append(overlay);
    overlay.addEventListener("mousemove", (ev) => {
      const r = svg.getBoundingClientRect();
      const relX = (ev.clientX - r.left) / r.width * W;
      let i = Math.round((relX - padL) / plotW * (points.length - 1));
      i = Math.max(0, Math.min(points.length - 1, i));
      const p = points[i];
      cross.setAttribute("x1", xAt(i)); cross.setAttribute("x2", xAt(i)); cross.setAttribute("opacity", 1);
      tip.style.display = "block";
      tip.textContent = "";
      tip.append(h("b", { text: timeHMS(p.t).slice(0, 5) }));
      for (const s of series) tip.append(h("div", { class: "row" },
        h("span", {}, h("span", { class: "sw", style: "display:inline-block;width:9px;height:9px;border-radius:2px;background:" + s.color }), " " + s.name),
        h("b", { text: num(p[s.key]) })));
      const px = (ev.clientX - r.left);
      tip.style.left = Math.min(r.width - 150, px + 12) + "px";
      tip.style.top = "8px";
    });
    overlay.addEventListener("mouseleave", () => { cross.setAttribute("opacity", 0); tip.style.display = "none"; });
    wrap.textContent = "";
    wrap.append(svg, tip, legend());
  }
  function legend() {
    const lg = h("div", { class: "legend" });
    for (const s of series) {
      const b = h("button", { class: off[s.key] ? "off" : null, onclick: () => { off[s.key] = !off[s.key]; draw(); } },
        h("span", { class: "sw", style: "background:" + s.color }), s.name);
      lg.append(b);
    }
    return lg;
  }
  draw();
  return wrap;
}

/* ---------------- Shell ---------------- */
const NAV = [
  { sec: "WAF" },
  { href: "#/overview", icon: "dash", label: "Overview" },
  { href: "#/web-acl", icon: "acl", label: "Web ACL" },
  { href: "#/signature", icon: "sig", label: "Signature" },
  { href: "#/ip-set", icon: "ipset", label: "IP sets" },
  { href: "#/log", icon: "log", label: "Request log" },
  { sec: "Shield" },
  { href: "#/shield", icon: "shield", label: "Shield overview" },
  { href: "#/shield/ban", icon: "ban", label: "Blocked IPs" },
  { sec: "System" },
  { href: "#/settings", icon: "settings", label: "Settings" },
];

function buildShell() {
  const m = State.meta;
  const modeBlock = m.mode === "block";
  const search = h("div", { class: "search" },
    h("input", { type: "search", placeholder: "Search signatures or CVEs…", "aria-label": "Search signatures",
      onkeydown: (e) => { if (e.key === "Enter" && e.target.value.trim()) location.hash = "#/signature?q=" + encodeURIComponent(e.target.value.trim()); } }),
    ico("search", "si"));

  const userBtn = h("button", { "aria-haspopup": "true", "aria-expanded": "false", "data-testid": "user-menu" },
    ico("user"), h("span", { text: m.user }), ico("chevron"));
  const menu = h("div", { class: "menu", hidden: true, role: "menu" },
    h("div", { class: "mi-head" }, h("b", { text: m.user }), h("small", { text: "Session valid for " + m.session_max_hour + "h" })),
    h("form", { method: "post", action: "/logout" },
      h("button", { class: "mi-btn", type: "submit", "data-testid": "logout" }, ico("logout"), "Log out")));
  userBtn.addEventListener("click", (e) => { e.stopPropagation(); const open = menu.hidden; menu.hidden = !open; userBtn.setAttribute("aria-expanded", String(open)); });
  document.addEventListener("click", () => { if (!menu.hidden) { menu.hidden = true; userBtn.setAttribute("aria-expanded", "false"); } });

  const topnav = h("header", { class: "topnav" },
    h("button", { class: "icon-btn hamburger", "aria-label": "Navigation menu", html: I.menu,
      onclick: () => { State.navOpen = !State.navOpen; document.getElementById("app").classList.toggle("nav-open", State.navOpen); } }),
    h("a", { class: "brand", href: "#/overview" }, ico("shield"), h("span", {}, h("b", { text: "ExactusWAF" }), " ", h("span", { text: "Console" }))),
    search,
    h("div", { class: "spacer" }),
    h("div", { class: "tn-right" },
      h("span", { class: "chip", title: "WAF mode" }, h("span", { class: "dot " + (modeBlock ? "dot-green" : "dot-amber") }), modeBlock ? "Mode: Block" : "Mode: Monitor"),
      h("span", { class: "chip backend", title: "Protected resource" }, backendHost(m.backend)),
      h("button", { id: "themeBtn", class: "icon-btn", "aria-label": "Toggle theme", html: State.theme === "dark" ? I.sun : I.moon,
        onclick: () => setTheme(State.theme === "dark" ? "light" : "dark") }),
      h("div", { class: "usermenu" }, userBtn, menu)));

  const sidenav = h("nav", { class: "sidenav", "aria-label": "Main navigation" },
    h("h2", { text: "ExactusWAF & Shield" }),
    NAV.map((n) => n.sec ? h("div", { class: "sec", text: n.sec }) :
      h("a", { href: n.href, "data-nav": n.href }, ico(n.icon), n.label)),
    h("div", { class: "foot", text: "ExactusWAF v2.0" }));

  const scrim = h("div", { class: "scrim", onclick: () => { State.navOpen = false; document.getElementById("app").classList.remove("nav-open"); } });
  const content = h("main", { class: "content", id: "content" });
  const app = h("div", { class: "app", id: "app" }, topnav, h("div", { class: "layout" }, sidenav, scrim, content));
  document.body.textContent = "";
  document.body.append(app);
}
function backendHost(u) { try { return new URL(u).host; } catch (e) { return u; } }

function setPage(nodes, crumbs) {
  const content = document.getElementById("content");
  content.textContent = "";
  const flashbar = h("div", { class: "flashbar", id: "flashbar" });
  content.append(flashbar);
  drainFlash(flashbar);
  if (crumbs) content.append(breadcrumbs(crumbs));
  for (const n of [].concat(nodes)) if (n) content.append(n);
  content.scrollTop = 0; window.scrollTo(0, 0);
  State.navOpen = false; document.getElementById("app").classList.remove("nav-open");
}
function breadcrumbs(items) {
  const bc = h("nav", { class: "breadcrumbs", "aria-label": "Breadcrumb" });
  items.forEach((it, i) => {
    if (i) bc.append(h("span", { class: "sep", text: "›" }));
    bc.append(it.href ? h("a", { href: it.href, text: it.label }) : h("span", { text: it.label }));
  });
  return bc;
}
function pageHead(title, desc, actions) {
  return h("div", { class: "page-head" },
    h("div", { class: "ph-main" }, h("h1", { text: title }), desc ? h("div", { class: "desc", text: desc }) : null),
    actions ? h("div", { class: "ph-actions" }, actions) : null);
}
function setActiveNav(base) {
  document.querySelectorAll("[data-nav]").forEach((a) => {
    const on = a.getAttribute("data-nav") === base;
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
}
function loading() { return h("div", { class: "container" }, h("div", { class: "c-body" },
  h("div", { class: "skeleton", style: "width:40%;margin-bottom:12px" }),
  h("div", { class: "skeleton", style: "width:80%;margin-bottom:10px" }),
  h("div", { class: "skeleton", style: "width:65%" }))); }

/* ================= PAGES ================= */
const Pages = {};

/* ---- Overview ---- */
Pages.ringkasan = async function () {
  setActiveNav("#/overview");
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Overview" }]);
  host.append(loading());
  async function refresh() {
    let stats, series;
    try { [stats, series] = await Promise.all([API.get("/api/stats"), API.get("/api/series?minutes=60")]); }
    catch (e) { return; }
    const monitor = stats.mode !== "block";
    const kpis = h("div", { class: "kpis" },
      kpi("Total requests", num(stats.total_requests)),
      kpi("Allowed", num(stats.total_allowed), "allowed"),
      kpi("Blocked", num(stats.total_blocked), "blocked"),
      kpi("Counted (Count)", num(stats.total_counted), "counted"),
      kpi("Active signatures", num(stats.rules_count)),
      kpi("Uptime", fmtUptime(stats.uptime_seconds)));
    const topRules = (stats.rules || []).slice(0, 8).map((r) => r);
    const rulesTbl = table(
      [{ label: "Signature", render: (r) => h("div", {}, h("div", { text: r.rule_name }), r.cve ? h("small", { class: "muted mono", text: r.cve }) : null) },
       { label: "Severity", render: (r) => sevBadge(r.severity) },
       { label: "Hits", num: true, render: (r) => num(r.count) }],
      topRules, { empty: "No signatures triggered yet." });
    const ipTbl = table(
      [{ label: "IP address", key: "ip", mono: true }, { label: "Hits", num: true, render: (r) => num(r.count) }],
      (stats.top_ips || []).slice(0, 8), { empty: "No IPs recorded yet." });
    const recent = (stats.recent || []).slice(0, 15);
    const recentTbl = table(
      [{ label: "Time", render: (e) => h("span", { class: "nowrap", text: new Date(e.time).toLocaleTimeString("en-US", { hour12: false }) }) },
       { label: "IP", key: "ip", mono: true },
       { label: "Method", key: "method" },
       { label: "Path", mono: true, render: (e) => h("span", { title: e.path, text: trunc(e.path, 40) }) },
       { label: "Signature", key: "rule_name" },
       { label: "Severity", render: (e) => sevBadge(e.severity) },
       { label: "Action", render: (e) => aksiBadge(e.action) }],
      recent, { empty: "No attacks detected yet." });

    host.textContent = "";
    mount(host,
      pageHead("Overview", "Traffic and threats on the protected resource.",
        h("a", { class: "btn link", href: "#/web-acl/" + State.meta.active_acl.id, "data-testid": "active-acl-link" },
          "Active Web ACL: " + State.meta.active_acl.name)),
      monitor ? warnBanner("Monitor mode is on — every signatures is only counted (Count); nothing is blocked.") : null,
      kpis,
      container({ title: "Traffic (last 60 minutes)", desc: "Requests per minute by WAF inspection result." }, lineChart(series.points)),
      h("div", { class: "grid-2" },
        container({ title: "Most triggered signatures", count: (stats.rules || []).length }, rulesTbl),
        container({ title: "Top IPs by hits", count: (stats.top_ips || []).length }, ipTbl)),
      container({ title: "Recent attacks" }, recentTbl));
  }
  await refresh(); poll(refresh, 5000);
};
function kpi(label, value, cls) { return h("div", { class: "kpi" }, h("div", { class: "k-label", text: label }), h("div", { class: "k-value " + (cls || ""), text: value })); }
function warnBanner(msg) { return h("div", { class: "flash warning", style: "margin-bottom:16px" }, ico("warn", "fi"), h("span", { text: msg })); }
function trunc(s, n) { s = s || ""; return s.length > n ? s.slice(0, n) + "…" : s; }
function aksiBadge(a) {
  const map = { blocked: ["act-block", "Blocked"], "ip-blocked": ["act-block", "IP blocked"], "rate-limited": ["act-block", "Rate limit"],
    "auto-banned": ["act-block", "Auto-ban"], counted: ["act-count", "Counted"], monitored: ["act-count", "Monitored"] };
  const v = map[a] || ["act-count", a];
  return h("span", { class: "badge " + v[0], text: v[1] });
}

/* ---- Web ACL list ---- */
Pages["web-acl"] = async function (q) {
  setActiveNav("#/web-acl");
  if (q && q.has("new")) return Pages.aclEditor(null);
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Web ACL" }]);
  host.append(loading());
  let data;
  try { data = await API.get("/api/webacls"); } catch (e) { host.textContent = ""; host.append(errBox(e)); return; }
  const rows = data.acls;
  const tbl = table(
    [{ label: "Name", render: (a) => h("div", {}, h("div", {}, h("a", { href: "#/web-acl/" + a.id, text: a.name }),
        a.active ? h("span", { class: "badge", style: "margin-left:8px;background:rgba(3,127,12,.12);color:var(--success)", text: "Active" }) : null),
        a.description ? h("small", { class: "muted", text: trunc(a.description, 70) }) : null) },
     { label: "Signature", num: true, render: (a) => num(a.rule_count) },
     { label: "Block", num: true, render: (a) => num(a.block_count) },
     { label: "Count", num: true, render: (a) => num(a.count_count) },
     { label: "Capacity", render: (a) => capMeter(a.capacity, a.max_capacity) },
     { label: "Updated", render: (a) => h("span", { class: "nowrap muted", text: dateStr(a.updated_at) }) },
     { label: "", render: (a) => aclRowActions(a) }],
    rows);
  host.textContent = "";
  host.append(
    pageHead("Web ACL", "A set of signatures and their actions (Block/Count). One active Web ACL protects your site.",
      h("a", { class: "btn primary", href: "#/web-acl?new" }, ico("plus"), "Create Web ACL")),
    container({ title: "Web ACL", count: rows.length, flush: true }, tbl));
};
function capMeter(cap, max) {
  const pct = Math.min(100, Math.round(cap / max * 100));
  return h("div", { style: "min-width:120px" },
    h("div", { class: "meter" + (cap > max ? " over" : ""), title: cap + " / " + max + " WCU" }, h("div", { style: "width:" + pct + "%" })),
    h("small", { class: "muted", text: cap + " / " + max + " WCU" }));
}
function aclRowActions(a) {
  const wrap = h("div", { class: "row-gap nowrap" });
  if (!a.active) wrap.append(h("button", { class: "btn small", onclick: (e) => { e.stopPropagation(); activateACL(a); } }, ico("play"), "Activate"));
  wrap.append(h("a", { class: "btn small link", href: "#/web-acl/" + a.id + "/edit", onclick: (e) => e.stopPropagation() }, "Edit"));
  if (!a.active) wrap.append(h("button", { class: "btn small link danger", "aria-label": "Delete " + a.name, onclick: (e) => { e.stopPropagation(); deleteACL(a); } }, ico("trash")));
  return wrap;
}
async function activateACL(a) {
  confirmModal("Activate Web ACL", 'Make "' + a.name + '" the active Web ACL? The change applies to the WAF engine immediately.',
    "Activate", false, async () => { await API.post("/api/webacls/" + a.id + "/activate"); await refreshMeta(); flashAfter("success", 'Web ACL "' + a.name + '" is now active.'); route(); });
}
async function deleteACL(a) {
  confirmModal("Delete Web ACL", 'Delete "' + a.name + '"? This action cannot be undone.',
    "Delete", true, async () => { await API.del("/api/webacls/" + a.id); flashAfter("success", 'Web ACL "' + a.name + '" deleted.'); route(); });
}

/* ---- Web ACL detail ---- */
Pages.aclDetail = async function (id) {
  setActiveNav("#/web-acl");
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Web ACL", href: "#/web-acl" }, { label: id }]);
  host.append(loading());
  let a;
  try { a = await API.get("/api/webacls/" + id); } catch (e) { host.textContent = ""; host.append(errBox(e)); return; }
  const actions = h("div", { class: "row-gap" },
    a.active ? statusEl("ok", "Active Web ACL") : h("button", { class: "btn", onclick: () => activateACL({ id: a.id, name: a.name }) }, ico("play"), "Activate"),
    h("a", { class: "btn", href: "#/web-acl/" + a.id + "/edit" }, ico("edit"), "Edit"));
  const rulesTbl = table(
    [{ label: "Signature", render: (r) => h("div", {}, h("b", { text: r.name }), r.cve ? h("small", { class: "muted mono", text: " " + r.cve }) : null) },
     { label: "Group", render: (r) => r.group_name },
     { label: "Target", render: (r) => h("span", { class: "mono", text: r.target }) },
     { label: "Severity", render: (r) => sevBadge(r.severity) },
     { label: "Action", render: (r) => actionBadge(r.action) }],
    a.rules, { empty: "This Web ACL has no signatures yet." });
  host.textContent = "";
  host.append(
    pageHead(a.name, a.description || "—", actions),
    container({ title: "Overview" }, h("div", { class: "kv" },
      kv("Status", a.active ? statusEl("ok", "Active") : statusEl("muted", "Inactive")),
      kv("Signatures", String(a.rules.length)),
      kv("Capacity", capMeter(a.capacity, a.max_capacity)),
      kv("Created", dateTimeStr(a.created_at)),
      kv("Updated", dateTimeStr(a.updated_at)))),
    container({ title: "Signatures in this Web ACL", count: a.rules.length, flush: true }, rulesTbl));
};
function kv(k, v) { const val = h("div", { class: "v" }); if (v && v.nodeType) val.append(v); else val.textContent = v; return h("div", {}, h("div", { class: "k", text: k }), val); }

/* ---- Web ACL editor (create/edit) ---- */
Pages.aclEditor = async function (id) {
  setActiveNav("#/web-acl");
  const editing = !!id;
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Web ACL", href: "#/web-acl" }, { label: editing ? "Edit" : "Create new" }]);
  host.append(loading());
  let cat, existing = null;
  try {
    cat = await API.get("/api/signatures");
    if (editing) existing = await API.get("/api/webacls/" + id);
  } catch (e) { host.textContent = ""; host.append(errBox(e)); return; }

  // state: map signaturesId -> action ('block'|'count') atau undefined (tidak dipilih)
  const chosen = {};
  if (existing) for (const r of existing.rules) chosen[r.signature_id] = r.action;

  const nameInp = h("input", { class: "inp", value: existing ? existing.name : "", maxlength: "64", placeholder: "e.g. store-protection", "data-testid": "acl-name" });
  const descInp = h("textarea", { class: "inp", placeholder: "Short description (optional)" }); if (existing) descInp.value = existing.description;
  const capLabel = h("small", { class: "muted" });
  const capBar = h("div", { class: "meter" }, h("div", {}));
  const chosenCount = h("span", {});

  // bobot kapasitas = target: all=3, body=2, lainnya=1
  const weight = (sig) => sig.target === "all" ? 3 : sig.target === "body" ? 2 : 1;
  const byId = {}; for (const s of cat.signatures) byId[s.id] = s;
  function updateCap() {
    let cap = 0, n = 0;
    for (const sid in chosen) if (chosen[sid]) { cap += weight(byId[sid]); n++; }
    const pct = Math.min(100, Math.round(cap / 1500 * 100));
    capBar.firstChild.style.width = pct + "%";
    capBar.classList.toggle("over", cap > 1500);
    capLabel.textContent = cap + " / 1500 WCU";
    chosenCount.textContent = n + " signatures selected";
  }

  // bangun picker per grup
  const picker = h("div", { class: "picker" });
  const byGroup = {};
  for (const s of cat.signatures) (byGroup[s.group_id] = byGroup[s.group_id] || { name: s.group_name, items: [] }).items.push(s);
  // Deklarasikan sebelum loop: sigRow() memakainya saat picker dibangun.
  const syncFns = [];
  function sync() { syncFns.forEach((f) => f()); updateCap(); }
  for (const g of cat.groups) {
    const grp = byGroup[g.id]; if (!grp) continue;
    const body = h("div", { class: "g-body" });
    const rows = grp.items.map((s) => sigRow(s));
    body.append(...rows);
    const head = h("div", { class: "g-head" },
      ico("chevron", "chev"),
      h("span", { class: "g-name", text: g.name }),
      h("span", { class: "g-meta", text: grp.items.length + " signatures" }),
      h("button", { class: "btn small", type: "button", onclick: (e) => { e.stopPropagation(); grp.items.forEach((s) => { chosen[s.id] = "block"; }); sync(); } }, "Block all"),
      h("button", { class: "btn small link", type: "button", onclick: (e) => { e.stopPropagation(); grp.items.forEach((s) => { chosen[s.id] = "count"; }); sync(); } }, "Count all"),
      h("button", { class: "btn small link", type: "button", onclick: (e) => { e.stopPropagation(); grp.items.forEach((s) => { delete chosen[s.id]; }); sync(); } }, "Clear"));
    const box = h("div", { class: "grp" }, head, body);
    head.addEventListener("click", () => box.classList.toggle("collapsed"));
    picker.append(box);
  }
  function sigRow(s) {
    const chk = h("input", { type: "checkbox", class: "chk", "aria-label": "Select " + s.name });
    const blockBtn = h("button", { class: "", type: "button", text: "Block", onclick: () => { chosen[s.id] = "block"; sync(); } });
    const countBtn = h("button", { class: "", type: "button", text: "Count", onclick: () => { chosen[s.id] = "count"; sync(); } });
    const pill = h("div", { class: "pill-toggle" }, blockBtn, countBtn);
    chk.addEventListener("change", () => { if (chk.checked) chosen[s.id] = chosen[s.id] || "block"; else delete chosen[s.id]; sync(); });
    const upd = () => {
      const act = chosen[s.id];
      chk.checked = !!act;
      blockBtn.className = act === "block" ? "on-block" : "";
      countBtn.className = act === "count" ? "on-count" : "";
      pill.style.opacity = act ? "1" : ".5";
    };
    syncFns.push(upd); upd();
    return h("div", { class: "sig-row", dataset: { sig: s.id } }, chk,
      h("div", { class: "s-name" }, h("b", { text: s.name }), h("small", {}, (s.cve ? s.cve + " · " : ""), sevLabel(s.severity), " · ", s.target)),
      h("div", { class: "s-act" }, pill));
  }
  updateCap();

  const saveBtn = h("button", { class: "btn primary", "data-testid": "acl-save", onclick: save }, ico("check"), editing ? "Save changes" : "Create Web ACL");
  async function save() {
    const name = nameInp.value.trim();
    if (!name) { flash("error", "Web ACL name is required."); nameInp.focus(); return; }
    const rules = [];
    for (const sid in chosen) if (chosen[sid]) rules.push({ signature_id: sid, action: chosen[sid] });
    if (rules.length === 0) { flash("error", "Select at least one signature."); return; }
    saveBtn.disabled = true; saveBtn.textContent = "Saving…";
    try {
      const body = { name, description: descInp.value.trim(), rules };
      const res = editing ? await API.put("/api/webacls/" + id, body) : await API.post("/api/webacls", body);
      await refreshMeta();
      flashAfter("success", editing ? "Web ACL updated." : 'Web ACL "' + name + '" created.');
      location.hash = "#/web-acl/" + res.id;
    } catch (e) { saveBtn.disabled = false; saveBtn.innerHTML = ""; saveBtn.append(ico("check"), document.createTextNode(editing ? "Save changes" : "Create Web ACL")); flash("error", e.message); }
  }

  host.textContent = "";
  host.append(
    pageHead(editing ? "Edit Web ACL" : "Create Web ACL", "Pick signatures from the catalog and set each action: Block blocks, Count only counts."),
    container({ title: "Details" }, h("div", {},
      h("label", { class: "field" }, h("span", { class: "lbl", text: "Name" }), nameInp),
      h("label", { class: "field" }, h("span", { class: "lbl", text: "Description" }), descInp),
      h("div", { class: "row-gap", style: "justify-content:space-between" }, chosenCount,
        h("div", { style: "min-width:220px" }, capBar, capLabel)))),
    container({ title: "Signature catalog", desc: "Check to add; choose Block or Count per signature." }, picker),
    h("div", { class: "row-gap", style: "justify-content:flex-end;margin-top:4px" },
      h("a", { class: "btn link", href: editing ? "#/web-acl/" + id : "#/web-acl", text: "Cancel" }), saveBtn));
};
function sevLabel(s) { return { critical: "Critical", high: "High", medium: "Medium", low: "Low" }[s] || s; }

/* ---- Signature catalog ---- */
Pages.signature = async function (q) {
  setActiveNav("#/signature");
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Signature" }]);
  host.append(loading());
  let cat;
  try { cat = await API.get("/api/signatures"); } catch (e) { host.textContent = ""; host.append(errBox(e)); return; }
  const initQ = q && q.get("q") ? q.get("q") : "";
  const searchInp = h("input", { class: "inp", type: "search", placeholder: "Search name, CVE, category…", value: initQ });
  const groupSel = h("select", { class: "inp", style: "max-width:220px" },
    h("option", { value: "", text: "All groups" }), cat.groups.map((g) => h("option", { value: g.id, text: g.name })));
  const body = h("div", {});
  function apply() {
    const term = searchInp.value.trim().toLowerCase(), gid = groupSel.value;
    const rows = cat.signatures.filter((s) =>
      (!gid || s.group_id === gid) &&
      (!term || (s.name + " " + s.cve + " " + s.category + " " + s.id).toLowerCase().includes(term)));
    body.textContent = "";
    body.append(h("div", { class: "muted", style: "padding:10px 16px;border-bottom:1px solid var(--divider)", text: rows.length + " of " + cat.signatures.length + " signatures" }));
    body.append(table(
      [{ label: "ID", key: "id", mono: true },
       { label: "Name", key: "name" },
       { label: "CVE", render: (s) => s.cve ? h("span", { class: "mono", text: s.cve }) : h("span", { class: "muted", text: "—" }) },
       { label: "Group", render: (s) => s.group_name },
       { label: "Severity", render: (s) => sevBadge(s.severity) },
       { label: "Target", render: (s) => h("span", { class: "mono", text: s.target }) }],
      rows, { empty: "No matching signatures." }));
  }
  searchInp.addEventListener("input", apply); groupSel.addEventListener("change", apply);
  host.textContent = "";
  host.append(
    pageHead("Signatures & rule groups", "Catalog of " + cat.signatures.length + " detection signatures (version " + cat.version + ", updated " + cat.updated + ")."),
    container({ title: "Catalog", flush: true },
      h("div", {}, h("div", { class: "tbl-tools" }, h("div", { class: "search-inp", style: "flex:1;min-width:200px" }, ico("search"), searchInp), groupSel), body)));
  apply();
};

/* ---- IP sets ---- */
Pages["ip-set"] = async function () {
  setActiveNav("#/ip-set");
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "IP sets" }]);
  host.append(loading());
  let s;
  try { s = await API.get("/api/shield"); } catch (e) { host.textContent = ""; host.append(errBox(e)); return; }
  const ipTable = (list, empty) => table([{ label: "IP address", key: "ip", mono: true, render: (x) => h("span", { class: "mono", text: x }) }],
    list.map((ip) => ip), { empty }) ;
  host.textContent = "";
  host.append(
    pageHead("IP sets", "IPs that are always blocked or always allowed. Managed via the config file."),
    h("div", { class: "flash info", style: "margin-bottom:16px" }, ico("info", "fi"),
      h("span", { text: "IP sets are read-only in the console for now. Edit ip_blocklist / ip_allowlist in config.yaml and restart." })),
    h("div", { class: "grid-2" },
      container({ title: "Always blocked", count: s.blocklist.length, flush: true }, listOrEmpty(s.blocklist, "No permanently blocked IPs.")),
      container({ title: "Always allowed", count: s.allowlist.length, flush: true }, listOrEmpty(s.allowlist, "No allowlisted IPs."))));
};
function listOrEmpty(list, empty) {
  if (!list || list.length === 0) return emptyState(empty);
  return h("div", { class: "table-wrap" }, h("table", { class: "tbl" }, h("tbody", {},
    list.map((ip) => h("tr", {}, h("td", { class: "mono", text: ip }))))));
}

/* ---- Request log ---- */
Pages.log = async function () {
  setActiveNav("#/log");
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Request log" }]);
  host.append(loading());
  const filterInp = h("input", { class: "inp", type: "search", placeholder: "Filter: IP, path, signatures…" });
  let latest = [];
  const body = h("div", {});
  function render() {
    const term = filterInp.value.trim().toLowerCase();
    const rows = latest.filter((e) => !term || ((e.ip + " " + e.path + " " + e.rule_name + " " + e.method + " " + (e.cve || "")).toLowerCase().includes(term)));
    body.textContent = "";
    body.append(table(
      [{ label: "Time", render: (e) => h("span", { class: "nowrap", text: dateTimeStr(e.time) }) },
       { label: "IP", key: "ip", mono: true },
       { label: "Method", key: "method" },
       { label: "Path", mono: true, render: (e) => h("span", { title: e.path, text: trunc(e.path, 48) }) },
       { label: "Signature", render: (e) => h("div", {}, h("div", { text: e.rule_name }), e.cve ? h("small", { class: "muted mono", text: e.cve }) : null) },
       { label: "Severity", render: (e) => sevBadge(e.severity) },
       { label: "Action", render: (e) => aksiBadge(e.action) }],
      rows, { empty: term ? "Nothing matches the filter." : "No requests recorded yet." }));
  }
  filterInp.addEventListener("input", render);
  async function refresh() { try { const s = await API.get("/api/stats"); latest = s.recent || []; render(); } catch (e) {} }
  host.textContent = "";
  host.append(
    pageHead("Request log", "The most recent requests inspected by the WAF (up to 200)."),
    container({ title: "Log", flush: true }, h("div", {}, h("div", { class: "tbl-tools" }, h("div", { class: "search-inp", style: "flex:1;min-width:220px" }, ico("search"), filterInp)), body)));
  await refresh(); poll(refresh, 5000);
};

/* ---- Shield overview ---- */
Pages.shield = async function () {
  setActiveNav("#/shield");
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Shield" }]);
  host.append(loading());
  async function refresh() {
    let s; try { s = await API.get("/api/shield"); } catch (e) { return; }
    const ab = s.autoban;
    host.textContent = "";
    host.append(
      pageHead("Shield overview", "Second layer of defense: auto-ban repeat attackers and rate limiting.",
        h("a", { class: "btn", href: "#/shield/ban" }, ico("ban"), "View blocked IPs")),
      h("div", { class: "kpis" },
        kpi("Auto-ban", ab.enabled ? "Active" : "Inactive"),
        kpi("Currently blocked IPs", num(s.bans.length), "blocked"),
        kpi("Rate limit", s.rate_limit.enabled ? num(s.rate_limit.requests_per_minute) + "/mnt" : "Inactive")),
      container({ title: "Auto-ban settings" }, h("div", { class: "kv" },
        kv("Status", ab.enabled ? statusEl("ok", "Active") : statusEl("muted", "Inactive")),
        kv("Threshold", ab.max_strikes + " attacks within " + ab.window_minutes + " minutes"),
        kv("Block duration", ab.ban_minutes + " minutes"),
        kv("Block scope", ab.scope === "ip_ua" ? "IP + browser type (safe for CGNAT)" : "Whole IP"))),
      container({ title: "Rate limiting" }, h("div", { class: "kv" },
        kv("Status", s.rate_limit.enabled ? statusEl("ok", "Active") : statusEl("muted", "Inactive")),
        kv("Batas", num(s.rate_limit.requests_per_minute) + " requests / minute per IP"),
        kv("Burst", num(s.rate_limit.burst)),
        kv("Trust proxy headers", s.trust_proxy_headers ? statusEl("warn", "Yes (X-Forwarded-For)") : statusEl("muted", "No")))));
  }
  await refresh(); poll(refresh, 5000);
};

/* ---- Shield bans ---- */
Pages["shield/ban"] = async function () {
  setActiveNav("#/shield/ban");
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Shield", href: "#/shield" }, { label: "Blocked IPs" }]);
  host.append(loading());
  async function refresh() {
    let s; try { s = await API.get("/api/shield"); } catch (e) { return; }
    const tbl = table(
      [{ label: "IP address", key: "ip", mono: true },
       { label: "Ends", render: (b) => h("span", { class: "nowrap", text: new Date(b.until).toLocaleTimeString("en-US", { hour12: false }) }) },
       { label: "Time left", render: (b) => fmtDur(b.seconds_left) },
       { label: "", render: (b) => h("button", { class: "btn small", onclick: () => unban(b) }, "Unblock") }],
      s.bans, { empty: "No IPs currently auto-blocked." });
    host.textContent = "";
    host.append(
      pageHead("Auto-blocked IPs", "IPs temporarily blocked by auto-ban. Unblock if needed."),
      container({ title: "Active blocks", count: s.bans.length, flush: true }, tbl));
  }
  async function unban(b) {
    try { await API.post("/api/shield/unban", { key: b.key }); flash("success", "Block for " + b.ip + " lifted."); refresh(); }
    catch (e) { flash("error", e.message); }
  }
  await refresh(); poll(refresh, 5000);
};

/* ---- Settings ---- */
Pages.pengaturan = async function () {
  setActiveNav("#/settings");
  const host = h("div", {});
  setPage(host, [{ label: "ExactusWAF" }, { label: "Settings" }]);
  host.append(loading());
  let s; try { s = await API.get("/api/settings"); } catch (e) { host.textContent = ""; host.append(errBox(e)); return; }

  const seg = h("div", { class: "seg", role: "group", "aria-label": "Mode WAF" });
  const mkBtn = (val, label) => h("button", { class: s.mode === val ? "on" : "", text: label, onclick: () => setMode(val) });
  const bBtn = mkBtn("block", "Block"), mBtn = mkBtn("monitor", "Monitor");
  seg.append(bBtn, mBtn);
  async function setMode(val) {
    if (val === s.mode) return;
    try { await API.post("/api/mode", { mode: val }); s.mode = val;
      bBtn.className = val === "block" ? "on" : ""; mBtn.className = val === "monitor" ? "on" : "";
      await refreshMeta(); flash("success", "Mode changed to " + (val === "block" ? "Block" : "Monitor") + "."); }
    catch (e) { flash("error", e.message); }
  }

  host.textContent = "";
  host.append(
    pageHead("Settings", "ExactusWAF configuration. Most settings come from config.yaml; mode can be changed here."),
    container({ title: "Operating mode", desc: "Block: attacks are rejected. Monitor: every signatures is only counted (Count)." },
      h("div", {}, seg, h("div", { class: "muted mt8", text: s.mode === "block" ? "Requests matching a Block signatures are rejected." : "Monitor mode: nothing is blocked, only recorded." }))),
    container({ title: "General" }, h("div", { class: "kv" },
      kv("Protected backend", h("span", { class: "mono", text: s.backend })),
      kv("Listening on", h("span", { class: "mono", text: s.listen })),
      kv("Console on", h("span", { class: "mono", text: s.dashboard_listen })),
      kv("HTTPS", s.tls_enabled ? statusEl("ok", "Active") : statusEl("muted", "Inactive")),
      kv("Telegram notifications", s.telegram_enabled ? statusEl("ok", "Active") : statusEl("muted", "Inactive")),
      kv("Log file", s.log_file ? h("span", { class: "mono", text: s.log_file }) : h("span", { class: "muted", text: "to screen/container" })))),
    container({ title: "Rate limit & proxy" }, h("div", { class: "kv" },
      kv("Rate limit", s.rate_limit.enabled ? num(s.rate_limit.requests_per_minute) + "/mnt (burst " + s.rate_limit.burst + ")" : "Inactive"),
      kv("Trust proxy headers", s.trust_proxy_headers ? statusEl("warn", "Yes") : statusEl("muted", "No")),
      kv("Data directory", s.data_dir ? h("span", { class: "mono", text: s.data_dir }) : h("span", { class: "muted", text: "(Web ACL in memory only)" })))));
};

/* ---------------- util error ---------------- */
function errBox(e) { return h("div", { class: "flash error" }, ico("alert", "fi"), h("span", { text: e.message || "Something went wrong." })); }

/* ---------------- Router ---------------- */
async function refreshMeta() { try { State.meta = await API.get("/api/meta"); updateTopbar(); } catch (e) {} }
function updateTopbar() {
  const m = State.meta; if (!m) return;
  // refresh mode chip + active acl shown on next render; cheap full rebuild of topbar chip:
  const chip = document.querySelector(".topnav .chip");
  if (chip) { const block = m.mode === "block"; chip.textContent = ""; chip.append(h("span", { class: "dot " + (block ? "dot-green" : "dot-amber") }), block ? "Mode: Block" : "Mode: Monitor"); }
}

function parseHash() {
  let hash = location.hash.replace(/^#/, "") || "/overview";
  const qi = hash.indexOf("?");
  let query = null;
  if (qi >= 0) { query = new URLSearchParams(hash.slice(qi + 1)); hash = hash.slice(0, qi); }
  const parts = hash.split("/").filter(Boolean); // e.g. ['web-acl','id','edit']
  return { parts, query };
}

async function route() {
  stopPoll(); clearFlash && document.getElementById("flashbar") && clearFlash();
  const { parts, query } = parseHash();
  const p0 = parts[0] || "overview";
  try {
    if (p0 === "overview") return await Pages.ringkasan();
    if (p0 === "signature") return await Pages.signature(query);
    if (p0 === "ip-set") return await Pages["ip-set"]();
    if (p0 === "log") return await Pages.log();
    if (p0 === "settings") return await Pages.pengaturan();
    if (p0 === "shield") return parts[1] === "ban" ? await Pages["shield/ban"]() : await Pages.shield();
    if (p0 === "web-acl") {
      if (!parts[1]) return await Pages["web-acl"](query);
      if (parts[2] === "edit") return await Pages.aclEditor(parts[1]);
      return await Pages.aclDetail(parts[1]);
    }
    return await Pages.ringkasan();
  } catch (e) {
    if (e.message === "401") return;
    const c = document.getElementById("content");
    if (c) { c.textContent = ""; c.append(h("div", { class: "flashbar", id: "flashbar" }), errBox(e)); }
  }
}

/* ---------------- Boot ---------------- */
async function boot() {
  loadTheme();
  try { State.meta = await API.get("/api/meta"); }
  catch (e) { if (e.message === "401") return; document.body.textContent = "Failed to load console: " + e.message; return; }
  buildShell();
  window.addEventListener("hashchange", route);
  await route();
}
boot();
