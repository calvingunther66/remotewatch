"use strict";

// ---------- tiny helpers ----------
const $ = (sel, root = document) => root.querySelector(sel);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) n.append(kid.nodeType ? kid : document.createTextNode(kid));
  return n;
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

function relTime(ts) {
  if (!ts) return "—";
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}

function flash(node, kind = "success", ms = 4000) {
  const box = $("#msg");
  box.innerHTML = "";
  const p = el("p", { class: kind === "error" ? "error" : "success" }, node);
  box.append(p);
  if (ms) setTimeout(() => { if (box.contains(p)) p.remove(); }, ms);
}

// ---------- state ----------
const state = { keys: [], reports: [], authenticated: false, view: "trackers", map: null, layer: null };

// ---------- data loading ----------
async function loadAll() {
  const [{ keys }, { reports }, auth] = await Promise.all([
    api("/api/keys"),
    api("/api/reports"),
    api("/api/auth/status"),
  ]);
  state.keys = keys;
  state.reports = reports;
  state.authenticated = auth.authenticated;
  render();
}

// ---------- rendering ----------
function render() {
  renderAuthBadge();
  renderTiles();
  renderKeysTable();
  renderFixes();
  if (state.view === "map") renderMap();
}

function renderAuthBadge() {
  const badge = $("#auth-badge");
  badge.innerHTML = "";
  const dot = el("span", { class: "s-dot " + (state.authenticated ? "s-good" : "s-muted") });
  const b = el("button", {
    class: "badge", style: "cursor:pointer",
    onclick: openAuthModal,
  }, dot, state.authenticated ? "Apple ID connected" : "Connect Apple ID");
  badge.append(b);

  $("#nav-account").textContent = state.authenticated ? "connected" : "not connected";
  $("#btn-refresh").disabled = !state.authenticated;
}

function renderTiles() {
  const located = state.keys.filter((k) => k.last_report).length;
  const totalReports = state.reports.length;
  let last = 0;
  for (const k of state.keys) if (k.last_report && k.last_report.timestamp > last) last = k.last_report.timestamp;

  const tiles = [
    ["trackers", String(state.keys.length), state.keys.length === 1 ? "1 keyfile" : state.keys.length + " keyfiles"],
    ["located", String(located), located ? "seen on the network" : "none located yet"],
    ["reports cached", String(totalReports), "decrypted fixes"],
    ["last fix", last ? relTime(last) : "—", state.authenticated ? "auto via FindMy" : "connect to track"],
  ];
  const root = $("#stat-tiles");
  root.innerHTML = "";
  for (const [label, value, sub] of tiles) {
    root.append(el("div", { class: "card tile" },
      el("div", { class: "label" }, label),
      el("div", { class: "value" }, value),
      el("div", { class: "sub" }, sub),
    ));
  }
}

function renderKeysTable() {
  const body = $("#keys-body");
  body.innerHTML = "";
  $("#keys-empty").style.display = state.keys.length ? "none" : "block";
  $("#page-sub").textContent = state.keys.length
    ? `${state.keys.length} tracker${state.keys.length === 1 ? "" : "s"} · ${state.reports.length} cached fixes`
    : "clone AirTags, generate keys, watch them on the FindMy network";

  for (const k of state.keys) {
    const lr = k.last_report;
    const stale = !lr || Date.now() / 1000 - lr.timestamp > 3 * 3600;
    const pin = el("span", { class: "map-pin pin-preview" + (stale ? " stale" : ""),
      style: "width:11px;height:11px" });

    const pos = lr ? el("a", { href: `https://maps.google.com/maps?q=${lr.lat},${lr.lon}`, target: "_blank" },
      `${lr.lat.toFixed(4)}, ${lr.lon.toFixed(4)}`) : el("span", { class: "muted" }, "—");

    const actions = el("div", { class: "row", style: "gap:6px;justify-content:flex-end" },
      lr ? el("button", { class: "mini", onclick: () => locateOnMap(k) }, "locate") : null,
      el("button", { class: "mini", onclick: () => downloadKey(k) }, "keys"),
      el("button", { class: "mini danger", onclick: () => deleteKey(k) }, "✕"),
    );

    body.append(el("tr", {},
      el("td", {}, pin),
      el("td", {}, el("b", {}, k.name)),
      el("td", {}, el("span", { class: "mac" }, k.mac)),
      el("td", {}, relTime(lr && lr.timestamp)),
      el("td", { class: "num" }, String(k.report_count)),
      el("td", { class: "num" }, pos),
      el("td", {}, actions),
    ));
  }
}

function renderFixes() {
  const body = $("#fixes-body");
  body.innerHTML = "";
  const fixes = [...state.reports].sort((a, b) => b.timestamp - a.timestamp).slice(0, 200);
  $("#fixes-empty").style.display = fixes.length ? "none" : "block";
  $("#map-count").textContent = fixes.length ? `${fixes.length} points` : "";
  for (const f of fixes) {
    body.append(el("tr", {},
      el("td", {}, el("b", {}, f.key)),
      el("td", {}, new Date(f.timestamp * 1000).toLocaleString()),
      el("td", { class: "num" }, f.lat.toFixed(5)),
      el("td", { class: "num" }, f.lon.toFixed(5)),
      el("td", { class: "num" }, String(f.conf)),
    ));
  }
}

// ---------- map ----------
function ensureMap() {
  if (typeof L === "undefined") return null; // Leaflet (CDN) unavailable
  if (state.map) return state.map;
  state.map = L.map("map", { zoomControl: true }).setView([20, 0], 2);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 19,
    attribution: "© OpenStreetMap",
  }).addTo(state.map);
  state.layer = L.layerGroup().addTo(state.map);
  return state.map;
}

function renderMap() {
  const map = ensureMap();
  if (!map) {
    $("#map").innerHTML =
      '<div class="empty" style="padding:60px 20px">map library could not load — check network access</div>';
    return;
  }
  setTimeout(() => map.invalidateSize(), 0);
  state.layer.clearLayers();

  // group reports by tracker to draw a trail + latest pin per key
  const byKey = {};
  for (const r of state.reports) (byKey[r.key] ||= []).push(r);

  const bounds = [];
  for (const [name, pts] of Object.entries(byKey)) {
    pts.sort((a, b) => a.timestamp - b.timestamp);
    const latlngs = pts.map((p) => [p.lat, p.lon]);
    latlngs.forEach((ll) => bounds.push(ll));
    if (latlngs.length > 1) {
      L.polyline(latlngs, { color: "#c15f3c", weight: 2, opacity: 0.55, dashArray: "4 5" }).addTo(state.layer);
    }
    const latest = pts[pts.length - 1];
    const stale = Date.now() / 1000 - latest.timestamp > 3 * 3600;
    const icon = L.divIcon({ className: "", html: `<div class="map-pin${stale ? " stale" : ""}"></div>`, iconSize: [16, 16], iconAnchor: [8, 8] });
    L.marker([latest.lat, latest.lon], { icon })
      .bindPopup(`<b>${name}</b><br>${new Date(latest.timestamp * 1000).toLocaleString()}<br>${latest.lat.toFixed(5)}, ${latest.lon.toFixed(5)} · conf ${latest.conf}`)
      .addTo(state.layer);
  }
  if (bounds.length) map.fitBounds(bounds, { padding: [40, 40], maxZoom: 16 });
}

function locateOnMap(k) {
  switchView("map");
  renderMap();
  const lr = k.last_report;
  if (lr && state.map) state.map.setView([lr.lat, lr.lon], 15);
}

// ---------- navigation ----------
function switchView(view) {
  state.view = view;
  $("#view-trackers").style.display = view === "trackers" ? "block" : "none";
  $("#view-map").style.display = view === "map" ? "block" : "none";
  $(".page-title").textContent = view === "map" ? "Map" : "Trackers";
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  if (view === "map") renderMap();
}

// ---------- actions ----------
async function downloadKey(k) {
  window.location = `/api/keys/${encodeURIComponent(k.name)}/download`;
}

async function deleteKey(k) {
  if (!confirm(`Delete tracker "${k.name}"? The .keys file is removed from the server.`)) return;
  try {
    await api(`/api/keys/${encodeURIComponent(k.name)}`, { method: "DELETE" });
    flash(`Deleted ${k.name}.`);
    await loadAll();
  } catch (e) {
    flash(e.message, "error");
  }
}

async function refreshReports() {
  const btn = $("#btn-refresh");
  const label = $("#refresh-label");
  btn.disabled = true;
  label.innerHTML = '<span class="spinner"></span> fetching…';
  try {
    const hours = Number($("#hours").value);
    const r = await api("/api/reports/refresh", { method: "POST", body: { hours, prefix: "" } });
    let note = `${r.total} report${r.total === 1 ? "" : "s"} decrypted`;
    if (r.missing && r.missing.length) note += ` · ${r.missing.length} tracker(s) not yet seen`;
    flash(note, r.total ? "success" : "error");
    await loadAll();
  } catch (e) {
    flash(e.message, "error");
  } finally {
    btn.disabled = !state.authenticated;
    label.textContent = "↻ Refresh locations";
  }
}

// ---------- modals ----------
function closeModal() { $("#modal-root").innerHTML = ""; }

function modal(title, ...content) {
  const root = $("#modal-root");
  root.innerHTML = "";
  const box = el("div", { class: "modal" },
    el("div", { class: "row spread" }, el("h3", {}, title), el("button", { class: "ghost mini", onclick: closeModal }, "close")),
    ...content,
  );
  const backdrop = el("div", { class: "modal-backdrop", onclick: (e) => { if (e.target === backdrop) closeModal(); } }, box);
  root.append(backdrop);
  return box;
}

function openCreateModal() {
  const count = el("input", { type: "number", min: "1", max: "50", value: "1" });
  const prefix = el("input", { type: "text", placeholder: "e.g. backpack (optional)" });
  const out = el("div");
  const submit = el("button", { class: "primary" }, "Generate");

  submit.addEventListener("click", async () => {
    submit.disabled = true;
    submit.innerHTML = '<span class="spinner"></span> generating…';
    try {
      const r = await api("/api/keys", { method: "POST", body: { count: Number(count.value) || 1, prefix: prefix.value } });
      out.innerHTML = "";
      out.append(el("p", { class: "success" }, `Created ${r.created.length} keyfile${r.created.length === 1 ? "" : "s"}.`));
      const pre = el("pre", { class: "output" }, r.created.map((k) =>
        `● ${k.name}\n  MAC:     ${k.mac}\n  payload: ${k.payload}`).join("\n\n"));
      out.append(pre);
      out.append(el("p", { class: "muted", style: "font-style:italic;font-size:12.5px" },
        "Copy each .keys file to your Flipper at Apps_Data/FindMyFlipper/, or use the MAC + payload directly."));
      await loadAll();
    } catch (e) {
      out.innerHTML = "";
      out.append(el("p", { class: "error" }, e.message));
    } finally {
      submit.disabled = false;
      submit.textContent = "Generate";
    }
  });

  modal("Create .keys",
    el("p", { class: "muted", style: "font-style:italic;margin:0" },
      "Mint fresh OpenHaystack key pairs. Private keys stay on the server; the browser only sees the public MAC + payload."),
    el("label", { class: "field" }, "how many", count),
    el("label", { class: "field" }, "name prefix", prefix),
    el("div", { class: "row" }, submit),
    out,
  );
}

function openAuthModal() {
  if (state.authenticated) return openSignedInModal();

  const user = el("input", { type: "text", placeholder: "you@icloud.com", autocomplete: "username" });
  const pass = el("input", { type: "password", placeholder: "Apple ID password", autocomplete: "current-password" });
  const method = el("select", {},
    el("option", { value: "sms" }, "Text me a code (SMS)"),
    el("option", { value: "trusted_device" }, "Trusted device prompt"),
  );
  const out = el("div");
  const submit = el("button", { class: "primary" }, "Sign in");

  submit.addEventListener("click", async () => {
    submit.disabled = true;
    submit.innerHTML = '<span class="spinner"></span> signing in…';
    out.innerHTML = "";
    try {
      const r = await api("/api/auth/login", { method: "POST", body: { username: user.value.trim(), password: pass.value, method: method.value } });
      if (r.status === "needs_2fa") {
        show2fa(r.session_id, r.method);
      } else {
        closeModal();
        flash("Apple ID connected.");
        await loadAll();
      }
    } catch (e) {
      out.append(el("p", { class: "error" }, e.message));
      submit.disabled = false;
      submit.textContent = "Sign in";
    }
  });

  modal("Connect Apple ID",
    el("p", { class: "muted", style: "font-style:italic;margin:0" },
      "Needed to query the FindMy network for location reports. Credentials are used once for Apple sign-in; only the resulting token is stored on the server."),
    el("label", { class: "field" }, "Apple ID", user),
    el("label", { class: "field" }, "password", pass),
    el("label", { class: "field" }, "2FA method", method),
    el("div", { class: "row" }, submit),
    el("p", { class: "muted", style: "font-style:italic;font-size:12px" },
      "Requires a reachable anisette server (ANISETTE_URL). See the README."),
    out,
  );
}

function show2fa(sessionId, method) {
  const code = el("input", { type: "text", inputmode: "numeric", placeholder: "123456", maxlength: "8" });
  const out = el("div");
  const submit = el("button", { class: "primary" }, "Verify");

  submit.addEventListener("click", async () => {
    submit.disabled = true;
    submit.innerHTML = '<span class="spinner"></span> verifying…';
    out.innerHTML = "";
    try {
      await api("/api/auth/verify", { method: "POST", body: { session_id: sessionId, code: code.value.trim() } });
      closeModal();
      flash("Apple ID connected.");
      await loadAll();
    } catch (e) {
      out.append(el("p", { class: "error" }, e.message));
      submit.disabled = false;
      submit.textContent = "Verify";
    }
  });

  modal("Two-factor code",
    el("p", { class: "muted", style: "font-style:italic;margin:0" },
      method === "trusted_device"
        ? "Enter the 6-digit code shown on your trusted Apple device."
        : "Enter the 6-digit code Apple just texted you."),
    el("label", { class: "field" }, "code", code),
    el("div", { class: "row" }, submit),
    out,
  );
  code.focus();
}

function openSignedInModal() {
  const out = el("div");
  const signout = el("button", { class: "danger" }, "Sign out");
  signout.addEventListener("click", async () => {
    try {
      await api("/api/auth/logout", { method: "POST" });
      closeModal();
      flash("Signed out of Apple ID.");
      await loadAll();
    } catch (e) {
      out.append(el("p", { class: "error" }, e.message));
    }
  });
  modal("Apple ID",
    el("p", { class: "success", style: "margin:0" }, "Connected to the FindMy network."),
    el("p", { class: "muted", style: "font-style:italic;font-size:12.5px" },
      "The stored search-party token lets RemoteWatch pull location reports. Sign out to remove it from the server."),
    el("div", { class: "row" }, signout),
    out,
  );
}

// ---------- wire up ----------
document.querySelectorAll(".nav-item").forEach((n) =>
  n.addEventListener("click", () => switchView(n.dataset.view)));
$("#btn-create").addEventListener("click", openCreateModal);
$("#btn-refresh").addEventListener("click", refreshReports);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });

loadAll().catch((e) => flash("Could not load: " + e.message, "error"));
