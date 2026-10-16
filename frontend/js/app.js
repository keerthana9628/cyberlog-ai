// CYBERLOG AI frontend - plain JavaScript. Set window.API_BASE (in index.html) when the backend is on another domain.
const API = window.API_BASE || "";
const $ = s => document.querySelector(s);
const charts = {};
let sessionId = null, report = "";
const SEV = {LOW:"#3fb950", MEDIUM:"#d29922", HIGH:"#f0883e", CRITICAL:"#f85149"};
const TYPES = ["Brute Force","Port Scan","Unauthorized Access","Request Spike","Suspicious Login","Anomaly"];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const when = t => new Date(t * 1000).toISOString().replace("T", " ").slice(0, 19);
const sev = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;

async function api(path, opts) {
  let r;
  try { r = await fetch(API + "/api" + path, opts); } catch (e) { throw new Error("Cannot reach the backend. Is Spring Boot running?"); }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || "Request failed (" + r.status + ")");
  return j;
}
function toast(msg, err) { const t = $("#toast"); t.textContent = msg; t.className = "toast" + (err ? " err" : ""); setTimeout(() => t.classList.add("hidden"), 4500); }
function guard(fn) { return async (...a) => { try { await fn(...a); } catch (e) { $("#overlay").classList.add("hidden"); toast(e.message, true); } }; }

// ---------- tabs ----------
function show(tab) {
  document.querySelectorAll(".tab").forEach(s => s.classList.toggle("active", s.id === tab));
  document.querySelectorAll("#nav button").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
  ({dashboard: loadDash, ai: loadDash, threats: loadThreats, ips: loadIps, logs: loadLogs}[tab] || (() => {}))();
}
document.querySelectorAll("#nav button").forEach(b => b.onclick = guard(() => show(b.dataset.tab)));

// ---------- upload ----------
const drop = $("#drop");
$("#browse").onclick = () => $("#file").click();
$("#file").onchange = e => e.target.files[0] && handleFile(e.target.files[0]);
drop.ondragover = e => { e.preventDefault(); drop.classList.add("over"); };
drop.ondragleave = () => drop.classList.remove("over");
drop.ondrop = e => { e.preventDefault(); drop.classList.remove("over"); e.dataTransfer.files[0] && handleFile(e.dataTransfer.files[0]); };
const handleFile = guard(async file => {
  const fd = new FormData(); fd.append("file", file);
  const r = await api("/logs/upload", {method: "POST", body: fd});
  sessionId = r.sessionId;
  $("#fileinfo").innerHTML = `<div><span>File name</span>${esc(r.fileName)}</div><div><span>File size</span>${(r.size/1024).toFixed(1)} KB</div><div><span>Records</span>${r.records}${r.skippedLines ? " ("+r.skippedLines+" lines skipped)" : ""}</div><div><span>Detected format</span>${esc(r.format)}</div>`;
  $("#fileinfo").classList.remove("hidden"); $("#analyze").classList.remove("hidden");
  toast("File uploaded. Click ANALYZE LOG.");
});
$("#analyze").onclick = guard(async () => {
  $("#overlay").classList.remove("hidden");
  const steps = ["Parsing logs…", "Running rule-based detection…", "Running AI anomaly detection…", "Scoring risk & saving results…"];
  let i = 0; $("#ov-text").textContent = steps[0];
  const iv = setInterval(() => $("#ov-text").textContent = steps[Math.min(++i, 3)], 900);
  try {
    const r = await api("/logs/analyze", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({sessionId})});
    toast(`Done: ${r.threats} threats found.` + (r.aiAvailable ? "" : " (AI service offline: rule-based results only)"), !r.aiAvailable);
  } finally { clearInterval(iv); $("#overlay").classList.add("hidden"); }
  show("dashboard");
});

// ---------- dashboard ----------
function chart(id, type, labels, data, colors, label) {
  charts[id]?.destroy();
  const axis = {ticks: {color: "#8592b3"}, grid: {color: "#1f2b4a"}};
  charts[id] = new Chart($("#" + id), {type, data: {labels, datasets: [{label, data, backgroundColor: colors, borderColor: type === "line" ? "#58a6ff" : "#0a0e1a", fill: type === "line", tension: .3}]},
    options: {plugins: {legend: {display: type === "doughnut", labels: {color: "#d7def0"}}}, scales: type === "doughnut" ? {} : {x: axis, y: {...axis, beginAtZero: true}}}});
}
async function loadDash() {
  const d = await api("/dashboard");
  $("#dash-empty").classList.toggle("hidden", d.hasData); $("#dash-body").classList.toggle("hidden", !d.hasData);
  if (!d.hasData) return;
  const c = (l, v, col) => `<div class="card stat"><small>${l}</small><b style="color:${col}">${v}</b></div>`;
  $("#cards").innerHTML = c("Total log events", d.totalEvents, "#58a6ff") + c("Normal events", d.normalEvents, "#3fb950") + c("Suspicious events", d.suspiciousEvents, "#f0883e") +
    c("Threats detected", d.threats, "#f85149") + c("Critical threats", d.criticalThreats, "#f85149") + c("High-risk IPs", d.highRiskIps, "#f0883e") +
    c("Calculated Security Score", d.securityScore + "/100", d.securityScore > 75 ? "#3fb950" : d.securityScore > 50 ? "#d29922" : "#f85149");
  chart("c-sev", "doughnut", d.bySeverity.map(x => x.k), d.bySeverity.map(x => x.v), d.bySeverity.map(x => SEV[x.k]));
  chart("c-type", "bar", d.byType.map(x => x.k), d.byType.map(x => x.v), "#a371f7", "Threats");
  chart("c-time", "line", d.timeline.map(x => when(x.t).slice(11, 16)), d.timeline.map(x => x.c), "#58a6ff33", "Events");
  chart("c-ips", "bar", d.topIps.map(x => x.ip), d.topIps.map(x => x.risk_score), "#f85149", "Risk");
  chart("c-ai", "doughnut", ["Normal", "Anomalous"], [d.normalVsAnomalous.normal, d.normalVsAnomalous.anomalous], ["#3fb950", "#f85149"]);
  chart("c-status", "bar", d.statusDist.map(x => x.k), d.statusDist.map(x => x.v), "#58a6ff", "Requests");
  const a = d.ai;
  $("#ai-body").className = "";
  $("#ai-body").innerHTML = `<div class="cards"><div class="card stat"><small>Anomalous IPs</small><b>${a.anomalies}</b></div><div class="card stat"><small>Anomaly percentage</small><b>${a.anomalyPercent}%</b></div><div class="card stat"><small>AI risk score</small><b>${a.aiRiskScore}</b></div></div>
   <p class="muted">Isolation Forest (scikit-learn) is an educational anomaly-detection model, not a certified security system. ${d.session.ai_available ? "" : "<b>The AI service was offline for this analysis.</b>"}</p>
   <div class="card scroll"><table><tr><th>IP</th><th>Requests</th><th>Anomaly score</th><th>Why it was flagged</th></tr>${a.topAnomalies.map(x => `<tr><td><code>${esc(x.ip)}</code></td><td>${x.requests}</td><td>${x.anomaly_score}</td><td>${esc(x.ai_reason)}</td></tr>`).join("") || '<tr><td colspan="4">No anomalies found.</td></tr>'}</table></div>`;
}

// ---------- filters (used by Threats and Log Explorer) ----------
document.querySelectorAll(".filters").forEach(f => {
  const p = f.dataset.p;
  f.innerHTML = `<input id="${p}-q" placeholder="Search…"><input id="${p}-ip" placeholder="IP address"><select id="${p}-sev"><option value="">Severity</option>${Object.keys(SEV).map(s => `<option>${s}</option>`).join("")}</select>
   <select id="${p}-type"><option value="">Threat type</option>${TYPES.map(s => `<option>${s}</option>`).join("")}</select><input id="${p}-from" type="datetime-local" title="From"><input id="${p}-to" type="datetime-local" title="To">`;
  f.querySelectorAll("input,select").forEach(el => el.oninput = guard(() => p === "t" ? loadThreats() : loadLogs()));
});
function qs(p) {
  const v = id => $("#" + p + "-" + id).value, u = new URLSearchParams();
  [["q","q"],["ip","ip"],["sev","severity"],["type","type"]].forEach(([i,k]) => v(i) && u.set(k, v(i)));
  ["from","to"].forEach(i => v(i) && u.set(i, Math.floor(new Date(v(i) + "Z").getTime() / 1000)));  // logs are UTC
  return "?" + u;
}
async function loadThreats() {
  const rows = await api("/threats" + qs("t"));
  $("#t-table").innerHTML = `<tr><th>Timestamp (UTC)</th><th>IP Address</th><th>Threat Type</th><th>Severity</th><th>Confidence</th><th>Reason</th><th>Status</th></tr>` +
    (rows.map(r => `<tr class="click" data-id="${r.id}"><td>${when(r.ts)}</td><td><code>${esc(r.ip)}</code></td><td>${esc(r.type)}</td><td>${sev(r.severity)}</td><td>${Math.round(r.confidence * 100)}%</td><td>${esc(r.reason)}</td><td>${esc(r.status)}</td></tr>`).join("") || `<tr><td colspan="7" class="empty">No threats match.</td></tr>`);
  $("#t-table").querySelectorAll("tr.click").forEach(tr => tr.onclick = guard(() => detail(tr.dataset.id)));
}
async function detail(id) {
  const t = await api("/threats/" + id), f = JSON.parse(t.factors || "{}");
  $("#modal-body").innerHTML = `<h3>${esc(t.type)} ${sev(t.severity)}</h3><p><code>${esc(t.ip)}</code> · ${when(t.ts)} UTC · confidence ${Math.round(t.confidence * 100)}%</p><p>${esc(t.reason)}</p>
   <h4>Calculated Risk Score: ${t.score}/100</h4><div class="bar"><i style="width:${t.score}%;background:${SEV[t.severity]}"></i></div>
   <table><tr><th>Factor</th><th>Points</th></tr><tr><td>Rule-based finding</td><td>${f.rule_base ?? 0}</td></tr><tr><td>Frequency above threshold</td><td>${f.frequency ?? 0}</td></tr><tr><td>AI anomaly bonus</td><td>${f.ai_anomaly ?? 0}</td></tr></table>
   <p class="muted">0-25 LOW · 26-50 MEDIUM · 51-75 HIGH · 76-100 CRITICAL. A transparent heuristic, not a validated measurement.</p>`;
  $("#modal").classList.remove("hidden");
}
$("#close").onclick = () => $("#modal").classList.add("hidden");
async function loadIps() {
  const rows = await api("/ip-analysis");
  $("#ip-table").innerHTML = `<tr><th>IP Address</th><th>Requests</th><th>Failed logins</th><th>Successful logins</th><th>Threats</th><th>Risk score</th><th>Status</th></tr>` +
    (rows.map(r => `<tr><td><code>${esc(r.ip)}</code></td><td>${r.requests}</td><td>${r.failed_logins}</td><td>${r.successful_logins}</td><td>${r.threat_count}</td><td>${r.risk_score}</td><td>${esc(r.status)}</td></tr>`).join("") || `<tr><td colspan="7" class="empty">No data yet.</td></tr>`);
}
async function loadLogs() {
  const rows = await api("/logs" + qs("l"));
  $("#l-table").innerHTML = `<tr><th>Time (UTC)</th><th>IP</th><th>Result</th><th>Raw log entry</th></tr>` +
    (rows.map(r => `<tr><td>${when(r.ts)}</td><td><code>${esc(r.ip)}</code></td><td>${esc(r.result)}</td><td><code>${esc(r.raw)}</code></td></tr>`).join("") || `<tr><td colspan="4" class="empty">No logs match (showing up to 500).</td></tr>`);
}

// ---------- report ----------
$("#gen").onclick = guard(async () => {
  const r = await api("/reports"); report = r.markdown;
  $("#report").textContent = report; $("#dl").classList.remove("hidden");
});
$("#dl").onclick = () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([report], {type: "text/markdown"})); a.download = "cyberlog-report.md"; a.click(); };
