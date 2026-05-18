/**
 * SIEM Platform - Dashboard JavaScript
 * =====================================
 * WebSocket + Chart.js + real-time event feed
 * 
 * TODO: Fix the regex for IPv6 later
 * NOTE: Using Chart.js because D3 was overkill for this
 * HACK: Incrementing counters manually between API polls looks smoother
 */

console.log("[SIEM] Dashboard initialized.");

const API_BASE = "";  // same origin via nginx proxy

// ── State ──────────────────────────────────────────────────────────────────
let stats       = null;
let logs        = [];
let socket      = null;
let chartTime   = null;
let chartIPs    = null;
let chartSev    = null;
let attackTypes = null;
let isConnected = false;

// ── Socket.IO Connection ───────────────────────────────────────────────────
function initSocket() {
  try {
    socket = io({
      transports: ["websocket", "polling"],
      reconnectionAttempts: 10,
      reconnectionDelay: 2000,
    });

    socket.on("connect", () => {
      isConnected = true;
      console.log("[SIEM] 🟢 WebSocket connected:", socket.id);
      setConnectionStatus(true);
      socket.emit("subscribe", { room: "dashboard" });
      socket.emit("subscribe", { room: "alerts" });
    });

    socket.on("disconnect", () => {
      isConnected = false;
      console.log("[SIEM] 🔴 WebSocket disconnected");
      setConnectionStatus(false);
    });

    socket.on("stats_update", (data) => {
      stats = data;
      updateStatWidgets(data);
      updateCharts(data);
    });

    socket.on("new_alert", (alert) => {
      console.log("[SIEM] 🚨 Alert received:", alert.rule_name);
      showToast(alert.severity, `ALERT: ${alert.rule_name}`, alert.description || "Threshold exceeded");
      incrementAlertBadge();
    });

    socket.on("connect_error", (err) => {
      console.warn("[SIEM] Socket error:", err.message);
    });
  } catch (e) {
    console.warn("[SIEM] Socket.io not available, falling back to polling:", e);
  }
}

function setConnectionStatus(connected) {
  const dot = document.querySelector(".status-dot");
  const label = document.getElementById("ws-status");
  if (dot) {
    dot.className = "status-dot" + (connected ? "" : " red");
  }
  if (label) label.textContent = connected ? "LIVE" : "POLLING";
}

// ── API Helpers ────────────────────────────────────────────────────────────
async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── Stats ──────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    stats = await fetchJSON("/api/stats");
    updateStatWidgets(stats);
    updateCharts(stats);
  } catch (e) {
    console.warn("[SIEM] Stats load failed:", e);
  }
}

function updateStatWidgets(s) {
  animateCounter("stat-total-events",   s.total_events);
  animateCounter("stat-critical-alerts", s.critical_alerts);
  animateCounter("stat-blocked-ips",    s.blocked_ips);
  animateCounter("stat-active-threats", s.active_threats);

  // Update header metrics
  setText("header-threat-count", s.critical_alerts);
  if (s.critical_alerts > 0) {
    document.querySelector(".header-metric.danger")?.classList.add("danger");
  }
}

function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = parseInt(el.textContent.replace(/,/g, "")) || 0;
  const diff  = target - start;
  if (Math.abs(diff) < 1) return;
  const steps = 20;
  let step = 0;
  const timer = setInterval(() => {
    step++;
    const val = Math.round(start + (diff * step / steps));
    el.textContent = val.toLocaleString();
    if (step >= steps) clearInterval(timer);
  }, 25);
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

// ── Charts ─────────────────────────────────────────────────────────────────
function initCharts() {
  Chart.defaults.color = "#8899aa";
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 11;

  // 1. Events over time (line chart)
  const ctxTime = document.getElementById("chart-timeline")?.getContext("2d");
  if (ctxTime) {
    chartTime = new Chart(ctxTime, {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          label: "Events",
          data: [],
          borderColor: "#00d4ff",
          backgroundColor: "rgba(0,212,255,0.07)",
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: "#00d4ff",
          tension: 0.4,
          fill: true,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { color: "#1e2535" },
            ticks: { maxTicksLimit: 8, color: "#445566" }
          },
          y: {
            grid: { color: "#1e2535" },
            ticks: { color: "#445566" },
            beginAtZero: true,
          }
        },
        animation: { duration: 400 },
      }
    });
  }

  // 2. Top source IPs (horizontal bar)
  const ctxIPs = document.getElementById("chart-top-ips")?.getContext("2d");
  if (ctxIPs) {
    chartIPs = new Chart(ctxIPs, {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          label: "Requests",
          data: [],
          backgroundColor: [
            "rgba(255,56,96,0.7)", "rgba(255,140,0,0.7)", "rgba(255,215,0,0.7)",
            "rgba(0,212,255,0.7)", "rgba(155,93,229,0.7)", "rgba(0,255,136,0.7)",
            "rgba(255,56,96,0.5)", "rgba(255,140,0,0.5)",
          ],
          borderRadius: 3,
        }]
      },
      options: {
        indexAxis: "y",
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: "#1e2535" }, ticks: { color: "#445566" } },
          y: { grid: { display: false }, ticks: { color: "#8899aa", font: { size: 10 } } }
        },
        animation: { duration: 400 },
      }
    });
  }

  // 3. Severity donut
  const ctxSev = document.getElementById("chart-severity")?.getContext("2d");
  if (ctxSev) {
    chartSev = new Chart(ctxSev, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low", "Info"],
        datasets: [{
          data: [0, 0, 0, 0, 0],
          backgroundColor: ["#ff3860","#ff8c00","#ffd700","#00d4ff","#9b5de5"],
          borderColor: "#0f1117",
          borderWidth: 3,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        cutout: "65%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { boxWidth: 10, padding: 12, color: "#8899aa" }
          }
        },
        animation: { animateRotate: true, duration: 600 },
      }
    });
  }

  // 4. Attack types (radar / polar)
  const ctxAt = document.getElementById("chart-attack-types")?.getContext("2d");
  if (ctxAt) {
    attackTypes = new Chart(ctxAt, {
      type: "polarArea",
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: [
            "rgba(255,56,96,0.4)", "rgba(255,140,0,0.4)", "rgba(255,215,0,0.4)",
            "rgba(0,212,255,0.4)", "rgba(155,93,229,0.4)", "rgba(0,255,136,0.4)",
          ],
          borderColor: [
            "#ff3860","#ff8c00","#ffd700","#00d4ff","#9b5de5","#00ff88",
          ],
          borderWidth: 1,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { boxWidth: 10, padding: 8, color: "#8899aa" } }
        },
        scales: {
          r: {
            grid: { color: "#1e2535" },
            ticks: { display: false },
            pointLabels: { color: "#8899aa", font: { size: 10 } }
          }
        },
        animation: { duration: 600 },
      }
    });
  }
}

function updateCharts(s) {
  // Timeline chart
  if (chartTime && s.events_per_hour?.length) {
    chartTime.data.labels   = s.events_per_hour.map(e => e.hour);
    chartTime.data.datasets[0].data = s.events_per_hour.map(e => e.count);
    chartTime.update("none");
  }

  // Top IPs chart
  if (chartIPs && s.top_source_ips?.length) {
    const top8 = s.top_source_ips.slice(0, 8);
    chartIPs.data.labels   = top8.map(e => e.ip + (e.country !== "??" ? ` [${e.country}]` : ""));
    chartIPs.data.datasets[0].data = top8.map(e => e.count);
    chartIPs.update("none");
  }

  // Severity donut
  if (chartSev && s.severity_breakdown) {
    const b = s.severity_breakdown;
    chartSev.data.datasets[0].data = [
      b.critical || 0, b.high || 0, b.medium || 0, b.low || 0, b.info || 0
    ];
    chartSev.update("none");
  }

  // Attack types
  if (attackTypes && s.attack_types) {
    const entries = Object.entries(s.attack_types);
    attackTypes.data.labels = entries.map(([k]) => k);
    attackTypes.data.datasets[0].data = entries.map(([, v]) => v);
    attackTypes.update("none");
  }
}

// ── Log feed ───────────────────────────────────────────────────────────────
async function loadLiveLogs() {
  try {
    const data = await fetchJSON("/api/logs?limit=30");
    logs = data.logs || [];
    renderLogFeed(logs);
  } catch (e) {
    console.warn("[SIEM] Log feed load failed:", e);
  }
}

function renderLogFeed(logList) {
  const container = document.getElementById("log-feed-entries");
  if (!container) return;

  const html = logList.slice(0, 25).map(log => {
    const sev = log.severity || "info";
    const ts  = new Date(log.timestamp).toLocaleTimeString();
    return `
      <div class="log-entry" data-sev="${sev}">
        <span class="log-time">${ts}</span>
        <span class="badge badge-${sev}">${sev}</span>
        <span class="log-source-ip">${log.source_ip || "-"}</span>
        <span class="log-msg">${escHtml(log.message || log.event_type)}</span>
      </div>`;
  }).join("");

  container.innerHTML = html;
}

function prependLogEntry(log) {
  const container = document.getElementById("log-feed-entries");
  if (!container) return;
  const sev = log.severity || "info";
  const ts  = new Date(log.timestamp).toLocaleTimeString();
  const div = document.createElement("div");
  div.className = "log-entry";
  div.setAttribute("data-sev", sev);
  div.style.animation = "slideIn 0.3s ease";
  div.innerHTML = `
    <span class="log-time">${ts}</span>
    <span class="badge badge-${sev}">${sev}</span>
    <span class="log-source-ip">${log.source_ip || "-"}</span>
    <span class="log-msg">${escHtml(log.message || log.event_type)}</span>`;
  container.insertBefore(div, container.firstChild);
  // Keep feed to 30 entries
  while (container.children.length > 30) {
    container.removeChild(container.lastChild);
  }
}

// ── Toast notifications ────────────────────────────────────────────────────
function showToast(type, title, message, duration = 5000) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerHTML = `<div class="toast-title">${title}</div><div>${message}</div>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s";
    setTimeout(() => toast.remove(), 300);
  }, duration);
}





// ── Alert badge ────────────────────────────────────────────────────────────
let alertCount = 0;
function incrementAlertBadge() {
  alertCount++;
  const badge = document.getElementById("alert-badge");
  if (badge) badge.textContent = alertCount;
}

// ── Last alert timestamp ───────────────────────────────────────────────────
async function updateLastAlert() {
  try {
    const data = await fetchJSON("/api/alerts");
    const alerts = data.alerts || [];
    if (alerts.length > 0) {
      const last = new Date(alerts[0].timestamp);
      const el = document.getElementById("last-alert-time");
      if (el) el.textContent = last.toLocaleTimeString();
    }
  } catch (e) {}
}

// ── Utility ────────────────────────────────────────────────────────────────
function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ── Init ───────────────────────────────────────────────────────────────────
async function init() {
  console.log("[SIEM] 🔄 Initializing dashboard...");

  initCharts();
  initSocket();

  // Initial load
  await Promise.allSettled([loadStats(), loadLiveLogs(), updateLastAlert()]);

  // Polling fallback (WebSocket updates are primary, but this is the backup)
  // "If WebSocket fails, at least the charts update every 5s" — me at 2am
  setInterval(async () => {
    if (!isConnected) {
      await loadStats();
    }
  }, 5000);

  // Log feed refresh (always)
  setInterval(loadLiveLogs, 5000);

  setInterval(updateLastAlert, 30000);

  console.log("[SIEM] ✅ Dashboard ready. Stay paranoid.");
}

document.addEventListener("DOMContentLoaded", init);
