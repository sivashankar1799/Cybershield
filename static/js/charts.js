/* CyberShield AI — live dashboard charts + Server-Sent Events feed. */

let pieChartObj = null;
let gaugeChartObj = null;
let lineChartObj = null;

const $ = (id) => document.getElementById(id);

function chartDefaults() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    resizeDelay: 0,
  };
}

function renderCharts(data) {
  if (!window.Chart) {
    console.error("Chart.js is not loaded.");
    return;
  }

  const pie = $("pieChart");
  const gauge = $("gaugeChart");
  const line = $("lineChart");
  if (!pie || !gauge || !line) return;

  const labels = data.pie?.labels || [];
  const values = data.pie?.data || [];
  const score = Math.max(0, Math.min(100, Number(data.score ?? 0)));

  // Create each chart only once. Repeated API refreshes update the existing
  // chart instead of destroying/recreating it, which prevents visual jumping.
  if (!pieChartObj) {
    pieChartObj = new Chart(pie, {
      type: "doughnut",
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: ["#00d4ff", "#bf00ff", "#ff3860", "#ffb020", "#00ff88", "#7c83fd"],
          borderColor: "#0a0a0f",
          borderWidth: 2,
        }],
      },
      options: {
        ...chartDefaults(),
        plugins: {
          legend: { position: "bottom", labels: { color: "#e6edf3", boxWidth: 12 } },
        },
      },
    });
  }
  pieChartObj.data.labels = labels;
  pieChartObj.data.datasets[0].data = values;
  pieChartObj.update("none");

  if (!gaugeChartObj) {
    gaugeChartObj = new Chart(gauge, {
      type: "doughnut",
      data: {
        labels: ["Risk", "Remaining"],
        datasets: [{
          data: [0, 100],
          backgroundColor: ["#00ff88", "rgba(255,255,255,.08)"],
          borderWidth: 0,
          circumference: 180,
          rotation: 270,
          cutout: "72%",
        }],
      },
      options: {
        ...chartDefaults(),
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      },
    });
  }
  gaugeChartObj.data.datasets[0].data = [score, 100 - score];
  gaugeChartObj.update("none");
  const gaugeVal = $("gaugeVal");
  if (gaugeVal) gaugeVal.textContent = `${score}%`;

  if (!lineChartObj) {
    lineChartObj = new Chart(line, {
      type: "line",
      data: {
        labels: [],
        datasets: [
          {
            label: "Detected",
            data: [],
            borderColor: "#ff3860",
            backgroundColor: "rgba(255,56,96,.12)",
            fill: true,
            tension: 0.35,
            pointRadius: 2,
          },
          {
            label: "Blocked",
            data: [],
            borderColor: "#00ff88",
            backgroundColor: "rgba(0,255,136,.08)",
            fill: true,
            tension: 0.35,
            pointRadius: 2,
          },
        ],
      },
      options: {
        ...chartDefaults(),
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { labels: { color: "#e6edf3" } } },
        scales: {
          x: { ticks: { color: "#8b93a7" }, grid: { color: "rgba(255,255,255,.05)" } },
          y: { beginAtZero: true, ticks: { color: "#8b93a7" }, grid: { color: "rgba(255,255,255,.05)" } },
        },
      },
    });
  }
  lineChartObj.data.labels = data.line?.labels || [];
  lineChartObj.data.datasets[0].data = data.line?.detected || [];
  lineChartObj.data.datasets[1].data = data.line?.blocked || [];
  lineChartObj.update("none");
}

async function loadCharts() {
  try {
    const res = await fetch("/api/dashboard-data", { cache: "no-store" });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || "Dashboard API failed");
    renderCharts(data);
  } catch (err) {
    console.error("Dashboard chart error:", err);
  }
}

function severityClass(severity) {
  return {
    Critical: "badge-crit",
    High: "badge-high",
    Medium: "badge-med",
    Low: "badge-low",
    Info: "badge-info",
  }[severity] || "badge-info";
}

function addLiveEvent(event, prepend = true) {
  const feed = $("liveFeed");
  if (!feed) return;

  const item = document.createElement("div");
  item.className = "live-event";
  item.innerHTML = `
    <div class="live-event-main">
      <span class="badge ${severityClass(event.severity)}">${escapeHtml(event.severity || "Info")}</span>
      <strong>${escapeHtml(event.action || "EVENT")}</strong>
      <span>${escapeHtml(event.details || "Security activity recorded")}</span>
    </div>
    <div class="live-event-meta">${escapeHtml(event.timestamp || "")} · ${escapeHtml(event.ip || "Local")}</div>
  `;

  if (prepend) feed.prepend(item); else feed.appendChild(item);
  while (feed.children.length > 50) feed.removeChild(feed.lastElementChild);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
  }[c]));
}

async function loadRecentEvents() {
  try {
    const res = await fetch("/api/recent-events", { cache: "no-store" });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || "Recent events API failed");
    const feed = $("liveFeed");
    if (feed) feed.innerHTML = "";
    (data.events || []).reverse().forEach((event) => addLiveEvent(event, false));
    return data.events?.[0]?.id || 0;
  } catch (err) {
    console.error("Live feed initial load error:", err);
    return 0;
  }
}

function connectLiveFeed(initialLastId = 0) {
  let cursor = Number(initialLastId || 0);
  const status = $("liveStatus");
  if (status) status.textContent = "Connecting…";

  const url = cursor ? `/api/live-events?last_id=${encodeURIComponent(cursor)}` : "/api/live-events";
  const source = new EventSource(url);

  source.onopen = () => {
    if (status) {
      status.textContent = "Live";
      status.classList.add("live-connected");
    }
  };

  source.onmessage = (message) => {
    try {
      const event = JSON.parse(message.data);
      cursor = Math.max(cursor, Number(event.id || 0));
      addLiveEvent(event, true);
      if (status) status.textContent = "Live";
    } catch (err) {
      console.error("Invalid live event:", err);
    }
  };

  source.onerror = () => {
    if (status) {
      status.textContent = "Reconnecting…";
      status.classList.remove("live-connected");
    }
    source.close();
    setTimeout(() => connectLiveFeed(cursor), 2000);
  };
}

async function initLiveDashboard() {
  // charts.js is loaded globally. Do not call dashboard-only APIs from auth
  // pages such as /login and /forgot-password; login_required would return
  // HTML, which makes EventSource report a text/html MIME error.
  if (!$('liveFeed') || !$('lineChart')) return;

  await loadCharts();
  const lastId = await loadRecentEvents();
  connectLiveFeed(lastId);

  // Keep the charts synchronized with database changes even when the stream
  // only receives activity-log events.
  setInterval(loadCharts, 5000);
}

window.loadCharts = loadCharts;

document.addEventListener("DOMContentLoaded", initLiveDashboard);
