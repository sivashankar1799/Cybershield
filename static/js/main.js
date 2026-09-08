/* CyberShield AI — shared frontend helpers used across pages. */

// CSRF token injected via meta tag in base.html.
function csrfToken() {
    const m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : "";
  }
  
  // Generic JSON POST wrapper with CSRF header + error handling.
  async function apiPost(url, body) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken() },
        body: JSON.stringify(body || {}),
      });
      return await res.json();
    } catch (e) {
      return { success: false, error: e.message };
    }
  }
  
  // Copy text to clipboard with a toast.
  function copyText(text) {
    navigator.clipboard.writeText(text).then(() => toast("Copied to clipboard!"));
  }
  
  // Lightweight toast notification.
  function toast(msg, color = "#00ff88") {
    const t = document.createElement("div");
    t.textContent = msg;
    t.style.cssText =
      "position:fixed;bottom:24px;right:24px;z-index:9999;padding:12px 20px;border-radius:10px;" +
      "background:rgba(10,10,15,.95);border:1px solid " + color + ";color:" + color +
      ";box-shadow:0 4px 20px rgba(0,0,0,.4);font-size:.9rem";
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 2500);
  }
  
  // Sidebar toggle (mobile).
  document.addEventListener("DOMContentLoaded", () => {
    const toggle = document.getElementById("menuToggle");
    const sidebar = document.getElementById("sidebar");
    if (toggle && sidebar) {
      toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
      // Close the mobile navigation after selecting a page.
      sidebar.querySelectorAll("a.nav-link").forEach((link) => {
        link.addEventListener("click", () => sidebar.classList.remove("open"));
      });
    }
    // Live clock + IP widgets.
    const clock = document.getElementById("liveClock");
    if (clock) {
      setInterval(() => { clock.textContent = new Date().toLocaleTimeString(); }, 1000);
    }
    const ipEl = document.getElementById("liveIP");
    if (ipEl) {
      fetch("https://api.ipify.org?format=json")
        .then(r => r.json()).then(d => ipEl.textContent = d.ip)
        .catch(() => ipEl.textContent = "Local");
    }
  });
  
  // Severity badge class helper.
  function sevClass(sev) {
    return {
      Critical: "badge-crit", High: "badge-high", Medium: "badge-med",
      Low: "badge-low", Info: "badge-info", Safe: "badge-safe",
    }[sev] || "badge-info";
  }