const form = document.getElementById("scanForm");
const urlInput = document.getElementById("jobUrl");
const textInput = document.getElementById("jobText");
const scanBtn = document.getElementById("scanBtn");
const errorBox = document.getElementById("errorBox");
const loadingBox = document.getElementById("loadingBox");
const results = document.getElementById("results");
let currentScanId = null;

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  }[ch]));
}
function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}
function setLoading(on) {
  loadingBox.hidden = !on;
  scanBtn.disabled = on;
  scanBtn.querySelector("span").textContent = on ? "Analyzing..." : "Analyze advertisement";
}
function riskClass(level) {
  if (level === "High Risk") return "danger";
  if (level === "Medium Risk") return "warning";
  return "";
}
function renderResult(data) {
  currentScanId = data.scan_id;
  const cls = riskClass(data.level);
  document.getElementById("scoreValue").textContent = data.score;
  document.getElementById("scoreMeter").style.width = data.score + "%";
  document.getElementById("scoreMeter").style.background =
    cls === "danger" ? "#c44752" : cls === "warning" ? "#d49a36" : "#26966a";
  const label = document.getElementById("riskLabel");
  label.textContent = data.level;
  label.className = "risk-label " + cls;
  document.getElementById("riskSummary").textContent = data.summary;
  document.getElementById("findingCount").textContent = data.findings.length;
  document.getElementById("indicatorChip").textContent = data.findings.length + " indicators";
  document.getElementById("domainValue").textContent = data.domain?.domain || "Not supplied";
  document.getElementById("httpsValue").textContent =
    data.domain?.https === true ? "Enabled" : data.domain?.https === false ? "Not enabled" : "Not checked";
  document.getElementById("scanTime").textContent = data.scanned_at || "—";
  document.getElementById("scanReference").textContent = "SCAN #" + data.scan_id;
  const findings = document.getElementById("findingsList");
  findings.innerHTML = data.findings.map(f => {
    const sev = (f.severity || "info").toLowerCase();
    const ev = (f.evidence || []).map(e => `<div class="evidence">Evidence: ${esc(e)}</div>`).join("");
    return `<article class="finding-item">
      <div class="finding-main"><div class="finding-title">${esc(f.title)} <span style="color:#9aa5b5;font-weight:500">(+${f.points} pts)</span></div>
      <span class="severity ${esc(sev)}">${esc(f.severity)}</span></div>
      <p class="finding-desc">${esc(f.explanation)}</p>${ev}
    </article>`;
  }).join("");
  document.getElementById("recommendationsList").innerHTML =
    data.recommendations.map(r => `<li>${esc(r)}</li>`).join("");
  const notice = document.getElementById("fetchNotice");
  if (data.page_fetch_error) {
    notice.hidden = false;
    notice.textContent = "URL page could not be fetched: " + data.page_fetch_error +
      " Your pasted text was still analyzed.";
  } else if (data.page_info?.title) {
    notice.hidden = false;
    notice.textContent = "Fetched page title: " + data.page_info.title;
  } else {
    notice.hidden = true;
  }
  results.hidden = false;
  results.scrollIntoView({behavior:"smooth", block:"start"});
  loadHistory();
}
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  results.hidden = true;
  const url = urlInput.value.trim();
  const text = textInput.value.trim();
  if (!url && !text) {
    showError("Please paste a job URL, advertisement text, or both.");
    return;
  }
  setLoading(true);
  try {
    const response = await fetch("/api/scan", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({url, text})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The scan could not be completed.");
    renderResult(data);
  } catch (err) {
    showError(err.message || "Unexpected error. Please try again.");
  } finally {
    setLoading(false);
  }
});
document.getElementById("downloadBtn").addEventListener("click", () => {
  if (!currentScanId) return;
  window.location.href = `/api/report/${currentScanId}`;
});
async function loadHistory() {
  const box = document.getElementById("historyRows");
  try {
    const response = await fetch("/api/history");
    const rows = await response.json();
    if (!rows.length) {
      box.innerHTML = '<div class="empty-history">Your recent scans will appear here.</div>';
      return;
    }
    box.innerHTML = rows.map(row => {
      const c = row.level === "High Risk" ? "high" : row.level === "Medium Risk" ? "medium" : "low";
      return `<div class="history-row">
        <span>${esc(row.created_at)}</span>
        <span class="history-url" title="${esc(row.submitted_url || "Text-only scan")}">${esc(row.submitted_url || "Text-only scan")}</span>
        <span class="history-risk ${c}">${row.score}/100 · ${esc(row.level)}</span>
        <a class="history-download" href="/api/report/${row.id}" target="_blank" rel="noopener">PDF ↗</a>
      </div>`;
    }).join("");
  } catch {
    box.innerHTML = '<div class="empty-history">History is temporarily unavailable.</div>';
  }
}
document.getElementById("refreshHistory").addEventListener("click", loadHistory);
loadHistory();
