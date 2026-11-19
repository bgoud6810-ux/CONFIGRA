/**
 * static/js/cyber_scanner.js
 * Frontend logic for Page 1: Target input, validation, live progress polling,
 * cancellation, and automatic redirect.
 */

let activeScanId = null;
let pollInterval = null;
let lastStepLogged = "";

function authHeaders(extra) {
  const headers = Object.assign({}, extra || {});
  const meta = document.querySelector('meta[name="configra-api-key"]');
  if (meta && meta.content) {
    headers["X-API-Key"] = meta.content;
  }
  return headers;
}

function setPreset(url) {
  const input = document.getElementById("targetUrl");
  if (input) {
    input.value = url;
    input.focus();
  }
}

function toggleConfigPanel() {
  const grid = document.getElementById("configGrid");
  const icon = document.getElementById("configToggleIcon");
  if (!grid || !icon) return;

  if (grid.style.display === "none" || grid.style.display === "") {
    grid.style.display = "grid";
    icon.innerHTML = "&#x25B2;";
  } else {
    grid.style.display = "none";
    icon.innerHTML = "&#x25BC;";
  }
}

async function handleStartScan(event) {
  event.preventDefault();

  const urlInput = document.getElementById("targetUrl");
  const startBtn = document.getElementById("startScanBtn");
  const livePanel = document.getElementById("scanningLivePanel");
  const errorAlert = document.getElementById("scanErrorAlert");
  const termLog = document.getElementById("scanTerminalLog");
  const progressText = document.getElementById("scanStatusTitle");
  const progressBar = document.getElementById("cyberProgressBar");
  const pctNum = document.getElementById("scanPctNum");
  const cancelBtn = document.getElementById("cancelScanBtn");

  if (!urlInput || !urlInput.value.trim()) {
    return;
  }

  let targetUrl = urlInput.value.trim();
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "http://" + targetUrl;
    urlInput.value = targetUrl;
  }

  // Prevent duplicate submissions
  startBtn.disabled = true;
  if (cancelBtn) {
    cancelBtn.disabled = false;
    cancelBtn.style.display = "inline-flex";
    cancelBtn.textContent = "Cancel Scan";
  }
  errorAlert.style.display = "none";
  livePanel.style.display = "block";
  lastStepLogged = "";

  // Reset progress state
  progressBar.style.width = "10%";
  pctNum.innerText = "10%";
  progressText.innerText = "Validating target and initializing scan...";
  termLog.innerHTML = `<div>[INIT] Establishing connection to ${targetUrl}...</div>`;

  const scanMode = document.getElementById("cfgScanMode")?.value || "passive_public";
  const payload = {
    target_url: targetUrl,
    scan_mode: scanMode,
    delay: parseFloat(document.getElementById("cfgDelay")?.value || (scanMode === "passive_public" ? "0.5" : "0.3")),
    timeout: parseFloat(document.getElementById("cfgTimeout")?.value || "10.0"),
    insecure: document.getElementById("cfgInsecure")?.checked || false,
    i_have_permission: document.getElementById("cfgPermission")?.checked || false,
  };

  const modeLabel = scanMode === "passive_public" ? "Passive Public Inspection" : "Authorized Security Configuration Assessment";
  termLog.innerHTML = `<div>[INIT] Mode: ${modeLabel}</div><div>[INIT] Establishing connection to ${targetUrl}...</div>`;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload),
    });

    const data = await res.json();

    if (!res.ok || data.error) {
      throw new Error(data.error || "Failed to dispatch scan request.");
    }

    activeScanId = data.scan_id;
    appendLog(`[DISPATCH] Scan job queued. ID: ${activeScanId}${data.scan_mode ? ` (${data.scan_mode})` : ""}`);
    startPolling(activeScanId);

  } catch (err) {
    showError(err.message || "An unexpected error occurred while starting scan.");
  }
}

async function cancelActiveScan() {
  const cancelBtn = document.getElementById("cancelScanBtn");
  if (!activeScanId) return;
  if (cancelBtn) {
    cancelBtn.disabled = true;
    cancelBtn.textContent = "Cancelling...";
  }
  appendLog("[CANCEL] Requesting scan cancellation...");
  try {
    const res = await fetch(`/api/scan/${activeScanId}/cancel`, {
      method: "POST",
      headers: authHeaders(),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok && res.status !== 202) {
      appendLog(`[WARN] ${data.error || data.message || "Cancellation request could not be completed."}`);
      if (cancelBtn) {
        cancelBtn.disabled = false;
        cancelBtn.textContent = "Cancel Scan";
      }
      return;
    }
    if (data.message) appendLog(`[CANCEL] ${data.message}`);
  } catch (err) {
    appendLog(`[WARN] Failed to send cancellation request: ${err.message}`);
    if (cancelBtn) {
      cancelBtn.disabled = false;
      cancelBtn.textContent = "Cancel Scan";
    }
  }
}

function startPolling(scanId) {
  if (pollInterval) clearInterval(pollInterval);

  const doPoll = async () => {
    try {
      const res = await fetch(`/api/scan/${scanId}/status`);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || "Failed to query scan status.");
      }

      const data = await res.json();
      updateProgressUI(data);

      if (data.status === "completed") {
        clearInterval(pollInterval);
        appendLog("[SUCCESS] Scan completed. Compiling results...");
        finalizeScanUi("completed");
        setTimeout(() => {
          window.location.href = `/results/${scanId}`;
        }, 600);
      } else if (data.status === "failed") {
        clearInterval(pollInterval);
        appendLog("[FAILED] Scan failed. Loading recorded scan results...");
        if (data.error) appendLog(`[ERROR] ${data.error}`);
        finalizeScanUi("failed");
        // Navigate to this scan's own recorded result to avoid reusing any older scan result.
        setTimeout(() => {
          window.location.href = `/results/${scanId}`;
        }, 600);
      } else if (data.status === "cancelled") {
        clearInterval(pollInterval);
        appendLog("[CANCELLED] Scan was cancelled. Loading available results...");
        finalizeScanUi("cancelled");
        setTimeout(() => {
          window.location.href = `/results/${scanId}`;
        }, 600);
      } else if (data.status === "not_found") {
        clearInterval(pollInterval);
        finalizeScanUi("failed");
        showError(data.error || "Scan ID not found.");
      }
    } catch (err) {
      clearInterval(pollInterval);
      finalizeScanUi("failed");
      showError(err.message || "Error checking scan status.");
    }
  };

  doPoll();
  pollInterval = setInterval(doPoll, 750);
}

function updateProgressUI(data) {
  const progressBar = document.getElementById("cyberProgressBar");
  const pctNum = document.getElementById("scanPctNum");
  const progressText = document.getElementById("scanStatusTitle");
  const cancelBtn = document.getElementById("cancelScanBtn");

  const pct = Math.min(100, Math.max(0, data.progress || 10));
  if (progressBar) progressBar.style.width = pct + "%";
  if (pctNum) pctNum.innerText = pct + "%";
  if (progressText && data.step) progressText.innerText = data.step;

  if (cancelBtn) {
    if (data.status === "running") {
      cancelBtn.style.display = "inline-flex";
    } else if (data.status !== "running") {
      // keep visible state consistent while finalizing
    }
  }

  if (data.step && data.step !== lastStepLogged) {
    appendLog(`[EXEC] ${data.step}`);
    lastStepLogged = data.step;
  }
}

function finalizeScanUi(status) {
  const startBtn = document.getElementById("startScanBtn");
  const cancelBtn = document.getElementById("cancelScanBtn");
  if (startBtn) startBtn.disabled = false;
  if (cancelBtn) {
    cancelBtn.disabled = true;
    if (status === "cancelled") cancelBtn.textContent = "Cancelled";
    else if (status === "failed") cancelBtn.textContent = "Stopped";
    else cancelBtn.textContent = "Completed";
  }
}

function appendLog(msg) {
  const termLog = document.getElementById("scanTerminalLog");
  if (!termLog) return;

  const row = document.createElement("div");
  row.innerText = msg;
  termLog.appendChild(row);
  termLog.scrollTop = termLog.scrollHeight;
}

function showError(msg) {
  const startBtn = document.getElementById("startScanBtn");
  const errorAlert = document.getElementById("scanErrorAlert");
  const errorMsg = document.getElementById("scanErrorMsg");

  if (startBtn) startBtn.disabled = false;
  if (errorAlert) errorAlert.style.display = "block";
  if (errorMsg) errorMsg.innerText = msg;

  appendLog(`[ERROR] ${msg}`);
}

document.addEventListener("DOMContentLoaded", () => {
  const modeSelect = document.getElementById("cfgScanMode");
  const permLabel = document.getElementById("cfgPermissionLabel");
  const delayInput = document.getElementById("cfgDelay");
  const applyModeUi = () => {
    const mode = modeSelect?.value || "passive_public";
    if (permLabel) {
      permLabel.textContent =
        mode === "passive_public"
          ? "I confirm this public URL is appropriate for non-intrusive passive inspection"
          : "I have explicit authorization to perform this security configuration assessment";
    }
    if (delayInput && !delayInput.dataset.userEdited) {
      delayInput.value = mode === "passive_public" ? "0.5" : "0.3";
    }
  };
  if (modeSelect) {
    modeSelect.addEventListener("change", applyModeUi);
    applyModeUi();
  }
  if (delayInput) {
    delayInput.addEventListener("input", () => {
      delayInput.dataset.userEdited = "1";
    });
  }

  const bootScanId = window.__ACTIVE_SCAN_ID__ || null;
  const bootTarget = window.__ACTIVE_TARGET_URL__ || null;
  if (bootTarget) {
    const urlInput = document.getElementById("targetUrl");
    if (urlInput && !urlInput.value) urlInput.value = bootTarget;
  }
  if (bootScanId) {
    activeScanId = bootScanId;
    const startBtn = document.getElementById("startScanBtn");
    const livePanel = document.getElementById("scanningLivePanel");
    const errorAlert = document.getElementById("scanErrorAlert");
    const cancelBtn = document.getElementById("cancelScanBtn");
    if (startBtn) startBtn.disabled = true;
    if (errorAlert) errorAlert.style.display = "none";
    if (livePanel) livePanel.style.display = "block";
    if (cancelBtn) {
      cancelBtn.style.display = "inline-flex";
      cancelBtn.disabled = false;
      cancelBtn.textContent = "Cancel Scan";
    }
    appendLog(`[RESUME] Attached to running scan ${bootScanId}`);
    startPolling(bootScanId);
  }
});
