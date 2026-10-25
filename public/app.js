const API = (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost") && window.location.port === "5500"
  ? "http://127.0.0.1:8000"
  : "";

// --- State Management ---
let currentToken = localStorage.getItem("scamshield_token") || "";
let currentUser = null;
try {
  currentUser = JSON.parse(localStorage.getItem("scamshield_user") || "null");
} catch {
  currentUser = null;
}

// --- Utilities ---
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = "toast";
  const icon = type === "error" ? "🚨" : type === "success" ? "✓" : "✦";
  toast.innerHTML = `<span>${icon}</span> <span>${esc(message)}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateX(50px)";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function getAuthHeaders() {
  const headers = { "Content-Type": "application/json" };
  if (currentToken) {
    headers["Authorization"] = `Bearer ${currentToken}`;
  }
  return headers;
}

// --- Navigation Tabs ---
document.querySelectorAll(".nav-tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    const targetTab = btn.getAttribute("data-tab");
    const targetContent = document.getElementById(`tab-${targetTab}`);
    if (targetContent) {
      targetContent.classList.add("active");
    }

    if (targetTab === "vault") loadThreatVault();
    if (targetTab === "soc") loadSOCAnalytics();
  });
});

// --- User Profile & Auth UI ---
function renderAuthBar() {
  const container = document.getElementById("auth-container");
  if (!container) return;

  if (currentUser) {
    const roleClass = (currentUser.role || "user").toLowerCase();
    container.innerHTML = `
      <span class="role-tag ${roleClass}">${esc(currentUser.role || "User")}</span>
      <span style="font-size:13px;font-weight:600;color:var(--text-primary)">${esc(currentUser.full_name || currentUser.email)}</span>
      <button id="view-api-key-btn" class="btn-secondary" title="View Developer API Key">🔑 Key</button>
      <button id="logout-btn" class="btn-secondary" style="color:var(--crimson)">Sign Out</button>
    `;
    document.getElementById("view-api-key-btn")?.addEventListener("click", () => {
      document.getElementById("current-api-key").textContent = currentUser.api_key || "No key generated";
      document.getElementById("apikey-modal").classList.add("active");
    });
    document.getElementById("logout-btn")?.addEventListener("click", () => {
      currentToken = "";
      currentUser = null;
      localStorage.removeItem("scamshield_token");
      localStorage.removeItem("scamshield_user");
      renderAuthBar();
      showToast("Signed out successfully.");
    });
  } else {
    container.innerHTML = `
      <button id="login-modal-btn" class="btn-primary">Sign In / Demo</button>
    `;
    document.getElementById("login-modal-btn")?.addEventListener("click", () => {
      document.getElementById("auth-modal").classList.add("active");
    });
  }
}

// --- Modals Setup ---
function setupModals() {
  const authModal = document.getElementById("auth-modal");
  const apikeyModal = document.getElementById("apikey-modal");
  const reportModal = document.getElementById("report-modal");

  document.getElementById("auth-modal-close")?.addEventListener("click", () => authModal.classList.remove("active"));
  document.getElementById("apikey-modal-close")?.addEventListener("click", () => apikeyModal.classList.remove("active"));
  document.getElementById("report-modal-close")?.addEventListener("click", () => reportModal.classList.remove("active"));

  // Toggle Sign In vs Register Tabs
  let isRegister = false;
  const toggleSignIn = document.getElementById("toggle-signin-tab");
  const toggleReg = document.getElementById("toggle-register-tab");
  const nameGroup = document.getElementById("fullname-group");
  const submitBtn = document.getElementById("auth-submit-btn");

  toggleSignIn?.addEventListener("click", (e) => {
    e.preventDefault();
    isRegister = false;
    nameGroup.style.display = "none";
    toggleSignIn.style.borderColor = "var(--cyan)";
    toggleSignIn.style.color = "var(--cyan)";
    toggleReg.style.borderColor = "var(--border-subtle)";
    toggleReg.style.color = "var(--text-secondary)";
    submitBtn.textContent = "Sign In";
  });

  toggleReg?.addEventListener("click", (e) => {
    e.preventDefault();
    isRegister = true;
    nameGroup.style.display = "block";
    toggleReg.style.borderColor = "var(--cyan)";
    toggleReg.style.color = "var(--cyan)";
    toggleSignIn.style.borderColor = "var(--border-subtle)";
    toggleSignIn.style.color = "var(--text-secondary)";
    submitBtn.textContent = "Create Account";
  });

  // Auth Form Submit
  document.getElementById("auth-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const email = document.getElementById("auth-email").value.trim();
    const password = document.getElementById("auth-password").value.trim();
    const fullName = document.getElementById("auth-name")?.value.trim() || "User";

    submitBtn.disabled = true;
    submitBtn.textContent = "Authenticating...";

    const endpoint = isRegister ? `${API}/api/auth/register` : `${API}/api/auth/login`;
    const payload = isRegister ? { email, password, full_name: fullName } : { email, password };

    try {
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Authentication failed.");

      currentToken = data.access_token;
      currentUser = data.user;
      localStorage.setItem("scamshield_token", currentToken);
      localStorage.setItem("scamshield_user", JSON.stringify(currentUser));

      renderAuthBar();
      authModal.classList.remove("active");
      showToast(`Welcome, ${currentUser.full_name || currentUser.email}!`, "success");
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = isRegister ? "Create Account" : "Sign In";
    }
  });

  // 1-Click Demo Login Chips
  document.querySelectorAll(".demo-login-chip").forEach(chip => {
    chip.addEventListener("click", async () => {
      const role = chip.getAttribute("data-role");
      try {
        const resp = await fetch(`${API}/api/auth/demo-login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role })
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || "Demo login failed.");

        currentToken = data.access_token;
        currentUser = data.user;
        localStorage.setItem("scamshield_token", currentToken);
        localStorage.setItem("scamshield_user", JSON.stringify(currentUser));

        renderAuthBar();
        authModal.classList.remove("active");
        showToast(`Switched to demo role: ${role.toUpperCase()}`, "success");
      } catch (err) {
        showToast(err.message, "error");
      }
    });
  });

  // Copy API Key Button
  document.getElementById("copy-api-key-btn")?.addEventListener("click", () => {
    const key = document.getElementById("current-api-key").textContent;
    navigator.clipboard.writeText(key);
    showToast("API Key copied to clipboard!", "success");
  });

  // Open Report Scam Modal
  document.getElementById("open-report-modal-btn")?.addEventListener("click", () => {
    reportModal.classList.add("active");
  });

  // Submit Report Scam Form
  document.getElementById("report-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = document.getElementById("report-url").value.trim();
    const category = document.getElementById("report-category").value;
    const severity = document.getElementById("report-severity").value;
    const desc = document.getElementById("report-desc").value.trim();

    try {
      const resp = await fetch(`${API}/api/threats/report`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          url,
          threat_category: category,
          severity,
          description: desc,
          evidence_notes: "Reported via Community Threat Vault"
        })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Submission failed.");

      reportModal.classList.remove("active");
      showToast("Scam reported and verified!", "success");
      loadThreatVault();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

// --- Circular Risk Gauge & Scan Result Render ---
function renderScanResult(data) {
  const resultBox = document.getElementById("scan-result");
  resultBox.style.display = "block";

  const score = data.score || 0;
  const scoreVal = document.getElementById("gauge-score-val");
  scoreVal.textContent = score;

  // Circular gauge animation (circumference = 2 * PI * 65 ≈ 408.4)
  const circle = document.getElementById("gauge-circle");
  const circumference = 408.4;
  const offset = circumference - (score / 100) * circumference;
  circle.style.strokeDashoffset = offset;

  // Determine Color & Pill
  let strokeColor = "#10b981"; // Emerald
  let tierClass = "low";
  let tierLabel = "LOWER RISK / BENIGN";

  if (score >= 80) {
    strokeColor = "#f43f5e"; // Crimson
    tierClass = "critical";
    tierLabel = "CRITICAL THREAT";
  } else if (score >= 60) {
    strokeColor = "#ef4444"; // Red
    tierClass = "high";
    tierLabel = "HIGH RISK";
  } else if (score >= 30) {
    strokeColor = "#f59e0b"; // Amber
    tierClass = "moderate";
    tierLabel = "MODERATE RISK";
  }

  circle.style.stroke = strokeColor;
  scoreVal.style.color = strokeColor;

  const pill = document.getElementById("gauge-tier-pill");
  pill.className = `tier-badge ${tierClass}`;
  pill.textContent = tierLabel;

  // PDF Dossier Link
  const pdfBtn = document.getElementById("download-report-btn");
  if (data.id) {
    pdfBtn.href = `${API}/api/reports/${encodeURIComponent(data.id)}.pdf`;
    pdfBtn.style.display = "inline-flex";
  } else {
    pdfBtn.style.display = "none";
  }

  // Diagnostic Cards
  // 1. PyTorch Deep Learning
  const dl = data.dl || {};
  document.getElementById("diag-dl-score").textContent = dl.available ? `${dl.score_percent}%` : "Not Trained";
  document.getElementById("diag-dl-score").style.color = (dl.score_percent >= 50) ? "var(--crimson)" : "var(--emerald)";
  document.getElementById("diag-dl-desc").textContent = dl.details || "Character-level 1D-CNN + BiGRU neural classification.";
  const hotspots = document.getElementById("diag-dl-hotspots");
  if (dl.hotspot_tokens && dl.hotspot_tokens.length) {
    hotspots.textContent = `High-Risk Subsequences: [${dl.hotspot_tokens.join(", ")}]`;
  } else {
    hotspots.textContent = "";
  }

  // 2. Scikit-Learn ML Ensemble
  const ml = data.ml || {};
  document.getElementById("diag-ml-score").textContent = ml.available ? `${ml.probability_percent}%` : "Not Trained";
  document.getElementById("diag-ml-score").style.color = (ml.probability_percent >= 50) ? "var(--crimson)" : "var(--blue)";
  document.getElementById("diag-ml-desc").textContent = ml.details || "Random Forest 28-feature classification.";
  const topFeat = document.getElementById("diag-ml-features");
  if (ml.top_features && ml.top_features.length) {
    topFeat.textContent = `Top Indicators: ${ml.top_features.map(f => f.name).slice(0, 3).join(", ")}`;
  } else {
    topFeat.textContent = "";
  }

  // 3. Brand Typosquatting
  const brand = data.brand_spoof || {};
  const brandStat = document.getElementById("diag-brand-status");
  const brandDesc = document.getElementById("diag-brand-desc");
  if (brand.detected) {
    brandStat.textContent = `SPOOF: ${brand.impersonated_brand}`;
    brandStat.style.color = "var(--crimson)";
    brandDesc.textContent = brand.details || "Brand impersonation detected.";
  } else if (brand.is_legitimate_brand) {
    brandStat.textContent = `VERIFIED: ${brand.impersonated_brand}`;
    brandStat.style.color = "var(--emerald)";
    brandDesc.textContent = "Verified authentic corporate domain.";
  } else {
    brandStat.textContent = "Clean";
    brandStat.style.color = "var(--text-secondary)";
    brandDesc.textContent = "No corporate brand typosquatting found.";
  }

  // 4. SSL & Cryptographic Layer
  const ssl = data.ssl || {};
  const sslStat = document.getElementById("diag-ssl-status");
  const sslDesc = document.getElementById("diag-ssl-desc");
  if (ssl.valid) {
    sslStat.textContent = "Verified TLS";
    sslStat.style.color = "var(--emerald)";
    sslDesc.textContent = `Issuer: ${ssl.issuer || "Trusted CA"} · Cipher: ${ssl.cipher || "Strong"}`;
  } else {
    sslStat.textContent = "Untrusted / Plain";
    sslStat.style.color = "var(--crimson)";
    sslDesc.textContent = ssl.error || "No valid TLS certificate handshake.";
  }

  // Forensic Signals Grid
  const signalsContainer = document.getElementById("signals-container");
  signalsContainer.innerHTML = "";
  const signals = data.signals || [];
  document.getElementById("signal-count").textContent = `${signals.length} SIGNALS EVALUATED`;

  signals.forEach(s => {
    const pill = document.createElement("div");
    pill.className = `signal-pill ${s.risk ? "risk" : "safe"}`;
    pill.textContent = s.text;
    signalsContainer.appendChild(pill);
  });

  // Action Guidance
  const guidanceBox = document.getElementById("action-guidance");
  const actionHeadline = document.getElementById("action-headline");
  const actionBody = document.getElementById("action-body");
  const xai = data.xai || {};

  if (score >= 60) {
    guidanceBox.className = "action-banner critical";
    actionHeadline.textContent = "CRITICAL FRAUD THREAT IDENTIFIED";
    actionBody.textContent = xai.action_recommendation || "Do not enter passwords or payment details.";
  } else if (score >= 30) {
    guidanceBox.className = "action-banner" + (score >= 30 ? " critical" : " safe");
    guidanceBox.style.background = "rgba(245, 158, 11, 0.12)";
    guidanceBox.style.border = "1px solid rgba(245, 158, 11, 0.35)";
    actionHeadline.textContent = "ELEVATED RISK SIGNALS DETECTED";
    actionBody.textContent = xai.action_recommendation || "Exercise caution before transacting.";
  } else {
    guidanceBox.className = "action-banner safe";
    actionHeadline.textContent = "VERIFIED BENIGN PROFILE";
    actionBody.textContent = xai.action_recommendation || "No malicious indicators detected.";
  }

  // Scroll smoothly to results
  resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// --- Single URL Scan Form ---
function setupScanner() {
  const form = document.getElementById("scan-form");
  const urlInput = document.getElementById("scan-url");
  const scanBtn = document.getElementById("scan-btn");

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    scanBtn.disabled = true;
    scanBtn.innerHTML = `<span>Analyzing Neural Matrices...</span>`;

    try {
      const resp = await fetch(`${API}/api/scan`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ url })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Scan request failed.");

      renderScanResult(data);
      showToast("Threat audit completed successfully!", "success");
      loadRecentScans();
      loadHeroStats();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = `<span>Inspect Threat Profile</span> ➔`;
    }
  });

  // Demo Chips
  document.querySelectorAll(".demo-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const demoUrl = chip.getAttribute("data-url");
      urlInput.value = demoUrl;
      form.dispatchEvent(new Event("submit"));
    });
  });

  document.getElementById("refresh-scans-btn")?.addEventListener("click", loadRecentScans);
}

// --- Load Recent Scans Table ---
async function loadRecentScans() {
  const tbody = document.getElementById("scans-table-body");
  if (!tbody) return;

  try {
    const resp = await fetch(`${API}/api/scans?limit=15`);
    const data = await resp.json();
    const items = data.items || [];

    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text-muted)">No threat audits recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = items.map(item => {
      const score = item.score || 0;
      const scoreColor = score >= 60 ? "var(--crimson)" : score >= 30 ? "var(--amber)" : "var(--emerald)";
      const tierClass = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 30 ? "moderate" : "low";

      return `
        <tr>
          <td>
            <div class="url-cell" title="${esc(item.url)}">${esc(item.domain || item.url)}</div>
          </td>
          <td><b style="color:${scoreColor};font-family:var(--font-mono)">${score}/100</b></td>
          <td><span class="role-tag ${tierClass}">${esc(item.classification)}</span></td>
          <td style="font-family:var(--font-mono);font-size:11.5px">${esc(item.ml_probability)}%</td>
          <td style="font-family:var(--font-mono);font-size:11.5px">${esc(item.dl_score)}%</td>
          <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${esc(item.scanned_at)}</td>
          <td>
            <a href="${API}/api/reports/${encodeURIComponent(item.id)}.pdf" target="_blank" rel="noopener" class="btn-secondary" style="font-size:11px;padding:3px 8px">
              PDF #${esc(item.id)}
            </a>
          </td>
        </tr>
      `;
    }).join("");
  } catch {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--crimson)">Backend offline. Verify FastAPI service.</td></tr>`;
  }
}

// --- Batch URL Matrix ---
function setupBatchMatrix() {
  const textarea = document.getElementById("batch-input");
  const counter = document.getElementById("batch-counter");
  const runBtn = document.getElementById("run-batch-btn");
  const demoBtn = document.getElementById("load-batch-demo-btn");
  const exportBtn = document.getElementById("export-batch-btn");

  let lastBatchResults = [];

  textarea?.addEventListener("input", () => {
    const urls = textarea.value.split("\n").map(u => u.trim()).filter(Boolean);
    counter.textContent = `${urls.length} URL${urls.length === 1 ? "" : "s"} detected`;
  });

  demoBtn?.addEventListener("click", () => {
    textarea.value = [
      "https://google.com",
      "http://paypa1-account-verification-support.com/login.php",
      "https://amazon-prime-renewal-billing.xyz/claim",
      "https://apple.com/iphone",
      "http://binance-wallets-gift-claim.site/airdrop",
      "https://cheap-luxury-watches-discount-outlet.shop/sale-90"
    ].join("\n");
    textarea.dispatchEvent(new Event("input"));
  });

  runBtn?.addEventListener("click", async () => {
    const urls = textarea.value.split("\n").map(u => u.trim()).filter(Boolean);
    if (!urls.length) {
      showToast("Please enter at least one URL.", "error");
      return;
    }

    runBtn.disabled = true;
    runBtn.innerHTML = `<span>Processing Concurrently...</span>`;

    try {
      const resp = await fetch(`${API}/api/scan/batch`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({ urls })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Batch scan failed.");

      lastBatchResults = data.items || [];
      const resultsArea = document.getElementById("batch-results-area");
      const summary = document.getElementById("batch-stats-summary");
      const tbody = document.getElementById("batch-table-body");

      resultsArea.style.display = "block";
      summary.textContent = `Batch Execution: ${data.total_scanned} Audited · ${data.flagged_count} Flagged · ${data.high_risk_count} High Risk`;

      tbody.innerHTML = lastBatchResults.map(item => {
        const score = item.score || 0;
        const color = score >= 60 ? "var(--crimson)" : score >= 30 ? "var(--amber)" : "var(--emerald)";
        const tier = score >= 80 ? "critical" : score >= 60 ? "high" : score >= 30 ? "moderate" : "low";
        const brand = item.brand_spoof?.detected ? item.brand_spoof.impersonated_brand : "None";

        return `
          <tr>
            <td><div class="url-cell" title="${esc(item.url)}">${esc(item.domain || item.url)}</div></td>
            <td><b style="color:${color};font-family:var(--font-mono)">${score}/100</b></td>
            <td><span class="role-tag ${tier}">${esc(item.risk_tier || "LOW")}</span></td>
            <td>${esc(item.classification || "Scanned")}</td>
            <td style="font-family:var(--font-mono);font-size:11.5px">${esc(brand)}</td>
            <td>
              ${item.id ? `<a href="${API}/api/reports/${encodeURIComponent(item.id)}.pdf" target="_blank" rel="noopener" class="btn-secondary" style="font-size:11px;padding:3px 8px">PDF</a>` : "—"}
            </td>
          </tr>
        `;
      }).join("");

      showToast(`Batch completed: ${data.flagged_count} threat(s) flagged!`, "success");
      loadHeroStats();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      runBtn.disabled = false;
      runBtn.innerHTML = `<span>Execute Batch Scan</span> ➔`;
    }
  });

  exportBtn?.addEventListener("click", () => {
    if (!lastBatchResults.length) return;
    const blob = new Blob([JSON.stringify(lastBatchResults, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ScamShield-Batch-Audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Batch audit exported to JSON!", "success");
  });
}

// --- Quishing (QR Phishing) Scanner ---
function setupQuishingScanner() {
  const dropzone = document.getElementById("qr-dropzone");
  const fileInput = document.getElementById("qr-file-input");
  const demoBtn = document.getElementById("demo-qr-btn");

  dropzone?.addEventListener("click", () => fileInput.click());

  dropzone?.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });

  dropzone?.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));

  dropzone?.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) {
      handleQRFile(e.dataTransfer.files[0]);
    }
  });

  fileInput?.addEventListener("change", () => {
    if (fileInput.files.length) {
      handleQRFile(fileInput.files[0]);
    }
  });

  // Demo QR Generator (creates an in-browser QR test canvas)
  demoBtn?.addEventListener("click", () => {
    generateDemoQR("http://paypa1-account-verification-support.com/login.php");
  });
}

async function handleQRFile(file) {
  const resultArea = document.getElementById("qr-result-area");
  const decodedUrl = document.getElementById("qr-decoded-url");
  const resMeta = document.getElementById("qr-resolution");
  const threatCard = document.getElementById("qr-threat-card");

  showToast("Scanning QR code matrix...", "info");

  const formData = new FormData();
  formData.append("file", file);

  try {
    const resp = await fetch(`${API}/api/scan/qr`, {
      method: "POST",
      headers: currentToken ? { "Authorization": `Bearer ${currentToken}` } : {},
      body: formData
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "QR scan failed.");

    if (!data.success) {
      showToast(data.message || "No readable QR code found.", "error");
      return;
    }

    resultArea.style.display = "block";
    decodedUrl.textContent = data.decoded_url;
    resMeta.textContent = data.qr_metadata?.details || "";

    const scan = data.scan_result || {};
    const score = scan.score || 0;
    const scoreColor = score >= 60 ? "var(--crimson)" : score >= 30 ? "var(--amber)" : "var(--emerald)";

    threatCard.innerHTML = `
      <div style="background:rgba(10,15,28,0.9);border:1px solid var(--border-subtle);border-radius:12px;padding:20px;margin-top:14px">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
          <div>
            <span class="role-tag ${score >= 60 ? 'critical' : 'low'}">${esc(scan.classification)}</span>
            <h4 style="font-size:16px;margin-top:4px">${esc(scan.domain || data.decoded_url)}</h4>
          </div>
          <div style="font-family:var(--font-mono);font-size:26px;font-weight:800;color:${scoreColor}">${score}/100</div>
        </div>
        <p style="font-size:12.5px;color:var(--text-secondary);line-height:1.5">${esc(scan.xai?.action_recommendation || "Quishing analysis complete.")}</p>
        <div style="margin-top:14px">
          ${scan.id ? `<a href="${API}/api/reports/${encodeURIComponent(scan.id)}.pdf" target="_blank" rel="noopener" class="btn-primary" style="font-size:12px;padding:6px 14px">📥 Download Quishing Incident Dossier</a>` : ""}
        </div>
      </div>
    `;

    showToast("QR code decoded and analyzed!", "success");
    resultArea.scrollIntoView({ behavior: "smooth" });
  } catch (err) {
    showToast(err.message, "error");
  }
}

// Generate an SVG-based QR image for instant demo testing
function generateDemoQR(targetUrl) {
  // Use a public QR generator API or Canvas
  const qrApiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(targetUrl)}`;
  fetch(qrApiUrl)
    .then(r => r.blob())
    .then(blob => {
      const file = new File([blob], "demo_quishing_qr.png", { type: "image/png" });
      handleQRFile(file);
    })
    .catch(() => {
      showToast("Could not fetch remote demo QR. Please upload an image directly.", "error");
    });
}

// --- Brand Typosquatting Checker ---
function setupBrandChecker() {
  const input = document.getElementById("brand-input");
  const btn = document.getElementById("brand-btn");
  const resultArea = document.getElementById("brand-result-area");

  btn?.addEventListener("click", async () => {
    const url = input.value.trim();
    if (!url) return;

    btn.disabled = true;
    btn.textContent = "Analyzing Brand Distance...";

    try {
      const resp = await fetch(`${API}/api/brand/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Brand check failed.");

      resultArea.style.display = "block";
      const isDetected = data.detected;
      const isLegit = data.is_legitimate_brand;
      const statusColor = isDetected ? "var(--crimson)" : isLegit ? "var(--emerald)" : "var(--cyan)";

      resultArea.innerHTML = `
        <div style="background:rgba(10,15,28,0.9);border:1px solid var(--border-subtle);border-radius:12px;padding:22px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
            <span class="role-tag ${isDetected ? 'critical' : isLegit ? 'user' : 'analyst'}">
              ${isDetected ? 'ADVERSARIAL SPOOF DETECTED' : isLegit ? 'OFFICIAL BRAND DOMAIN' : 'NEUTRAL / UNKNOWN'}
            </span>
            <b style="font-family:var(--font-mono);font-size:14px;color:${statusColor}">Risk: +${data.risk_score || 0} pts</b>
          </div>
          <h4 style="font-size:16px;margin-bottom:6px">${esc(data.impersonated_brand ? `Target Brand: ${data.impersonated_brand}` : "No Target Brand Match")}</h4>
          <p style="font-size:13px;color:var(--text-secondary);line-height:1.6">${esc(data.details)}</p>
          ${data.legitimate_domain ? `<div style="font-family:var(--font-mono);font-size:12px;color:var(--cyan);margin-top:10px">Authentic Domain Reference: ➔ ${esc(data.legitimate_domain)}</div>` : ""}
        </div>
      `;
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Check Brand Distance";
    }
  });
}

// --- Community Threat Vault ---
async function loadThreatVault() {
  const tbody = document.getElementById("vault-table-body");
  if (!tbody) return;

  try {
    const resp = await fetch(`${API}/api/threats/community`);
    const data = await resp.json();
    const items = data.items || [];

    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--text-muted)">No community reports yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = items.map(r => {
      const sevClass = r.severity === "critical" ? "critical" : r.severity === "high" ? "high" : "moderate";
      return `
        <tr>
          <td><div class="url-cell" title="${esc(r.url)}">${esc(r.domain)}</div></td>
          <td><span class="role-tag user">${esc(r.threat_category)}</span></td>
          <td><span class="role-tag ${sevClass}">${esc(r.severity?.toUpperCase())}</span></td>
          <td style="max-width:260px;font-size:12px;color:var(--text-secondary)">${esc(r.description || "N/A")}</td>
          <td style="font-size:12px">${esc(r.reporter_name || "Community")}</td>
          <td><b style="color:var(--cyan);font-family:var(--font-mono)">▲ ${r.upvotes || 1}</b></td>
          <td>
            <button class="btn-secondary upvote-btn" data-id="${r.id}" style="font-size:11px;padding:3px 8px">
              ▲ Upvote
            </button>
          </td>
        </tr>
      `;
    }).join("");

    document.querySelectorAll(".upvote-btn").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        try {
          const vResp = await fetch(`${API}/api/threats/${id}/vote`, { method: "POST" });
          const vData = await vResp.json();
          if (vData.success) {
            btn.parentElement.previousElementSibling.innerHTML = `<b style="color:var(--cyan);font-family:var(--font-mono)">▲ ${vData.upvotes}</b>`;
            btn.disabled = true;
            btn.textContent = "✓ Voted";
            showToast("Report upvoted!", "success");
          }
        } catch {}
      });
    });
  } catch {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--crimson)">Could not load community vault.</td></tr>`;
  }
}

// --- SOC Analytics & System Audit Logs ---
async function loadSOCAnalytics() {
  try {
    const [statsResp, auditResp] = await Promise.all([
      fetch(`${API}/api/admin/overview`, { headers: getAuthHeaders() }),
      fetch(`${API}/api/admin/audit-logs?limit=15`, { headers: getAuthHeaders() })
    ]);

    const s = await statsResp.json();
    const a = await auditResp.json();

    // Populate Key Metric Tiles
    document.getElementById("soc-total-scans").textContent = s.total_scans ?? 0;
    document.getElementById("soc-high-risk").textContent = (s.high_risk_scans ?? 0) + (s.critical_threat_scans ?? 0);
    document.getElementById("soc-unique-domains").textContent = s.unique_domains ?? 0;
    document.getElementById("soc-ml-flagged").textContent = s.ai_engine_telemetry?.ml_flagged ?? 0;

    // Daily Bar Chart
    const dailyChart = document.getElementById("soc-daily-chart");
    const daily = s.daily || [];
    const maxScans = Math.max(1, ...daily.map(d => d.scans));

    if (daily.length) {
      dailyChart.innerHTML = daily.map(d => {
        const pct = Math.max(4, Math.round((d.scans / maxScans) * 100));
        return `
          <div class="bar-chart-row">
            <span>${esc(d.day)}</span>
            <div class="bar-track-wrap">
              <div class="bar-fill" style="width:${pct}%"></div>
            </div>
            <b>${d.scans}</b>
            <small style="color:var(--crimson)">${d.flagged} flagged</small>
          </div>
        `;
      }).join("");
    } else {
      dailyChart.innerHTML = `<p style="color:var(--text-muted);font-size:12px;padding:12px">No scan trends recorded yet.</p>`;
    }

    // Top Flagged Domains
    const topDomains = document.getElementById("soc-top-domains");
    const top = s.top_flagged_domains || [];
    if (top.length) {
      topDomains.innerHTML = top.map(t => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border-subtle);font-size:12px">
          <div>
            <b style="color:var(--text-primary)">${esc(t.domain)}</b>
            <div style="font-size:10.5px;color:var(--text-muted)">${t.scans} scan(s)</div>
          </div>
          <b style="color:var(--crimson);font-family:var(--font-mono)">${t.max_score}/100</b>
        </div>
      `).join("");
    } else {
      topDomains.innerHTML = `<p style="color:var(--text-muted);font-size:12px;padding:12px">No flagged domains yet.</p>`;
    }

    // Audit Trail Table
    const auditTbody = document.getElementById("soc-audit-table-body");
    const logs = a.logs || [];
    if (logs.length) {
      auditTbody.innerHTML = logs.map(l => `
        <tr>
          <td><span class="role-tag analyst">${esc(l.action)}</span></td>
          <td style="font-family:var(--font-mono);font-size:11.5px">${esc(l.target)}</td>
          <td style="font-size:12px;color:var(--text-secondary)">${esc(l.details)}</td>
          <td style="font-size:11.5px">${esc(l.user_email || "System")}</td>
          <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${esc(l.created_at)}</td>
        </tr>
      `).join("");
    } else {
      auditTbody.innerHTML = `<tr><td colspan="5" style="text-align:center;padding:16px;color:var(--text-muted)">No audit entries found.</td></tr>`;
    }
  } catch (err) {
    console.error("SOC load error:", err);
  }
}

// --- Hero Stats Auto-Refresh ---
async function loadHeroStats() {
  try {
    const resp = await fetch(`${API}/api/stats`);
    const s = await resp.json();
    document.getElementById("hero-total-scans").textContent = s.total_scans ?? 0;
    document.getElementById("hero-flagged-scans").textContent = s.flagged_scans ?? 0;
  } catch {}
}

// --- Initialization ---
document.addEventListener("DOMContentLoaded", () => {
  renderAuthBar();
  setupModals();
  setupScanner();
  setupBatchMatrix();
  setupQuishingScanner();
  setupBrandChecker();
  loadRecentScans();
  loadHeroStats();
});
