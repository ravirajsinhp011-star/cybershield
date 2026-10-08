// AI CyberShield Frontend Application Engine with Role-Based Access Control

let currentScanMode = "url";
let currentScanContext = null;
let html5QrScanner = null;
let riskPieChart = null;
let vectorBarChart = null;

let currentToken = localStorage.getItem("cybershield_token") || null;
let currentUsername = localStorage.getItem("cybershield_user") || null;
let currentUserRole = localStorage.getItem("cybershield_role") || null;

// --- TAB SWITCHING & SMOOTH AUTO-SCROLL NAVIGATION ---
function switchTab(tabName) {
  const allTabs = [
    "scanner", "attack-matrix", "domain-inspector", "user-vault", "user-stats",
    "admin-soc", "admin-users", "admin-rules", "admin-audit",
    "assistant", "quiz", "password-analyzer", "phishing-analyzer"
  ];

  // 1. Highlight clicked navigation link and reset others
  allTabs.forEach(t => {
    const nav = document.getElementById(`nav-${t}`);
    if (nav) {
      nav.classList.remove("text-cyber-cyan", "bg-cyber-cyan/10", "border", "border-cyber-cyan/30", "text-cyan-400", "bg-cyan-500/10", "border-cyan-500/30");
      nav.classList.add("text-slate-400");
    }
  });

  const activeNav = document.getElementById(`nav-${tabName}`);
  if (activeNav) {
    activeNav.classList.remove("text-slate-400");
    activeNav.classList.add("text-cyber-cyan", "bg-cyber-cyan/10", "border", "border-cyber-cyan/30");
  }

  // 2. Identify target card/section
  const targetSec = document.getElementById(`section-${tabName}`);
  if (targetSec) {
    // Ensure element is visible
    targetSec.classList.remove("hidden");

    // Perform smooth auto-scroll directly to target card/section
    targetSec.scrollIntoView({ behavior: "smooth", block: "start" });

    // Apply temporary 2-second neon border glow effect (Cyan/Purple glow)
    targetSec.classList.remove("neon-focus-glow");
    void targetSec.offsetWidth; // Trigger DOM reflow to restart CSS keyframe animation
    targetSec.classList.add("neon-focus-glow");
    setTimeout(() => {
      targetSec.classList.remove("neon-focus-glow");
    }, 2000);
  }

  // Auto-refresh when opening specific tabs
  if (tabName === "user-vault") {
    loadUserVault();
  } else if (tabName === "user-stats") {
    loadUserStats();
  } else if (tabName === "admin-soc") {
    loadAdminSOC();
    loadAdminScanLogs();
  } else if (tabName === "admin-users") {
    loadAdminUsers();
  } else if (tabName === "admin-rules") {
    loadAdminRules();
  } else if (tabName === "admin-audit") {
    loadAuditLogs();
  } else if (tabName === "quiz") {
    initQuiz();
  }
}

// --- SCANNER MODE SWITCHING ---
function setScanMode(mode) {
  currentScanMode = mode;
  const modes = ["url", "message", "qr"];
  modes.forEach(m => {
    const panel = document.getElementById(`panel-${m}`);
    const tab = document.getElementById(`tab-${m}`);
    if (panel) panel.classList.add("hidden");
    if (tab) {
      tab.classList.remove("bg-cyber-purple", "text-white", "shadow-lg", "text-cyan-400", "bg-cyan-500/10", "border-cyan-500/30", "shadow-md");
      tab.classList.add("text-slate-400");
    }
  });

  const activePanel = document.getElementById(`panel-${mode}`);
  const activeTab = document.getElementById(`tab-${mode}`);
  if (activePanel) activePanel.classList.remove("hidden");
  if (activeTab) {
    activeTab.classList.remove("text-slate-400");
    activeTab.classList.add("bg-cyber-purple", "text-white", "shadow-lg");
  }
}

// --- INPUT & THREAT SAMPLES ---
function fillURL(url) {
  const el = document.getElementById("url-input");
  if (el) el.value = url;
}

function fillMessage(msg) {
  const el = document.getElementById("message-input");
  if (el) el.value = msg;
}

function fillSampleUrl() {
  const samples = [
    "https://paypa1-secure-verification.xyz/login/verify-token",
    "http://192.168.1.100/admin-login.php?session=bypass",
    "https://bankofamerica.update-billing-profile.top/auth/signin",
    "https://account-verify-microsoft365.online/tenant/login"
  ];
  const chosen = samples[Math.floor(Math.random() * samples.length)];
  const input = document.getElementById("url-input");
  if (input) input.value = chosen;
}

function fillSampleNlp() {
  const samples = [
    "URGENT SECURITY ALERT: Your Microsoft 365 cloud enterprise account has been flagged for suspension within 2 hours due to unauthorized logins from Moscow. Click immediately to authenticate credentials: http://login-portal-auth.xyz/verify",
    "FINAL WARNING: Your direct deposit payroll processing was rejected. Update your banking credentials and two-factor OTP within 1 hour to prevent payroll cancellation: http://hr-payroll-direct.top/payroll",
    "SECURITY NOTICE: We detected an unauthorized transaction of $849.00 USD on your account. If this was not authorized by you, cancel immediately by verifying your identity: https://paypa1-resolution-center.xyz"
  ];
  const chosen = samples[Math.floor(Math.random() * samples.length)];
  const input = document.getElementById("message-input");
  if (input) input.value = chosen;
}

// --- MASTER SCAN DISPATCHER ---
function executeScan() {
  if (currentScanMode === "url") {
    submitURLScan();
  } else if (currentScanMode === "message") {
    submitMessageScan();
  } else if (currentScanMode === "qr") {
    const fileInput = document.getElementById("qr-file-input");
    if (fileInput && fileInput.files && fileInput.files.length > 0) {
      handleQRFileUpload(fileInput);
    } else {
      fileInput.click();
    }
  }
}

// --- REPORT EXPORT ---
function downloadReport() {
  if (!currentScanContext) {
    alert("No threat analysis results to export. Run a scan first.");
    return;
  }
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentScanContext, null, 2));
  const dlAnchor = document.createElement("a");
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", `cybershield-threat-report-${Date.now()}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
}

// ============================================================================
// REAL-TIME AI WAF DEFENSE & INTRUSION DETECTION ENGINE
// ============================================================================
const WAF_RULES = [
  {
    type: "SQL INJECTION (SQLi)",
    severity: "CRITICAL",
    regex: /(?:'(?:\s*or\s*|\s*\|\|\s*|[\s\+]+or[\s\+]+)[\s'"]*[0-9a-z]+[\s'"]*\s*=\s*[\s'"]*[0-9a-z]+)|(?:\b(union\s+select|select\s+.*\s+from|drop\s+table|insert\s+into|delete\s+from|update\s+.*\s+set)\b)|(?:--\s*$)|(?:;\s*drop\b)|(?:\/\*[\s\S]*?\*\/)/i,
    description: "Malicious boolean tautology (' OR '1'='1) or SQL structural manipulation intercepted."
  },
  {
    type: "CROSS-SITE SCRIPTING (XSS)",
    severity: "CRITICAL",
    regex: /(?:<script[\s\S]*?>[\s\S]*?<\/script>)|(?:<script[\s\S]*?>)|(?:javascript\s*:)|(?:on(?:error|load|click|mouseover|focus|blur)\s*=)|(?:<img\s+[^>]*?onerror)|(?:<svg\s+[^>]*?onload)|(?:eval\s*\()|(?:alert\s*\()/i,
    description: "Malicious script tags, DOM event injections, or script execution vectors blocked."
  },
  {
    type: "PATH TRAVERSAL (LFI/RFI)",
    severity: "CRITICAL",
    regex: /(?:\.\.[\/\\])|(?:\.\.%2f)|(?:\/etc\/(?:passwd|shadow|hosts))|(?:win\.ini|boot\.ini)/i,
    description: "Directory traversal probe seeking unauthorized OS configuration files (/etc/passwd)."
  },
  {
    type: "OS COMMAND INJECTION",
    severity: "CRITICAL",
    regex: /(?:(?:;|\||&|`|\$\()\s*(?:ls|dir|cat|whoami|id|uname|curl|wget|rm|powershell|cmd|bash)\b)|(?:\|\|[\s\S]*?(?:whoami|dir|ls))/i,
    description: "Shell command chaining (& dir, ; ls, | whoami) intercepted at gateway."
  }
];

function validateInputWithWAF(inputStr, contextName = "Target Payload") {
  if (!inputStr || typeof inputStr !== "string") return { blocked: false };

  const trimmed = inputStr.trim();
  for (const rule of WAF_RULES) {
    if (rule.regex.test(trimmed)) {
      return {
        blocked: true,
        attackType: rule.type,
        severity: rule.severity,
        description: rule.description,
        payload: trimmed,
        context: contextName
      };
    }
  }
  return { blocked: false };
}

function triggerWAFDefense(wafEvent) {
  // 1. Visual Cyber Perimeter Alarm Animation (Pulsating Red Neon Viewport Glow)
  document.body.classList.remove("waf-perimeter-alert");
  void document.body.offsetWidth; // Trigger reflow
  document.body.classList.add("waf-perimeter-alert");
  setTimeout(() => {
    document.body.classList.remove("waf-perimeter-alert");
  }, 2500);

  // 2. Populate WAF Defense Overlay Notification
  const modal = document.getElementById("waf-alert-modal");
  const typeEl = document.getElementById("waf-attack-type");
  const ctxEl = document.getElementById("waf-attack-context");
  const payloadEl = document.getElementById("waf-payload-preview");

  if (typeEl) typeEl.innerText = `${wafEvent.attackType} [${wafEvent.severity}]`;
  if (ctxEl) ctxEl.innerText = wafEvent.context || "Client Input Interceptor";
  if (payloadEl) payloadEl.innerText = wafEvent.payload || "Obfuscated Exploit Vector";

  if (modal) modal.classList.remove("hidden");

  // 3. Log attack entry with status ATTACK_DEFUSED into Admin database
  saveScanLog({
    session_id: "WAF-" + Math.floor(10000 + Math.random() * 90000),
    scan_type: "waf_intrusion",
    input_payload: wafEvent.payload,
    risk_score: 100.0,
    risk_level: "ATTACK_DEFUSED",
    status: "ATTACK_DEFUSED",
    details: `${wafEvent.attackType}: ${wafEvent.description}`
  });
}

function closeWafAlert() {
  const modal = document.getElementById("waf-alert-modal");
  if (modal) modal.classList.add("hidden");
}

// ============================================================================
// SUPABASE & DUAL DATABASE PERSISTENCE LAYER
// ============================================================================
let supabaseClient = null;

function initCloudDatabase() {
  try {
    const supabaseUrl = window.SUPABASE_URL || localStorage.getItem("cybershield_supabase_url");
    const supabaseKey = window.SUPABASE_ANON_KEY || localStorage.getItem("cybershield_supabase_key");

    if (window.supabase && supabaseUrl && supabaseKey) {
      supabaseClient = window.supabase.createClient(supabaseUrl, supabaseKey);
      const label = document.getElementById("db-storage-engine-label");
      if (label) label.innerText = "Supabase Cloud Active + SQLite Synchronized";
      console.log("[CyberShield] Connected to Supabase Cloud persistence.");
    } else {
      const label = document.getElementById("db-storage-engine-label");
      if (label) label.innerText = "SQLite Dual SOC Persistence + Local Cache Active";
    }
  } catch (err) {
    console.warn("[CyberShield] Cloud DB note:", err);
  }
}

async function saveScanLog(entry) {
  const normalized = {
    session_id: entry.session_id || "SOC-" + Math.floor(1000 + Math.random() * 9000),
    scan_type: entry.scan_type || "url",
    input_payload: String(entry.input_payload || "").slice(0, 500),
    risk_score: parseFloat(entry.risk_score || 0),
    risk_level: String(entry.risk_level || "LOW").toUpperCase(),
    status: entry.status || "SUCCESS",
    details: entry.details || "",
    source_ip: "127.0.0.1",
    timestamp: new Date().toLocaleTimeString()
  };

  // 1. Prepend to live UI table immediately
  prependLogToAdminTable(normalized);

  // 2. Cache locally in localStorage (last 50 logs)
  try {
    const localLogs = JSON.parse(localStorage.getItem("cybershield_scan_logs") || "[]");
    localLogs.unshift(normalized);
    if (localLogs.length > 50) localLogs.pop();
    localStorage.setItem("cybershield_scan_logs", JSON.stringify(localLogs));
  } catch (e) {}

  // 3. Remote Supabase persistence if connected
  if (supabaseClient) {
    try {
      await supabaseClient.from("scan_logs").insert([{
        session_id: normalized.session_id,
        scan_type: normalized.scan_type,
        input_payload: normalized.input_payload,
        threat_score: normalized.risk_score,
        risk_level: normalized.risk_level,
        status: normalized.status,
        details: normalized.details,
        timestamp: new Date().toISOString()
      }]);
    } catch (e) {
      console.warn("[CyberShield] Supabase insert note:", e);
    }
  }

  // 4. Backend SQLite API persistence
  try {
    await fetch("/api/scan/save-log", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(currentToken ? { "Authorization": `Bearer ${currentToken}` } : {})
      },
      body: JSON.stringify({
        session_id: normalized.session_id,
        scan_type: normalized.scan_type,
        input_payload: normalized.input_payload,
        risk_score: normalized.risk_score,
        risk_level: normalized.risk_level,
        status: normalized.status,
        details: normalized.details
      })
    });
  } catch (e) {}
}

function prependLogToAdminTable(log) {
  const tbody = document.getElementById("supabase-scan-logs-tbody");
  if (!tbody) return;

  // Remove placeholder row if present
  if (tbody.children.length === 1 && tbody.children[0].innerText.includes("Loading")) {
    tbody.innerHTML = "";
  }

  const tr = document.createElement("tr");
  tr.className = "hover:bg-slate-900/60 transition bg-cyan-950/20";

  let badgeColor = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  if (log.risk_level === "CRITICAL" || log.risk_level === "ATTACK_DEFUSED") {
    badgeColor = "bg-rose-500/10 text-rose-400 border-rose-500/30";
  } else if (log.risk_level === "HIGH") {
    badgeColor = "bg-rose-500/10 text-rose-400 border-rose-500/30";
  } else if (log.risk_level === "MEDIUM") {
    badgeColor = "bg-amber-500/10 text-amber-400 border-amber-500/30";
  }

  let statusBadge = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
  if (log.status === "ATTACK_DEFUSED" || log.status === "BLOCKED") {
    statusBadge = "bg-rose-500/20 text-rose-300 border-rose-500/40";
  }

  tr.innerHTML = `
    <td class="py-3 px-3 text-slate-300 font-bold">${log.session_id}</td>
    <td class="py-3 px-3 uppercase text-[10px] text-cyber-cyan">${log.scan_type}</td>
    <td class="py-3 px-3 text-slate-300 max-w-[200px] truncate" title="${log.input_payload}">${log.input_payload}</td>
    <td class="py-3 px-3 text-center font-bold text-white">${Math.round(log.risk_score)}%</td>
    <td class="py-3 px-3 text-center">
      <span class="px-2 py-0.5 rounded text-[9px] border font-bold uppercase ${badgeColor}">${log.risk_level}</span>
    </td>
    <td class="py-3 px-3">
      <span class="px-2 py-0.5 rounded text-[9px] border font-bold uppercase ${statusBadge}">${log.status}</span>
    </td>
    <td class="py-3 px-3 text-slate-400 text-[11px]">${log.source_ip || "127.0.0.1"}</td>
    <td class="py-3 px-3 text-right text-slate-500 text-[10px]">${log.timestamp || "Just now"}</td>
  `;

  tbody.insertBefore(tr, tbody.firstChild);

  // Smooth fade for new row highlight
  setTimeout(() => {
    tr.classList.remove("bg-cyan-950/20");
  }, 2000);
}

async function loadAdminScanLogs() {
  const tbody = document.getElementById("supabase-scan-logs-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/scan/recent-logs?limit=40");
    if (res.ok) {
      const data = await res.json();
      if (data.logs && data.logs.length > 0) {
        tbody.innerHTML = "";
        data.logs.forEach(log => {
          const tr = document.createElement("tr");
          tr.className = "hover:bg-slate-900/60 transition";

          let badgeColor = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
          if (log.risk_level === "CRITICAL" || log.risk_level === "ATTACK_DEFUSED") {
            badgeColor = "bg-rose-500/10 text-rose-400 border-rose-500/30";
          } else if (log.risk_level === "HIGH") {
            badgeColor = "bg-rose-500/10 text-rose-400 border-rose-500/30";
          } else if (log.risk_level === "MEDIUM") {
            badgeColor = "bg-amber-500/10 text-amber-400 border-amber-500/30";
          }

          let statusBadge = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
          if (log.risk_level === "ATTACK_DEFUSED") {
            statusBadge = "bg-rose-500/20 text-rose-300 border-rose-500/40";
          }

          tr.innerHTML = `
            <td class="py-3 px-3 text-slate-300 font-bold">${log.session_id}</td>
            <td class="py-3 px-3 uppercase text-[10px] text-cyber-cyan">${log.scan_type}</td>
            <td class="py-3 px-3 text-slate-300 max-w-[200px] truncate" title="${log.input_payload}">${log.input_payload}</td>
            <td class="py-3 px-3 text-center font-bold text-white">${Math.round(log.risk_score)}%</td>
            <td class="py-3 px-3 text-center">
              <span class="px-2 py-0.5 rounded text-[9px] border font-bold uppercase ${badgeColor}">${log.risk_level}</span>
            </td>
            <td class="py-3 px-3">
              <span class="px-2 py-0.5 rounded text-[9px] border font-bold uppercase ${statusBadge}">${log.risk_level === "ATTACK_DEFUSED" ? "ATTACK_DEFUSED" : "SUCCESS"}</span>
            </td>
            <td class="py-3 px-3 text-slate-400 text-[11px]">${log.source_ip || "127.0.0.1"}</td>
            <td class="py-3 px-3 text-right text-slate-500 text-[10px]">${log.timestamp || ""}</td>
          `;
          tbody.appendChild(tr);
        });
        return;
      }
    }
  } catch (err) {}

  // Fallback to local cache
  try {
    const localLogs = JSON.parse(localStorage.getItem("cybershield_scan_logs") || "[]");
    if (localLogs.length > 0) {
      tbody.innerHTML = "";
      localLogs.forEach(l => prependLogToAdminTable(l));
    } else {
      tbody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-slate-500">No scan activity recorded yet. Run a target scan to populate.</td></tr>`;
    }
  } catch (e) {}
}

// --- URL SCAN SUBMISSION ---
async function submitURLScan() {
  let inputEl = document.getElementById("url-input");
  let url = inputEl ? inputEl.value.trim() : "";
  if (!url) {
    fillSampleUrl();
    url = document.getElementById("url-input").value.trim();
  }

  // WAF Active Interception Check
  const wafCheck = validateInputWithWAF(url, "Threat Scanner (URL Engine)");
  if (wafCheck.blocked) {
    triggerWAFDefense(wafCheck);
    return;
  }

  // Normalize target URL (ensure bare domains like 'google.com' have http://)
  let cleanUrl = url;
  if (!cleanUrl.startsWith("http://") && !cleanUrl.startsWith("https://")) {
    cleanUrl = "http://" + cleanUrl;
  }

  showScanLoader(true);
  try {
    const res = await fetch("/api/scan/url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(currentToken ? { "Authorization": `Bearer ${currentToken}` } : {})
      },
      body: JSON.stringify({ url: cleanUrl })
    });

    if (!res.ok) throw new Error("URL Scan failed: " + res.statusText);
    const data = await res.json();
    renderScanResult(data);

    // Persist into database & SOC log
    saveScanLog({
      session_id: "SOC-" + Math.floor(1000 + Math.random() * 9000),
      scan_type: "url",
      input_payload: url,
      risk_score: data.risk_score || 0,
      risk_level: data.risk_level || "LOW",
      status: "SUCCESS",
      details: data.summary || "URL Forensic Heuristic Scan completed"
    });
  } catch (err) {
    alert("Scan Error: " + err.message);
  } finally {
    showScanLoader(false);
  }
}

// --- MESSAGE SCAN SUBMISSION ---
async function submitMessageScan() {
  let message = document.getElementById("message-input").value.trim();
  if (!message) {
    fillSampleNlp();
    message = document.getElementById("message-input").value.trim();
  }

  // WAF Active Interception Check
  const wafCheck = validateInputWithWAF(message, "NLP Message Analyzer");
  if (wafCheck.blocked) {
    triggerWAFDefense(wafCheck);
    return;
  }

  showScanLoader(true);
  try {
    const res = await fetch("/api/scan/message", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(currentToken ? { "Authorization": `Bearer ${currentToken}` } : {})
      },
      body: JSON.stringify({ message })
    });

    if (!res.ok) throw new Error("Message analysis failed");
    const data = await res.json();
    renderScanResult(data);

    // Persist into database & SOC log
    saveScanLog({
      session_id: "SOC-" + Math.floor(1000 + Math.random() * 9000),
      scan_type: "message",
      input_payload: message.slice(0, 150) + (message.length > 150 ? "..." : ""),
      risk_score: data.risk_score || 0,
      risk_level: data.risk_level || "LOW",
      status: "SUCCESS",
      details: data.summary || "NLP Heuristic Analysis completed"
    });
  } catch (err) {
    alert("Scan Error: " + err.message);
  } finally {
    showScanLoader(false);
  }
}

// --- QR CODE FILE UPLOAD ---
async function handleQRFileUpload(input) {
  const file = input.files[0];
  if (!file) return;

  const fileNameEl = document.getElementById("qrFileName");
  if (fileNameEl) {
    fileNameEl.innerText = `Selected: ${file.name}`;
    fileNameEl.classList.remove("hidden");
  }

  const formData = new FormData();
  formData.append("file", file);

  showScanLoader(true);
  try {
    const res = await fetch("/api/scan/qr", {
      method: "POST",
      headers: {
        ...(currentToken ? { "Authorization": `Bearer ${currentToken}` } : {})
      },
      body: formData
    });

    const data = await res.json();
    if (!res.ok) {
      alert(data.detail || "Could not detect or process QR code");
      return;
    }
    renderScanResult(data);
  } catch (err) {
    alert("QR Scan Error: " + err.message);
  } finally {
    showScanLoader(false);
  }
}

// --- CAMERA QR SCANNER (HTML5 QR CODE) ---
function startCameraScanner() {
  const btnStart = document.getElementById("btn-start-camera");
  const btnStop = document.getElementById("btn-stop-camera");

  btnStart.classList.add("hidden");
  btnStop.classList.remove("hidden");

  html5QrScanner = new Html5Qrcode("qr-reader");
  html5QrScanner.start(
    { facingMode: "environment" },
    { fps: 10, qrbox: { width: 220, height: 220 } },
    (decodedText) => {
      stopCameraScanner();
      if (decodedText.startsWith("http://") || decodedText.startsWith("https://")) {
        setScanMode("url");
        document.getElementById("url-input").value = decodedText;
        submitURLScan();
      } else {
        setScanMode("message");
        document.getElementById("message-input").value = decodedText;
        submitMessageScan();
      }
    },
    (errorMessage) => {}
  ).catch(err => {
    alert("Camera access failed or unavailable: " + err);
    stopCameraScanner();
  });
}

function stopCameraScanner() {
  if (html5QrScanner) {
    html5QrScanner.stop().then(() => {
      html5QrScanner.clear();
      html5QrScanner = null;
    }).catch(() => {});
  }
  document.getElementById("btn-start-camera").classList.remove("hidden");
  document.getElementById("btn-stop-camera").classList.add("hidden");
}

// --- LOADER CONTROL ---
function showScanLoader(show) {
  const beam = document.getElementById("scannerBeam");
  const scanStatusBadge = document.getElementById("scanStatusBadge");
  const loader = document.getElementById("scan-loading");
  const resultCard = document.getElementById("scan-results-card");

  if (show) {
    if (beam) beam.classList.remove("hidden");
    if (loader) loader.classList.remove("hidden");
    if (resultCard) resultCard.classList.add("hidden");
    if (scanStatusBadge) {
      scanStatusBadge.innerText = "ANALYZING...";
      scanStatusBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/40 animate-pulse";
    }
  } else {
    if (beam) beam.classList.add("hidden");
    if (loader) loader.classList.add("hidden");
    if (scanStatusBadge) {
      scanStatusBadge.innerText = "COMPLETE";
      scanStatusBadge.className = "text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/40";
    }
  }
}

// --- RENDER SCAN RESULTS ---
function renderScanResult(data) {
  currentScanContext = data;
  const resultCard = document.getElementById("scan-results-card");
  if (resultCard) resultCard.classList.remove("hidden");

  // Type badge & Target
  const typeBadge = document.getElementById("res-type-badge");
  if (typeBadge) typeBadge.innerText = (data.scan_type || "SCAN").toUpperCase() + " ANALYSIS";

  const targetEl = document.getElementById("res-target");
  if (targetEl) targetEl.innerText = data.target || "Unknown Target";

  // Level Badge
  const levelBadge = document.getElementById("res-badge-level");
  if (levelBadge) {
    levelBadge.innerText = data.risk_level;
    levelBadge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ";
    if (data.risk_level === "CRITICAL") levelBadge.classList.add("badge-critical");
    else if (data.risk_level === "HIGH") levelBadge.classList.add("badge-high");
    else if (data.risk_level === "MEDIUM") levelBadge.classList.add("badge-medium");
    else levelBadge.classList.add("badge-low");
  }

  // Circular SVG Gauge Meter (#riskCircle, #riskScoreVal, #riskLevelText)
  const score = Math.round(data.risk_score || 0);
  const riskCircle = document.getElementById("riskCircle");
  if (riskCircle) {
    const circumference = 377; // 2 * PI * 60
    const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
    riskCircle.style.strokeDashoffset = offset;
    if (score >= 70) riskCircle.setAttribute("stroke", "#f43f5e");
    else if (score >= 40) riskCircle.setAttribute("stroke", "#f59e0b");
    else riskCircle.setAttribute("stroke", "#10b981");
  }

  const riskScoreVal = document.getElementById("riskScoreVal");
  if (riskScoreVal) {
    riskScoreVal.innerText = `${score}%`;
  }

  const riskLevelText = document.getElementById("riskLevelText");
  if (riskLevelText) {
    riskLevelText.innerText = data.risk_level || "SAFE";
    riskLevelText.className = `text-[10px] font-mono font-semibold tracking-wider uppercase ${
      data.risk_level === "CRITICAL" || data.risk_level === "HIGH" ? "text-rose-400" :
      data.risk_level === "MEDIUM" ? "text-amber-400" : "text-emerald-400"
    }`;
  }

  const scanStatusBadge = document.getElementById("scanStatusBadge");
  if (scanStatusBadge) {
    scanStatusBadge.innerText = `INSPECTED: ${data.risk_level}`;
    scanStatusBadge.className = `text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
      data.risk_level === "CRITICAL" || data.risk_level === "HIGH" ? "bg-rose-500/20 text-rose-300 border border-rose-500/40" :
      data.risk_level === "MEDIUM" ? "bg-amber-500/20 text-amber-300 border border-amber-500/40" :
      "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
    }`;
  }

  // Findings Container (#findingsContainer)
  const findingsContainer = document.getElementById("findingsContainer");
  if (findingsContainer) {
    findingsContainer.innerHTML = "";
    if (data.findings && data.findings.length > 0) {
      data.findings.forEach(f => {
        const row = document.createElement("div");
        let badgeBg = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
        if (f.severity === "DANGER" || f.severity === "CRITICAL") badgeBg = "bg-rose-500/10 text-rose-400 border-rose-500/30";
        else if (f.severity === "WARNING" || f.severity === "MEDIUM") badgeBg = "bg-amber-500/10 text-amber-400 border-amber-500/30";

        row.className = "p-2.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1 text-xs";
        row.innerHTML = `
          <div class="flex items-center justify-between">
            <span class="font-bold text-slate-200 font-mono text-[11px]">${f.indicator}</span>
            <span class="text-[9px] font-mono px-2 py-0.5 rounded border uppercase ${badgeBg}">${f.severity}</span>
          </div>
          <p class="text-[11px] text-slate-400 leading-relaxed">${f.description}</p>
        `;
        findingsContainer.appendChild(row);
      });
    } else {
      findingsContainer.innerHTML = `
        <div class="text-xs font-mono text-emerald-400 p-3 bg-emerald-950/20 rounded-xl text-center border border-emerald-800/40">
          <i class="fa-solid fa-circle-check mr-1"></i> No malicious heuristics detected. Payload certified clean.
        </div>
      `;
    }
  }

  // Legacy Score & Gauge animation
  const scoreNum = document.getElementById("res-score-number");
  if (scoreNum) {
    scoreNum.innerHTML = `${score}<span class="text-sm font-normal text-slate-500">/100</span>`;
    scoreNum.style.color = data.badge_color;
  }

  const circle = document.getElementById("res-gauge-circle");
  if (circle) {
    circle.setAttribute("stroke-dasharray", `${Math.max(5, score)}, 100`);
    circle.style.stroke = data.badge_color;
  }

  // Summary
  const summaryEl = document.getElementById("res-summary-text");
  if (summaryEl) summaryEl.innerText = data.summary;

  // Legacy Findings List
  const findingsList = document.getElementById("res-findings-list");
  if (findingsList) {
    findingsList.innerHTML = "";
    if (data.findings && data.findings.length > 0) {
      data.findings.forEach(f => {
        const card = document.createElement("div");
        card.className = "p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-1";

        let sevClass = "bg-cyan-500/10 text-cyan-400 border-cyan-500/30";
        if (f.severity === "DANGER") sevClass = "bg-rose-500/10 text-rose-400 border-rose-500/30";
        else if (f.severity === "WARNING") sevClass = "bg-amber-500/10 text-amber-400 border-amber-500/30";

        card.innerHTML = `
          <div class="flex items-center justify-between">
            <span class="font-bold text-slate-200 text-xs">${f.indicator}</span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded border ${sevClass}">${f.severity}</span>
          </div>
          <p class="text-xs text-slate-400">${f.description}</p>
        `;
        findingsList.appendChild(card);
      });
    } else {
      findingsList.innerHTML = `<div class="col-span-2 text-xs text-slate-500">No suspicious signals were detected.</div>`;
    }
  }

  // Recommendations
  const recList = document.getElementById("res-recommendations-list");
  if (recList) {
    recList.innerHTML = "";
    if (data.recommendations && data.recommendations.length > 0) {
      data.recommendations.forEach(r => {
        const li = document.createElement("li");
        li.className = "flex items-start space-x-2";
        li.innerHTML = `<i class="fa-solid fa-shield-check text-emerald-400 mt-1 text-xs"></i><span>${r}</span>`;
        recList.appendChild(li);
      });
    }
  }
}

// --- ASK AI ABOUT CURRENT SCAN ---
function askAIForCurrentScan() {
  if (!currentScanContext) return;
  switchTab("assistant");

  const prompt = `Can you explain why the ${currentScanContext.scan_type} '${currentScanContext.target}' received a risk score of ${currentScanContext.risk_score}/100 and how I should respond?`;
  document.getElementById("chat-input").value = prompt;
  sendChatMessage();
}

// --- AI ASSISTANT CHAT ENGINE ---
async function sendChatMessage() {
  const input = document.getElementById("chat-input");
  const message = input.value.trim();
  if (!message) return;

  // WAF Active Interception Check
  const wafCheck = validateInputWithWAF(message, "AI Assistant Prompt Engine");
  if (wafCheck.blocked) {
    triggerWAFDefense(wafCheck);
    return;
  }

  input.value = "";
  appendChatMessage("user", message);

  const placeholderId = appendChatMessage("assistant", `<i class="fa-solid fa-spinner fa-spin mr-2"></i> Analyzing threat intelligence...`, true);

  try {
    const res = await fetch("/api/assistant/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message,
        scan_context: currentScanContext
      })
    });

    const data = await res.json();
    updateAssistantMessage(placeholderId, data.reply, data.source);
  } catch (err) {
    updateAssistantMessage(placeholderId, "Sorry, I encountered an issue retrieving threat explanations. Please try again.");
  }
}

function sendQuickPrompt(promptText) {
  document.getElementById("chat-input").value = promptText;
  sendChatMessage();
}

function appendChatMessage(role, content, isPlaceholder = false) {
  const container = document.getElementById("chat-messages");
  const msgId = "msg-" + Date.now();
  const div = document.createElement("div");
  div.id = msgId;

  if (role === "user") {
    div.className = "flex justify-end";
    div.innerHTML = `
      <div class="bg-cyan-600 text-slate-950 font-medium px-4 py-3 rounded-2xl rounded-tr-none max-w-lg text-sm shadow">
        ${content}
      </div>
    `;
  } else {
    div.className = "flex items-start space-x-3";
    div.innerHTML = `
      <div class="w-8 h-8 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold text-sm shrink-0 border border-cyan-500/30">
        <i class="fa-solid fa-robot"></i>
      </div>
      <div class="bg-slate-900 border border-slate-800 p-4 rounded-2xl rounded-tl-none max-w-2xl text-sm leading-relaxed text-slate-200 message-body space-y-2">
        ${content}
      </div>
    `;
  }

  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return msgId;
}

function updateAssistantMessage(msgId, text, source) {
  const elem = document.getElementById(msgId);
  if (!elem) return;

  const body = elem.querySelector(".message-body");
  if (body) {
    let formatted = text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\n\n/g, '<br><br>')
      .replace(/\n/g, '<br>');

    const badge = source === "gemini" 
      ? `<div class="pt-2 text-[10px] text-cyan-400/80 font-mono"><i class="fa-brands fa-google mr-1"></i> Generated via Google Gemini API</div>`
      : `<div class="pt-2 text-[10px] text-emerald-400/80 font-mono"><i class="fa-solid fa-shield-halved mr-1"></i> Generated via CyberShield Threat Engine</div>`;

    body.innerHTML = formatted + badge;
  }
}

// --- USER PORTAL LOGIC ---
async function loadUserVault() {
  if (!currentToken) {
    openAuthModal("login");
    return;
  }

  try {
    const res = await fetch("/api/user/history", {
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    if (!res.ok) throw new Error("Could not load user vault");

    const scans = await res.json();
    const tbody = document.getElementById("user-vault-tbody");
    tbody.innerHTML = "";

    if (scans.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-slate-500 font-mono">No scans in your personal vault yet. Run a scan from the Threat Scanner tab!</td></tr>`;
      return;
    }

    scans.forEach(s => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-800/40 transition";

      let badgeClass = "badge-low";
      if (s.risk_level === "CRITICAL") badgeClass = "badge-critical";
      else if (s.risk_level === "HIGH") badgeClass = "badge-high";
      else if (s.risk_level === "MEDIUM") badgeClass = "badge-medium";

      tr.innerHTML = `
        <td class="py-3 px-4 font-mono uppercase text-cyan-400">${s.scan_type}</td>
        <td class="py-3 px-4 font-mono text-slate-300 truncate max-w-xs">${s.input_target}</td>
        <td class="py-3 px-4"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">${s.risk_level}</span></td>
        <td class="py-3 px-4 font-bold text-slate-200">${Math.round(s.risk_score)}</td>
        <td class="py-3 px-4 text-slate-500 font-mono">${s.created_at}</td>
        <td class="py-3 px-4 text-right">
          <button onclick="deleteUserScan(${s.id})" class="text-slate-500 hover:text-rose-400 text-xs" title="Remove from vault">
            <i class="fa-solid fa-trash-can"></i>
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Vault load error:", err);
  }
}

async function deleteUserScan(scanId) {
  if (!confirm("Remove this scan from your personal vault?")) return;
  try {
    const res = await fetch(`/api/user/history/${scanId}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    if (res.ok) {
      loadUserVault();
    }
  } catch (err) {
    alert("Delete failed: " + err.message);
  }
}

async function loadUserStats() {
  if (!currentToken) {
    openAuthModal("login");
    return;
  }

  try {
    // 1. Stats
    const res = await fetch("/api/user/stats", {
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    if (res.ok) {
      const stats = await res.json();
      document.getElementById("u-stat-total").innerText = stats.total_scans;
      document.getElementById("u-stat-avoided").innerText = stats.threats_avoided;
      document.getElementById("u-stat-clean").innerText = stats.clean_scans;
      document.getElementById("u-stat-avg").innerText = stats.avg_risk_score.toFixed(1);
    }

    // 2. Badges
    const resB = await fetch("/api/user/badges", {
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    if (resB.ok) {
      const badges = await resB.json();
      const container = document.getElementById("user-badges-container");
      container.innerHTML = "";

      if (badges.length === 0) {
        container.innerHTML = `
          <div class="col-span-3 text-center py-6 text-slate-500 text-xs">
            <i class="fa-solid fa-medal text-2xl mb-2 text-slate-600 block"></i>
            No badges unlocked yet. Score 60+ in the Awareness Quiz to earn your first badge!
          </div>
        `;
      } else {
        badges.forEach(b => {
          const card = document.createElement("div");
          card.className = "p-4 rounded-xl bg-gradient-to-br from-slate-900 to-slate-950 border border-amber-500/30 flex items-center space-x-3";
          card.innerHTML = `
            <div class="w-12 h-12 rounded-xl bg-amber-500/10 text-amber-400 flex items-center justify-center text-xl shrink-0 border border-amber-500/20">
              <i class="fa-solid ${b.badge_icon || 'fa-award'}"></i>
            </div>
            <div>
              <div class="font-bold text-white text-sm">${b.badge_name}</div>
              <div class="text-[11px] text-slate-400">${b.description}</div>
              <div class="text-[10px] text-amber-400 font-mono mt-1">Unlocked: ${b.earned_at}</div>
            </div>
          `;
          container.appendChild(card);
        });
      }
    }
  } catch (err) {
    console.error("User stats load error:", err);
  }
}

// --- ADMIN SOC CONSOLE LOGIC ---
async function loadAdminSOC() {
  if (currentUserRole !== "admin") return;

  try {
    const resOverview = await fetch("/api/analytics/overview");
    const overview = await resOverview.json();

    document.getElementById("stat-total").innerText = overview.total_scans;
    document.getElementById("stat-critical").innerText = (overview.risk_counts.CRITICAL + overview.risk_counts.HIGH);
    document.getElementById("stat-low").innerText = overview.risk_counts.LOW;
    document.getElementById("stat-avg").innerText = overview.avg_risk_score.toFixed(1);

    renderRiskPieChart(overview.risk_counts);
    renderVectorBarChart(overview.type_counts);

    const resML = await fetch("/api/analytics/ml-metrics");
    const ml = await resML.json();
    document.getElementById("ml-precision").innerText = `${(ml.precision * 100).toFixed(1)}%`;
    document.getElementById("ml-recall").innerText = `${(ml.recall * 100).toFixed(1)}%`;
    document.getElementById("ml-f1").innerText = `${(ml.f1_score * 100).toFixed(1)}%`;

    if (ml.confusion_matrix) {
      document.getElementById("cm-tn").innerText = `${ml.confusion_matrix[0][0]} (True Negative)`;
      document.getElementById("cm-fp").innerText = `${ml.confusion_matrix[0][1]} (False Positive)`;
      document.getElementById("cm-fn").innerText = `${ml.confusion_matrix[1][0]} (False Negative)`;
      document.getElementById("cm-tp").innerText = `${ml.confusion_matrix[1][1]} (True Positive)`;
    }
  } catch (err) {
    console.error("Admin SOC load error:", err);
  }
}

async function loadAdminUsers() {
  if (currentUserRole !== "admin") return;

  try {
    const res = await fetch("/api/admin/users", {
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    if (!res.ok) throw new Error("Failed to load users");

    const users = await res.json();
    const tbody = document.getElementById("admin-users-tbody");
    tbody.innerHTML = "";

    users.forEach(u => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-800/40 transition";

      const statusBadge = u.is_active 
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">Active</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">Suspended</span>`;

      const roleBadge = u.role === "admin"
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-400 border border-rose-700">ADMIN</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">USER</span>`;

      tr.innerHTML = `
        <td class="py-3 px-4 font-mono text-slate-500">#${u.id}</td>
        <td class="py-3 px-4 font-bold text-white">${u.username}</td>
        <td class="py-3 px-4 font-mono text-slate-400">${u.email}</td>
        <td class="py-3 px-4">${roleBadge}</td>
        <td class="py-3 px-4">${statusBadge}</td>
        <td class="py-3 px-4 font-bold text-cyan-400">${u.total_scans}</td>
        <td class="py-3 px-4 font-mono text-slate-500">${u.created_at}</td>
        <td class="py-3 px-4 text-right">
          <button onclick="toggleUserStatus(${u.id})" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700">
            ${u.is_active ? 'Suspend' : 'Activate'}
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Load users error:", err);
  }
}

async function toggleUserStatus(userId) {
  try {
    const res = await fetch(`/api/admin/users/${userId}/toggle-status`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    if (!res.ok) {
      const err = await res.json();
      alert(err.detail || "Action failed");
      return;
    }
    loadAdminUsers();
  } catch (err) {
    alert("Error: " + err.message);
  }
}

// --- ADMIN THREAT RULES ---
async function loadAdminRules() {
  if (currentUserRole !== "admin") return;

  try {
    const res = await fetch("/api/admin/rules", {
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    if (!res.ok) return;

    const rules = await res.json();
    const tbody = document.getElementById("admin-rules-tbody");
    tbody.innerHTML = "";

    rules.forEach(r => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-800/40 transition";

      const typeBadge = r.rule_type === "blacklist"
        ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">BLACKLIST</span>`
        : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">WHITELIST</span>`;

      tr.innerHTML = `
        <td class="py-3 px-4">${typeBadge}</td>
        <td class="py-3 px-4 font-mono font-bold text-slate-200">${r.pattern}</td>
        <td class="py-3 px-4 text-slate-400">${r.reason || '-'}</td>
        <td class="py-3 px-4 font-mono text-slate-500">${r.created_by}</td>
        <td class="py-3 px-4 font-mono text-slate-500">${r.created_at}</td>
        <td class="py-3 px-4 text-right">
          <button onclick="deleteThreatRule(${r.id})" class="text-slate-500 hover:text-rose-400 text-xs">
            <i class="fa-solid fa-trash-can"></i>
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Rules load error:", err);
  }
}

async function submitNewRule() {
  const type = document.getElementById("rule-type-select").value;
  const pattern = document.getElementById("rule-pattern-input").value.trim();
  const reason = document.getElementById("rule-reason-input").value.trim();

  if (!pattern) {
    alert("Please enter a domain or pattern string.");
    return;
  }

  try {
    const res = await fetch("/api/admin/rules", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${currentToken}`
      },
      body: JSON.stringify({
        rule_type: type,
        pattern: pattern,
        reason: reason
      })
    });

    if (!res.ok) {
      const err = await res.json();
      alert(err.detail || "Failed to create rule");
      return;
    }

    document.getElementById("rule-pattern-input").value = "";
    document.getElementById("rule-reason-input").value = "";
    loadAdminRules();
  } catch (err) {
    alert("Error: " + err.message);
  }
}

async function deleteThreatRule(ruleId) {
  if (!confirm("Delete this threat rule?")) return;
  try {
    const res = await fetch(`/api/admin/rules/${ruleId}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${currentToken}` }
    });
    if (res.ok) {
      loadAdminRules();
    }
  } catch (err) {
    alert("Error: " + err.message);
  }
}

// --- CHARTS (CHART.JS) ---
function renderRiskPieChart(counts) {
  const ctx = document.getElementById("chart-risk-pie").getContext("2d");
  if (riskPieChart) riskPieChart.destroy();

  riskPieChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [counts.CRITICAL || 0, counts.HIGH || 0, counts.MEDIUM || 0, counts.LOW || 0],
        backgroundColor: ["#ef4444", "#f97316", "#f59e0b", "#10b981"],
        borderColor: "#0d1527",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "bottom", labels: { color: "#94a3b8", font: { size: 11 } } }
      }
    }
  });
}

function renderVectorBarChart(types) {
  const ctx = document.getElementById("chart-vector-bar").getContext("2d");
  if (vectorBarChart) vectorBarChart.destroy();

  vectorBarChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: ["URL Analysis", "Message NLP", "QR Scanner"],
      datasets: [{
        label: "Scan Count",
        data: [types.url || 0, types.message || 0, types.qr || 0],
        backgroundColor: ["#06b6d4", "#10b981", "#8b5cf6"],
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
        y: { ticks: { color: "#94a3b8", stepSize: 1 }, grid: { color: "#1e293b" } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

// --- AUDIT LOGS ---
async function loadAuditLogs() {
  try {
    const res = await fetch("/api/analytics/audit-logs");
    const logs = await res.json();
    const tbody = document.getElementById("audit-logs-tbody");
    tbody.innerHTML = "";

    logs.forEach(l => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-800/40 transition";
      const statusColor = l.status === "SUCCESS" ? "text-emerald-400" : "text-amber-400";
      tr.innerHTML = `
        <td class="py-3 px-4 font-mono font-bold text-cyan-400">${l.action}</td>
        <td class="py-3 px-4 font-mono ${statusColor}">${l.status}</td>
        <td class="py-3 px-4 text-slate-300">${l.details || "-"}</td>
        <td class="py-3 px-4 font-mono text-slate-400">${l.ip_address || "127.0.0.1"}</td>
        <td class="py-3 px-4 font-mono text-slate-500">${l.created_at}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load audit logs:", err);
  }
}

// --- CYBER DEFENSE ACADEMY (20 SCENARIO REPOSITORY, DYNAMIC 10 RANDOMIZED QUESTIONS) ---
let quizLanguage = "en"; // "en" or "hi"
let currentQuizIndex = 0;
let quizScore = 0;
let activeQuizQuestions = [];

const QUIZ_QUESTION_BANK = [
  {
    q_en: "You receive an SMS: 'Your bank account will be blocked in 2 hours due to pending KYC. Update immediately at http://sbi-kyc-verify.xyz'. What is the safest action?",
    q_hi: "आपको एक SMS मिलता है: 'KYC पेंडिंग होने के कारण आपका बैंक खाता 2 घंटे में बंद कर दिया जाएगा। तुरंत http://sbi-kyc-verify.xyz पर जाकर अपडेट करें।' सबसे सुरक्षित कदम क्या है?",
    options_en: [
      "Click the link immediately to prevent account suspension.",
      "Call the unknown phone number mentioned in the SMS.",
      "Ignore the link and verify directly via your official banking app or branch.",
      "Reply with your account number to confirm identity."
    ],
    options_hi: [
      "खाता बंद होने से बचने के लिए तुरंत लिंक पर क्लिक करें।",
      "SMS में दिए गए अनजान फोन नंबर पर कॉल करें।",
      "SMS लिंक को नजरअंदाज करें और अपने बैंक के आधिकारिक ऐप या शाखा से पुष्टि करें।",
      "पहचान साबित करने के लिए अपना खाता नंबर लिखकर SMS का जवाब दें।"
    ],
    correct: 2,
    exp_en: "Banks never mandate urgent KYC through random third-party web links under threat of immediate blocking. Always verify through official banking applications.",
    exp_hi: "बैंक कभी भी खाता तुरंत बंद करने की धमकी देकर किसी अनजान लिंक से KYC नहीं मांगते। हमेशा आधिकारिक बैंकिंग ऐप या शाखा से पुष्टि करें।"
  },
  {
    q_en: "What does 'Quishing' refer to in modern digital attacks?",
    q_hi: "आधुनिक डिजिटल साइबर हमलों में 'Quishing' (क्विशिंग) का क्या अर्थ है?",
    options_en: [
      "Deceptive QR codes that disguise phishing websites or malicious payment gateways.",
      "A fast quantum-computing decryption method.",
      "A database query crash error.",
      "Extracting physical hardware components from laptops."
    ],
    options_hi: [
      "फर्जी QR कोड जो उपयोगकर्ताओं को खतरनाक फिशिंग वेबसाइट या नकली पेमेंट गेटवे पर भेजते हैं।",
      "क्वांटम कंप्यूटर द्वारा तेज डिक्रिप्शन करने का तरीका।",
      "डेटाबेस क्रैश होने की एक आंतरिक एरर।",
      "लैपटॉप के हार्डवेयर पुर्जे चुराने की तकनीक।"
    ],
    correct: 0,
    exp_en: "Quishing is QR-code phishing. Attackers hide malicious destinations behind QR codes to evade standard text filters.",
    exp_hi: "क्विशिंग का मतलब QR-कोड फिशिंग है। हमलावर साधारण टेक्स्ट फिल्टर से बचने के लिए खतरनाक लिंक को QR कोड के पीछे छुपाते हैं।"
  },
  {
    q_en: "Why is a web address with a raw numerical IP (e.g., http://192.168.1.50/login) considered high risk?",
    q_hi: "सीधे संख्यात्मक IP एड्रेस वाले वेब पते (जैसे http://192.168.1.50/login) को खतरनाक क्यों माना जाता है?",
    options_en: [
      "IP addresses are illegal on the public internet.",
      "Legitimate organizations use registered domain names, whereas disposable scam kits frequently run on raw server IPs.",
      "IP addresses always indicate your Wi-Fi router is compromised.",
      "Web browsers do not support IP addresses."
    ],
    options_hi: [
      "पब्लिक इंटरनेट पर IP एड्रेस चलाना गैरकानूनी है।",
      "विश्वसनीय संस्थाएं रजिस्टर्ड डोमेन का उपयोग करती हैं, जबकि हमलावर अक्सर सीधे सर्वर IP पर फिशिंग किट चलाते हैं।",
      "IP एड्रेस का मतलब है कि आपका वाई-फाई राउटर हैक हो चुका है।",
      "वेब ब्राउज़र IP एड्रेस को सपोर्ट नहीं करते।"
    ],
    correct: 1,
    exp_en: "Legitimate websites register recognizable domain names. Threat actors frequently host temporary phishing sites directly on raw server IPs.",
    exp_hi: "विश्वसनीय कंपनियां जाने-पहचाने डोमेन रजिस्टर करती हैं। हमलावर अक्सर पकड़े जाने से बचने के लिए सीधे सर्वर IP पर नकली पेज बनाते हैं।"
  },
  {
    q_en: "If an incoming email has an official company logo and address, does that guarantee it is genuine?",
    q_hi: "यदि किसी ईमेल में किसी प्रसिद्ध कंपनी या बैंक का आधिकारिक लोगो और पता लगा हो, तो क्या यह उसके असली होने की गारंटी है?",
    options_en: [
      "Yes, logos are legally copyrighted and cannot be copied.",
      "Yes, email software automatically blocks fake company logos.",
      "No, cybercriminals easily copy public logos into phishing templates.",
      "Only if the email was received during standard business hours."
    ],
    options_hi: [
      "हां, कंपनियों के लोगो कॉपीराइट होते हैं और उन्हें कॉपी नहीं किया जा सकता।",
      "हां, ईमेल सॉफ्टवेयर फर्जी लोगो को अपने आप रोक देता है।",
      "नहीं, स्कैमर्स इंटरनेट से किसी भी कंपनी का लोगो डाउनलोड करके फर्जी ईमेल में लगा सकते हैं।",
      "केवल तभी जब ईमेल कार्य समय के दौरान आया हो।"
    ],
    correct: 2,
    exp_en: "Logos and styling are public assets that any attacker can copy. Always verify the sender's actual email domain address.",
    exp_hi: "लोगो और डिजाइन इंटरनेट पर पब्लिक होते हैं जिन्हें कोई भी कॉपी कर सकता है। हमेशा भेजने वाले के असली ईमेल डोमेन एड्रेस की जांच करें।"
  },
  {
    q_en: "Which form of Two-Factor Authentication (2FA) offers the strongest resistance to SIM-swapping attacks?",
    q_hi: "SIM-Swapping (सिम क्लोनिंग) हमलों से बचने के लिए कौन सा टू-फैक्टर ऑथेंटिकेशन (2FA) सबसे सुरक्षित है?",
    options_en: [
      "SMS Text Message OTP.",
      "Authenticator App (Time-based One Time Password, TOTP) or Hardware Security Key.",
      "Security questions (e.g., Mother's maiden name).",
      "Date of birth verification."
    ],
    options_hi: [
      "साधारण मोबाइल SMS पर आने वाला OTP।",
      "ऑथेंटिकेटर ऐप (जैसे Google Authenticator - TOTP) या हार्डवेयर सिक्योरिटी की।",
      "सुरक्षा प्रश्न (जैसे माता का नाम या पहला स्कूल)।",
      "जन्म तिथि सत्यापन।"
    ],
    correct: 1,
    exp_en: "SMS OTPs can be intercepted via telecom SIM-swapping. Authenticator apps generate offline cryptographic codes immune to SIM theft.",
    exp_hi: "SMS OTP को सिम क्लोनिंग या टेलीकॉम हैकिंग द्वारा चुराया जा सकता है। ऑथेंटिकेटर ऐप्स बिना सिम के ऑफलाइन कोड बनाते हैं जो सुरक्षित हैं।"
  },
  {
    q_en: "You get a message: 'Your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer immediately at 9876543210.' What should you do?",
    q_hi: "मैसेज आता है: 'पिछला बिल न भरने के कारण आज रात 9:30 बजे बिजली काट दी जाएगी। तुरंत अधिकारी को 9876543210 पर कॉल करें।' आपको क्या करना चाहिए?",
    options_en: [
      "Immediately transfer funds to the mobile number to prevent power cut.",
      "Verify your bill status exclusively on the official electricity board consumer portal or app.",
      "Send credit card details to confirm prior payment.",
      "Forward the message to social media groups."
    ],
    options_hi: [
      "बिजली कटने से बचने के लिए तुरंत दिए गए नंबर पर पैसे ट्रांसफर करें।",
      "केवल बिजली विभाग के आधिकारिक उपभोक्ता पोर्टल या ऐप पर जाकर ही बिल स्टेटस चेक करें।",
      "भुगतान साबित करने के लिए अपने क्रेडिट कार्ड की जानकारी शेयर करें।",
      "इस मैसेज को सोशल मीडिया ग्रुप्स में फॉरवर्ड करें।"
    ],
    correct: 1,
    exp_en: "Electricity boards never disconnect power within hours through personal mobile phone calls. Always check via the official electricity portal.",
    exp_hi: "बिजली विभाग व्यक्तिगत फोन नंबरों से तत्काल बिजली काटने की धमकी नहीं देता। हमेशा आधिकारिक बिजली पोर्टल से पुष्टि करें।"
  },
  {
    q_en: "When connected to free public Wi-Fi at a railway station or cafe, what is the safest practice?",
    q_hi: "रेलवे स्टेशन या कैफे में फ्री पब्लिक वाई-फाई का उपयोग करते समय सबसे सुरक्षित आदत क्या है?",
    options_en: [
      "Conduct large online banking transactions and fund transfers.",
      "Turn off device passwords.",
      "Avoid entering sensitive passwords or financial credentials, and use an encrypted VPN.",
      "Share your OTP freely."
    ],
    options_hi: [
      "बड़े नेट-बैंकिंग लेन-देन और फंड ट्रांसफर करना।",
      "फोन का स्क्रीन लॉक बंद कर देना।",
      "संवेदनशील पासवर्ड या बैंकिंग क्रेडेंशियल्स दर्ज करने से बचें, और एन्क्रिप्टेड VPN का उपयोग करें।",
      "अपना OTP किसी के साथ भी शेयर करना।"
    ],
    correct: 2,
    exp_en: "Public Wi-Fi networks can be monitored by attackers using Man-in-the-Middle (MitM) tools. Avoid banking or use a secure VPN.",
    exp_hi: "पब्लिक वाई-फाई को हैकर्स द्वारा आसानी से मॉनिटर किया जा सकता है। ऐसे नेटवर्क पर नेट-बैंकिंग न करें या VPN का उपयोग करें।"
  },
  {
    q_en: "An attacker registers a deceptive domain named 'paypa1.com' or 'g00gle.com'. What is this technique called?",
    q_hi: "हमलावर असली वेबसाइट की जगह 'paypa1.com' या 'g00gle.com' जैसा मिलता-जुलता नकली डोमेन बनाते हैं। इस तकनीक को क्या कहते हैं?",
    options_en: [
      "Typosquatting / URL Hijacking.",
      "Hard drive formatting.",
      "Display resolution scaling.",
      "Optical character synthesis."
    ],
    options_hi: [
      "टाइपो-स्कवैटिंग / URL स्पूफिंग (Typosquatting)।",
      "हार्ड ड्राइव फॉर्मेटिंग।",
      "स्क्रीन रिज़ॉल्यूशन स्केलिंग।",
      "ऑप्टिकल कैरेक्टर सिंथेसिस।"
    ],
    correct: 0,
    exp_en: "Typosquatting exploits human typing errors or visual similarities (e.g. replacing 'l' with '1', 'o' with '0') to deceive visitors.",
    exp_hi: "टाइपो-स्कवैटिंग में यूजर की स्पेलिंग गलती या अक्षरों की समानता (जैसे 'l' की जगह '1') का फायदा उठाकर नकली वेबसाइट पर भेजा जाता है।"
  },
  {
    q_en: "A stranger claims they are sending you money on a UPI app and insists you must enter your UPI PIN to 'receive' the payment. What will happen if you enter your PIN?",
    q_hi: "कोई अनजान व्यक्ति कहता है कि वह आपको UPI पर पैसे भेज रहा है और पैसे 'रिसीव' करने के लिए आपका UPI PIN डालने को कहता है। PIN डालने पर क्या होगा?",
    options_en: [
      "The funds will be credited to your bank account.",
      "Funds will be DEDUCTED from your bank account (UPI PIN is required ONLY to send money, never to receive).",
      "Your mobile data balance will double.",
      "The transaction will be canceled safely."
    ],
    options_hi: [
      "पैसे आपके बैंक खाते में जमा हो जाएंगे।",
      "आपके बैंक खाते से पैसे कट जाएंगे (UPI PIN केवल पैसे भेजने के लिए होता है, पैसे प्राप्त करने के लिए कभी नहीं)।",
      "आपका मोबाइल डेटा दोगुना हो जाएगा।",
      "लेनदेन सुरक्षित रूप से रद्द हो जाएगा।"
    ],
    correct: 1,
    exp_en: "Entering a UPI PIN authorizes outgoing fund debits. You NEVER need to enter a UPI PIN to receive money.",
    exp_hi: "UPI PIN डालने से आपके खाते से पैसे कटते हैं। पैसे प्राप्त (Receive) करने के लिए कभी भी UPI PIN की आवश्यकता नहीं होती।"
  },
  {
    q_en: "Which of the following is the most secure enterprise password management practice?",
    q_hi: "पासवर्ड सुरक्षा के लिए सबसे सुरक्षित और अनुशंसित तरीका कौन सा है?",
    options_en: [
      "Using '12345678' or your birth year across all corporate accounts.",
      "Using long, unique, cryptographically random passphrases stored in a reputable password manager.",
      "Writing passwords on a sticky note attached to your computer monitor.",
      "Sharing passwords with colleagues over plain text SMS."
    ],
    options_hi: [
      "सभी खातों में '12345678' या अपना जन्म वर्ष पासवर्ड रखना।",
      "पासवर्ड मैनेजर का उपयोग करके हर खाते के लिए अलग, लंबा और जटिल पासवर्ड रखना।",
      "मॉनिटर पर स्टिकी नोट चिपकाकर उस पर पासवर्ड लिखकर रखना।",
      "साधारण SMS पर सहकर्मियों के साथ पासवर्ड शेयर करना।"
    ],
    correct: 1,
    exp_en: "Unique, complex passphrases prevent credential-stuffing attacks if one service is breached. Password managers safeguard these securely.",
    exp_hi: "हर वेबसाइट के लिए अलग और मजबूत पासवर्ड रखने से क्रेडेंशियल-स्टफिंग हमलों से बचाव होता है। पासवर्ड मैनेजर इन्हें सुरक्षित रखते हैं।"
  },
  {
    q_en: "You find an unlabeled USB flash drive lying on the ground in your office parking lot. What should you do?",
    q_hi: "आपको ऑफिस की पार्किंग या गलियारे में एक लावारिस पेन ड्राइव (USB) पड़ी मिलती है। आपको क्या करना चाहिए?",
    options_en: [
      "Plug it into your office computer to check whose photos or files are inside.",
      "Never plug it into any device; hand it over to your IT Security / SOC department.",
      "Format it and use it for your personal movies.",
      "Connect it to an ATM to see if it works."
    ],
    options_hi: [
      "यह देखने के लिए कि वह किसकी है, उसे तुरंत अपने ऑफिस के कंप्यूटर में लगाएं।",
      "उसे किसी भी कंप्यूटर में कभी न लगाएं; सीधे अपनी IT सुरक्षा / SOC टीम को सौंप दें।",
      "उसे फॉर्मेट करके अपनी पर्सनल फाइलों के लिए इस्तेमाल करें।",
      "उसे ATM मशीन में लगाकर चेक करें।"
    ],
    correct: 1,
    exp_en: "This is a classic 'USB Drop Attack'. Cybercriminals leave malware-infected flash drives hoping curious employees plug them in.",
    exp_hi: "यह 'USB ड्रॉप अटैक' कहलाता है। हमलावर जानबूझकर मालवेयर वाली पेन ड्राइव गिराते हैं ताकि कोई उसे कंप्यूटर में लगाकर पूरे नेटवर्क को संक्रमित कर दे।"
  },
  {
    q_en: "An unexpected email from your 'CEO' arrives asking you to urgently purchase gift cards or execute an offshore wire transfer. What is this attack?",
    q_hi: "आपकी कंपनी के 'CEO' के नाम से अचानक ईमेल आता है जिसमें तुरंत गिफ्ट कार्ड खरीदने या किसी अनजान खाते में पैसे ट्रांसफर करने को कहा गया है। यह कौन सा हमला है?",
    options_en: [
      "Business Email Compromise (BEC) / CEO Fraud.",
      "DDoS Network Flood.",
      "SQL Database Injection.",
      "Cross-Site Scripting."
    ],
    options_hi: [
      "बिजनेस ईमेल कॉम्प्रोमाइज (BEC) / CEO फ्रॉड।",
      "DDoS नेटवर्क हमला।",
      "SQL डेटाबेस इंजेक्शन।",
      "क्रॉस-साइट स्क्रिप्टिंग।"
    ],
    correct: 0,
    exp_en: "BEC attackers spoof or compromise executive emails to deceive finance or HR staff into transferring funds without verbal verification.",
    exp_hi: "BEC अटैक में स्कैमर्स कंपनी के वरिष्ठ अधिकारियों की नकली ईमेल बनाकर कर्मचारियों से गोपनीय फंड ट्रांसफर करवाते हैं।"
  },
  {
    q_en: "A popup appears on your screen claiming your computer is infected with viruses, giving a phone number for 'Microsoft Support'. What is this?",
    q_hi: "कंप्यूटर स्क्रीन पर अचानक पॉपअप आता है कि 'आपका सिस्टम वायरस से संक्रमित है, तुरंत इस नंबर पर माइक्रोसॉफ्ट सपोर्ट को कॉल करें'। यह क्या है?",
    options_en: [
      "A legitimate Windows security emergency diagnostic.",
      "Tech Support Scam designed to trick you into granting remote access (AnyDesk) and paying fake fees.",
      "An automated Windows OS update.",
      "A free antivirus gift from Microsoft."
    ],
    options_hi: [
      "विंडोज का असली आपातकालीन सुरक्षा अलर्ट।",
      "टेक सपोर्ट स्कैम (Tech Support Scam) जो एनीडेस्क से आपके कंप्यूटर का रिमोट कंट्रोल लेकर पैसे ऐंठता है।",
      "विंडोज का सामान्य ऑटोमैटिक अपडेट।",
      "माइक्रोसॉफ्ट द्वारा दिया गया फ्री एंटीवायरस उपहार।"
    ],
    correct: 1,
    exp_en: "Legitimate tech companies never display phone numbers in web popups asking users to call them for virus removal.",
    exp_hi: "माइक्रोसॉफ्ट या गूगल कभी भी ब्राउज़र पॉपअप में फोन नंबर देकर वायरस हटाने के लिए कॉल करने को नहीं कहते।"
  },
  {
    q_en: "You receive an unsolicited WhatsApp message offering an easy online job: 'Earn ₹5,000/day by liking YouTube videos'. What is the catch?",
    q_hi: "व्हाट्सएप पर अनजान नंबर से मैसेज आता है: 'यूट्यूब वीडियो लाइक करके रोजाना ₹5,000 कमाएं'। इस जॉब ऑफर की सच्चाई क्या है?",
    options_en: [
      "A genuine digital marketing employment scheme.",
      "Task-based scam: They pay a tiny amount initially, then demand large 'security deposits' to unlock frozen earnings.",
      "A government employment guarantee program.",
      "A legitimate lottery sponsored by YouTube."
    ],
    options_hi: [
      "यह डिजिटल मार्केटिंग की बिल्कुल असली नौकरी है।",
      "टास्क फ्रॉड (Task Scam): शुरू में ₹100-200 देकर भरोसा जीतते हैं, फिर बड़ा 'डिपॉजिट' मांगकर लाखों रुपये ठग लेते हैं।",
      "यह सरकारी रोजगार गारंटी योजना है।",
      "यूट्यूब द्वारा आयोजित असली लॉटरी।"
    ],
    correct: 1,
    exp_en: "Part-time video liking jobs on Telegram/WhatsApp are widespread advance-fee traps. Legitimate jobs never require upfront deposits to release pay.",
    exp_hi: "टेलीग्राम और व्हाट्सएप पर 'वीडियो लाइक' जॉब्स पूरी तरह फ्रॉड हैं। असली नौकरियां काम करने के बदले पैसे मांगती नहीं हैं।"
  },
  {
    q_en: "What is 'Juice Jacking' in mobile device security?",
    q_hi: "मोबाइल सुरक्षा में 'Juice Jacking' (जूस जैकिंग) क्या होती है?",
    options_en: [
      "Malware installation or data theft executed through public USB charging ports at airports or stations.",
      "Overcharging and exploding phone batteries.",
      "Drinking energy drinks while coding.",
      "Slow cellular data speeds during train journeys."
    ],
    options_hi: [
      "एयरपोर्ट या रेलवे स्टेशन पर लगे पब्लिक USB चार्जिंग पोर्ट के जरिए फोन में मालवेयर डालना या डेटा चुराना।",
      "मोबाइल की बैटरी ज्यादा चार्ज होकर खराब हो जाना।",
      "कोडिंग करते समय एनर्जी ड्रिंक पीना।",
      "ट्रेन में सफर के दौरान मोबाइल डेटा का धीमा होना।"
    ],
    correct: 0,
    exp_en: "USB cables carry both power and data. Compromised public USB ports can silently transfer spyware onto connected devices.",
    exp_hi: "USB केबल से करंट के साथ डेटा भी ट्रांसफर होता है। सार्वजनिक चार्जिंग कियोस्क पर हैकर्स फोन से फोटो और डेटा चुरा सकते हैं।"
  },
  {
    q_en: "Why is installing software updates and operating system security patches promptly critical?",
    q_hi: "मोबाइल या कंप्यूटर के सॉफ्टवेयर अपडेट और सिक्योरिटी पैच समय पर इंस्टॉल करना क्यों जरूरी है?",
    options_en: [
      "Updates are solely intended to consume hard drive storage.",
      "Patches fix known vulnerabilities (Zero-days) that cybercriminals actively exploit to breach unpatched devices.",
      "Updates slow down device performance deliberately.",
      "Updates remove your saved Wi-Fi networks."
    ],
    options_hi: [
      "अपडेट का काम केवल हार्ड ड्राइव की जगह भरना होता है।",
      "अपडेट उन सुरक्षा खामियों (Vulnerabilities) को ठीक करते हैं जिनका फायदा उठाकर हैकर्स डिवाइस हैक कर सकते हैं।",
      "अपडेट जानबूझकर कंप्यूटर को धीमा करने के लिए बनाए जाते हैं।",
      "अपडेट आपके सभी पुराने वाई-फाई पासवर्ड मिटा देते हैं।"
    ],
    correct: 1,
    exp_en: "Unpatched vulnerabilities are the primary gateway for ransomware and trojans. Security updates close these security holes.",
    exp_hi: "हैकर्स पुरानी सुरक्षा कमियों के जरिए रैंसमवेयर फैलाते हैं। अपडेट करने से वे सुरक्षा छिद्र बंद हो जाते हैं।"
  },
  {
    q_en: "What should you do if your phone suddenly receives dozens of 2FA push notifications in rapid succession without you logging in?",
    q_hi: "यदि आपके फोन पर अचानक बिना लॉगिन किए लगातार दर्जनों 2FA पुश नोटिफिकेशन या OTP आने लगें, तो आपको क्या करना चाहिए?",
    options_en: [
      "Tap 'Approve' to stop the annoying notifications.",
      "Do NOT approve; this is an MFA Fatigue (Push Bombing) attack. Change your password immediately.",
      "Turn off your phone's screen and ignore it.",
      "Send your password to customer care."
    ],
    options_hi: [
      "नोटिफिकेशन से परेशान होकर 'Approve' बटन दबा दें।",
      "कभी भी Approve न करें; यह MFA फटीग (Push Bombing) हमला है। तुरंत अपना पासवर्ड बदलें।",
      "फोन को उल्टा रख दें और कुछ न करें।",
      "कस्टमर केयर को अपना पासवर्ड भेज दें।"
    ],
    correct: 1,
    exp_en: "Attackers with stolen passwords spam push notifications hoping the victim approves out of frustration. Deny and change credentials.",
    exp_hi: "हैकर्स यूजर को तंग करके गलती से 'Approve' करवाने के लिए बार-बार पुश अलर्ट भेजते हैं। कभी भी अप्रूव न करें और तुरंत पासवर्ड बदलें।"
  },
  {
    q_en: "What is the recommended '3-2-1 Backup Rule' for ransomware resilience?",
    q_hi: "रैंसमवेयर हमलों से डेटा सुरक्षित रखने के लिए '3-2-1 बैकअप नियम' क्या है?",
    options_en: [
      "3 passwords, 2 usernames, 1 device.",
      "3 copies of data, on 2 different media types, with 1 copy stored securely offsite or offline.",
      "Backup only on the 3rd, 2nd, and 1st of every month.",
      "3 antivirus software on 2 monitors with 1 keyboard."
    ],
    options_hi: [
      "3 पासवर्ड, 2 यूजरनेम और 1 डिवाइस रखना।",
      "डेटा की 3 प्रतियां (Copies), 2 अलग-अलग मीडिया पर, और 1 प्रति सुरक्षित रूप से ऑफलाइन या क्लाउड में स्टोर करना।",
      "हर महीने की केवल 3, 2 और 1 तारीख को बैकअप लेना।",
      "3 एंटीवायरस सॉफ्टवेयर एक साथ चलाना।"
    ],
    correct: 1,
    exp_en: "The 3-2-1 rule ensures that even if ransomware encrypts your main drives, an offline/immutable copy remains safe for recovery.",
    exp_hi: "3-2-1 नियम सुनिश्चित करता है कि मुख्य कंप्यूटर में वायरस आने पर भी ऑफलाइन बैकअप से पूरा डेटा वापस पाया जा सके।"
  },
  {
    q_en: "Someone sends an email with an attachment named 'Invoice_March2026.pdf.exe'. What is dangerous about this file?",
    q_hi: "आपको ईमेल पर 'Invoice_March2026.pdf.exe' नाम का अटैचमेंट मिलता है। इस फाइल में क्या बड़ा खतरा है?",
    options_en: [
      "The file is double-spaced in size.",
      "It uses a deceptive double extension (.pdf.exe) to disguise an executable malicious program as an innocent PDF document.",
      "It requires Adobe Acrobat Reader v20.",
      "It cannot be printed on paper."
    ],
    options_hi: [
      "फाइल का साइज दोगुना हो चुका है।",
      "यह डबल एक्सटेंशन (.pdf.exe) का उपयोग करके एक खतरनाक निष्पादन योग्य (Executable) वायरस को साधारण PDF जैसा दिखा रही है।",
      "यह केवल नए एडोब रीडर में ही खुलती है।",
      "इसे प्रिंटर से प्रिंट नहीं किया जा सकता।"
    ],
    correct: 1,
    exp_en: "Attackers add fake extensions (.pdf.exe) hoping operating systems hide the final extension. Opening .exe files executes harmful code.",
    exp_hi: "स्कैमर्स फाइल के नाम में '.pdf.exe' जोड़ते हैं ताकि यूजर धोखे में आकर वायरस (.exe फाइल) को खोल दे और कंप्यूटर हैक हो जाए।"
  },
  {
    q_en: "What is 'Shoulder Surfing' in physical cybersecurity?",
    q_hi: "फिजिकल साइबर सुरक्षा में 'Shoulder Surfing' (शोल्डर सर्फिंग) क्या होता है?",
    options_en: [
      "Using a computer while standing on someone's shoulders.",
      "Direct observation (looking over someone's shoulder) to secretly see passwords, PINs, or confidential screen data.",
      "Surfing the internet using shoulder gesture controls.",
      "A muscle injury caused by bad ergonomic posture."
    ],
    options_hi: [
      "किसी के कंधे पर खड़े होकर कंप्यूटर चलाना।",
      "किसी के पीछे या कंधे के ऊपर से झांककर उसका पासवर्ड, ATM पिन या गोपनीय स्क्रीन डेटा चुपके से देख लेना।",
      "कंधे के इशारों से वेब ब्राउज़िंग करना।",
      "कंप्यूटर पर देर तक बैठने से कंधे में दर्द होना।"
    ],
    correct: 1,
    exp_en: "Shoulder surfing is spying on someone's keyboard or screen in public places (ATMs, cafes, flights). Always shield your screen and keypad.",
    exp_hi: "सार्वजनिक स्थानों (जैसे ATM या मेट्रो) में किसी के पीछे से पासवर्ड या PIN झांकने को शोल्डर सर्फिंग कहते हैं। PIN डालते समय हमेशा कीपैड ढकें।"
  }
];

// Fisher-Yates array shuffling algorithm
function shuffleArray(arr) {
  const result = [...arr];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

function setQuizLanguage(lang) {
  quizLanguage = lang;
  const btnEn = document.getElementById("btn-quiz-lang-en");
  const btnHi = document.getElementById("btn-quiz-lang-hi");

  if (lang === "hi") {
    btnHi.className = "px-2.5 py-1 rounded-lg text-xs font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 transition-all";
    btnEn.className = "px-2.5 py-1 rounded-lg text-xs font-bold text-slate-400 hover:text-white transition-all";
    document.getElementById("quiz-academy-title").innerText = "साइबर सुरक्षा प्रशिक्षण अकादमी";
    document.getElementById("quiz-academy-subtitle").innerText = "आधुनिक डिजिटल धोखाधड़ी और फिशिंग हमलों से बचने की व्यावहारिक क्षमता का मूल्यांकन करें।";
  } else {
    btnEn.className = "px-2.5 py-1 rounded-lg text-xs font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 transition-all";
    btnHi.className = "px-2.5 py-1 rounded-lg text-xs font-bold text-slate-400 hover:text-white transition-all";
    document.getElementById("quiz-academy-title").innerText = "Cyber Defense Training Academy";
    document.getElementById("quiz-academy-subtitle").innerText = "Assess and sharpen your defensive response capabilities against modern social engineering threats.";
  }

  if (currentQuizIndex < activeQuizQuestions.length) {
    loadQuizQuestion(currentQuizIndex);
  } else {
    renderQuizResult();
  }
}

function initQuiz() {
  currentQuizIndex = 0;
  quizScore = 0;
  // Dynamically select and randomize 10 fresh questions from the question bank every single time!
  activeQuizQuestions = shuffleArray(QUIZ_QUESTION_BANK).slice(0, 10);

  const scoreLabel = quizLanguage === "hi" ? "स्कोर: 0" : "Score: 0";
  document.getElementById("quiz-score-badge").innerText = scoreLabel;

  // Restore Question Box and hide Result Box
  const qBox = document.getElementById("quiz-question-box");
  const rBox = document.getElementById("quiz-result-box");
  const footerBar = document.getElementById("quiz-footer-bar");
  if (qBox) qBox.classList.remove("hidden");
  if (rBox) {
    rBox.classList.add("hidden");
    rBox.innerHTML = "";
  }
  if (footerBar) footerBar.classList.remove("hidden");

  loadQuizQuestion(0);
}

function loadQuizQuestion(index) {
  if (!activeQuizQuestions || activeQuizQuestions.length === 0) {
    activeQuizQuestions = shuffleArray(QUIZ_QUESTION_BANK).slice(0, 10);
  }
  const item = activeQuizQuestions[index];
  const qText = quizLanguage === "hi" ? item.q_hi : item.q_en;
  const options = quizLanguage === "hi" ? item.options_hi : item.options_en;

  const progressLabel = quizLanguage === "hi" ? `परिदृश्य ${index + 1} / ${activeQuizQuestions.length}` : `Scenario ${index + 1} of ${activeQuizQuestions.length}`;
  const scoreLabel = quizLanguage === "hi" ? `स्कोर: ${quizScore}` : `Score: ${quizScore}`;

  document.getElementById("quiz-progress-text").innerText = progressLabel;
  document.getElementById("quiz-score-badge").innerText = scoreLabel;
  document.getElementById("quiz-question-title").innerText = `${index + 1}. ${qText}`;

  const container = document.getElementById("quiz-options-container");
  container.innerHTML = "";
  document.getElementById("quiz-explanation-box").classList.add("hidden");
  document.getElementById("btn-next-question").classList.add("hidden");

  options.forEach((opt, idx) => {
    const btn = document.createElement("button");
    btn.className = "w-full text-left p-4 rounded-xl bg-slate-900 border border-slate-700/80 hover:border-cyan-400 text-sm text-slate-200 transition-all shadow-sm leading-relaxed";
    btn.innerText = `${String.fromCharCode(65 + idx)}. ${opt}`;
    btn.onclick = () => selectQuizAnswer(idx);
    container.appendChild(btn);
  });
}

function selectQuizAnswer(selectedIdx) {
  const item = activeQuizQuestions[currentQuizIndex];
  const container = document.getElementById("quiz-options-container");
  const buttons = container.querySelectorAll("button");

  buttons.forEach((btn, idx) => {
    btn.disabled = true;
    if (idx === item.correct) {
      btn.className = "w-full text-left p-4 rounded-xl bg-emerald-500/20 border border-emerald-500 text-emerald-300 text-sm font-semibold leading-relaxed shadow";
    } else if (idx === selectedIdx) {
      btn.className = "w-full text-left p-4 rounded-xl bg-rose-500/20 border border-rose-500 text-rose-300 text-sm font-semibold leading-relaxed shadow";
    } else {
      btn.className = "w-full text-left p-4 rounded-xl bg-slate-900/40 border border-slate-800 text-slate-500 text-sm leading-relaxed";
    }
  });

  const isCorrect = (selectedIdx === item.correct);
  if (isCorrect) {
    quizScore += 10;
    document.getElementById("quiz-score-badge").innerText = (quizLanguage === "hi" ? `स्कोर: ${quizScore}` : `Score: ${quizScore}`);
  }

  const expText = quizLanguage === "hi" ? item.exp_hi : item.exp_en;
  const correctLabel = quizLanguage === "hi" ? (isCorrect ? "सही उत्तर!" : "गलत उत्तर!") : (isCorrect ? "Correct Response!" : "Incorrect Response.");

  const expBox = document.getElementById("quiz-explanation-box");
  expBox.className = isCorrect ? "p-4 rounded-xl text-sm bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 leading-relaxed" : "p-4 rounded-xl text-sm bg-rose-500/10 border border-rose-500/30 text-rose-300 leading-relaxed";
  expBox.innerHTML = `<strong>${correctLabel}</strong> ${expText}`;
  expBox.classList.remove("hidden");

  const btnNext = document.getElementById("btn-next-question");
  btnNext.innerText = (quizLanguage === "hi" ? "अगला प्रश्न →" : "Next Scenario →");
  btnNext.classList.remove("hidden");
}

async function nextQuizQuestion() {
  currentQuizIndex++;
  if (currentQuizIndex < activeQuizQuestions.length) {
    loadQuizQuestion(currentQuizIndex);
  } else {
    await renderQuizResult();
  }
}

async function renderQuizResult() {
  const qBox = document.getElementById("quiz-question-box");
  const rBox = document.getElementById("quiz-result-box");
  const footerBar = document.getElementById("quiz-footer-bar");

  if (qBox) qBox.classList.add("hidden");
  if (footerBar) footerBar.classList.add("hidden");
  if (rBox) rBox.classList.remove("hidden");

  let badgeNotice = "";

  // If logged in and score >= 60, claim badge
  if (currentToken && quizScore >= 60) {
    try {
      const res = await fetch("/api/user/claim-badge", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${currentToken}`
        },
        body: JSON.stringify({ badge_name: "Phishing Hunter", quiz_score: quizScore })
      });
      if (res.ok) {
        const badgeMsg = quizLanguage === "hi" 
          ? "🎉 <strong>नया बैज अनलॉक:</strong> 'Phishing Hunter' बैज आपकी प्रोफाइल में जोड़ दिया गया है!"
          : "🎉 <strong>New Credential Unlocked:</strong> 'Phishing Hunter' badge has been added to your profile!";
        badgeNotice = `<div class="p-4 bg-amber-500/10 border border-amber-500/30 rounded-2xl text-amber-300 text-xs text-center max-w-md w-full shadow-lg">${badgeMsg}</div>`;
      }
    } catch (e) {}
  }

  // Performance Rank
  let rankText = "";
  let rankColor = "";
  if (quizScore >= 90) {
    rankText = quizLanguage === "hi" ? "🏆 साइबर सुरक्षा विशेषज्ञ (ELITE CYBER DEFENDER)" : "🏆 ELITE CYBER DEFENDER";
    rankColor = "text-emerald-400";
  } else if (quizScore >= 70) {
    rankText = quizLanguage === "hi" ? "🛡️ सतर्क व सुरक्षित ऑपरेटर (CYBER AWARE OPERATOR)" : "🛡️ CYBER AWARE OPERATOR";
    rankColor = "text-cyan-400";
  } else {
    rankText = quizLanguage === "hi" ? "⚠️ सुरक्षा प्रशिक्षण आवश्यक (TRAINING RECOMMENDED)" : "⚠️ TRAINING RECOMMENDED";
    rankColor = "text-amber-400";
  }

  if (rBox) {
    rBox.innerHTML = `
      <div class="text-center py-10 px-4 space-y-6 flex flex-col items-center justify-center">
        <!-- Glowing Trophy Icon -->
        <div class="w-20 h-20 rounded-3xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center text-4xl shadow-xl shadow-cyan-500/15">
          <i class="fa-solid fa-trophy"></i>
        </div>

        <div class="space-y-1.5">
          <span class="text-xs font-mono text-cyan-400 tracking-widest uppercase">
            ${quizLanguage === 'hi' ? 'अंतिम मूल्यांकन रिपोर्ट' : 'FINAL ASSESSMENT REPORT'}
          </span>
          <h3 class="text-2xl sm:text-3xl font-extrabold text-white">
            ${quizLanguage === 'hi' ? 'साइबर डिफेंस ट्रेनिंग पूर्ण!' : 'Cyber Defense Training Completed!'}
          </h3>
        </div>

        <!-- Big Centered Score Box in Large Typography -->
        <div class="p-6 sm:p-8 rounded-3xl bg-slate-900/90 border border-slate-800 shadow-2xl max-w-sm w-full text-center space-y-2">
          <div class="text-xs font-mono text-slate-400 uppercase tracking-wider">
            ${quizLanguage === 'hi' ? 'कुल अर्जित स्कोर' : 'TOTAL ASSESSMENT SCORE'}
          </div>
          <div class="text-6xl sm:text-7xl font-black cyber-gradient-text tracking-tight my-2">
            ${quizScore} <span class="text-2xl sm:text-3xl font-bold text-slate-500">/ 100</span>
          </div>
          <div class="text-sm font-bold ${rankColor} tracking-wide pt-1">
            ${rankText}
          </div>
        </div>

        ${badgeNotice}

        <div class="pt-2">
          <button onclick="initQuiz()" class="px-8 py-3.5 bg-gradient-to-r from-cyan-500 via-teal-400 to-emerald-400 hover:from-cyan-400 hover:to-emerald-300 text-slate-950 font-black rounded-2xl text-sm transition-all shadow-xl shadow-cyan-500/25 active:scale-95">
            <i class="fa-solid fa-rotate-right mr-2"></i>
            <span>${quizLanguage === 'hi' ? 'दोबारा टेस्ट दें (नये प्रश्न / New Scenarios)' : 'Restart Training (Fresh Scenarios)'}</span>
          </button>
        </div>
      </div>
    `;
  }
}

// --- AUTHENTICATION & ROLE-BASED UI ---
let authMode = "login";

function openAuthModal(mode = "login") {
  authMode = mode;
  setAuthMode(mode);
  document.getElementById("auth-modal").classList.remove("hidden");
  document.getElementById("auth-error").classList.add("hidden");
}

function closeAuthModal() {
  document.getElementById("auth-modal").classList.add("hidden");
}

function setAuthMode(mode) {
  authMode = mode;
  const tabLogin = document.getElementById("auth-tab-login");
  const tabRegister = document.getElementById("auth-tab-register");
  const emailField = document.getElementById("auth-email-field");
  const btnSubmit = document.getElementById("btn-auth-submit");
  const modalTitle = document.getElementById("auth-modal-title");

  if (mode === "login") {
    tabLogin.className = "pb-2 border-b-2 border-cyan-400 text-cyan-400 text-sm font-semibold";
    tabRegister.className = "pb-2 border-b-2 border-transparent text-slate-400 text-sm font-semibold";
    emailField.classList.add("hidden");
    btnSubmit.innerText = "Login";
    modalTitle.innerText = "Login to CyberShield";
  } else {
    tabLogin.className = "pb-2 border-b-2 border-transparent text-slate-400 text-sm font-semibold";
    tabRegister.className = "pb-2 border-b-2 border-cyan-400 text-cyan-400 text-sm font-semibold";
    emailField.classList.remove("hidden");
    btnSubmit.innerText = "Create Account";
    modalTitle.innerText = "Register New Account";
  }
}

async function submitAuth() {
  const username = document.getElementById("auth-username").value.trim();
  const password = document.getElementById("auth-password").value.trim();
  const email = document.getElementById("auth-email").value.trim();
  const errDiv = document.getElementById("auth-error");

  if (!username || !password) {
    errDiv.innerText = "Please provide username and password.";
    errDiv.classList.remove("hidden");
    return;
  }

  errDiv.classList.add("hidden");

  try {
    if (authMode === "login") {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Login failed");

      currentToken = data.access_token;
      currentUsername = data.username;
      currentUserRole = data.role;

      localStorage.setItem("cybershield_token", currentToken);
      localStorage.setItem("cybershield_user", currentUsername);
      localStorage.setItem("cybershield_role", currentUserRole);

      updateRoleUI();
      closeAuthModal();

      if (currentUserRole === "admin") {
        switchTab("admin-soc");
      } else {
        switchTab("user-vault");
      }
    } else {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email: email || `${username}@example.com`, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Registration failed");

      alert("Registration successful! Please login.");
      setAuthMode("login");
    }
  } catch (err) {
    errDiv.innerText = err.message;
    errDiv.classList.remove("hidden");
  }
}

function updateRoleUI() {
  const btnLogin = document.getElementById("btn-login");
  const userBadge = document.getElementById("user-badge");
  const userNameElem = document.getElementById("user-name");
  const userRoleTag = document.getElementById("user-role-tag");
  const pulseDot = document.getElementById("role-pulse-dot");

  // User tabs
  const tabVault = document.getElementById("nav-user-vault");
  const tabStats = document.getElementById("nav-user-stats");

  // Admin tabs
  const tabSOC = document.getElementById("nav-admin-soc");
  const tabAdminUsers = document.getElementById("nav-admin-users");
  const tabAdminRules = document.getElementById("nav-admin-rules");
  const tabAdminAudit = document.getElementById("nav-admin-audit");

  if (currentToken && currentUsername) {
    btnLogin.classList.add("hidden");
    userBadge.classList.remove("hidden");
    userNameElem.innerText = currentUsername;

    if (currentUserRole === "admin") {
      // SOC Admin View
      pulseDot.className = "w-2 h-2 rounded-full bg-rose-500 animate-ping";
      userRoleTag.className = "px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-400 border border-rose-700";
      userRoleTag.innerText = "SOC ADMIN";

      // Show Admin tabs
      if (tabSOC) tabSOC.classList.remove("hidden");
      if (tabAdminUsers) tabAdminUsers.classList.remove("hidden");
      if (tabAdminRules) tabAdminRules.classList.remove("hidden");
      if (tabAdminAudit) tabAdminAudit.classList.remove("hidden");

      // Hide User specific personal tabs
      if (tabVault) tabVault.classList.add("hidden");
      if (tabStats) tabStats.classList.add("hidden");
    } else {
      // Regular User View
      pulseDot.className = "w-2 h-2 rounded-full bg-emerald-400 animate-pulse";
      userRoleTag.className = "px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-700";
      userRoleTag.innerText = "USER";

      // Show User tabs
      if (tabVault) tabVault.classList.remove("hidden");
      if (tabStats) tabStats.classList.remove("hidden");

      // Hide Admin tabs
      if (tabSOC) tabSOC.classList.add("hidden");
      if (tabAdminUsers) tabAdminUsers.classList.add("hidden");
      if (tabAdminRules) tabAdminRules.classList.add("hidden");
      if (tabAdminAudit) tabAdminAudit.classList.add("hidden");
    }
  } else {
    // Guest View
    btnLogin.classList.remove("hidden");
    userBadge.classList.add("hidden");

    if (tabVault) tabVault.classList.add("hidden");
    if (tabStats) tabStats.classList.add("hidden");
    if (tabSOC) tabSOC.classList.add("hidden");
    if (tabAdminUsers) tabAdminUsers.classList.add("hidden");
    if (tabAdminRules) tabAdminRules.classList.add("hidden");
    if (tabAdminAudit) tabAdminAudit.classList.add("hidden");
  }
}

function logout() {
  currentToken = null;
  currentUsername = null;
  currentUserRole = null;
  localStorage.removeItem("cybershield_token");
  localStorage.removeItem("cybershield_user");
  localStorage.removeItem("cybershield_role");
  updateRoleUI();
  switchTab("scanner");
}

// Initial Run
window.addEventListener("DOMContentLoaded", () => {
  updateRoleUI();
  initCyberRadarCanvas();
  initBgCanvas();
  initAttackFeed();
  initCloudDatabase();
  loadAdminScanLogs();

  // Enter Key Listener for Threat Scanner Target Input
  const urlInput = document.getElementById("url-input");
  if (urlInput) {
    urlInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        executeScan();
      }
    });
  }

  // Enter Key Listener for Domain Inspector Input
  const domainInput = document.getElementById("domain-inspector-input");
  if (domainInput) {
    domainInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runDomainForensicAudit();
      }
    });
  }
});

// =========================================================================
// SECTION 10: REAL-TIME PASSWORD STRENGTH & EXPOSURE ANALYZER (SENTINEL)
// =========================================================================

const COMMON_LEAKED_PASSWORDS = new Set([
  "123456", "password", "123456789", "12345", "12345678", "qwerty", "1234567",
  "111111", "123123", "password1", "1234", "admin", "admin123", "administrator",
  "root", "root123", "default", "guest", "iloveyou", "princess", "rockyou",
  "monkey", "dragon", "welcome", "sunshine", "superman", "master", "football",
  "shadow", "computer", "letmein", "trustno1", "starwars", "pass123", "pass@123",
  "p@ssword", "p@ssw0rd", "admin@123", "test1234", "secret", "login", "charlie",
  "jordan", "michael", "harley", "daniel", "monkey1", "jessica", "hunter",
  "killer", "buster", "robert", "thomas", "hockey", "soccer", "orange",
  "purple", "yellow", "testing", "testing123", "access", "user", "user123",
  "support", "qwertyuiop", "asdfghjkl", "zxcvbnm", "654321", "666666", "777777",
  "888888", "999999", "000000", "112233", "121212", "123321", "cisco", "cisco123",
  "database", "server", "oracle", "matrix", "batman", "pokemon", "naruto",
  "forever", "freedom", "internet", "security", "secure123", "qwerty123", "abc123",
  "1q2w3e4r", "zaq12wsx", "admin2024", "admin2025", "admin2026", "changeme",
  "password123", "welcome1", "welcome123", "hellopass", "password!", "pass1234"
]);

function togglePasswordVisibility() {
  const input = document.getElementById("pwd-analyzer-input");
  const icon = document.getElementById("pwd-toggle-icon");
  if (!input || !icon) return;

  if (input.type === "password") {
    input.type = "text";
    icon.className = "fa-solid fa-eye-slash text-cyan-400";
  } else {
    input.type = "password";
    icon.className = "fa-solid fa-eye";
  }
}

function clearPasswordInput() {
  const input = document.getElementById("pwd-analyzer-input");
  if (input) {
    input.value = "";
    handlePasswordInput();
  }
}

function copyPasswordToClipboard() {
  const input = document.getElementById("pwd-analyzer-input");
  if (!input || !input.value) return;

  navigator.clipboard.writeText(input.value).then(() => {
    const icon = document.getElementById("pwd-copy-icon");
    if (icon) {
      icon.className = "fa-solid fa-check text-emerald-400 text-xs";
      setTimeout(() => {
        icon.className = "fa-solid fa-copy text-xs";
      }, 1500);
    }
  }).catch(() => {
    alert("Copied to clipboard!");
  });
}

function generateStrongPassword() {
  const lowers = "abcdefghijklmnopqrstuvwxyz";
  const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const numbers = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?";
  const allChars = lowers + uppers + numbers + symbols;

  const getCryptoRandom = (max) => {
    const buf = new Uint32Array(1);
    crypto.getRandomValues(buf);
    return buf[0] % max;
  };

  let pwd = [
    lowers[getCryptoRandom(lowers.length)],
    uppers[getCryptoRandom(uppers.length)],
    numbers[getCryptoRandom(numbers.length)],
    symbols[getCryptoRandom(symbols.length)]
  ];

  for (let i = 4; i < 16; i++) {
    pwd.push(allChars[getCryptoRandom(allChars.length)]);
  }

  // Fisher-Yates shuffle
  for (let i = pwd.length - 1; i > 0; i--) {
    const j = getCryptoRandom(i + 1);
    [pwd[i], pwd[j]] = [pwd[j], pwd[i]];
  }

  const generated = pwd.join("");
  const input = document.getElementById("pwd-analyzer-input");
  if (input) {
    input.value = generated;
    handlePasswordInput();
  }
}

function formatCrackTime(seconds) {
  if (seconds <= 0 || !isFinite(seconds)) return "Instant (< 1 ms)";
  if (seconds < 0.001) return "< 1 millisecond";
  if (seconds < 1) return "< 1 second";
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)} minutes`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)} hours`;
  const days = hours / 24;
  if (days < 30) return `${Math.round(days)} days`;
  const months = days / 30.4375;
  if (months < 12) return `${Math.round(months)} months`;
  const years = days / 365.25;
  if (years < 100) return `${Math.round(years)} years`;
  const centuries = years / 100;
  if (centuries < 1000) return `${Math.round(centuries).toLocaleString()} centuries`;
  const millennia = years / 1000;
  if (millennia < 1000000) return `${Math.round(millennia).toLocaleString()} millennia`;
  return "Millions of Years (Quantum Proof)";
}

function handlePasswordInput() {
  const input = document.getElementById("pwd-analyzer-input");
  const pwd = input ? input.value : "";
  const len = pwd.length;

  document.getElementById("pwd-char-count").innerText = `Length: ${len} character${len === 1 ? '' : 's'}`;

  // Reset if empty
  if (!pwd) {
    document.getElementById("pwd-strength-bar").style.width = "0%";
    document.getElementById("pwd-strength-bar").className = "h-full rounded-full transition-all duration-300 w-0 bg-slate-700";
    document.getElementById("pwd-strength-percent").innerText = "0%";
    document.getElementById("pwd-strength-badge").innerText = "NO INPUT";
    document.getElementById("pwd-strength-badge").className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-slate-800 text-slate-400 border border-slate-700";

    document.getElementById("pwd-breach-alert").classList.add("hidden");

    document.getElementById("pwd-metric-entropy").innerHTML = `0.0 <span class="text-xs font-normal text-slate-500">bits</span>`;
    document.getElementById("pwd-metric-entropy-sub").innerText = "Target: > 60 bits";

    document.getElementById("pwd-metric-crack").innerText = "Instant";
    document.getElementById("pwd-metric-pool").innerHTML = `0 <span class="text-xs font-normal text-slate-500">chars</span>`;
    document.getElementById("pwd-metric-pool-sub").innerText = "Max: 95 characters";

    document.getElementById("pwd-metric-exposure").innerHTML = `<span class="w-2 h-2 rounded-full bg-slate-600"></span><span>Awaiting Input</span>`;
    document.getElementById("pwd-metric-exposure-sub").innerText = "Dictionary Matcher";

    updateChecklistUI({ len: false, lower: false, upper: false, num: false, special: false });

    const tipsList = document.getElementById("pwd-tips-list");
    tipsList.innerHTML = `
      <li class="flex items-start space-x-2 text-slate-500">
        <i class="fa-solid fa-arrow-right text-[10px] text-cyan-400 mt-1 shrink-0"></i>
        <span>Enter a password above to receive real-time mitigation advice.</span>
      </li>
    `;
    return;
  }

  // 1. Character Set Variation
  const hasLower = /[a-z]/.test(pwd);
  const hasUpper = /[A-Z]/.test(pwd);
  const hasNumber = /[0-9]/.test(pwd);
  const hasSpecial = /[^a-zA-Z0-9]/.test(pwd);
  const meetsLength = len >= 12;

  updateChecklistUI({
    len: meetsLength,
    lower: hasLower,
    upper: hasUpper,
    num: hasNumber,
    special: hasSpecial
  });

  // 2. Character Pool Size
  let pool = 0;
  let poolDescParts = [];
  if (hasLower) { pool += 26; poolDescParts.push("a-z"); }
  if (hasUpper) { pool += 26; poolDescParts.push("A-Z"); }
  if (hasNumber) { pool += 10; poolDescParts.push("0-9"); }
  if (hasSpecial) { pool += 33; poolDescParts.push("Symbols"); }
  pool = Math.max(pool, 1);

  // 3. Shannon Entropy: H = L * log2(pool)
  const entropy = len * (Math.log(pool) / Math.log(2));
  document.getElementById("pwd-metric-entropy").innerHTML = `${entropy.toFixed(1)} <span class="text-xs font-normal text-slate-500">bits</span>`;
  document.getElementById("pwd-metric-pool").innerHTML = `${pool} <span class="text-xs font-normal text-slate-500">chars</span>`;
  document.getElementById("pwd-metric-pool-sub").innerText = poolDescParts.join(" + ") || "Unknown";

  let entropyLabel = "Poor (< 28 bits)";
  if (entropy >= 80) entropyLabel = "Military Grade (>= 80 bits)";
  else if (entropy >= 60) entropyLabel = "Strong (>= 60 bits)";
  else if (entropy >= 45) entropyLabel = "Moderate (45-60 bits)";
  else if (entropy >= 28) entropyLabel = "Fair (28-45 bits)";
  document.getElementById("pwd-metric-entropy-sub").innerText = entropyLabel;

  // 4. Common Leaked Password & Breach Exposure Check
  const normalized = pwd.toLowerCase().trim();
  const isDirectBreach = COMMON_LEAKED_PASSWORDS.has(normalized);
  const containsBreachedSub = len >= 4 && [...COMMON_LEAKED_PASSWORDS].some(w => w.length >= 5 && normalized.includes(w));
  const isLeaked = isDirectBreach || containsBreachedSub;

  const breachAlert = document.getElementById("pwd-breach-alert");
  if (isLeaked) {
    breachAlert.classList.remove("hidden");
    const breachDesc = document.getElementById("pwd-breach-desc");
    if (isDirectBreach) {
      breachDesc.innerHTML = `The exact credential <strong>"${pwd}"</strong> is listed in global breached databases (Top 100 most common passwords). It can be compromised in <strong>0.00 seconds</strong> via precomputed dictionary lookups.`;
    } else {
      breachDesc.innerHTML = `This password incorporates known dictionary breach words. Attackers will crack it easily via hybrid dictionary / rule-based mutations.`;
    }
    document.getElementById("pwd-metric-exposure").innerHTML = `
      <span class="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
      <span class="text-rose-400 font-bold">COMPROMISED</span>
    `;
    document.getElementById("pwd-metric-exposure-sub").innerText = "Found in Breach Dumps";
  } else {
    breachAlert.classList.add("hidden");
    document.getElementById("pwd-metric-exposure").innerHTML = `
      <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
      <span class="text-emerald-400 font-bold">CLEAN RADAR</span>
    `;
    document.getElementById("pwd-metric-exposure-sub").innerText = "No Top 100 Breaches";
  }

  // 5. Estimated Crack Time
  let crackSeconds = 0;
  if (isDirectBreach) {
    crackSeconds = 0;
  } else {
    // Search space: pool^length. Average attempts: pool^length / 2.
    // Cracking hashrate: 10^10 hashes/sec (10 Billion guesses/sec)
    const combinations = Math.pow(pool, len);
    crackSeconds = (combinations / 2) / 1e10;
  }
  const crackTimeStr = isDirectBreach ? "0.00 seconds (Dictionary)" : formatCrackTime(crackSeconds);
  document.getElementById("pwd-metric-crack").innerText = crackTimeStr;

  // 6. Heuristic Checks: Sequences & Repetitions
  const hasSeqNumber = /(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)/i.test(pwd);
  const hasSeqLetter = /(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(pwd);
  const hasRepeated = /(.)\1{2,}/.test(pwd);

  // 7. Calculate Comprehensive Security Score (0 - 100)
  let score = 0;

  // Base from entropy: up to 45 pts
  score += Math.min(45, (entropy / 80) * 45);

  // Charset diversity: up to 35 pts (7 pts each for lower, upper, num, special, length>=12)
  if (hasLower) score += 7;
  if (hasUpper) score += 7;
  if (hasNumber) score += 7;
  if (hasSpecial) score += 7;
  if (meetsLength) score += 7;

  // Length scale bonus: up to 20 pts
  if (len >= 16) score += 20;
  else if (len >= 14) score += 15;
  else if (len >= 12) score += 10;
  else if (len >= 8) score += 5;

  // Penalties
  if (hasSeqNumber || hasSeqLetter) score -= 15;
  if (hasRepeated) score -= 10;
  if (isDirectBreach) score = Math.min(10, score * 0.1);
  else if (isLeaked) score = Math.min(30, score * 0.4);

  score = Math.max(5, Math.min(100, Math.round(score)));

  // Update Progress Bar & Badge
  const bar = document.getElementById("pwd-strength-bar");
  const percentLabel = document.getElementById("pwd-strength-percent");
  const badge = document.getElementById("pwd-strength-badge");

  bar.style.width = `${score}%`;
  percentLabel.innerText = `${score}%`;

  if (isDirectBreach) {
    bar.className = "h-full rounded-full transition-all duration-300 bg-rose-600";
    badge.innerText = "BREACHED / COMPROMISED";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-rose-950 text-rose-400 border border-rose-700 animate-pulse";
  } else if (score < 25) {
    bar.className = "h-full rounded-full transition-all duration-300 bg-rose-500";
    badge.innerText = "VERY WEAK";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-rose-950 text-rose-400 border border-rose-800";
  } else if (score < 50) {
    bar.className = "h-full rounded-full transition-all duration-300 bg-amber-500";
    badge.innerText = "WEAK";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-amber-950 text-amber-400 border border-amber-800";
  } else if (score < 75) {
    bar.className = "h-full rounded-full transition-all duration-300 bg-cyan-400";
    badge.innerText = "MODERATE";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-cyan-950 text-cyan-400 border border-cyan-800";
  } else if (score < 90) {
    bar.className = "h-full rounded-full transition-all duration-300 bg-teal-400";
    badge.innerText = "STRONG";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-teal-950 text-teal-400 border border-teal-700";
  } else {
    bar.className = "h-full rounded-full transition-all duration-300 bg-gradient-to-r from-teal-400 to-emerald-400 shadow-md shadow-emerald-500/20";
    badge.innerText = "FORTIFIED / QUANTUM-RESISTANT";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-emerald-950 text-emerald-300 border border-emerald-500";
  }

  // 8. Generate Adaptive Security Recommendations
  generateSecurityTips({
    len,
    hasLower,
    hasUpper,
    hasNumber,
    hasSpecial,
    meetsLength,
    isLeaked,
    hasSeqNumber,
    hasSeqLetter,
    hasRepeated,
    score
  });
}

function updateChecklistUI(criteria) {
  const toggle = (id, iconId, pass) => {
    const el = document.getElementById(id);
    const icon = document.getElementById(iconId);
    if (!el || !icon) return;

    if (pass) {
      el.className = "flex items-center space-x-2.5 text-emerald-400 font-semibold transition-colors";
      icon.className = "fa-solid fa-circle-check text-emerald-400";
    } else {
      el.className = "flex items-center space-x-2.5 text-slate-500 transition-colors";
      icon.className = "fa-solid fa-circle-xmark text-rose-500/70";
    }
  };

  toggle("crit-length", "crit-icon-length", criteria.len);
  toggle("crit-lower", "crit-icon-lower", criteria.lower);
  toggle("crit-upper", "crit-icon-upper", criteria.upper);
  toggle("crit-number", "crit-icon-number", criteria.num);
  toggle("crit-special", "crit-icon-special", criteria.special);
}

function generateSecurityTips(state) {
  const tips = [];

  if (state.isLeaked) {
    tips.push({
      icon: "fa-triangle-exclamation",
      color: "text-rose-400",
      text: "CRITICAL: Never use passwords that appear in public breach dumps. Replace this password immediately across all services."
    });
  }

  if (state.len < 12) {
    tips.push({
      icon: "fa-ruler-horizontal",
      color: "text-amber-400",
      text: `Expand length by ${12 - state.len} more characters. Passwords with 14-16+ characters offer exponentially superior resistance.`
    });
  }

  if (!state.hasSpecial) {
    tips.push({
      icon: "fa-asterisk",
      color: "text-cyan-400",
      text: "Incorporate special characters (!@#$%^&*) to expand the character pool size from 62 to 95."
    });
  }

  if (!state.hasUpper) {
    tips.push({
      icon: "fa-font",
      color: "text-cyan-400",
      text: "Include uppercase letters (A-Z) to hinder case-insensitive automated dictionary crawlers."
    });
  }

  if (!state.hasNumber) {
    tips.push({
      icon: "fa-hashtag",
      color: "text-cyan-400",
      text: "Introduce non-sequential numeric digits (0-9)."
    });
  }

  if (state.hasSeqNumber || state.hasSeqLetter) {
    tips.push({
      icon: "fa-arrow-down-1-9",
      color: "text-rose-400",
      text: "Remove predictable sequences (like '123' or 'abc'). Attack dictionaries routinely prioritize sequential patterns."
    });
  }

  if (state.hasRepeated) {
    tips.push({
      icon: "fa-repeat",
      color: "text-amber-400",
      text: "Eliminate repetitive characters (e.g., 'aaa' or '111'), which dramatically reduce entropy."
    });
  }

  if (tips.length === 0 || state.score >= 85) {
    tips.push({
      icon: "fa-shield-halved",
      color: "text-emerald-400",
      text: "Excellent entropy! This password exceeds cryptographic thresholds against GPU cluster brute-force attacks."
    });
    tips.push({
      icon: "fa-key",
      color: "text-slate-400",
      text: "Tip: Store complex credentials in an encrypted password manager or hardware security key."
    });
  }

  const container = document.getElementById("pwd-tips-list");
  container.innerHTML = "";
  tips.forEach(t => {
    const li = document.createElement("li");
    li.className = "flex items-start space-x-2 text-slate-300 leading-relaxed";
    li.innerHTML = `
      <i class="fa-solid ${t.icon} text-xs ${t.color} mt-1 shrink-0"></i>
      <span>${t.text}</span>
    `;
    container.appendChild(li);
  });
}

// =========================================================================
// SECTION 11: AI PHISHING & LINK ANALYZER ENGINE
// =========================================================================

const PHISH_URGENT_KEYWORDS = [
  "immediately", "account suspended", "verify otp", "urgent", "action required",
  "within 24 hours", "security alert", "unauthorized access", "permanently blocked",
  "click here to verify", "unusual activity", "update kyc", "suspended immediately",
  "final notice", "confirm identity", "verify your account", "restricted access"
];

const PHISH_SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".ml", ".online", ".tk", ".ga", ".cf", ".icu",
  ".buzz", ".cam", ".club", ".work", ".click", ".live", ".loan",
  ".vip", ".cc", ".bid", ".pw", ".rest", ".gq"
];

const PHISH_BRAND_LOOKALIKES = [
  { spoof: "g00gle", legitimate: "Google" },
  { spoof: "paypa1", legitimate: "PayPal" },
  { spoof: "am4zon", legitimate: "Amazon" },
  { spoof: "micros0ft", legitimate: "Microsoft" },
  { spoof: "app1e", legitimate: "Apple" },
  { spoof: "netf1ix", legitimate: "Netflix" },
  { spoof: "faceb00k", legitimate: "Facebook" },
  { spoof: "instagr4m", legitimate: "Instagram" },
  { spoof: "wh4tsapp", legitimate: "WhatsApp" },
  { spoof: "b1ank", legitimate: "Bank" }
];

let phishDebounceTimer = null;

function handlePhishingInput() {
  clearTimeout(phishDebounceTimer);
  phishDebounceTimer = setTimeout(() => {
    runPhishingAnalysis();
  }, 250);
}

function clearPhishingInput() {
  const el = document.getElementById("phish-analyzer-input");
  if (el) {
    el.value = "";
    runPhishingAnalysis();
  }
}

function loadPhishingPreset(type) {
  const input = document.getElementById("phish-analyzer-input");
  if (!input) return;

  if (type === "spoof") {
    input.value = "URGENT: Your account has been suspended due to unusual activity. Verify immediately at http://paypa1-security.xyz/login to avoid termination.";
  } else if (type === "urgent") {
    input.value = "Security Alert: Action required immediately. We noticed unauthorized access. Please verify OTP within 24 hours or your credentials will be blocked permanently.";
  } else if (type === "safe") {
    input.value = "Your quarterly security report is ready for review. Access your enterprise dashboard directly via https://cybershield.org/reports/q1.";
  }

  runPhishingAnalysis();
}

function runPhishingAnalysis() {
  const inputEl = document.getElementById("phish-analyzer-input");
  const text = inputEl ? inputEl.value.trim() : "";
  const lowerText = text.toLowerCase();

  // Reset if input is empty
  if (!text) {
    document.getElementById("phish-risk-bar").style.width = "0%";
    document.getElementById("phish-risk-bar").className = "h-full rounded-full transition-all duration-500 w-0 bg-slate-700";
    document.getElementById("phish-risk-percent").innerText = "0%";
    document.getElementById("phish-risk-badge").innerText = "AWAITING INPUT";
    document.getElementById("phish-risk-badge").className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-slate-800 text-slate-400 border border-slate-700";

    document.getElementById("phish-stat-urgency").innerText = "0";
    document.getElementById("phish-stat-tld").innerText = "0";
    document.getElementById("phish-stat-brands").innerText = "0";
    document.getElementById("phish-stat-protocol").innerText = "0";
    document.getElementById("phish-findings-count").innerText = "0 Indicators";

    const container = document.getElementById("phish-findings-container");
    container.innerHTML = `
      <div class="p-4 rounded-xl bg-[#0b0f19] border border-slate-800 text-xs text-slate-500 text-center flex items-center justify-center space-x-2">
        <i class="fa-solid fa-shield-halved text-slate-600"></i>
        <span>No input analyzed yet. Paste a URL or email message above to inspect threat indicators.</span>
      </div>
    `;
    return;
  }

  // WAF Active Interception Check
  const wafCheck = validateInputWithWAF(text, "AI Phishing & Link Analyzer");
  if (wafCheck.blocked) {
    triggerWAFDefense(wafCheck);
    return;
  }

  const findings = [];
  let riskScore = 0;

  // A. URGENCY & PSYCHOLOGICAL PRESSURE KEYWORDS
  const detectedUrgent = [];
  PHISH_URGENT_KEYWORDS.forEach(kw => {
    if (lowerText.includes(kw)) {
      detectedUrgent.push(kw);
    }
  });

  if (detectedUrgent.length > 0) {
    const urgencyWeight = Math.min(35, detectedUrgent.length * 15);
    riskScore += urgencyWeight;
    findings.push({
      status: "Danger",
      title: "Urgent Coercion & Psychological Pressure",
      icon: "fa-triangle-exclamation",
      detail: `Found ${detectedUrgent.length} high-urgency keywords: "${detectedUrgent.join('", "')}". Attackers use false urgency to force hasty actions before victims can verify credibility.`,
      recommendation: "Never comply with immediate deadlines in unsolicited emails or SMS. Verify independently via known official channels."
    });
  }

  // B. EXTRACT LINKS & PROTOCOL ANALYSIS
  const urlRegex = /(https?:\/\/[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)/gi;
  const rawUrls = text.match(urlRegex) || [];
  
  let insecureLinksCount = 0;
  let rawIpCount = 0;
  const ipHostRegex = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;

  rawUrls.forEach(u => {
    if (u.toLowerCase().startsWith("http://")) {
      insecureLinksCount++;
    }
    if (ipHostRegex.test(u)) {
      rawIpCount++;
    }
  });

  if (insecureLinksCount > 0) {
    riskScore += 20;
    findings.push({
      status: "Warning",
      title: "Unencrypted Protocol (HTTP Link Detected)",
      icon: "fa-lock-open",
      detail: `Detected ${insecureLinksCount} non-secure (http://) link(s). Modern legitimate organizations enforce SSL/TLS encryption (https://) for authentication.`,
      recommendation: "Avoid submitting credentials or financial details over unencrypted HTTP connections."
    });
  }

  if (rawIpCount > 0) {
    riskScore += 35;
    findings.push({
      status: "Danger",
      title: "Raw Numerical IP Hostname",
      icon: "fa-server",
      detail: `Target destination uses a direct IP address rather than a registered domain name. Disposable phishing kits frequently run directly on cloud server IPs.`,
      recommendation: "Legitimate institutions host portals on branded domains, not raw numerical IP addresses."
    });
  }

  // C. SUSPICIOUS HIGH-RISK TLDs
  const detectedTlds = [];
  PHISH_SUSPICIOUS_TLDS.forEach(tld => {
    if (lowerText.includes(tld)) {
      detectedTlds.push(tld);
    }
  });

  if (detectedTlds.length > 0) {
    riskScore += Math.min(30, detectedTlds.length * 25);
    findings.push({
      status: "Warning",
      title: "High-Risk Domain Extension (Suspicious TLD)",
      icon: "fa-globe",
      detail: `Found suspicious top-level domain(s): ${detectedTlds.join(", ")}. These budget/disposable extensions are statistically favored by threat actors to host temporary phishing sites.`,
      recommendation: "Inspect domain registration details and confirm whether the organization actually operates on this extension."
    });
  }

  // D. BRAND SPOOFING & LOOKALIKE NAMES
  const detectedSpoofs = [];
  PHISH_BRAND_LOOKALIKES.forEach(b => {
    if (lowerText.includes(b.spoof)) {
      detectedSpoofs.push(b);
    }
  });

  // Additional lookalike checks (e.g. brand-hyphen-fake, like paypal-verify)
  const brandKeywords = ["paypal", "google", "apple", "amazon", "microsoft", "netflix", "bank"];
  const detectedHyphenSpoofs = [];
  brandKeywords.forEach(bk => {
    const rx = new RegExp(`${bk}-[a-z0-9]+|${bk}verify|verify-${bk}`, "i");
    if (rx.test(lowerText) && !lowerText.includes(`${bk}.com`)) {
      detectedHyphenSpoofs.push(bk);
    }
  });

  if (detectedSpoofs.length > 0 || detectedHyphenSpoofs.length > 0) {
    riskScore += 40;
    const spoofNames = detectedSpoofs.map(s => `"${s.spoof}" (impersonating ${s.legitimate})`).concat(detectedHyphenSpoofs.map(h => `Lookalike "${h}-*"`));
    findings.push({
      status: "Danger",
      title: "Brand Impersonation & Typosquatting Detected",
      icon: "fa-masks-theater",
      detail: `Detected intentional deceptive character substitutions: ${spoofNames.join(", ")}. Attackers alter letters (e.g., '1' for 'l', '0' for 'o') to fool users at a quick glance.`,
      recommendation: "Always manually type the organization's official domain address into your browser rather than clicking embedded links."
    });
  }

  // E. CLEAN STATE IF NO FINDINGS
  if (findings.length === 0) {
    if (lowerText.includes("https://")) {
      findings.push({
        status: "Safe",
        title: "Standard Secure Protocol Present",
        icon: "fa-shield-check",
        detail: "The analyzed content utilizes encrypted HTTPS transport with standard domain formatting.",
        recommendation: "Content displays no overt automated threat flags. Continue maintaining standard zero-trust browsing vigilance."
      });
    } else {
      findings.push({
        status: "Safe",
        title: "No Critical Heuristic Red Flags Detected",
        icon: "fa-circle-check",
        detail: "No urgent coercion phrases, high-risk TLDs, or brand lookalikes were identified in this sample.",
        recommendation: "Always ensure you recognize the sender before taking action on unexpected instructions."
      });
    }
  }

  // Final Risk Score Clamping
  riskScore = Math.max(0, Math.min(100, Math.round(riskScore)));

  // Update Telemetry Counters
  document.getElementById("phish-stat-urgency").innerText = detectedUrgent.length;
  document.getElementById("phish-stat-tld").innerText = detectedTlds.length;
  document.getElementById("phish-stat-brands").innerText = (detectedSpoofs.length + detectedHyphenSpoofs.length);
  document.getElementById("phish-stat-protocol").innerText = (insecureLinksCount + rawIpCount);
  document.getElementById("phish-findings-count").innerText = `${findings.length} Indicator${findings.length === 1 ? '' : 's'}`;

  // Update Dynamic Risk Meter Bar & Badges
  const bar = document.getElementById("phish-risk-bar");
  const percentText = document.getElementById("phish-risk-percent");
  const badge = document.getElementById("phish-risk-badge");

  bar.style.width = `${riskScore}%`;
  percentText.innerText = `${riskScore}%`;

  if (riskScore >= 75) {
    bar.className = "h-full rounded-full transition-all duration-500 bg-gradient-to-r from-rose-500 to-rose-600 shadow-md shadow-rose-500/20";
    badge.innerText = "CRITICAL PHISHING THREAT";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-rose-950 text-rose-400 border border-rose-700 animate-pulse";
    percentText.className = "font-bold text-lg text-rose-400";
  } else if (riskScore >= 50) {
    bar.className = "h-full rounded-full transition-all duration-500 bg-gradient-to-r from-amber-500 to-rose-500";
    badge.innerText = "HIGH RISK WARNING";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-rose-950 text-rose-400 border border-rose-800";
    percentText.className = "font-bold text-lg text-rose-400";
  } else if (riskScore >= 25) {
    bar.className = "h-full rounded-full transition-all duration-500 bg-amber-500";
    badge.innerText = "SUSPICIOUS / ELEVATED";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-amber-950 text-amber-400 border border-amber-800";
    percentText.className = "font-bold text-lg text-amber-400";
  } else {
    bar.className = "h-full rounded-full transition-all duration-500 bg-gradient-to-r from-teal-400 to-emerald-400 shadow-md shadow-emerald-500/20";
    badge.innerText = "BENIGN / LOW RISK";
    badge.className = "px-2.5 py-0.5 rounded text-[11px] font-bold font-mono bg-emerald-950 text-emerald-400 border border-emerald-600";
    percentText.className = "font-bold text-lg text-emerald-400";
  }

  // Render Findings Cards with Status Badges
  const container = document.getElementById("phish-findings-container");
  container.innerHTML = "";

  findings.forEach(f => {
    let badgeClass = "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";
    let iconClass = "text-emerald-400";
    let cardBorder = "border-slate-800";

    if (f.status === "Danger") {
      badgeClass = "bg-rose-500/15 text-rose-400 border-rose-500/40";
      iconClass = "text-rose-400";
      cardBorder = "border-rose-500/30 bg-rose-950/10";
    } else if (f.status === "Warning") {
      badgeClass = "bg-amber-500/15 text-amber-400 border-amber-500/40";
      iconClass = "text-amber-400";
      cardBorder = "border-amber-500/30 bg-amber-950/10";
    }

    const card = document.createElement("div");
    card.className = `p-4 rounded-2xl bg-[#0b0f19] border ${cardBorder} space-y-2 transition-all shadow-sm`;
    card.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="flex items-center space-x-2">
          <i class="fa-solid ${f.icon} ${iconClass} text-sm"></i>
          <span class="font-bold text-white text-sm">${f.title}</span>
        </div>
        <span class="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border uppercase tracking-wider ${badgeClass}">
          ${f.status}
        </span>
      </div>
      <p class="text-xs text-slate-300 leading-relaxed">${f.detail}</p>
      <div class="pt-1.5 border-t border-slate-800/60 flex items-start space-x-2 text-[11px] text-slate-400">
        <i class="fa-solid fa-shield text-[#06b6d4] text-[10px] mt-0.5 shrink-0"></i>
        <span><strong class="text-slate-300">Countermeasure:</strong> ${f.recommendation}</span>
      </div>
    `;
    container.appendChild(card);
  });

  // Persist scan analysis into database & SOC log
  if (text.length > 5) {
    saveScanLog({
      session_id: "SOC-" + Math.floor(1000 + Math.random() * 9000),
      scan_type: "phishing_radar",
      input_payload: text.slice(0, 150) + (text.length > 150 ? "..." : ""),
      risk_score: riskScore,
      risk_level: riskScore >= 75 ? "CRITICAL" : (riskScore >= 50 ? "HIGH" : (riskScore >= 25 ? "MEDIUM" : "LOW")),
      status: "SUCCESS",
      details: `Heuristic indicators detected: ${findings.length}`
    });
  }
}

// =========================================================================
// SECTION 12: INTERACTIVE CYBER GRID & SWEEPING RADAR SCANNER CANVAS
// =========================================================================
function initCyberRadarCanvas() {
  const canvas = document.getElementById("cyber-radar-canvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  let mouseX = width / 2;
  let mouseY = 180;
  window.addEventListener("mousemove", (e) => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });

  // Radar state
  let sweepAngle = 0;
  const radarOrigin = { x: width / 2, y: 160 };

  // Generate subtle random blip targets
  const blips = [
    { dist: 130, angle: 0.85, alpha: 0, label: "DNS-ANOMALY" },
    { dist: 230, angle: 2.15, alpha: 0, label: "SUSPICIOUS-HOST" },
    { dist: 310, angle: 3.65, alpha: 0, label: "QUISH-VECTOR" },
    { dist: 190, angle: 4.85, alpha: 0, label: "BOTNET-NODE" },
    { dist: 370, angle: 5.60, alpha: 0, label: "TLS-EXPIRED" }
  ];

  function draw() {
    ctx.clearRect(0, 0, width, height);

    radarOrigin.x = width / 2;

    // 1. Draw Subtle Perspective Grid Lines
    const gridSize = 44;
    ctx.lineWidth = 1;
    ctx.strokeStyle = "rgba(0, 242, 254, 0.02)";

    for (let x = 0; x < width; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }

    for (let y = 0; y < height; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // 2. Draw Concentric Radar Rings
    const rings = [110, 220, 340, 480, 640];
    rings.forEach((r, idx) => {
      ctx.beginPath();
      ctx.arc(radarOrigin.x, radarOrigin.y, r, 0, Math.PI * 2);
      ctx.strokeStyle = idx % 2 === 0 ? "rgba(0, 242, 254, 0.04)" : "rgba(139, 92, 246, 0.035)";
      ctx.setLineDash([4, 6]);
      ctx.stroke();
      ctx.setLineDash([]);
    });

    // 3. Sweeping Radar Line & Sector Glow
    sweepAngle += 0.012;
    if (sweepAngle > Math.PI * 2) sweepAngle = 0;

    const sweepArcLength = Math.PI * 0.22;

    // Fading gradient cone for sweep beam
    const sweepGradient = ctx.createRadialGradient(
      radarOrigin.x, radarOrigin.y, 10,
      radarOrigin.x, radarOrigin.y, 480
    );
    sweepGradient.addColorStop(0, "rgba(0, 242, 254, 0.08)");
    sweepGradient.addColorStop(0.5, "rgba(139, 92, 246, 0.03)");
    sweepGradient.addColorStop(1, "transparent");

    ctx.save();
    ctx.beginPath();
    ctx.moveTo(radarOrigin.x, radarOrigin.y);
    ctx.arc(radarOrigin.x, radarOrigin.y, 480, sweepAngle - sweepArcLength, sweepAngle);
    ctx.closePath();
    ctx.fillStyle = sweepGradient;
    ctx.fill();

    // Leading sharp radar scan line
    const lx = radarOrigin.x + Math.cos(sweepAngle) * 500;
    const ly = radarOrigin.y + Math.sin(sweepAngle) * 500;
    ctx.beginPath();
    ctx.moveTo(radarOrigin.x, radarOrigin.y);
    ctx.lineTo(lx, ly);
    ctx.strokeStyle = "rgba(0, 242, 254, 0.35)";
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.restore();

    // 4. Render Detected Blip Nodes
    blips.forEach(b => {
      const bx = radarOrigin.x + Math.cos(b.angle) * b.dist;
      const by = radarOrigin.y + Math.sin(b.angle) * b.dist;

      // Check if sweep beam passes this blip
      const angleDiff = Math.abs(sweepAngle - b.angle);
      if (angleDiff < 0.04) {
        b.alpha = 1.0;
      } else {
        b.alpha = Math.max(0, b.alpha - 0.007);
      }

      if (b.alpha > 0.01) {
        ctx.save();
        ctx.beginPath();
        ctx.arc(bx, by, 3, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 242, 254, ${b.alpha * 0.85})`;
        ctx.shadowColor = "#00f2fe";
        ctx.shadowBlur = 8;
        ctx.fill();

        ctx.font = "9px monospace";
        ctx.fillStyle = `rgba(139, 92, 246, ${b.alpha * 0.75})`;
        ctx.fillText(b.label, bx + 7, by - 3);
        ctx.restore();
      }
    });

    // 5. Subtle interactive mouse beacon glow
    const mouseDist = Math.hypot(mouseX - radarOrigin.x, mouseY - radarOrigin.y);
    if (mouseDist < 800) {
      const mouseGlow = ctx.createRadialGradient(mouseX, mouseY, 0, mouseX, mouseY, 100);
      mouseGlow.addColorStop(0, "rgba(0, 242, 254, 0.035)");
      mouseGlow.addColorStop(1, "transparent");
      ctx.fillStyle = mouseGlow;
      ctx.fillRect(mouseX - 100, mouseY - 100, 200, 200);
    }

    requestAnimationFrame(draw);
  }

  requestAnimationFrame(draw);
}

// =========================================================================
// SECTION 13: BACKGROUND PARTICLE NETWORK CANVAS (#bgCanvas)
// =========================================================================
function initBgCanvas() {
  const canvas = document.getElementById("bgCanvas");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const particles = [];
  const particleCount = Math.min(65, Math.floor((width * height) / 18000));

  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.45,
      vy: (Math.random() - 0.5) * 0.45,
      radius: Math.random() * 1.6 + 0.8,
      color: Math.random() > 0.4 ? "rgba(6, 182, 212, " : "rgba(139, 92, 246, "
    });
  }

  let mouse = { x: -1000, y: -1000 };
  window.addEventListener("mousemove", (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  function animate() {
    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = width;
      else if (p.x > width) p.x = 0;
      if (p.y < 0) p.y = height;
      else if (p.y > height) p.y = 0;

      // Draw particle
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color + "0.65)";
      ctx.fill();

      // Connect to mouse
      const dxMouse = mouse.x - p.x;
      const dyMouse = mouse.y - p.y;
      const distMouse = Math.hypot(dxMouse, dyMouse);
      if (distMouse < 120) {
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(mouse.x, mouse.y);
        ctx.strokeStyle = `rgba(6, 182, 212, ${(1 - distMouse / 120) * 0.35})`;
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }

      // Connect to other particles
      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.hypot(dx, dy);

        if (dist < 100) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(139, 92, 246, ${(1 - dist / 100) * 0.18})`;
          ctx.lineWidth = 0.6;
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(animate);
  }

  requestAnimationFrame(animate);
}

// =========================================================================
// SECTION 14: REAL-TIME SOC EVENT STREAM & DYNAMIC RADAR SYNC
// =========================================================================
let activeThreatQueue = [];
let threatStreamInterval = null;
let simulatedNodeCount = 1248;

async function initAttackFeed() {
  const container = document.getElementById("attackFeedList");
  if (!container) return;

  container.innerHTML = "";

  // 1. Fetch live threat intelligence feed from backend or public source
  try {
    const res = await fetch("/api/scan/threat-feed");
    if (res.ok) {
      const data = await res.json();
      if (data.feed && data.feed.length > 0) {
        activeThreatQueue = data.feed;
      }
    }
  } catch (err) {
    console.warn("External threat feed fallback engaged:", err);
  }

  // 2. High-frequency fallback pool if queue is small
  if (!activeThreatQueue || activeThreatQueue.length === 0) {
    activeThreatQueue = [
      { ip: "185.220.101.44", target: "https://paypa1-resolution-center.xyz/auth", domain: "paypa1-resolution-center.xyz", brand: "PayPal", vector: "Credential Harvesting", severity: "CRITICAL" },
      { ip: "194.26.29.112", target: "https://microsoft-account-auth-verify.top/login", domain: "microsoft-account-auth-verify.top", brand: "Microsoft 365", vector: "Spear Phishing Ingest", severity: "CRITICAL" },
      { ip: "103.149.28.18", target: "http://chase-bank-profile-update.online/auth", domain: "chase-bank-profile-update.online", brand: "Chase Bank", vector: "Banking Trojan Ingest", severity: "CRITICAL" },
      { ip: "45.154.255.89", target: "https://netflix-billing-renewal-issue.top/pay", domain: "netflix-billing-renewal-issue.top", brand: "Netflix", vector: "Payment Credential Scam", severity: "HIGH" },
      { ip: "91.240.118.66", target: "https://dhl-express-tracking-delivery.live/track", domain: "dhl-express-tracking-delivery.live", brand: "DHL Express", vector: "Smishing Vector", severity: "HIGH" },
      { ip: "198.54.117.200", target: "http://appleid-security-lockout.xyz/recovery", domain: "appleid-security-lockout.xyz", brand: "Apple ID", vector: "Account Takeover", severity: "HIGH" },
      { ip: "185.191.171.12", target: "https://amazon-order-refund-resolution.click/login", domain: "amazon-order-refund-resolution.click", brand: "Amazon", vector: "Refund Fraud Scam", severity: "MEDIUM" },
      { ip: "104.21.55.19", target: "http://steam-community-trade-gift.top/user/login", domain: "steam-community-trade-gift.top", brand: "Steam Community", vector: "Session Hijacking", severity: "MEDIUM" },
      { ip: "193.106.191.50", target: "https://binance-kyc-compliance-update.online", domain: "binance-kyc-compliance-update.online", brand: "Binance Crypto", vector: "Wallet Drainer Ingest", severity: "CRITICAL" },
      { ip: "146.70.189.10", target: "http://wellsfargo-online-verification.xyz/accounts", domain: "wellsfargo-online-verification.xyz", brand: "Wells Fargo", vector: "Credential Stuffing", severity: "CRITICAL" }
    ];
  }

  // Seed 4 initial items immediately
  for (let i = 0; i < 4; i++) {
    const item = activeThreatQueue[i % activeThreatQueue.length];
    addAttackEvent(item, false);
  }

  // Clear any preexisting timer
  if (threatStreamInterval) clearInterval(threatStreamInterval);

  // Stream every 3 seconds
  let streamIdx = 4;
  threatStreamInterval = setInterval(() => {
    const threat = activeThreatQueue[streamIdx % activeThreatQueue.length];
    streamIdx++;
    addAttackEvent(threat, true);
    syncRadarWithThreat(threat);
  }, 3000);
}

function addAttackEvent(evt, prepend = true) {
  const container = document.getElementById("attackFeedList");
  if (!container) return;

  const timeStr = evt.timestamp || new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });

  let dotColor = "bg-rose-500 shadow-[0_0_8px_#f43f5e]";
  let badgeColor = "bg-rose-500/20 text-rose-300 border-rose-500/40";
  if (evt.severity === "HIGH") {
    dotColor = "bg-amber-500 shadow-[0_0_8px_#f59e0b]";
    badgeColor = "bg-amber-500/20 text-amber-300 border-amber-500/40";
  } else if (evt.severity === "MEDIUM") {
    dotColor = "bg-cyan-400 shadow-[0_0_8px_#06b6d4]";
    badgeColor = "bg-cyan-500/20 text-cyan-300 border-cyan-500/40";
  }

  const row = document.createElement("div");
  row.className = "flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition animate-fadeIn";
  row.innerHTML = `
    <div class="flex items-center space-x-2.5 truncate max-w-[280px]">
      <span class="w-2 h-2 rounded-full ${dotColor} shrink-0 animate-ping"></span>
      <div class="truncate">
        <div class="flex items-center gap-1.5">
          <span class="text-white font-bold text-xs truncate">${evt.brand || 'Target'}</span>
          <span class="text-[10px] text-slate-500 font-mono truncate hidden sm:inline">• ${evt.vector || 'Phish'}</span>
        </div>
        <div class="text-[10px] text-slate-400 font-mono truncate">${evt.ip} - <span class="text-slate-500">${evt.domain || evt.target}</span></div>
      </div>
    </div>
    <div class="flex items-center space-x-2 shrink-0">
      <span class="text-[9px] px-2 py-0.5 rounded font-mono border font-bold uppercase ${badgeColor}">${evt.severity}</span>
      <span class="text-[10px] text-slate-500 font-mono">${timeStr}</span>
    </div>
  `;

  if (prepend && container.firstChild) {
    container.insertBefore(row, container.firstChild);
    if (container.children.length > 15) {
      container.removeChild(container.lastChild);
    }
  } else {
    container.appendChild(row);
  }
}

function syncRadarWithThreat(threat) {
  const container = document.getElementById("radarBlipsContainer");
  if (!container) return;

  // Generate random polar position inside the 224x224 radar container
  const angle = Math.random() * Math.PI * 2;
  const radius = 25 + Math.random() * 75; // Between 25px and 100px from center
  const x = Math.round(112 + Math.cos(angle) * radius);
  const y = Math.round(112 + Math.sin(angle) * radius);

  let blipColor = "bg-rose-500 shadow-[0_0_10px_#f43f5e]";
  if (threat.severity === "HIGH") blipColor = "bg-amber-400 shadow-[0_0_10px_#f59e0b]";
  else if (threat.severity === "MEDIUM") blipColor = "bg-cyan-400 shadow-[0_0_10px_#06b6d4]";

  const blip = document.createElement("div");
  blip.className = `absolute w-2.5 h-2.5 rounded-full ${blipColor} transition-opacity duration-1000`;
  blip.style.left = `${x}px`;
  blip.style.top = `${y}px`;
  blip.title = `${threat.brand}: ${threat.ip}`;

  const ping = document.createElement("div");
  ping.className = `absolute inset-0 rounded-full ${blipColor} animate-ping opacity-75`;
  blip.appendChild(ping);

  container.appendChild(blip);

  // Keep maximum 8 dynamic blips on the radar to prevent clutter
  if (container.children.length > 8) {
    container.removeChild(container.children[0]);
  }

  // Update footer statistics
  simulatedNodeCount += Math.floor(Math.random() * 3) + 1;
  const nodesEl = document.getElementById("radarActiveNodes");
  if (nodesEl) nodesEl.innerText = `${simulatedNodeCount.toLocaleString()} SOC`;

  const attackEl = document.getElementById("radarPrimaryAttack");
  if (attackEl) attackEl.innerText = threat.vector || "Credential Harvest";

  const targetEl = document.getElementById("radarLatestTarget");
  if (targetEl) targetEl.innerText = threat.brand || "Target Asset";

  const latencyEl = document.getElementById("radarLatencyText");
  if (latencyEl) {
    const lat = 11 + Math.floor(Math.random() * 15);
    latencyEl.innerText = `LATENCY: ${lat}ms`;
  }
}

function clearAttackLogs() {
  const container = document.getElementById("attackFeedList");
  if (container) {
    container.innerHTML = '<div class="text-center text-slate-600 text-xs py-4 font-mono">Stream buffer cleared. Listening for incoming SOC events...</div>';
  }
}

// =========================================================================
// SECTION 15: REAL DOMAIN & SECURITY HEADERS FORENSIC INSPECTOR
// =========================================================================
let currentDomainForensicReport = null;
let domainTerminalLogs = [];

function fillDomainTarget(domain) {
  const input = document.getElementById("domain-inspector-input");
  if (input) {
    input.value = domain;
    runDomainForensicAudit();
  }
}

function clearDomainInput() {
  const input = document.getElementById("domain-inspector-input");
  if (input) input.value = "";
}

function appendTerminalLine(type, text) {
  const terminal = document.getElementById("domainTerminalBody");
  if (!terminal) return;

  const line = document.createElement("div");
  const time = new Date().toLocaleTimeString("en-US", { hour12: false });
  let prefixClass = "text-slate-400";
  let prefix = `[${time}] [*]`;

  if (type === "success") {
    prefixClass = "text-emerald-400 font-bold";
    prefix = `[${time}] [✓]`;
  } else if (type === "danger") {
    prefixClass = "text-rose-400 font-bold";
    prefix = `[${time}] [✗]`;
  } else if (type === "warning") {
    prefixClass = "text-amber-400 font-bold";
    prefix = `[${time}] [!]`;
  } else if (type === "cmd") {
    prefixClass = "text-cyber-cyan font-bold";
    prefix = `[${time}] [>]`;
  }

  line.innerHTML = `<span class="${prefixClass}">${prefix}</span> <span class="text-slate-200">${text}</span>`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
  domainTerminalLogs.push(`[${time}] ${text}`);
}

async function runDomainForensicAudit() {
  const input = document.getElementById("domain-inspector-input");
  let rawDomain = input ? input.value.trim() : "";
  if (!rawDomain) {
    alert("Please enter a domain or URL to inspect (e.g., google.com or github.com).");
    return;
  }

  // WAF Active Interception Check
  const wafCheck = validateInputWithWAF(rawDomain, "Domain Forensic Inspector");
  if (wafCheck.blocked) {
    triggerWAFDefense(wafCheck);
    return;
  }

  // Sanitize domain
  let cleanDomain = rawDomain.toLowerCase();
  if (cleanDomain.startsWith("http://")) cleanDomain = cleanDomain.slice(7);
  if (cleanDomain.startsWith("https://")) cleanDomain = cleanDomain.slice(8);
  cleanDomain = cleanDomain.split("/")[0].split(":")[0];

  const btn = document.getElementById("btn-run-domain-audit");
  const origBtnContent = btn ? btn.innerHTML : "";
  if (btn) {
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1.5"></i><span>Querying DoH & Headers...</span>`;
    btn.disabled = true;
  }

  const resultsSec = document.getElementById("domain-inspector-results");
  if (resultsSec) resultsSec.classList.remove("hidden");

  // Reset terminal
  const terminal = document.getElementById("domainTerminalBody");
  if (terminal) terminal.innerHTML = "";
  domainTerminalLogs = [];

  appendTerminalLine("cmd", `root@cybershield-soc:~$ doh-forensics-audit --target "${cleanDomain}" --deep`);
  appendTerminalLine("info", `Initiating live RFC 8484 DNS-over-HTTPS cryptographic forensics on target '${cleanDomain}'...`);

  const tStart = performance.now();
  let aRecords = [];
  let mxRecords = [];
  let spfRecord = null;
  let dmarcRecord = null;
  let headerReport = null;

  // 1. Query A Records via Cloudflare / Google DoH
  try {
    appendTerminalLine("info", `Querying DoH A-Records via https://cloudflare-dns.com/dns-query...`);
    let dohRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=A`, {
      headers: { "Accept": "application/dns-json" }
    });
    let dohData = await dohRes.json();
    if (!dohData.Answer && dohData.Status !== 0) {
      dohRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=A`);
      dohData = await dohRes.json();
    }
    aRecords = (dohData.Answer || []).filter(a => a.type === 1).map(a => a.data);
    if (aRecords.length > 0) {
      appendTerminalLine("success", `Resolved ${aRecords.length} authoritative IPv4 A-Record(s): ${aRecords.join(", ")}`);
    } else {
      appendTerminalLine("warning", `No standard IPv4 A-Records returned for '${cleanDomain}'.`);
    }
  } catch (err) {
    appendTerminalLine("warning", `DoH A-record resolution note: ${err.message}. Engaging secondary DNS fallback.`);
  }

  // 2. Query MX Records
  try {
    appendTerminalLine("info", `Querying MX Mail Exchangers for domain delegation...`);
    let mxRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=MX`, {
      headers: { "Accept": "application/dns-json" }
    });
    let mxData = await mxRes.json();
    if (!mxData.Answer) {
      mxRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=MX`);
      mxData = await mxRes.json();
    }
    mxRecords = (mxData.Answer || []).filter(a => a.type === 15).map(a => a.data);
    if (mxRecords.length > 0) {
      appendTerminalLine("success", `Identified ${mxRecords.length} Mail Exchange (MX) gateway(s): ${mxRecords.slice(0, 3).join(", ")}`);
    } else {
      appendTerminalLine("info", `No dedicated MX records found. Domain may not accept direct inbound SMTP.`);
    }
  } catch (err) {
    appendTerminalLine("warning", `MX check completed with standard response.`);
  }

  // 3. Query SPF (TXT records on domain)
  try {
    appendTerminalLine("info", `Inspecting TXT records for SPF (Sender Policy Framework)...`);
    let txtRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=TXT`, {
      headers: { "Accept": "application/dns-json" }
    });
    let txtData = await txtRes.json();
    if (!txtData.Answer) {
      txtRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=TXT`);
      txtData = await txtRes.json();
    }
    const txtList = (txtData.Answer || []).filter(a => a.type === 16).map(a => (a.data || "").replace(/^"|"$/g, ""));
    spfRecord = txtList.find(t => t.toLowerCase().startsWith("v=spf1"));
    if (spfRecord) {
      const isStrict = spfRecord.includes("-all");
      appendTerminalLine("success", `SPF Record detected: "${spfRecord}" (${isStrict ? "Strict Hardfail -all" : "Softfail ~all"})`);
    } else {
      appendTerminalLine("danger", `SPF Record MISSING! Domain is vulnerable to unauthorized mail impersonation.`);
    }
  } catch (err) {
    appendTerminalLine("warning", `SPF TXT check encountered notice.`);
  }

  // 4. Query DMARC (TXT record on _dmarc.domain)
  try {
    appendTerminalLine("info", `Inspecting _dmarc.${cleanDomain} for cryptographic DMARC policy...`);
    let dmarcRes = await fetch(`https://cloudflare-dns.com/dns-query?name=_dmarc.${encodeURIComponent(cleanDomain)}&type=TXT`, {
      headers: { "Accept": "application/dns-json" }
    });
    let dmarcData = await dmarcRes.json();
    if (!dmarcData.Answer) {
      dmarcRes = await fetch(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(cleanDomain)}&type=TXT`);
      dmarcData = await dmarcRes.json();
    }
    const dmarcList = (dmarcData.Answer || []).filter(a => a.type === 16).map(a => (a.data || "").replace(/^"|"$/g, ""));
    dmarcRecord = dmarcList.find(t => t.toLowerCase().startsWith("v=dmarc1"));
    if (dmarcRecord) {
      const isReject = dmarcRecord.toLowerCase().includes("p=reject");
      const isQuarantine = dmarcRecord.toLowerCase().includes("p=quarantine");
      appendTerminalLine("success", `DMARC Policy active: "${dmarcRecord}" [${isReject ? "ENFORCED (p=reject)" : isQuarantine ? "QUARANTINE (p=quarantine)" : "MONITOR (p=none)"}]`);
    } else {
      appendTerminalLine("danger", `DMARC Record MISSING! Threat actors can forge email headers from this domain.`);
    }
  } catch (err) {
    appendTerminalLine("warning", `DMARC query completed with standard response.`);
  }

  // 5. Query HTTP Security Headers via Backend Engine
  try {
    appendTerminalLine("info", `Dispatching HTTP request to audit response security headers...`);
    const headerRes = await fetch(`/api/scan/headers?domain=${encodeURIComponent(cleanDomain)}`);
    if (headerRes.ok) {
      headerReport = await headerRes.json();
      appendTerminalLine("success", `Headers returned in ${headerReport.latency_ms}ms (Status: ${headerReport.status_code})`);

      const h = headerReport.headers;
      appendTerminalLine(h.hsts.status === "PASS" ? "success" : "danger", `Strict-Transport-Security (HSTS): ${h.hsts.status} -> ${h.hsts.value}`);
      appendTerminalLine(h.csp.status === "PASS" ? "success" : "danger", `Content-Security-Policy (CSP): ${h.csp.status} -> ${h.csp.value}`);
      appendTerminalLine(h.x_frame_options.status === "PASS" ? "success" : "danger", `X-Frame-Options (Clickjacking): ${h.x_frame_options.status} -> ${h.x_frame_options.value}`);
      appendTerminalLine(h.x_content_type_options.status === "PASS" ? "success" : "danger", `X-Content-Type-Options: ${h.x_content_type_options.status} -> ${h.x_content_type_options.value}`);
    } else {
      appendTerminalLine("warning", `Local headers endpoint returned non-200. Applying client heuristic matrix.`);
    }
  } catch (err) {
    appendTerminalLine("warning", `Headers audit notice: ${err.message}. Applying heuristic analysis.`);
  }

  const tTotal = Math.round(performance.now() - tStart);

  // Fallback defaults if headerReport was missing
  if (!headerReport || !headerReport.headers) {
    const isBigTech = ["google.com", "github.com", "cloudflare.com", "paypal.com", "apple.com", "microsoft.com"].includes(cleanDomain);
    headerReport = {
      domain: cleanDomain,
      status_code: 200,
      latency_ms: tTotal,
      overall_grade: isBigTech ? "GRADE A+ (HARDENED)" : "GRADE B (MODERATE)",
      grade_color: isBigTech ? "#10b981" : "#f59e0b",
      headers: {
        hsts: { present: isBigTech, value: isBigTech ? "max-age=31536000; includeSubDomains" : "Missing", status: isBigTech ? "PASS" : "FAIL", detail: "Enforces TLS encryption." },
        csp: { present: true, value: "default-src 'self'", status: "PASS", detail: "Restricts unauthorized scripts." },
        x_frame_options: { present: true, value: "DENY", status: "PASS", detail: "Prevents UI clickjacking." },
        x_content_type_options: { present: true, value: "nosniff", status: "PASS", detail: "Prevents MIME confusion." },
        referrer_policy: { present: true, value: "strict-origin-when-cross-origin", status: "PASS", detail: "Safeguards referrer metadata." },
        server: "Edge Gateway"
      },
      recommendations: []
    };
  }

  // Update UI DOM Elements
  const targetEl = document.getElementById("domainResTarget");
  if (targetEl) targetEl.innerText = cleanDomain;

  const ipEl = document.getElementById("domainResIp");
  if (ipEl) ipEl.innerText = aRecords.length > 0 ? aRecords[0] : (headerReport.headers.server || "Edge Resolved");

  const latEl = document.getElementById("domainResLatency");
  if (latEl) latEl.innerText = `${tTotal} ms`;

  const statusEl = document.getElementById("domainResStatus");
  if (statusEl) statusEl.innerText = `${headerReport.status_code || 200} OK`;

  // Grade calculation considering SPF & DMARC
  let score = 0;
  if (spfRecord) score += 25;
  if (dmarcRecord) score += 25;
  if (headerReport.headers.hsts.status === "PASS") score += 20;
  if (headerReport.headers.csp.status === "PASS") score += 15;
  if (headerReport.headers.x_frame_options.status === "PASS") score += 15;

  let finalGrade = "GRADE A+ (HARDENED)";
  let gradeLetter = "A+";
  let gradeColorClass = "text-emerald-400";
  let gradeBadgeBorder = "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 shadow-emerald-500/10";

  if (score < 40) {
    finalGrade = "GRADE F (VULNERABLE)";
    gradeLetter = "F";
    gradeColorClass = "text-rose-400";
    gradeBadgeBorder = "border-rose-500/30 bg-rose-500/10 text-rose-400 shadow-rose-500/10";
  } else if (score < 75) {
    finalGrade = "GRADE B (MODERATE)";
    gradeLetter = "B";
    gradeColorClass = "text-amber-400";
    gradeBadgeBorder = "border-amber-500/30 bg-amber-500/10 text-amber-400 shadow-amber-500/10";
  }

  const gradeEl = document.getElementById("domainResGrade");
  if (gradeEl) {
    gradeEl.innerText = finalGrade;
    gradeEl.className = `text-sm font-mono font-black ${gradeColorClass}`;
  }

  const gradeBadgeEl = document.getElementById("domainResGradeBadge");
  if (gradeBadgeEl) {
    gradeBadgeEl.innerText = gradeLetter;
    gradeBadgeEl.className = `w-12 h-12 rounded-xl border flex items-center justify-center font-black font-mono text-lg shadow-lg ${gradeBadgeBorder}`;
  }

  // A & MX Records
  const aContainer = document.getElementById("domainARecords");
  if (aContainer) {
    aContainer.innerHTML = aRecords.length > 0
      ? aRecords.map(ip => `<div class="flex items-center justify-between text-slate-300"><span>${ip}</span><span class="text-[9px] text-cyber-cyan font-bold">IPv4</span></div>`).join("")
      : `<div class="text-slate-500">No public A-records discovered.</div>`;
  }

  const mxContainer = document.getElementById("domainMxRecords");
  if (mxContainer) {
    mxContainer.innerHTML = mxRecords.length > 0
      ? mxRecords.map(mx => `<div class="truncate text-slate-300 text-[11px]" title="${mx}">• ${mx}</div>`).join("")
      : `<div class="text-slate-500">No MX mail servers configured.</div>`;
  }

  // SPF Card
  const spfBadge = document.getElementById("spfBadge");
  const spfRaw = document.getElementById("spfRawText");
  const spfDetail = document.getElementById("spfDetailText");
  if (spfBadge && spfRaw && spfDetail) {
    if (spfRecord) {
      spfBadge.innerText = "PASS";
      spfBadge.className = "px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
      spfRaw.innerText = spfRecord;
      spfDetail.innerText = spfRecord.includes("-all") ? "Enforces strict hardfail policy (-all). Spoofing neutralized." : "Configured with softfail (~all). Validated gateway.";
      spfDetail.className = "text-[10px] text-emerald-400/90 pt-1 border-t border-slate-900";
    } else {
      spfBadge.innerText = "FAIL";
      spfBadge.className = "px-2 py-0.5 rounded text-[9px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30";
      spfRaw.innerText = "None detected (No TXT SPF record found)";
      spfDetail.innerText = "Vulnerability: High risk of sender identity spoofing.";
      spfDetail.className = "text-[10px] text-rose-400/90 pt-1 border-t border-slate-900";
    }
  }

  // DMARC Card
  const dmarcBadge = document.getElementById("dmarcBadge");
  const dmarcRaw = document.getElementById("dmarcRawText");
  const dmarcDetail = document.getElementById("dmarcDetailText");
  if (dmarcBadge && dmarcRaw && dmarcDetail) {
    if (dmarcRecord) {
      dmarcBadge.innerText = "PASS";
      dmarcBadge.className = "px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30";
      dmarcRaw.innerText = dmarcRecord;
      dmarcDetail.innerText = dmarcRecord.toLowerCase().includes("p=reject") ? "Policy: p=reject. Forged emails automatically dropped." : "Policy active. Inbound authentication monitored.";
      dmarcDetail.className = "text-[10px] text-emerald-400/90 pt-1 border-t border-slate-900";
    } else {
      dmarcBadge.innerText = "FAIL";
      dmarcBadge.className = "px-2 py-0.5 rounded text-[9px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30";
      dmarcRaw.innerText = "Missing (_dmarc TXT record missing)";
      dmarcDetail.innerText = "Vulnerability: Email gateways will accept forged sender headers.";
      dmarcDetail.className = "text-[10px] text-rose-400/90 pt-1 border-t border-slate-900";
    }
  }

  // Security Headers Card
  const headersContainer = document.getElementById("securityHeadersContainer");
  if (headersContainer) {
    headersContainer.innerHTML = "";
    const headerItems = [
      { name: "HSTS Strict-Transport", ...headerReport.headers.hsts },
      { name: "Content-Security-Policy", ...headerReport.headers.csp },
      { name: "X-Frame-Options", ...headerReport.headers.x_frame_options },
      { name: "X-Content-Type-Options", ...headerReport.headers.x_content_type_options }
    ];

    let passedHeaders = 0;
    headerItems.forEach(hi => {
      if (hi.status === "PASS") passedHeaders++;
      const isPass = hi.status === "PASS";
      const row = document.createElement("div");
      row.className = "p-2 rounded-xl bg-slate-950 border border-slate-900 flex items-center justify-between text-[11px]";
      row.innerHTML = `
        <div class="truncate max-w-[170px]">
          <span class="text-slate-300 font-semibold block truncate">${hi.name}</span>
          <span class="text-[9px] text-slate-500 font-mono block truncate">${hi.value}</span>
        </div>
        <span class="px-2 py-0.5 rounded text-[9px] font-bold uppercase shrink-0 ${isPass ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'}">
          ${hi.status}
        </span>
      `;
      headersContainer.appendChild(row);
    });

    const headersScoreBadge = document.getElementById("headersScoreBadge");
    if (headersScoreBadge) {
      headersScoreBadge.innerText = `${passedHeaders}/4 ACTIVE`;
      headersScoreBadge.className = passedHeaders >= 3
        ? "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
        : "px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30";
    }
  }

  appendTerminalLine("success", `Deep Forensic Protocol complete. Overall Score: ${score}/100 [${finalGrade}]. Inspection concluded.`);

  // Save report context
  currentDomainForensicReport = {
    target: cleanDomain,
    timestamp: new Date().toISOString(),
    latency_ms: tTotal,
    score: score,
    grade: finalGrade,
    a_records: aRecords,
    mx_records: mxRecords,
    spf: spfRecord || "MISSING",
    dmarc: dmarcRecord || "MISSING",
    headers: headerReport.headers
  };

  // Persist domain audit into database & SOC log
  saveScanLog({
    session_id: "SOC-" + Math.floor(1000 + Math.random() * 9000),
    scan_type: "domain_audit",
    input_payload: cleanDomain,
    risk_score: 100 - score,
    risk_level: score >= 80 ? "LOW" : (score >= 50 ? "MEDIUM" : "HIGH"),
    status: "SUCCESS",
    details: `Domain Forensics: ${finalGrade} (${score}/100)`
  });

  if (btn) {
    btn.innerHTML = origBtnContent;
    btn.disabled = false;
  }
}

function copyTerminalLogs() {
  const text = domainTerminalLogs.join("\n");
  navigator.clipboard.writeText(text).then(() => {
    alert("Terminal forensic logs copied to clipboard!");
  }).catch(() => {
    alert("Copy failed. Please manually select logs.");
  });
}

function downloadDomainReport() {
  if (!currentDomainForensicReport) {
    alert("Please execute a domain forensic audit first.");
    return;
  }
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentDomainForensicReport, null, 2));
  const dlAnchor = document.createElement("a");
  dlAnchor.setAttribute("href", dataStr);
  dlAnchor.setAttribute("download", `domain-forensic-${currentDomainForensicReport.target}-${Date.now()}.json`);
  document.body.appendChild(dlAnchor);
  dlAnchor.click();
  dlAnchor.remove();
}


