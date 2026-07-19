/* ══════════════════════════════════════════
   SENTRIX Pro Edition — app.js  v7.0
   Bug Bounty Edition — Stealth + Real Findings
   ══════════════════════════════════════════ */

let currentFindings = [];
let scanTarget      = '';
let aiReportText    = '';
let isScanning      = false;
let activeMode      = 'active';
const BACKEND       = 'http://localhost:5000';

// Auth state
let authConfig = { login_url: '', username: '', password: '', auth_token: '' };
let bountyMode = false;

// ─────────────────────────────────────────
// STARTUP
// ─────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  const modal = document.getElementById('apiModal');
  if (modal) modal.classList.add('hidden');
  const alive = await checkBackend();
  const el = document.getElementById('apiKeyStatus');
  if (alive) { el.textContent = '✓ AI READY'; el.style.color = 'var(--low)'; }
  else        { el.textContent = '⚠ BACKEND OFFLINE'; el.style.color = 'var(--crit)'; }
  setModeButton('active');
});

// ─────────────────────────────────────────
// MODE BUTTONS
// ─────────────────────────────────────────
function toggleOpt(btn) {
  setModeButton(btn.id.replace('opt-', ''));
}

function setModeButton(mode) {
  activeMode = mode;
  ['passive','active','deep'].forEach(m => {
    const btn = document.getElementById('opt-' + m);
    if (btn) btn.classList.toggle('active', m === mode);
  });
  const labels = {
    passive: '30 pages — Headers, Secrets, CORS only',
    active:  '100 pages — Full scan (SQLi, XSS, LFI, IDOR, Write IDOR, Mass Assignment...)',
    deep:    '500 pages — Maximum depth, all modules, all payloads'
  };
  const hint = document.getElementById('modeHint');
  if (hint) hint.textContent = labels[mode] || '';
}

// ─────────────────────────────────────────
// TERMINAL LOG
// ─────────────────────────────────────────
function log(msg, type) {
  type = type || 'info';
  const terminal = document.getElementById('terminal');
  const time = new Date().toTimeString().slice(0,8);
  const line = document.createElement('div');
  line.className = 'log-line';
  line.innerHTML = `<span class="log-time">[${time}]</span><span class="log-msg ${type}">${escHtml(msg)}</span>`;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}

function setProgress(pct, label) {
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('progressPct').textContent = Math.round(pct) + '%';
  if (label) document.getElementById('progressLabel').textContent = label;
}

function stepActive(id) { const el = document.getElementById('step-'+id); if(el) el.className = 'step-chip active'; }
function stepDone(id)   { const el = document.getElementById('step-'+id); if(el) el.className = 'step-chip done'; }

function setStatus(state) {
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  dot.className = 'status-dot' + (state==='scanning' ? ' scanning' : state==='error' ? ' error' : '');
  txt.textContent = state.toUpperCase();
}

// ─────────────────────────────────────────
// AUTH PANEL
// ─────────────────────────────────────────
function toggleAuthPanel() {
  const panel = document.getElementById('authPanel');
  const btn   = document.getElementById('authToggleBtn');
  if (!panel) return;
  const open = panel.classList.toggle('visible');
  if (btn) btn.textContent = open ? '▲ HIDE AUTH' : '▼ SET AUTH (OPTIONAL)';
}

function clearAuth() {
  ['loginUrl','authUser','authPass','authToken'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  authConfig = { login_url: '', username: '', password: '', auth_token: '' };
  log('Auth cleared.', 'info');
}

// ─────────────────────────────────────────
// RESET UI
// ─────────────────────────────────────────
function resetUI() {
  currentFindings = []; aiReportText = '';
  document.getElementById('scanBtn').textContent = '■ STOP';
  document.getElementById('scanBtn').classList.add('scanning');
  document.getElementById('progressPanel').classList.add('visible');
  document.getElementById('statsRow').classList.add('hidden');
  document.getElementById('findingsList').innerHTML = '';
  document.getElementById('findingsCount').textContent = 'Scanning...';
  document.getElementById('aiContent').innerHTML = '<span class="muted-text">Waiting for scan results...</span>';
  document.getElementById('generateReportBtn').disabled = true;
  document.getElementById('exportBtn').classList.add('hidden');
  document.getElementById('scorePanel').classList.add('hidden');
  document.getElementById('attackPathPanel').classList.add('hidden');
  document.getElementById('terminal').innerHTML = '';
  document.getElementById('aiThinking').classList.add('hidden');

  const allSteps = ['recon','headers','secrets','sqli','xss','lfi','redirect',
                    'ssrf','idor','write-idor','mass-assign','auth','ssl','ai'];
  allSteps.forEach(s => {
    const el = document.getElementById('step-'+s);
    if (el) el.className = 'step-chip';
  });

  window._wafWarned = false;
  window._wafBannerShown = false;
  window._authLogged = false;

  const authBadge = document.getElementById('authBadge');
  if (authBadge) {
    const hasAuth = authConfig.login_url || authConfig.auth_token;
    authBadge.style.display = hasAuth ? 'inline-flex' : 'none';
    if (hasAuth) authBadge.textContent = '🔐 ' + (authConfig.auth_token ? 'TOKEN' : authConfig.username);
  }

  setProgress(0, 'INITIALIZING...');
  setStatus('scanning');
}

// ─────────────────────────────────────────
// BACKEND CHECK
// ─────────────────────────────────────────
async function checkBackend() {
  try { const r = await fetch(BACKEND+'/ping'); const d = await r.json(); return d.status==='ok'; }
  catch(e) { return false; }
}

// ─────────────────────────────────────────
// MAIN SCAN
// ─────────────────────────────────────────
async function startScan() {
  if (isScanning) { stopScan(); return; }
  const rawUrl = document.getElementById('targetUrl').value.trim();
  if (!rawUrl) { document.getElementById('targetUrl').focus(); return; }
  scanTarget = rawUrl.startsWith('http') ? rawUrl : 'http://'+rawUrl;

  const backendUp = await checkBackend();
  if (!backendUp) {
    alert('Backend not running!\n\nOpen terminal and run:\n\n  python backend.py\n\nThen try again.');
    return;
  }

  isScanning = true;
  resetUI();
  log(`Target: ${scanTarget}`, 'info');
  log(`Mode: ${activeMode.toUpperCase()}`, 'info');
  log('Connected to SENTRIX Pro backend ✓', 'success');

  const rpsInput = document.getElementById('rateLimit');
  let rps = rpsInput ? parseInt(rpsInput.value) || 10 : 10;
  bountyMode = document.getElementById('bountyMode')?.checked || false;
  if (bountyMode) {
    rps = Math.min(rps, 2);
    if (rpsInput) rpsInput.value = rps;
    log('⚡ BOUNTY MODE — 2 req/sec, jittered delays, stealth headers', 'warn');
  }

  authConfig = {
    login_url:  document.getElementById('loginUrl')?.value  || '',
    username:   document.getElementById('authUser')?.value  || '',
    password:   document.getElementById('authPass')?.value  || '',
    auth_token: document.getElementById('authToken')?.value || '',
  };

  const hasAuth = authConfig.login_url || authConfig.auth_token;
  if (hasAuth) {
    log(`AUTH: ${authConfig.auth_token ? 'Using direct token' : authConfig.username + ' @ ' + authConfig.login_url}`, 'success');
  }

  try {
    await fetch(BACKEND+'/scan', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        target:      scanTarget,
        mode:        activeMode,
        rate_limit:  rps,
        login_url:   authConfig.login_url,
        username:    authConfig.username,
        password:    authConfig.password,
        auth_token:  authConfig.auth_token,
        bounty_mode: bountyMode,
        ua_suffix:   document.getElementById('uaSuffix')?.value.trim() || '',
      })
    });
  } catch(e) { log('Failed: '+e.message, 'danger'); isScanning=false; return; }

  // All modules including new Write IDOR + Mass Assignment
  const stepMap = {
    'RECON':          { id:'recon',       label:'CRAWLING — DISCOVERING ENDPOINTS...' },
    'SEC HEADERS':    { id:'headers',     label:'CHECKING SECURITY HEADERS...' },
    'SECRETS':        { id:'secrets',     label:'SCANNING FOR EXPOSED SECRETS...' },
    'SQL INJECTION':  { id:'sqli',        label:'TESTING SQL INJECTION (500+ PAYLOADS)...' },
    'XSS':            { id:'xss',         label:'TESTING XSS (CONTEXT-AWARE + WAF BYPASS)...' },
    'LFI':            { id:'lfi',         label:'TESTING LOCAL FILE INCLUSION...' },
    'OPEN REDIRECT':  { id:'redirect',    label:'TESTING OPEN REDIRECT...' },
    'SSRF':           { id:'ssrf',        label:'TESTING SERVER-SIDE REQUEST FORGERY...' },
    'IDOR':           { id:'idor',        label:'TESTING IDOR — UNAUTHORIZED READ ACCESS...' },
    'WRITE IDOR':     { id:'write-idor',  label:'TESTING WRITE IDOR — UNAUTHORIZED MODIFICATION...' },
    'MASS ASSIGNMENT':{ id:'mass-assign', label:'TESTING MASS ASSIGNMENT — PRIVILEGE ESCALATION...' },
    'BROKEN AUTH':    { id:'auth',        label:'TESTING AUTHENTICATION...' },
    'SSL/TLS':        { id:'ssl',         label:'CHECKING SSL/TLS...' },
    'COMPLETE':       { id:'ai',          label:'SCAN COMPLETE' }
  };

  let lastStep='', lastLog=0, lastFind=0;

  const poll = setInterval(async () => {
    try {
      const state = await (await fetch(BACKEND+'/status')).json();
      const si = stepMap[state.step];
      setProgress(state.progress, si ? si.label : state.step);

      if (state.step !== lastStep) {
        if (stepMap[lastStep]) stepDone(stepMap[lastStep].id);
        if (si && state.step !== 'COMPLETE') stepActive(si.id);
        lastStep = state.step;
      }

      state.logs.slice(lastLog).forEach(l => log(l.msg, l.level));
      lastLog = state.logs.length;

      state.findings.slice(lastFind).forEach(f => addFinding(f));
      lastFind = state.findings.length;

      const reqEl = document.getElementById('reqCounter');
      if (reqEl) {
        reqEl.textContent = `${state.total_requests || 0} reqs  |  ${state.req_per_sec || 0} req/s`;
        if (state.blocked) reqEl.style.color = 'var(--crit)';
      }

      if (state.blocked && !window._wafWarned) {
        window._wafWarned = true;
        log('⚠ Rate limiting detected — switching to stealth mode.', 'warn');
      }
      // Show WAF banner only if hard WAF blocks accumulated (real WAF, not auth 403s)
      if (state.waf_blocks >= 3 && !window._wafBannerShown) {
        window._wafBannerShown = true;
        log('🛡 WAF DETECTED — Multiple blocks. Rate reduced.', 'danger');
      }

      if (state.authenticated && !window._authLogged) {
        window._authLogged = true;
        log(`AUTH: ✓ Scanning as: ${state.auth_user || 'authenticated user'}`, 'success');
        const authBadge = document.getElementById('authBadge');
        if (authBadge) { authBadge.style.display = 'inline-flex'; authBadge.textContent = `🔐 ${state.auth_user || 'AUTHED'}`; }
      }

      if (state.done) {
        clearInterval(poll);
        window._authLogged = false;
        window._wafWarned = false;
        window._wafBannerShown = false;
        Object.values(stepMap).forEach(s => stepDone(s.id));
        setProgress(100, 'SCAN COMPLETE');
        updateStats(); buildAttackPath();
        document.getElementById('statsRow').classList.remove('hidden');
        document.getElementById('scorePanel').classList.remove('hidden');
        document.getElementById('attackPathPanel').classList.remove('hidden');
        document.getElementById('generateReportBtn').disabled = false;
        document.getElementById('findingsCount').textContent = currentFindings.length + ' findings';
        setStatus('idle');
        document.getElementById('scanBtn').textContent = 'SCAN';
        document.getElementById('scanBtn').classList.remove('scanning');
        isScanning = false;
        const authNote = state.authenticated ? ` (as ${state.auth_user})` : '';
        log(`Scan complete — ${currentFindings.length} findings${authNote}`, 'success');
      }
    } catch(e) {
      log('Lost connection: '+e.message, 'danger');
      clearInterval(poll);
      isScanning = false;
    }
  }, 1000);
}

function stopScan() {
  isScanning = false;
  document.getElementById('scanBtn').textContent = 'SCAN';
  document.getElementById('scanBtn').classList.remove('scanning');
  setStatus('idle');
  log('Scan stopped by user.', 'warn');
}

// ─────────────────────────────────────────
// ADD FINDING — with curl verify command
// ─────────────────────────────────────────
function addFinding(f) {
  currentFindings.push(f);
  const list = document.getElementById('findingsList');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  // Severity icon
  const icons = { critical: '◉', high: '◈', medium: '◇', low: '○' };
  const icon = icons[f.severity] || '◇';

  // Timestamp display
  const tsHtml = f.timestamp
    ? `<div class="detail-section"><div class="detail-label">Found At</div><div class="detail-timestamp">${f.timestamp}</div></div>`
    : '';

  // Curl command block — the key new feature for manual verification
  const curlHtml = f.curl
    ? `<div class="detail-section">
        <div class="detail-label">Manual Verify</div>
        <div class="curl-block">
          <code class="curl-code">${escHtml(f.curl)}</code>
          <button class="curl-copy-btn" onclick="copyCurl(this, ${JSON.stringify(f.curl).replace(/'/g,'&#39;')})">COPY</button>
        </div>
       </div>`
    : '';

  const item = document.createElement('div');
  item.className = `finding-item sev-${f.severity}`;
  item.innerHTML = `
    <div class="finding-row">
      <span class="sev-badge ${f.severity}">${icon} ${f.severity}</span>
      <span class="finding-name">${escHtml(f.name)}</span>
      <span class="finding-endpoint">${escHtml(shortUrl(f.endpoint))}</span>
      <span class="finding-chevron">▼</span>
    </div>
    <div class="finding-detail">
      <div class="detail-section">
        <div class="detail-label">Description</div>
        <div class="detail-text">${escHtml(f.description)}</div>
      </div>
      <div class="detail-section">
        <div class="detail-label">Evidence / Payload</div>
        <div class="detail-code">${escHtml(f.payload)}</div>
      </div>
      ${curlHtml}
      ${tsHtml}
      <div class="detail-section">
        <div class="detail-label">Remediation</div>
        <div class="detail-fix">${escHtml(f.remediation)}</div>
      </div>
    </div>`;

  item.addEventListener('click', (e) => {
    // Don't collapse when clicking copy button
    if (e.target.classList.contains('curl-copy-btn')) return;
    item.classList.toggle('expanded');
  });
  list.appendChild(item);
}

function copyCurl(btn, curlCmd) {
  navigator.clipboard.writeText(curlCmd).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'COPIED!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
  });
}

// ─────────────────────────────────────────
// STATS + RISK RING
// ─────────────────────────────────────────
function updateStats() {
  const counts = { critical:0, high:0, medium:0, low:0 };
  currentFindings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  document.getElementById('statTotal').textContent = currentFindings.length;
  document.getElementById('statCrit').textContent  = counts.critical;
  document.getElementById('statHigh').textContent  = counts.high;
  document.getElementById('statMed').textContent   = counts.medium;
  document.getElementById('statLow').textContent   = counts.low;

  const rawRisk   = counts.critical*25 + counts.high*12 + counts.medium*5 + counts.low*2;
  const riskScore = Math.max(5, 100 - Math.min(100, rawRisk));

  setTimeout(() => {
    const arc = document.getElementById('riskArc');
    arc.style.strokeDashoffset = 201 - (riskScore/100)*201;
    let color, grade, desc;
    if      (riskScore < 30) { color='var(--crit)'; grade='F'; desc='Critical Risk'; }
    else if (riskScore < 50) { color='var(--high)'; grade='D'; desc='High Risk'; }
    else if (riskScore < 65) { color='var(--med)';  grade='C'; desc='Moderate Risk'; }
    else if (riskScore < 80) { color='var(--warn)'; grade='B'; desc='Low Risk'; }
    else                     { color='var(--low)';  grade='A'; desc='Minimal Risk'; }
    arc.style.stroke = color;
    document.getElementById('riskNum').textContent   = riskScore;
    document.getElementById('riskNum').style.color   = color;
    document.getElementById('riskGrade').textContent = grade;
    document.getElementById('riskGrade').style.color = color;
    document.getElementById('riskDesc').textContent  = desc;
  }, 200);
}

// ─────────────────────────────────────────
// ATTACK PATH
// ─────────────────────────────────────────
function buildAttackPath() {
  const has = (kw) => currentFindings.some(f => f.name.toLowerCase().includes(kw.toLowerCase()));
  const hasSQLi      = has('SQL');
  const hasXSS       = has('XSS');
  const hasLFI       = has('LFI') || has('File Inclusion');
  const hasSSRF      = has('SSRF');
  const hasIDOR      = has('IDOR');
  const hasWriteIDOR = has('Write IDOR');
  const hasMassAssign= has('Mass Assignment');
  const hasAuth      = has('Brute') || has('Default Cred');
  const hasSecrets   = has('Secret') || has('Exposed') || has('API Key') || has('Password in Source');
  const hasRedirect  = has('Redirect');

  const steps = [
    { label: 'Attacker identifies target and maps attack surface', active: true, danger: false },
    { label: hasSecrets   ? '↳ Exposed secrets/API keys → instant credential access'     : 'Passive recon — no secrets exposed',   active: hasSecrets,    danger: hasSecrets },
    { label: hasMassAssign? '↳ Mass Assignment → role=admin → full privilege escalation'  : 'No mass assignment found',             active: hasMassAssign, danger: hasMassAssign },
    { label: hasSQLi      ? '↳ SQL Injection → full database dump'                        : 'No SQLi found',                        active: hasSQLi,       danger: hasSQLi },
    { label: hasLFI       ? '↳ LFI → /etc/passwd, config files, source code'             : 'No LFI found',                         active: hasLFI,        danger: hasLFI },
    { label: hasSSRF      ? '↳ SSRF → cloud metadata, internal services'                 : 'No SSRF found',                        active: hasSSRF,       danger: hasSSRF },
    { label: hasWriteIDOR ? '↳ Write IDOR → modify/delete any user\'s data'              : hasIDOR ? '↳ IDOR → read all user records' : 'No IDOR found', active: hasIDOR||hasWriteIDOR, danger: hasWriteIDOR },
    { label: hasXSS       ? '↳ XSS → steal session cookie, keylog, phishing'             : 'No XSS found',                         active: hasXSS,        danger: hasXSS },
    { label: hasAuth      ? '↳ Default creds / brute force → account takeover'           : 'Auth hardened',                        active: hasAuth,       danger: hasAuth },
    { label: hasRedirect  ? '↳ Open Redirect → phishing with trusted domain'             : 'No open redirect',                     active: hasRedirect,   danger: false },
    {
      label: (hasMassAssign || (hasSQLi && hasSSRF)) ? '⚠ CRITICAL: Full system compromise likely' :
             (hasSQLi || hasLFI || hasWriteIDOR)     ? '⚠ HIGH: Data breach likely' :
             (hasXSS  || hasIDOR)                    ? '⚠ MEDIUM: Account takeover possible' : 'Limited attack surface',
      active: hasSQLi||hasLFI||hasSSRF||hasXSS||hasIDOR||hasWriteIDOR||hasMassAssign,
      danger: hasMassAssign||hasSQLi||hasLFI||hasSSRF||hasWriteIDOR
    },
  ];

  const chain = document.getElementById('pathChain');
  chain.innerHTML = '';
  steps.forEach((s, i) => {
    const div = document.createElement('div');
    div.className = `path-step${s.active?' active':''}${s.danger?' danger':''}`;
    div.innerHTML = `<div class="path-num">${i+1}</div><span>${s.label}</span>`;
    chain.appendChild(div);
    if (i < steps.length-1) {
      const arrow = document.createElement('div');
      arrow.className='path-arrow'; arrow.textContent='│';
      chain.appendChild(arrow);
    }
  });
}

// ─────────────────────────────────────────
// AI REPORT
// ─────────────────────────────────────────
async function generateReport() {
  if (currentFindings.length === 0) return;
  document.getElementById('generateReportBtn').disabled = true;
  document.getElementById('aiThinking').classList.remove('hidden');
  document.getElementById('aiContent').innerHTML = '';

  try {
    const response = await fetch(BACKEND+'/report', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ target: scanTarget, findings: currentFindings })
    });
    const data = await response.json();
    document.getElementById('aiThinking').classList.add('hidden');

    if (data.error) {
      document.getElementById('aiContent').innerHTML = `<span style="color:var(--crit)">Error: ${escHtml(data.error)}</span>`;
      document.getElementById('generateReportBtn').disabled = false;
      return;
    }

    aiReportText = data.report;
    const formatted = aiReportText
      .replace(/\*\*(.+?)\*\*/g, '<strong style="color:var(--accent)">$1</strong>')
      .replace(/^## (.+)$/gm, '<div style="color:var(--accent2);font-family:Orbitron,monospace;font-size:11px;letter-spacing:2px;margin-top:14px;margin-bottom:6px;">$1</div>')
      .replace(/\n/g, '<br>');
    document.getElementById('aiContent').innerHTML = formatted;
    document.getElementById('exportBtn').classList.remove('hidden');

  } catch(err) {
    document.getElementById('aiThinking').classList.add('hidden');
    document.getElementById('aiContent').innerHTML = `<span style="color:var(--crit)">Could not reach backend: ${escHtml(err.message)}</span>`;
    document.getElementById('generateReportBtn').disabled = false;
  }
}

// ─────────────────────────────────────────
// EXPORT — includes curl commands
// ─────────────────────────────────────────
function exportReport() {
  const counts = { critical:0, high:0, medium:0, low:0 };
  currentFindings.forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

  // Sort by severity
  const order = { critical:0, high:1, medium:2, low:3 };
  const sorted = [...currentFindings].sort((a,b) => (order[a.severity]||4) - (order[b.severity]||4));

  let out = 'SENTRIX PRO — VULNERABILITY REPORT\n' + '═'.repeat(60) + '\n';
  out += `Target   : ${scanTarget}\n`;
  out += `Mode     : ${activeMode.toUpperCase()}\n`;
  out += `Date     : ${new Date().toLocaleString()}\n`;
  out += `Findings : ${currentFindings.length} total  `;
  out += `(Critical:${counts.critical}  High:${counts.high}  Medium:${counts.medium}  Low:${counts.low})\n`;
  out += '═'.repeat(60) + '\n\n';

  // Critical/High findings first — these are bug bounty targets
  const highPrio = sorted.filter(f => ['critical','high'].includes(f.severity));
  const lowPrio  = sorted.filter(f => !['critical','high'].includes(f.severity));

  if (highPrio.length > 0) {
    out += '┌─ HIGH PRIORITY FINDINGS (' + highPrio.length + ') ─────────────────────\n\n';
    highPrio.forEach((f, i) => {
      out += `[${i+1}] ${f.severity.toUpperCase()} — ${f.name}\n`;
      out += `    Endpoint    : ${f.endpoint}\n`;
      out += `    Description : ${f.description}\n`;
      out += `    Evidence    : ${f.payload}\n`;
      if (f.curl) {
        out += `    Verify      : ${f.curl}\n`;
      }
      if (f.timestamp) {
        out += `    Found At    : ${f.timestamp}\n`;
      }
      out += `    Remediation : ${f.remediation}\n`;
      out += '\n' + '─'.repeat(60) + '\n\n';
    });
  }

  if (lowPrio.length > 0) {
    out += '┌─ INFORMATIONAL / MEDIUM (' + lowPrio.length + ') ──────────────────────\n\n';
    lowPrio.forEach((f, i) => {
      out += `[${i+1}] ${f.severity.toUpperCase()} — ${f.name}\n`;
      out += `    Endpoint    : ${f.endpoint}\n`;
      out += `    Evidence    : ${f.payload}\n`;
      out += `    Remediation : ${f.remediation}\n\n`;
    });
  }

  if (aiReportText) {
    out += '═'.repeat(60) + '\nAI ANALYSIS\n' + '═'.repeat(60) + '\n\n' + aiReportText + '\n';
  }

  const blob = new Blob([out], { type:'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  let siteName = 'report';
  try { siteName = new URL(scanTarget).hostname.replace('www.',''); } catch(e) {}
  a.download = siteName + '_sentrix_' + new Date().toISOString().slice(0,10) + '.txt';
  a.click();
}

// ─────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────
function shortUrl(url) {
  try { const u = new URL(url); return (u.pathname+u.search).slice(0,40)||'/'; }
  catch(e) { return String(url).slice(0,40); }
}

function escHtml(str) {
  if (typeof str !== 'string') str = String(str || '');
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}