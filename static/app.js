/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
   PII::SCANNER v3.0 â€” Frontend Logic (ML Edition)
   â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

// â”€â”€ Tab Switching â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

function switchTab(name) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const tab = document.querySelector(`.tab[data-tab="${name}"]`);
    const panel = document.getElementById(`panel${name.charAt(0).toUpperCase() + name.slice(1)}`);
    if (tab) tab.classList.add('active');
    if (panel) panel.classList.add('active');
    if (name === 'dashboard') refreshDashboard();
}

// â”€â”€ Clock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function updateClock() {
    const el = document.getElementById('headerTime');
    if (el) el.textContent = new Date().toLocaleTimeString('en-US', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();


// â”€â”€ Dashboard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function refreshDashboard() {
    try {
        const resp = await fetch('/api/stats');
        const data = await resp.json();

        document.getElementById('statScans').textContent = data.total_scans;
        document.getElementById('statFindings').textContent = data.total_findings;
        const activeTotal = (data.active_scans || 0) + (data.active_monitors || 0);
        document.getElementById('statActive').textContent = activeTotal;

        const risks = data.risk_distribution || {};
        let risk = 'â€”';
        if (risks.CRITICAL > 0) risk = 'CRIT';
        else if (risks.HIGH > 0) risk = 'HIGH';
        else if (risks.MEDIUM > 0) risk = 'MED';
        else if (data.total_scans > 0) risk = 'LOW';
        document.getElementById('statRisk').textContent = risk;

        const total = Math.max(data.total_findings, 1);
        updateBar('riskCritical', 'riskCritCount', risks.CRITICAL || 0, total);
        updateBar('riskHigh', 'riskHighCount', risks.HIGH || 0, total);
        updateBar('riskMedium', 'riskMedCount', risks.MEDIUM || 0, total);
        updateBar('riskLow', 'riskLowCount', risks.LOW || 0, total);

        const feed = document.getElementById('activityFeed');
        if (data.recent_scans && data.recent_scans.length > 0) {
            feed.innerHTML = data.recent_scans.map(s => {
                const r = s.overall_risk || 'LOW';
                const cls = r === 'CRITICAL' ? 'crit' : r === 'HIGH' ? 'high' : 'low';
                return `
                    <div class="activity-item">
                        <span class="activity-badge ${cls}">${r}</span>
                        <span class="activity-text">${esc(s.query)} â€” ${s.total_findings} findings</span>
                        <span class="activity-time">${new Date(s.timestamp).toLocaleTimeString()}</span>
                    </div>
                `;
            }).join('');
        } else {
            feed.innerHTML = '<div class="empty-state">No scans yet.</div>';
        }
    } catch (e) { console.error('Dashboard error:', e); }
}

function updateBar(barId, countId, count, total) {
    const pct = Math.min((count / total) * 100, 100);
    document.getElementById(barId).style.width = pct + '%';
    document.getElementById(countId).textContent = count;
}

// â”€â”€ Web Search Scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

let currentScanId = null;
let pollInterval = null;
let sseSource = null;
let currentMonitorId = null;
let monitorPollInterval = null;

async function startScan() {
    const query = document.getElementById('scanQuery').value.trim();
    if (!query) {
        document.getElementById('scanQuery').style.borderColor = 'var(--red)';
        setTimeout(() => document.getElementById('scanQuery').style.borderColor = '', 2000);
        return;
    }

    showProgress('WEB SCAN IN PROGRESS');
    addLog(`Web search scan: "${query}"`);

    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query }),
        });
        const data = await resp.json();
        currentScanId = data.scan_id;
        addLog(`Scan ID: ${data.scan_id}`);
        connectSSE(currentScanId);
        pollInterval = setInterval(() => pollScan(currentScanId), 2000);
    } catch (e) {
        addLog('ERROR: ' + e.message);
        hideProgress();
    }
}

// â”€â”€ SSE Stream â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function connectSSE(scanId) {
    if (sseSource) sseSource.close();
    sseSource = new EventSource(`/api/scan/${scanId}/stream`);

    sseSource.addEventListener('progress', (e) => {
        const d = JSON.parse(e.data);
        setProgress(d.progress);
    });

    sseSource.addEventListener('log', (e) => {
        const d = JSON.parse(e.data);
        appendLogLine(d.message);
    });

    sseSource.addEventListener('completed', (e) => {
        const d = JSON.parse(e.data);
        addLog(`âœ“ COMPLETE â€” ${d.total_findings} PII | Risk: ${d.overall_risk}`);
        setProgress(100);
    });

    sseSource.addEventListener('done', () => {
        if (sseSource) { sseSource.close(); sseSource = null; }
    });

    sseSource.addEventListener('error', () => {
        if (sseSource) { sseSource.close(); sseSource = null; }
    });
}

// â”€â”€ Poll Scan Status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async function pollScan(scanId) {
    try {
        const resp = await fetch(`/api/scan/${scanId}`);
        const data = await resp.json();

        setProgress(data.progress);

        // Update log from server
        if (data.log && data.log.length) {
            const logEl = document.getElementById('progressLog');
            const existing = logEl.querySelectorAll('.log-line').length;
            data.log.slice(existing).forEach(entry => {
                const line = document.createElement('div');
                line.className = 'log-line';
                line.textContent = entry;
                logEl.appendChild(line);
                logEl.scrollTop = logEl.scrollHeight;
            });
        }

        if (data.status === 'completed') {
            clearInterval(pollInterval);
            pollInterval = null;
            if (sseSource) { sseSource.close(); sseSource = null; }
            setTimeout(() => {
                renderResults(data);
                switchTab('results');
                hideProgress();
            }, 500);
            refreshDashboard();
        } else if (data.status === 'error') {
            clearInterval(pollInterval);
            pollInterval = null;
            if (sseSource) { sseSource.close(); sseSource = null; }
            addLog('ERROR: ' + (data.error || 'Unknown'));
            hideProgress();
        }
    } catch (e) { console.error('Poll error:', e); }
}

// â”€â”€ Progress Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function showProgress(title = 'SCAN IN PROGRESS') {
    const overlay = document.getElementById('progressOverlay');
    const titleEl = document.getElementById('progressTitle');
    const progressEl = document.getElementById('scanProgress');
    if (overlay) overlay.classList.remove('hidden');
    if (progressEl) progressEl.classList.remove('hidden');
    if (titleEl) titleEl.textContent = title;
    setProgress(0);
    const logEl = document.getElementById('progressLog');
    if (logEl) {
        logEl.innerHTML = '';
        logEl.dataset.monitorLogCount = '0';
    }
}

function hideProgress() {
    const overlay = document.getElementById('progressOverlay');
    if (overlay) overlay.classList.add('hidden');
}

function setProgress(pct) {
    const normalized = Math.max(0, Math.min(100, Number(pct) || 0));
    document.getElementById('progressFill').style.width = normalized + '%';
    document.getElementById('progressPct').textContent = normalized.toFixed(0) + '%';
}

function addLog(msg) {
    const line = `[${new Date().toLocaleTimeString()}] ${msg}`;
    appendLogLine(line);
}

function appendLogLine(text) {
    const log = document.getElementById('progressLog');
    const div = document.createElement('div');
    div.className = 'log-line';
    div.textContent = text;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
}

// â”€â”€ URL Scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function setMonitorFieldVisible(inputId, visible) {
    const input = document.getElementById(inputId);
    if (!input) return;
    const wrapper = input.closest('.form-group');
    if (wrapper) wrapper.style.display = visible ? '' : 'none';
}

function updateMonitorFields() {
    const modeEl = document.getElementById('monMode');
    if (!modeEl) return;
    const mode = modeEl.value;

    const showWeb = mode === 'web' || mode === 'all';
    const showUrl = mode === 'url' || mode === 'all';
    const showSocial = mode === 'social' || mode === 'all';
    const showEmail = mode === 'email' || mode === 'all';

    setMonitorFieldVisible('monQuery', showWeb);
    setMonitorFieldVisible('monUrl', showUrl);
    setMonitorFieldVisible('monPlatform', showSocial);
    setMonitorFieldVisible('monHandle', showSocial);
    setMonitorFieldVisible('monEmail', showEmail);
}

async function startMonitoring() {
    const mode = (document.getElementById('monMode')?.value || 'all').trim();
    const payload = {
        mode,
        query: document.getElementById('monQuery')?.value.trim() || null,
        url: document.getElementById('monUrl')?.value.trim() || null,
        platform: document.getElementById('monPlatform')?.value.trim() || null,
        handle: document.getElementById('monHandle')?.value.trim() || null,
        email: document.getElementById('monEmail')?.value.trim() || null,
        max_results: 5,
        interval_seconds: 120,
        duration_minutes: parseInt(document.getElementById('monDuration')?.value || '60', 10),
    };
    if (mode === 'web' && !payload.query) {
        addLog('ERROR: Web mode requires a query');
        return;
    }
    if (mode === 'url' && !payload.url) {
        addLog('ERROR: URL mode requires a URL');
        return;
    }
    if (mode === 'social' && (!payload.platform || !payload.handle)) {
        addLog('ERROR: Social mode requires platform and handle');
        return;
    }
    if (mode === 'email' && !payload.email) {
        addLog('ERROR: Email mode requires an email target');
        return;
    }
    if (mode === 'all' && !payload.query && !payload.url && !payload.email && !(payload.platform && payload.handle)) {
        addLog('ERROR: All mode requires at least one target');
        return;
    }

    const startBtn = document.getElementById('btnStartMonitor');
    if (startBtn) {
        startBtn.disabled = true;
        startBtn.textContent = 'STARTING...';
    }

    showProgress('MONITORING IN PROGRESS');
    addLog(`Starting monitor in ${mode.toUpperCase()} mode`);

    try {
        const resp = await fetch('/api/monitor/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Monitor start failed');

        currentMonitorId = data.monitor_id;
        if (monitorPollInterval) clearInterval(monitorPollInterval);
        monitorPollInterval = setInterval(() => pollMonitor(currentMonitorId), 3000);

        addLog(`Monitor started: ${currentMonitorId}`);
        document.getElementById('monitorStatus').textContent =
            `Running monitor ${currentMonitorId}. Ends at ${new Date(data.ends_at).toLocaleString()}`;
        await pollMonitor(currentMonitorId);
    } catch (e) {
        addLog('ERROR: ' + e.message);
        hideProgress();
    } finally {
        if (startBtn) {
            startBtn.disabled = false;
            startBtn.textContent = 'START MONITORING';
        }
    }
}

async function stopMonitoring() {
    if (!currentMonitorId) {
        addLog('No active monitor to stop');
        return;
    }

    try {
        const resp = await fetch(`/api/monitor/${currentMonitorId}/stop`, { method: 'POST' });
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Stop failed');
        addLog(`Stopping monitor ${currentMonitorId}...`);
        await pollMonitor(currentMonitorId);
    } catch (e) {
        addLog('ERROR: ' + e.message);
        hideProgress();
    }
}

async function pollMonitor(monitorId) {
    if (!monitorId) return;

    try {
        const resp = await fetch(`/api/monitor/${monitorId}`);
        const data = await resp.json();
        if (!resp.ok) throw new Error(data.detail || 'Monitor status failed');

        const startedAt = data.started_at ? new Date(data.started_at).getTime() : null;
        const endsAt = data.ends_at ? new Date(data.ends_at).getTime() : null;
        if (startedAt && endsAt && endsAt > startedAt) {
            const pct = Math.max(0, Math.min(100, ((Date.now() - startedAt) / (endsAt - startedAt)) * 100));
            setProgress(pct);
        }

        const logEl = document.getElementById('progressLog');
        const existing = parseInt(logEl.dataset.monitorLogCount || '0', 10);
        if (Array.isArray(data.log) && data.log.length > existing) {
            data.log.slice(existing).forEach(entry => appendLogLine(entry));
            logEl.dataset.monitorLogCount = String(data.log.length);
        }

        const summary = data.last_summary || {};
        const nextRun = data.next_run_at ? new Date(data.next_run_at).toLocaleTimeString() : '-';
        document.getElementById('monitorStatus').textContent =
            `Status: ${data.status || 'unknown'} | Runs: ${data.run_count || 0} | ` +
            `Total findings: ${data.total_findings || 0} | In-app alerts: ${data.alerts_sent || 0} | ` +
            `Last risk: ${summary.overall_risk || '-'} | Next run: ${nextRun}`;

        if (['completed', 'stopped', 'error'].includes(data.status)) {
            if (monitorPollInterval) {
                clearInterval(monitorPollInterval);
                monitorPollInterval = null;
            }
            setProgress(100);
            currentMonitorId = null;
            hideProgress();
            refreshDashboard();
        }
    } catch (e) {
        addLog('ERROR: ' + e.message);
        hideProgress();
        if (monitorPollInterval) {
            clearInterval(monitorPollInterval);
            monitorPollInterval = null;
        }
    }
}

async function scanURL() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
        document.getElementById('urlInput').style.borderColor = 'var(--red)';
        setTimeout(() => document.getElementById('urlInput').style.borderColor = '', 2000);
        return;
    }

    const btn = document.getElementById('btnUrlScan');
    btn.disabled = true;
    btn.textContent = 'SCANNING...';
    showProgress('URL SCAN IN PROGRESS');
    setProgress(15);
    addLog(`URL scan: ${url}`);

    try {
        const resp = await fetch('/api/scan/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });
        const data = await resp.json();
        setProgress(75);
        addLog(`Title: "${data.title || 'Untitled'}"`);
        addLog(`Content: ${data.content_length.toLocaleString()} chars`);
        addLog(`PII found: ${data.pii_count}`);

        if (data.detection_methods) {
            const m = Object.entries(data.detection_methods).map(([k, v]) => `${k}:${v}`).join(', ');
            addLog(`Methods: ${m}`);
        }

        setProgress(100);

        renderURLResult(data);
        switchTab('results');
        hideProgress();
        refreshDashboard();
    } catch (e) {
        addLog('ERROR: ' + e.message);
        hideProgress();
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">ðŸŒ</span> SCAN URL';
    }
}

function renderURLResult(data) {
    const sum = document.getElementById('resultsSummary');
    sum.classList.remove('hidden');
    document.getElementById('resTotalFindings').textContent = data.pii_count || 0;
    document.getElementById('resTotalSources').textContent = '1';

    const risk = data.pii_count > 0 ? (data.pii_findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH') : 'LOW';
    const riskEl = document.getElementById('resOverallRisk');
    riskEl.textContent = risk;
    riskEl.className = 'summary-value risk-badge ' + risk;

    const methods = data.detection_methods || {};
    document.getElementById('resMethods').textContent = Object.entries(methods).map(([k, v]) => `${k}:${v}`).join(' ');

    const container = document.getElementById('resultsList');
    const findings = data.pii_findings || [];

    if (findings.length === 0) {
        container.innerHTML = '<div class="empty-state">âœ“ No PII detected</div>';
        return;
    }

    container.innerHTML = `
        <div class="result-card expanded">
            <div class="result-card-header">
                <div class="result-source">
                    <span class="source-badge">URL</span>
                    <span class="result-title">${esc(data.title || data.url)}</span>
                </div>
                <div class="result-meta">
                    <span class="pii-count-badge has-findings">${data.pii_count} PII</span>
                </div>
            </div>
            <div class="result-card-body" style="display:block">
                ${findings.map(f => renderFinding(f)).join('')}
                <a class="result-url" href="${esc(data.url)}" target="_blank">${esc(data.url)}</a>
            </div>
        </div>
    `;
}

// â”€â”€ File Upload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');

if (dropZone) {
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) uploadFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) uploadFile(fileInput.files[0]);
    });
}

async function uploadFile(file) {
    showProgress('FILE SCAN IN PROGRESS');
    setProgress(20);
    addLog(`Upload: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);

    const fd = new FormData();
    fd.append('file', file);

    try {
        const resp = await fetch('/api/scan/file', { method: 'POST', body: fd });
        if (!resp.ok) { addLog('ERROR: Upload failed'); return; }

        const data = await resp.json();
        setProgress(75);
        addLog(`Found ${data.pii_count} PII items`);
        if (data.by_method) {
            const m = Object.entries(data.by_method).map(([k, v]) => `${k}:${v}`).join(', ');
            addLog(`Methods: ${m}`);
        }

        setProgress(100);

        renderFileResult(data);
        switchTab('results');
        hideProgress();
        refreshDashboard();
    } catch (e) { addLog('ERROR: ' + e.message);
        hideProgress(); }
}

async function scanSocial() {
    const platform = document.getElementById('socialPlatform').value;
    const handle = document.getElementById('socialHandle').value.trim();
    if (!handle) return;

    const btn = document.getElementById('btnSocialScan');
    btn.disabled = true;
    btn.innerHTML = 'SCANNING...';

    showProgress('SOCIAL SCAN IN PROGRESS');
    setProgress(12);
    const prog = document.getElementById('scanProgress');
    const log = document.getElementById('progressLog');
    prog.classList.remove('hidden');
    log.innerHTML = `<div>[${new Date().toLocaleTimeString()}] Starting direct API scan for ${platform.toUpperCase()}: @${handle}</div>`;

    try {
        const resp = await fetch('/api/scan/social', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ platform, handle }),
        });

        const data = await resp.json();
        if (resp.status !== 200) throw new Error(data.detail || 'Social scan failed');
        setProgress(75);

        const totalPii = data.reduce((acc, r) => acc + (r.pii_count || 0), 0);
        log.innerHTML += `<div style="color:var(--green)">[${new Date().toLocaleTimeString()}] Deep Discovery complete: ${totalPii} PII found across ${data.length} sources</div>`;

        // Switch to results tab
        switchTab('results');
        renderResultsList(data);
        setProgress(100);
        hideProgress();
        refreshDashboard();
    } catch (e) {
        log.innerHTML += `<div style="color:var(--red)">[${new Date().toLocaleTimeString()}] ERROR: ${e.message}</div>`;
        addLog('ERROR: ' + e.message);
        hideProgress();
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">ðŸ“±</span> SCAN PROFILE';
    }
}

async function scanEmail() {
    const email = document.getElementById('emailInput').value.trim();
    if (!email) return;

    const btn = document.getElementById('btnEmailScan');
    btn.disabled = true;
    btn.innerHTML = 'DISCOVERING...';

    showProgress('EMAIL DISCOVERY IN PROGRESS');
    setProgress(12);
    const prog = document.getElementById('scanProgress');
    const log = document.getElementById('progressLog');
    prog.classList.remove('hidden');
    log.innerHTML = `<div>[${new Date().toLocaleTimeString()}] Starting Email Identity Discovery for: ${email}</div>`;

    try {
        const resp = await fetch('/api/scan/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
        });

        const data = await resp.json();
        if (resp.status !== 200) throw new Error(data.detail || 'Email discovery failed');
        setProgress(75);

        const totalPii = data.reduce((acc, r) => acc + (r.pii_count || 0), 0);
        log.innerHTML += `<div style="color:var(--green)">[${new Date().toLocaleTimeString()}] Email Discovery complete: ${totalPii} PII found across ${data.length} sources</div>`;

        // Switch to results tab
        switchTab('results');
        renderResultsList(data);
        setProgress(100);
        hideProgress();
        refreshDashboard();
    } catch (e) {
        log.innerHTML += `<div style="color:var(--red)">[${new Date().toLocaleTimeString()}] ERROR: ${e.message}</div>`;
        addLog('ERROR: ' + e.message);
        hideProgress();
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span class="btn-icon">ðŸ“§</span> DISCOVER IDENTITY';
    }
}

function renderFileResult(data) {
    const sum = document.getElementById('resultsSummary');
    sum.classList.remove('hidden');
    document.getElementById('resTotalFindings').textContent = data.pii_count || 0;
    document.getElementById('resTotalSources').textContent = '1';

    const sev = data.by_severity || {};
    const risk = sev.CRITICAL ? 'CRITICAL' : sev.HIGH ? 'HIGH' : sev.MEDIUM ? 'MEDIUM' : 'LOW';
    const riskEl = document.getElementById('resOverallRisk');
    riskEl.textContent = risk;
    riskEl.className = 'summary-value risk-badge ' + risk;

    document.getElementById('resMethods').textContent = Object.entries(data.by_method || {}).map(([k, v]) => `${k}:${v}`).join(' ');

    const container = document.getElementById('resultsList');
    const findings = data.findings || [];

    if (findings.length === 0) {
        container.innerHTML = '<div class="empty-state">âœ“ No PII detected</div>';
        return;
    }

    container.innerHTML = `
        <div class="result-card expanded">
            <div class="result-card-header">
                <div class="result-source">
                    <span class="source-badge" style="color:var(--yellow);border-color:var(--yellow)">FILE</span>
                    <span class="result-title">${esc(data.filename)}</span>
                </div>
                <div class="result-meta">
                    <span class="pii-count-badge has-findings">${data.pii_count} PII</span>
                </div>
            </div>
            <div class="result-card-body" style="display:block">
                ${findings.map(f => renderFinding(f)).join('')}
            </div>
        </div>
    `;
}

// â”€â”€ Text Analysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function renderResults(scanData) {
    const sum = document.getElementById('resultsSummary');
    sum.classList.remove('hidden');
    document.getElementById('resTotalFindings').textContent = scanData.total_pii || 0;
    document.getElementById('resTotalSources').textContent = (scanData.findings || []).length;

    const riskEl = document.getElementById('resOverallRisk');
    riskEl.textContent = scanData.overall_risk || 'LOW';
    riskEl.className = 'summary-value risk-badge ' + (scanData.overall_risk || 'LOW');

    const methods = scanData.by_method || {};
    document.getElementById('resMethods').textContent = Object.entries(methods).map(([k, v]) => `${k}:${v}`).join(' ');

    renderResultsList(scanData.findings || []);
}

function renderResultsList(findings) {
    const container = document.getElementById('resultsList');
    if (!findings || findings.length === 0) {
        container.innerHTML = '<div class="empty-state">No results.</div>';
        return;
    }

    container.innerHTML = findings.map((f, i) => {
        if (f.error) {
            return `<div class="result-card"><div class="result-card-header"><div class="result-source">
                <span class="source-badge" style="color:var(--red);border-color:var(--red)">ERROR</span>
                <span class="result-title" style="color:var(--red)">${esc(f.error)}</span>
            </div></div></div>`;
        }

        const title = f.title || f.url || 'Untitled';
        const url = f.url || '';
        const pii = f.pii_count || 0;
        const fList = f.pii_findings || [];
        const methods = f.detection_methods || {};
        const methodStr = Object.entries(methods).map(([k, v]) => `<span class="pii-method">${k}:${v}</span>`).join(' ');

        // Severity breakdown for this card
        const sevCounts = {};
        fList.forEach(p => { sevCounts[p.severity] = (sevCounts[p.severity] || 0) + 1; });
        const sevSummary = Object.entries(sevCounts).map(([s, c]) => {
            const col = s === 'CRITICAL' ? 'var(--red)' : s === 'HIGH' ? 'var(--orange)' : s === 'MEDIUM' ? 'var(--yellow)' : 'var(--green)';
            return `<span style="color:${col};font-weight:700;font-size:10px;letter-spacing:1px">${c} ${s}</span>`;
        }).join(' Â· ');

        // Longer content excerpt (500 chars)
        let excerpt = '';
        if (f.raw_content && f.raw_content.length > 30) {
            const txt = f.raw_content.substring(0, 500).replace(/\n/g, ' ').trim();
            excerpt = `<div class="content-excerpt">
                <strong>PAGE CONTENT:</strong> ${esc(txt)}${f.raw_content.length > 500 ? '...' : ''}
                <span class="chars">[${f.content_length?.toLocaleString() || f.raw_content.length.toLocaleString()} chars total]</span>
            </div>`;
        }

        // Group findings by type for cleaner display
        const findingsByType = {};
        fList.forEach(p => {
            if (!findingsByType[p.type]) findingsByType[p.type] = [];
            findingsByType[p.type].push(p);
        });

        let findingsHtml = '';
        if (fList.length > 0) {
            findingsHtml = Object.entries(findingsByType).map(([type, items]) => {
                const sevColor = items[0].severity === 'CRITICAL' ? 'var(--red)' :
                    items[0].severity === 'HIGH' ? 'var(--orange)' :
                        items[0].severity === 'MEDIUM' ? 'var(--yellow)' : 'var(--green)';
                return `
                    <div class="findings-group">
                        <div class="findings-group-header">
                            <span class="pii-type-badge" style="border-color:${sevColor};color:${sevColor}">${type}</span>
                            <span style="color:var(--text-dim);font-size:10px">${items.length} occurrence${items.length > 1 ? 's' : ''}</span>
                            <span style="color:${sevColor};font-size:10px;font-weight:700">${items[0].severity}</span>
                        </div>
                        ${items.map(p => `
                            <a class="pii-finding-detail finding-link" href="${esc(url)}" target="_blank" title="Click to view source">
                                <div class="finding-row">
                                    <span class="pii-value">${esc(p.value || p.masked_value)}</span>
                                    <span class="pii-confidence">${(p.confidence * 100).toFixed(0)}%</span>
                                    ${p.method ? `<span class="pii-method">${p.method.toUpperCase()}</span>` : ''}
                                    <span class="open-icon">â†—</span>
                                </div>
                                ${p.context ? `<div class="finding-context">${esc(p.context)}</div>` : ''}
                            </a>
                        `).join('')}
                    </div>
                `;
            }).join('');
        } else {
            findingsHtml = '<div style="color:var(--green);font-size:12px;padding:12px 0">âœ“ No PII detected on this page</div>';
        }

        // Cards are EXPANDED by default â€” clicking header opens source URL
        return `
            <div class="result-card expanded" id="rc${i}">
                <div class="result-card-header">
                    <div class="result-source" onclick="${url ? `window.open('${esc(url).replace(/'/g, "\\'")}', '_blank')` : ''}" style="cursor:${url ? 'pointer' : 'default'};flex:1">
                        <span class="source-badge">WEB</span>
                        <a class="result-title-link" ${url ? `href="${esc(url)}" target="_blank"` : ''} onclick="event.stopPropagation()">${esc(title)}</a>
                        ${url ? '<span class="open-icon">â†—</span>' : ''}
                    </div>
                    <div class="result-meta">
                        ${methodStr}
                        <span class="pii-count-badge ${pii > 0 ? 'has-findings' : 'no-findings'}">${pii} PII</span>
                        <button class="toggle-btn" onclick="event.stopPropagation();toggleCard('rc${i}')">â–¼</button>
                    </div>
                </div>
                <div class="result-card-body">
                    <div class="result-card-summary">
                        <div class="summary-row">
                            <span style="color:var(--text-dim);font-size:11px">SEVERITY:</span> ${sevSummary || '<span style="color:var(--green)">CLEAN</span>'}
                        </div>
                        <div class="summary-row">
                            <span style="color:var(--text-dim);font-size:11px">DETECTION:</span> ${methodStr || 'â€”'}
                        </div>
                    </div>
                    ${findingsHtml}
                    ${excerpt}
                    ${url ? `<a class="result-url-link" href="${esc(url)}" target="_blank">
                        <span class="link-icon">â†—</span> OPEN SOURCE: ${esc(url)}
                    </a>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function renderFinding(f) {
    const sevColor = f.severity === 'CRITICAL' ? 'var(--red)' :
        f.severity === 'HIGH' ? 'var(--orange)' :
            f.severity === 'MEDIUM' ? 'var(--yellow)' : 'var(--green)';
    return `
        <div class="pii-finding-detail">
            <div class="finding-row">
                <span class="pii-type-badge" style="border-color:${sevColor};color:${sevColor}">${f.type}</span>
                <span class="pii-value">${esc(f.value || f.masked_value)}</span>
                <span class="pii-confidence">${(f.confidence * 100).toFixed(0)}%</span>
                <span class="severity-tag" style="color:${sevColor};border-color:${sevColor}">${f.severity}</span>
                ${f.method ? `<span class="pii-method">${f.method.toUpperCase()}</span>` : ''}
            </div>
            ${f.context ? `<div class="finding-context">${esc(f.context)}</div>` : ''}
        </div>
    `;
}

function toggleCard(id) { document.getElementById(id)?.classList.toggle('expanded'); }

// â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

// â”€â”€ Init â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

refreshDashboard();
updateMonitorFields();`r`n`r`n`r`n`r`n
