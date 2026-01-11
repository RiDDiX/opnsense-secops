// OPNsense Security Auditor - Dashboard JavaScript
let currentLang = 'en';
let translations = {};
let latestReport = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initLanguage();
    loadConfig();
    loadReports();
    loadIgnoreList();

    // Event listeners
    document.getElementById('start-scan-btn').addEventListener('click', startScan);
    document.getElementById('save-config-btn').addEventListener('click', saveConfig);
    document.getElementById('refresh-btn').addEventListener('click', () => location.reload());
    document.getElementById('language-select').addEventListener('change', (e) => changeLanguage(e.target.value));
});

// Navigation
function initNavigation() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            showPage(page);
        });
    });
}

function showPage(pageName) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    document.getElementById(`page-${pageName}`).classList.add('active');
    document.querySelector(`[data-page="${pageName}"]`).classList.add('active');
}

// Language
async function initLanguage() {
    currentLang = localStorage.getItem('language') || 'en';
    document.getElementById('language-select').value = currentLang;
    await loadTranslations(currentLang);
    applyTranslations();
}

async function loadTranslations(lang) {
    const response = await fetch(`/api/translations/${lang}`);
    const data = await response.json();
    if (data.success) {
        translations = data.translations;
    }
}

function changeLanguage(lang) {
    currentLang = lang;
    localStorage.setItem('language', lang);
    loadTranslations(lang).then(() => applyTranslations());
}

function applyTranslations() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (translations[key]) {
            el.textContent = translations[key];
        }
    });
}

function t(key) {
    return translations[key] || key;
}

// Configuration
async function loadConfig() {
    const response = await fetch('/api/config');
    const data = await response.json();
    if (data.success) {
        document.getElementById('opnsense-host').value = data.opnsense.host || '';
        document.getElementById('scan-network').value = data.opnsense.scan_network || '';
        document.getElementById('additional-networks').value = data.opnsense.additional_networks || '';

        const opts = data.scan_options;
        document.getElementById('aggressive-scan').checked = opts.aggressive_scan || false;
        document.getElementById('port-scan-timeout').value = opts.port_scan_timeout || 300;
        document.getElementById('max-parallel-scans').value = opts.max_parallel_scans || 10;
        document.getElementById('enable-vulnerability-scan').checked = opts.enable_vulnerability_scan !== false;
    }
}

async function saveConfig() {
    const config = {
        opnsense: {
            host: document.getElementById('opnsense-host').value,
            scan_network: document.getElementById('scan-network').value,
            additional_networks: document.getElementById('additional-networks').value
        },
        exceptions: {
            scan_options: {
                aggressive_scan: document.getElementById('aggressive-scan').checked,
                port_scan_timeout: parseInt(document.getElementById('port-scan-timeout').value),
                max_parallel_scans: parseInt(document.getElementById('max-parallel-scans').value),
                enable_vulnerability_scan: document.getElementById('enable-vulnerability-scan').checked
            }
        }
    };

    const response = await fetch('/api/config', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(config)
    });

    const data = await response.json();
    showToast(data.success ? 'success' : 'error', data.message || (data.success ? t('success') : t('error')));
}

// Scan
async function startScan() {
    document.getElementById('scan-status-indicator').className = 'status-running';
    document.getElementById('scan-status-text').textContent = t('scan_running');

    const response = await fetch('/api/scan/start', {method: 'POST'});
    const data = await response.json();

    if (data.success) {
        showToast('success', t('scan_running'));
        setTimeout(loadReports, 5000);
    } else {
        showToast('error', data.error);
        document.getElementById('scan-status-indicator').className = 'status-idle';
    }
}

// Reports
async function loadReports() {
    const response = await fetch('/api/reports');
    const data = await response.json();

    if (data.success && data.reports.length > 0) {
        const latest = data.reports[0];
        await loadReport(latest.filename);
        displayReportsList(data.reports);
    }
}

async function loadReport(filename) {
    const response = await fetch(`/api/reports/${filename}`);
    const data = await response.json();

    if (data.success) {
        latestReport = data.report;
        displayFindings(data.report);
    }
}

function displayFindings(report) {
    const allFindings = [
        ...(report.firewall_findings || []),
        ...(report.port_findings || []),
        ...(report.dns_findings || []),
        ...(report.vlan_findings || []),
        ...(report.vulnerability_findings || [])
    ];

    const bySeverity = {critical: [], high: [], medium: [], low: []};

    allFindings.forEach(f => {
        const sev = (f.severity || 'LOW').toLowerCase();
        if (bySeverity[sev]) bySeverity[sev].push(f);
    });

    ['critical', 'high', 'medium', 'low'].forEach(sev => {
        document.getElementById(`${sev}-count`).textContent = bySeverity[sev].length;
        document.getElementById(`${sev}-badge`).textContent = bySeverity[sev].length;

        const container = document.getElementById(`${sev}-findings`);
        container.innerHTML = bySeverity[sev].map(f => createFindingHTML(f, sev)).join('');
    });
}

function createFindingHTML(finding, severity) {
    return `
        <div class="finding-item">
            <div class="finding-header">
                <div class="finding-title">${finding.issue || finding.title || 'Issue'}</div>
                <div class="finding-actions">
                    <button class="btn btn-small" onclick="addToIgnore(${JSON.stringify(finding).replace(/"/g, '&quot;')})">
                        ${t('add_to_ignore')}
                    </button>
                </div>
            </div>
            <div class="finding-details">
                <div class="detail-row">
                    <span class="detail-label">${t('reason')}:</span>
                    <span class="detail-value">${finding.reason || finding.description || ''}</span>
                </div>
                ${finding.cvss_score ? `
                <div class="detail-row">
                    <span class="detail-label">${t('cvss_score')}:</span>
                    <span class="detail-value">${finding.cvss_score}</span>
                </div>` : ''}
            </div>
            ${finding.solution ? `
            <div class="solution-box">
                <strong>💡 ${t('solution')}:</strong>
                ${finding.solution}
            </div>` : ''}
        </div>
    `;
}

function displayReportsList(reports) {
    const container = document.getElementById('reports-list');
    container.innerHTML = reports.map(r => `
        <div class="report-item">
            <div class="report-info">
                <h4>${r.timestamp}</h4>
                <div class="report-meta">${new Date(r.created).toLocaleString()}</div>
            </div>
            <div class="report-actions">
                <button class="btn btn-small" onclick="loadReport('${r.filename}')">
                    <i class="fas fa-eye"></i> ${t('view_details')}
                </button>
                <a href="/api/reports/${r.filename}/download" class="btn btn-small">
                    <i class="fas fa-download"></i> ${t('download')}
                </a>
            </div>
        </div>
    `).join('');
}

// Ignore List
async function loadIgnoreList() {
    const response = await fetch('/api/ignore-list');
    const data = await response.json();

    if (data.success) {
        displayIgnoreList(data.ignore_list);
    }
}

function displayIgnoreList(ignoreList) {
    Object.keys(ignoreList).forEach(category => {
        const container = document.getElementById(`ignore-${category}-list`);
        if (container) {
            container.innerHTML = (ignoreList[category] || []).map((item, idx) => `
                <div class="ignore-item">
                    <div>${JSON.stringify(item)}</div>
                    <button class="btn btn-small" onclick="removeFromIgnore('${category}', ${idx})">
                        <i class="fas fa-trash"></i> ${t('delete')}
                    </button>
                </div>
            `).join('');
        }
    });
}

async function addToIgnore(finding) {
    const item = {
        port: finding.port,
        host: finding.host,
        reason: finding.issue
    };

    const response = await fetch('/api/ignore-list/add', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({category: 'ports', item})
    });

    const data = await response.json();
    showToast(data.success ? 'success' : 'error', data.message);
    if (data.success) loadIgnoreList();
}

async function removeFromIgnore(category, index) {
    const response = await fetch('/api/ignore-list/remove', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({category, index})
    });

    const data = await response.json();
    showToast(data.success ? 'success' : 'error', data.message);
    if (data.success) loadIgnoreList();
}

// Toast
function showToast(type, message) {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<div>${message}</div>`;

    document.getElementById('toast-container').appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}
