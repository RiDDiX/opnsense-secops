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
    loadSecurityScore();
    loadOptimalConfig();
    checkInitialScanStatus();

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

// Scan Progress
let scanPollingInterval = null;

async function startScan() {
    const response = await fetch('/api/scan/start', {method: 'POST'});
    const data = await response.json();

    if (data.success) {
        showScanProgress();
        startProgressPolling();
        showToast('success', 'Scan started');
    } else {
        showToast('error', data.error || 'Failed to start scan');
    }
}

function showScanProgress() {
    document.getElementById('scan-progress-overlay').classList.remove('hidden');
    document.getElementById('scan-status-indicator').className = 'status-running';
    document.getElementById('scan-status-text').textContent = 'Running';
}

function hideScanProgress() {
    document.getElementById('scan-progress-overlay').classList.add('hidden');
}

function updateProgressUI(status) {
    document.getElementById('progress-fill').style.width = status.progress + '%';
    document.getElementById('progress-percent').textContent = status.progress + '%';
    document.getElementById('progress-step').textContent = status.current_step || 'Processing...';
    document.getElementById('step-current').textContent = status.step_number || 0;
    document.getElementById('step-total').textContent = status.total_steps || 7;
    
    // Update status indicator
    const indicator = document.getElementById('scan-status-indicator');
    const statusText = document.getElementById('scan-status-text');
    
    if (status.status === 'running' || status.status === 'cancelling') {
        indicator.className = 'status-running';
        statusText.textContent = status.status === 'cancelling' ? 'Cancelling...' : 'Running';
    } else if (status.status === 'completed') {
        indicator.className = 'status-completed';
        statusText.textContent = 'Completed';
    } else if (status.status === 'failed' || status.status === 'cancelled') {
        indicator.className = 'status-failed';
        statusText.textContent = status.status === 'cancelled' ? 'Cancelled' : 'Failed';
    } else {
        indicator.className = 'status-idle';
        statusText.textContent = 'Idle';
    }
    
    // Disable cancel button if not running
    const cancelBtn = document.getElementById('cancel-scan-btn');
    if (cancelBtn) {
        cancelBtn.disabled = status.status !== 'running';
        if (status.status === 'cancelling') {
            cancelBtn.textContent = 'Cancelling...';
            cancelBtn.disabled = true;
        }
    }
}

function startProgressPolling() {
    // Clear any existing interval
    if (scanPollingInterval) {
        clearInterval(scanPollingInterval);
    }
    
    // Poll every 1 second
    scanPollingInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/scan/status');
            const data = await response.json();
            
            if (data.success) {
                updateProgressUI(data);
                
                // Stop polling when scan completes or fails
                if (['completed', 'failed', 'cancelled', 'idle'].includes(data.status)) {
                    clearInterval(scanPollingInterval);
                    scanPollingInterval = null;
                    
                    // Hide progress after a delay
                    setTimeout(() => {
                        hideScanProgress();
                        
                        if (data.status === 'completed') {
                            showToast('success', 'Scan completed successfully');
                            loadReports();
                            loadSecurityScore();
                        } else if (data.status === 'failed') {
                            showToast('error', 'Scan failed: ' + (data.error || 'Unknown error'));
                        } else if (data.status === 'cancelled') {
                            showToast('warning', 'Scan cancelled');
                        }
                    }, 1500);
                }
            }
        } catch (e) {
            console.error('Failed to poll scan status:', e);
        }
    }, 1000);
}

async function cancelScan() {
    const cancelBtn = document.getElementById('cancel-scan-btn');
    cancelBtn.disabled = true;
    cancelBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cancelling...';
    
    try {
        const response = await fetch('/api/scan/cancel', {method: 'POST'});
        const data = await response.json();
        
        if (data.success) {
            showToast('warning', 'Cancellation requested');
        } else {
            showToast('error', data.error || 'Failed to cancel');
            cancelBtn.disabled = false;
            cancelBtn.innerHTML = '<i class="fas fa-times"></i> Cancel Scan';
        }
    } catch (e) {
        showToast('error', 'Failed to cancel scan');
        cancelBtn.disabled = false;
        cancelBtn.innerHTML = '<i class="fas fa-times"></i> Cancel Scan';
    }
}

// Check scan status on page load
async function checkInitialScanStatus() {
    try {
        const response = await fetch('/api/scan/status');
        const data = await response.json();
        
        if (data.success && data.status === 'running') {
            showScanProgress();
            updateProgressUI(data);
            startProgressPolling();
        }
    } catch (e) {
        console.error('Failed to check initial scan status:', e);
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
        ...(report.vulnerability_findings || []),
        ...(report.system_findings || [])
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

// Security Score
async function loadSecurityScore() {
    try {
        const response = await fetch('/api/security-score');
        const data = await response.json();

        if (data.success) {
            displaySecurityScore(data);
        }
    } catch (e) {
        console.error('Failed to load security score:', e);
    }
}

function displaySecurityScore(data) {
    const scoreEl = document.getElementById('security-score');
    const gradeEl = document.getElementById('security-grade');
    const circleEl = document.getElementById('score-circle');
    const timestampEl = document.getElementById('score-timestamp');
    const actionsList = document.getElementById('priority-actions-list');

    if (data.score !== null) {
        scoreEl.textContent = data.score;
        gradeEl.textContent = `Grade: ${data.grade}`;
        
        // Apply grade class
        const gradeClass = `grade-${data.grade.toLowerCase()}`;
        circleEl.className = `score-circle ${gradeClass}`;
        gradeEl.className = `grade ${gradeClass}`;

        if (data.timestamp) {
            timestampEl.textContent = `Last scan: ${data.timestamp}`;
        }

        // Display priority actions
        if (data.priority_actions && data.priority_actions.length > 0) {
            actionsList.innerHTML = data.priority_actions.map(action => `
                <li class="${action.severity.toLowerCase()}">
                    <span class="action-severity">${action.severity}</span>
                    ${action.issue || action.action}
                </li>
            `).join('');
        } else {
            actionsList.innerHTML = '<li class="low">No critical actions required</li>';
        }
    } else {
        scoreEl.textContent = '--';
        gradeEl.textContent = 'N/A';
        timestampEl.textContent = 'Run a scan to get your security score';
        actionsList.innerHTML = '<li class="medium">Run a security scan to see priority actions</li>';
    }
}

// Optimal Configuration
async function loadOptimalConfig() {
    try {
        const response = await fetch('/api/optimal-config');
        const data = await response.json();

        if (data.success) {
            displayOptimalConfig(data.recommendations);
        }
    } catch (e) {
        console.error('Failed to load optimal config:', e);
    }
}

function displayOptimalConfig(recommendations) {
    // Display implementation guide
    const phasesContainer = document.getElementById('implementation-phases');
    if (recommendations.implementation_guide && phasesContainer) {
        phasesContainer.innerHTML = recommendations.implementation_guide.map(phase => `
            <div class="phase-card">
                <div class="phase-header">
                    <span class="phase-title">Phase ${phase.phase}: ${phase.title}</span>
                    <span class="phase-duration">${phase.duration}</span>
                </div>
                <ul class="phase-steps">
                    ${phase.steps.map(step => `<li>${step}</li>`).join('')}
                </ul>
            </div>
        `).join('');
    }

    // Display category recommendations
    if (recommendations.categories) {
        displayCategoryRecommendations('firewall', recommendations.categories.firewall);
        displayCategoryRecommendations('dns', recommendations.categories.dns);
        displayCategoryRecommendations('network', recommendations.categories.network);
        displayCategoryRecommendations('system', recommendations.categories.system);
        displayCategoryRecommendations('monitoring', recommendations.categories.monitoring);
    }

    // Display optimal config summary
    const configDetails = document.getElementById('optimal-config-details');
    if (recommendations.optimal_config && configDetails) {
        configDetails.innerHTML = Object.entries(recommendations.optimal_config).map(([category, settings]) => `
            <div class="config-category-card">
                <h5>${formatCategoryName(category)}</h5>
                <ul>
                    ${Object.entries(settings).map(([key, value]) => `
                        <li>
                            <span class="config-key">${formatSettingName(key)}</span>
                            <span class="config-value">${value}</span>
                        </li>
                    `).join('')}
                </ul>
            </div>
        `).join('');
    }
}

function displayCategoryRecommendations(category, data) {
    const container = document.getElementById(`${category}-recommendations`);
    if (!container || !data) return;

    let html = '';

    if (data.recommendations) {
        html = data.recommendations.map(rec => `
            <div class="recommendation-item">
                <h5>${rec.setting || rec.name}</h5>
                ${rec.description ? `<p>${rec.description}</p>` : ''}
                ${rec.steps ? `
                    <ol class="recommendation-steps">
                        ${rec.steps.map(step => `<li>${step}</li>`).join('')}
                    </ol>
                ` : ''}
            </div>
        `).join('');
    }

    // Add VLAN structure for network category
    if (category === 'network' && data.recommended_vlan_structure) {
        html += `
            <div class="recommendation-item">
                <h5>Recommended VLAN Structure</h5>
                <table style="width:100%; border-collapse: collapse; margin-top: 0.5rem;">
                    <tr style="background:#f8f9fa;">
                        <th style="padding:0.5rem; text-align:left; border:1px solid #ecf0f1;">VLAN ID</th>
                        <th style="padding:0.5rem; text-align:left; border:1px solid #ecf0f1;">Name</th>
                        <th style="padding:0.5rem; text-align:left; border:1px solid #ecf0f1;">Purpose</th>
                    </tr>
                    ${data.recommended_vlan_structure.map(vlan => `
                        <tr>
                            <td style="padding:0.5rem; border:1px solid #ecf0f1;">${vlan.vlan_id}</td>
                            <td style="padding:0.5rem; border:1px solid #ecf0f1;">${vlan.name}</td>
                            <td style="padding:0.5rem; border:1px solid #ecf0f1;">${vlan.purpose}</td>
                        </tr>
                    `).join('')}
                </table>
            </div>
        `;
    }

    container.innerHTML = html || '<p style="padding:1rem; color:#7f8c8d;">No specific recommendations</p>';
}

function formatCategoryName(name) {
    return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatSettingName(name) {
    return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
