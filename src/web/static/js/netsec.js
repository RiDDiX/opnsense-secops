/**
 * NetSec Auditor - Security Operations Dashboard
 * Frontend controller for OPNsense security audit operations
 */

(function() {
    'use strict';

    const API = {
        config: '/api/config',
        scan: {
            start: '/api/scan/start',
            status: '/api/scan/status', 
            cancel: '/api/scan/cancel',
            internal: '/api/scan/internal',
            internalStatus: '/api/scan/internal/status',
            internalCancel: '/api/scan/internal/cancel'
        },
        reports: '/api/reports',
        ignoreList: '/api/ignore-list',
        networks: '/api/networks/fetch',
        networkConfig: '/api/config/networks',
        securityScore: '/api/security-score',
        optimalConfig: '/api/optimal-config',
        translations: '/api/translations'
    };

    let state = {
        lang: localStorage.getItem('netsec_lang') || 'en',
        i18n: {},
        report: null,
        networks: [],
        scanPoll: null,
        internalPoll: null,
        logCount: 0,
        internalLogCount: 0
    };

    // DOM ready
    document.addEventListener('DOMContentLoaded', init);

    function init() {
        setupNav();
        setupEventHandlers();
        loadTranslations(state.lang);
        loadConfiguration();
        fetchReportList();
        fetchIgnoreList();
        fetchSecurityMetrics();
        fetchHardeningGuide();
        checkRunningScans();
        loadNetworkConfig();
    }

    // Navigation
    function setupNav() {
        document.querySelectorAll('.nav-item').forEach(el => {
            el.addEventListener('click', e => {
                e.preventDefault();
                switchPage(el.dataset.page);
            });
        });
    }

    function switchPage(name) {
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        
        const page = document.getElementById('page-' + name);
        const nav = document.querySelector('[data-page="' + name + '"]');
        
        if (page) page.classList.add('active');
        if (nav) nav.classList.add('active');
    }

    // Event handlers
    function setupEventHandlers() {
        document.getElementById('start-scan-btn').addEventListener('click', startSecurityScan);
        document.getElementById('save-config-btn').addEventListener('click', saveConfiguration);
        document.getElementById('refresh-btn').addEventListener('click', () => window.location.reload());
        document.getElementById('language-select').addEventListener('change', e => {
            state.lang = e.target.value;
            localStorage.setItem('netsec_lang', state.lang);
            loadTranslations(state.lang);
        });
    }

    // i18n
    async function loadTranslations(lang) {
        try {
            const res = await fetch(API.translations + '/' + lang);
            const data = await res.json();
            if (data.success) {
                state.i18n = data.translations;
                applyTranslations();
            }
        } catch (err) {
            console.warn('Translation load failed:', err);
        }
    }

    function applyTranslations() {
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.dataset.i18n;
            if (state.i18n[key]) el.textContent = state.i18n[key];
        });
        document.getElementById('language-select').value = state.lang;
    }

    function t(key) {
        return state.i18n[key] || key;
    }

    // Configuration
    async function loadConfiguration() {
        try {
            const res = await fetch(API.config);
            const data = await res.json();
            
            if (data.success) {
                document.getElementById('opnsense-host').value = data.opnsense.host || '';
                document.getElementById('api-key').value = data.opnsense.api_key || '';
                document.getElementById('api-secret').value = data.opnsense.api_secret || '';
                
                const opts = data.scan_options || {};
                document.getElementById('aggressive-scan').checked = !!opts.aggressive_scan;
                document.getElementById('port-scan-timeout').value = opts.port_scan_timeout || 300;
                document.getElementById('max-parallel-scans').value = opts.max_parallel_scans || 10;
                document.getElementById('enable-vulnerability-scan').checked = opts.enable_vulnerability_scan !== false;
            }
        } catch (err) {
            console.error('Config load error:', err);
        }
    }

    async function saveConfiguration() {
        const payload = {
            opnsense: {
                host: document.getElementById('opnsense-host').value.trim(),
                api_key: document.getElementById('api-key').value.trim(),
                api_secret: document.getElementById('api-secret').value.trim()
            },
            exceptions: {
                scan_options: {
                    aggressive_scan: document.getElementById('aggressive-scan').checked,
                    port_scan_timeout: parseInt(document.getElementById('port-scan-timeout').value, 10),
                    max_parallel_scans: parseInt(document.getElementById('max-parallel-scans').value, 10),
                    enable_vulnerability_scan: document.getElementById('enable-vulnerability-scan').checked
                }
            }
        };

        try {
            const res = await fetch(API.config, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            notify(data.success ? 'success' : 'error', data.message || (data.success ? 'Saved' : 'Error'));
        } catch (err) {
            notify('error', 'Failed to save configuration');
        }
    }

    // Security Scan
    async function startSecurityScan() {
        try {
            const res = await fetch(API.scan.start, { method: 'POST' });
            const data = await res.json();

            if (data.success) {
                showScanOverlay();
                pollScanProgress();
                notify('success', 'Scan initiated');
            } else {
                notify('error', data.error || 'Failed to start scan');
            }
        } catch (err) {
            notify('error', 'Connection error');
        }
    }

    function showScanOverlay() {
        document.getElementById('scan-progress-overlay').classList.remove('hidden');
        document.getElementById('scan-console-output').innerHTML = '';
        state.logCount = 0;
        updateStatusIndicator('running');
    }

    function hideScanOverlay() {
        document.getElementById('scan-progress-overlay').classList.add('hidden');
    }

    function pollScanProgress() {
        if (state.scanPoll) clearInterval(state.scanPoll);

        state.scanPoll = setInterval(async () => {
            try {
                const res = await fetch(API.scan.status);
                const data = await res.json();

                if (data.success) {
                    renderScanProgress(data);

                    if (['completed', 'failed', 'cancelled', 'idle'].includes(data.status)) {
                        clearInterval(state.scanPoll);
                        state.scanPoll = null;

                        setTimeout(() => {
                            hideScanOverlay();
                            if (data.status === 'completed') {
                                notify('success', 'Scan finished');
                                fetchReportList();
                                fetchSecurityMetrics();
                            } else if (data.status === 'failed') {
                                notify('error', 'Scan failed: ' + (data.error || 'Unknown'));
                            } else if (data.status === 'cancelled') {
                                notify('warning', 'Scan cancelled');
                            }
                        }, 1200);
                    }
                }
            } catch (err) {
                console.error('Poll error:', err);
            }
        }, 1000);
    }

    function renderScanProgress(data) {
        document.getElementById('progress-fill').style.width = data.progress + '%';
        document.getElementById('progress-percent').textContent = data.progress + '%';
        document.getElementById('progress-step').textContent = data.current_step || 'Processing...';
        document.getElementById('step-current').textContent = data.step_number || 0;
        document.getElementById('step-total').textContent = data.total_steps || 7;

        if (data.logs && data.logs.length > state.logCount) {
            appendConsoleLogs(data.logs.slice(state.logCount), 'scan-console-output');
            state.logCount = data.logs.length;
        }

        updateStatusIndicator(data.status);

        const cancelBtn = document.getElementById('cancel-scan-btn');
        if (cancelBtn) {
            cancelBtn.disabled = data.status !== 'running';
            if (data.status === 'cancelling') {
                cancelBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cancelling...';
                cancelBtn.disabled = true;
            }
        }
    }

    function appendConsoleLogs(logs, containerId) {
        const container = document.getElementById(containerId);
        logs.forEach(log => {
            const line = document.createElement('div');
            line.className = 'console-line ' + log.level;
            line.innerHTML = '<span class="timestamp">[' + log.timestamp + ']</span> ' + escapeHtml(log.message);
            container.appendChild(line);
        });
        container.scrollTop = container.scrollHeight;
    }

    function updateStatusIndicator(status) {
        const indicator = document.getElementById('scan-status-indicator');
        const textEl = document.getElementById('scan-status-text');
        
        indicator.className = '';
        
        switch (status) {
            case 'running':
            case 'cancelling':
                indicator.classList.add('status-running');
                textEl.textContent = status === 'cancelling' ? 'Stopping...' : 'Running';
                break;
            case 'completed':
                indicator.classList.add('status-completed');
                textEl.textContent = 'Completed';
                break;
            case 'failed':
            case 'cancelled':
                indicator.classList.add('status-failed');
                textEl.textContent = status === 'cancelled' ? 'Cancelled' : 'Failed';
                break;
            default:
                indicator.classList.add('status-idle');
                textEl.textContent = 'Idle';
        }
    }

    window.cancelScan = async function() {
        const btn = document.getElementById('cancel-scan-btn');
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Stopping...';

        try {
            const res = await fetch(API.scan.cancel, { method: 'POST' });
            const data = await res.json();
            if (!data.success) {
                notify('error', data.error || 'Cancel failed');
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-times"></i> Cancel';
            }
        } catch (err) {
            notify('error', 'Cancel request failed');
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-times"></i> Cancel';
        }
    };

    async function checkRunningScans() {
        try {
            const res = await fetch(API.scan.status);
            const data = await res.json();
            if (data.success && data.status === 'running') {
                showScanOverlay();
                renderScanProgress(data);
                pollScanProgress();
            }
        } catch (err) {
            // ignore
        }
    }

    // Reports
    async function fetchReportList() {
        try {
            const res = await fetch(API.reports);
            const data = await res.json();

            if (data.success && data.reports.length > 0) {
                loadReport(data.reports[0].filename);
                renderReportList(data.reports);
            }
        } catch (err) {
            console.error('Reports fetch error:', err);
        }
    }

    async function loadReport(filename) {
        try {
            const res = await fetch(API.reports + '/' + filename);
            const data = await res.json();
            if (data.success) {
                state.report = data.report;
                renderFindings(data.report);
            }
        } catch (err) {
            console.error('Report load error:', err);
        }
    }

    function renderFindings(report) {
        const findings = [
            ...(report.firewall_findings || []),
            ...(report.port_findings || []),
            ...(report.dns_findings || []),
            ...(report.vlan_findings || []),
            ...(report.vulnerability_findings || []),
            ...(report.system_findings || [])
        ];

        const grouped = { critical: [], high: [], medium: [], low: [] };

        findings.forEach(f => {
            const sev = (f.severity || 'LOW').toLowerCase();
            if (grouped[sev]) grouped[sev].push(f);
        });

        ['critical', 'high', 'medium', 'low'].forEach(sev => {
            document.getElementById(sev + '-count').textContent = grouped[sev].length;
            document.getElementById(sev + '-badge').textContent = grouped[sev].length;
            document.getElementById(sev + '-findings').innerHTML = grouped[sev].map(f => buildFindingCard(f)).join('');
        });
    }

    function buildFindingCard(finding) {
        const ifaceTag = finding.interface 
            ? '<span class="interface-tag">' + finding.interface + '</span>' 
            : '';

        const pathRow = finding.opnsense_path
            ? '<div class="detail-row"><span class="detail-label">Path:</span><span class="detail-value path-value">' + finding.opnsense_path + '</span></div>'
            : '';

        const steps = (finding.implementation_steps && finding.implementation_steps.length)
            ? '<div class="implementation-steps"><div class="steps-header" onclick="toggleSteps(this)"><strong>Implementation Guide</strong><i class="fas fa-chevron-down"></i></div><div class="steps-content hidden"><ol class="steps-list">' + finding.implementation_steps.map(s => '<li>' + s + '</li>').join('') + '</ol></div></div>'
            : '';

        const solution = finding.solution
            ? '<div class="solution-box"><strong>Recommendation</strong>' + finding.solution + '</div>'
            : '';

        return '<div class="finding-item"><div class="finding-header"><div class="finding-title">' + ifaceTag + (finding.issue || finding.title || 'Issue') + '</div><div class="finding-actions"><button class="btn btn-small btn-secondary" onclick=\'addToExclusions(' + JSON.stringify(finding).replace(/'/g, "\\'") + ')\'>' + t('add_to_ignore') + '</button></div></div><div class="finding-details">' + pathRow + '<div class="detail-row"><span class="detail-label">Details:</span><span class="detail-value">' + (finding.reason || finding.description || '') + '</span></div></div>' + solution + steps + '</div>';
    }

    window.toggleSteps = function(el) {
        const content = el.nextElementSibling;
        const icon = el.querySelector('i');
        content.classList.toggle('hidden');
        icon.classList.toggle('fa-chevron-down');
        icon.classList.toggle('fa-chevron-up');
    };

    function renderReportList(reports) {
        const container = document.getElementById('reports-list');
        container.innerHTML = reports.map(r => {
            const ts = new Date(r.created).toLocaleString();
            return '<div class="report-item"><div class="report-info"><h4>' + r.timestamp + '</h4><div class="report-meta">' + ts + '</div></div><div class="report-actions"><button class="btn btn-small btn-secondary" onclick="loadReport(\'' + r.filename + '\')"><i class="fas fa-eye"></i> View</button><a href="' + API.reports + '/' + r.filename + '/download" class="btn btn-small btn-secondary"><i class="fas fa-download"></i> Download</a></div></div>';
        }).join('');
    }

    window.loadReport = loadReport;

    // Ignore List / Exclusions
    async function fetchIgnoreList() {
        try {
            const res = await fetch(API.ignoreList);
            const data = await res.json();
            if (data.success) renderIgnoreList(data.ignore_list);
        } catch (err) {
            console.error('Ignore list fetch error:', err);
        }
    }

    function renderIgnoreList(list) {
        const cats = ['ports', 'firewall', 'dns', 'hosts'];
        cats.forEach(cat => {
            const container = document.getElementById('ignore-' + cat + '-list');
            if (!container) return;
            const items = list[cat] || list[cat + '_rules'] || [];
            container.innerHTML = items.map((item, idx) => 
                '<div class="ignore-item"><div>' + JSON.stringify(item) + '</div><button class="btn btn-small btn-danger" onclick="removeExclusion(\'' + cat + '\',' + idx + ')"><i class="fas fa-trash"></i></button></div>'
            ).join('') || '<div class="text-muted text-center">No exclusions</div>';
        });
    }

    window.addToExclusions = async function(finding) {
        const item = {
            port: finding.port,
            host: finding.host,
            reason: finding.issue
        };

        try {
            const res = await fetch(API.ignoreList + '/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ category: 'ports', item })
            });
            const data = await res.json();
            notify(data.success ? 'success' : 'error', data.message || 'Done');
            if (data.success) fetchIgnoreList();
        } catch (err) {
            notify('error', 'Failed to add exclusion');
        }
    };

    window.removeExclusion = async function(category, index) {
        try {
            const res = await fetch(API.ignoreList + '/remove', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ category, index })
            });
            const data = await res.json();
            notify(data.success ? 'success' : 'error', data.message || 'Done');
            if (data.success) fetchIgnoreList();
        } catch (err) {
            notify('error', 'Failed to remove exclusion');
        }
    };

    // Security Score
    async function fetchSecurityMetrics() {
        try {
            const res = await fetch(API.securityScore);
            const data = await res.json();
            if (data.success) renderSecurityScore(data);
        } catch (err) {
            console.error('Security score fetch error:', err);
        }
    }

    function renderSecurityScore(data) {
        const scoreEl = document.getElementById('security-score');
        const gradeEl = document.getElementById('security-grade');
        const circleEl = document.getElementById('score-circle');
        const timestampEl = document.getElementById('score-timestamp');
        const actionsList = document.getElementById('priority-actions-list');

        if (data.score !== null && data.score !== undefined) {
            scoreEl.textContent = data.score;
            gradeEl.textContent = 'Grade: ' + data.grade;

            const gradeClass = 'grade-' + data.grade.toLowerCase();
            circleEl.className = 'score-circle ' + gradeClass;
            circleEl.style.setProperty('--score', data.score);
            gradeEl.className = 'grade ' + gradeClass;

            if (data.timestamp) {
                timestampEl.textContent = 'Last scan: ' + data.timestamp;
            }

            if (data.priority_actions && data.priority_actions.length > 0) {
                actionsList.innerHTML = data.priority_actions.map(action => {
                    const sev = action.severity.toLowerCase();
                    return '<li class="' + sev + '"><span class="action-severity">' + action.severity + '</span>' + (action.issue || action.action) + '</li>';
                }).join('');
            } else {
                actionsList.innerHTML = '<li class="low">No critical actions pending</li>';
            }
        } else {
            scoreEl.textContent = '--';
            gradeEl.textContent = 'N/A';
            timestampEl.textContent = 'Run a scan to generate metrics';
            actionsList.innerHTML = '<li class="medium">Execute security scan to view priorities</li>';
        }
    }

    // Hardening Guide (Optimal Config)
    async function fetchHardeningGuide() {
        try {
            const res = await fetch(API.optimalConfig);
            const data = await res.json();
            if (data.success) renderHardeningGuide(data.recommendations);
        } catch (err) {
            console.error('Hardening guide fetch error:', err);
        }
    }

    function renderHardeningGuide(rec) {
        // Implementation phases
        const phasesEl = document.getElementById('implementation-phases');
        if (rec.implementation_guide && phasesEl) {
            phasesEl.innerHTML = rec.implementation_guide.map(phase => 
                '<div class="phase-card"><div class="phase-header"><span class="phase-title">Phase ' + phase.phase + ': ' + phase.title + '</span><span class="phase-duration">' + phase.duration + '</span></div><ul class="phase-steps">' + phase.steps.map(s => '<li>' + s + '</li>').join('') + '</ul></div>'
            ).join('');
        }

        // Category recommendations
        if (rec.categories) {
            renderCategoryRecs('firewall', rec.categories.firewall);
            renderCategoryRecs('dns', rec.categories.dns);
            renderCategoryRecs('network', rec.categories.network);
            renderCategoryRecs('system', rec.categories.system);
            renderCategoryRecs('monitoring', rec.categories.monitoring);
        }

        // Config summary
        const configEl = document.getElementById('optimal-config-details');
        if (rec.optimal_config && configEl) {
            configEl.innerHTML = Object.entries(rec.optimal_config).map(([cat, settings]) => {
                const rows = Object.entries(settings).map(([k, v]) => 
                    '<li><span class="config-key">' + formatLabel(k) + '</span><span class="config-value">' + v + '</span></li>'
                ).join('');
                return '<div class="config-category-card"><h5>' + formatLabel(cat) + '</h5><ul>' + rows + '</ul></div>';
            }).join('');
        }
    }

    function renderCategoryRecs(category, data) {
        const container = document.getElementById(category + '-recommendations');
        if (!container || !data) return;

        let html = '';
        if (data.recommendations) {
            html = data.recommendations.map(rec => {
                const steps = rec.steps 
                    ? '<ol class="recommendation-steps">' + rec.steps.map(s => '<li>' + s + '</li>').join('') + '</ol>' 
                    : '';
                return '<div class="recommendation-item"><h5>' + (rec.setting || rec.name) + '</h5>' + (rec.description ? '<p>' + rec.description + '</p>' : '') + steps + '</div>';
            }).join('');
        }

        if (category === 'network' && data.recommended_vlan_structure) {
            html += '<div class="recommendation-item"><h5>VLAN Structure</h5><table style="width:100%;border-collapse:collapse;margin-top:.5rem;font-size:.85rem"><tr style="background:var(--bg-elevated)"><th style="padding:.5rem;text-align:left;border:1px solid var(--border-dim)">ID</th><th style="padding:.5rem;text-align:left;border:1px solid var(--border-dim)">Name</th><th style="padding:.5rem;text-align:left;border:1px solid var(--border-dim)">Purpose</th></tr>' + data.recommended_vlan_structure.map(v => '<tr><td style="padding:.5rem;border:1px solid var(--border-dim)">' + v.vlan_id + '</td><td style="padding:.5rem;border:1px solid var(--border-dim)">' + v.name + '</td><td style="padding:.5rem;border:1px solid var(--border-dim)">' + v.purpose + '</td></tr>').join('') + '</table></div>';
        }

        container.innerHTML = html || '<p class="text-muted" style="padding:1rem">No specific recommendations</p>';
    }

    function formatLabel(str) {
        return str.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    }

    // Network Classification
    window.loadNetworksFromOPNsense = async function() {
        const btn = document.getElementById('load-networks-btn');
        const loader = document.getElementById('networks-loading');
        const noNetMsg = document.getElementById('no-networks-msg');
        const listEl = document.getElementById('networks-list');
        const actionsEl = document.getElementById('network-actions');

        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
        loader.classList.remove('hidden');
        noNetMsg.classList.add('hidden');

        try {
            const res = await fetch(API.networks);
            const data = await res.json();

            if (data.success && data.networks) {
                state.networks = data.networks;
                renderNetworkList(data.networks);
                listEl.classList.remove('hidden');
                actionsEl.classList.remove('hidden');
                notify('success', 'Loaded ' + data.networks.length + ' networks');
            } else {
                notify('error', data.error || 'Failed to load networks');
                noNetMsg.classList.remove('hidden');
            }
        } catch (err) {
            notify('error', 'Connection failed');
            noNetMsg.classList.remove('hidden');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-sync"></i> Load Networks from OPNsense';
            loader.classList.add('hidden');
        }
    };

    function renderNetworkList(networks) {
        const container = document.getElementById('networks-list');
        container.innerHTML = networks.map((net, idx) => {
            const typeClass = net.type || 'unset';
            const disabledClass = net.enabled ? '' : 'disabled-iface';
            const vlanTag = net.vlan_tag ? '<span><i class="fas fa-tag"></i> VLAN ' + net.vlan_tag + '</span>' : '';
            const gwInfo = net.gateway ? '<span><i class="fas fa-door-open"></i> GW: ' + net.gateway + '</span>' : '';
            const disabledBadge = !net.enabled ? '<span class="disabled-badge">Disabled</span>' : '';

            return '<div class="network-item ' + typeClass + ' ' + disabledClass + '" data-index="' + idx + '"><div class="network-info"><div class="network-name">' + (net.name || net.interface) + disabledBadge + '</div><div class="network-details"><span><i class="fas fa-network-wired"></i> ' + (net.network || 'N/A') + '</span><span><i class="fas fa-ethernet"></i> ' + net.interface + '</span>' + vlanTag + gwInfo + '</div></div><div class="network-type-selector"><button class="type-btn ignore ' + (!net.type ? 'active' : '') + '" onclick="setNetType(' + idx + ',null)">Ignore</button><button class="type-btn wan ' + (net.type === 'wan' ? 'active' : '') + '" onclick="setNetType(' + idx + ',\'wan\')">WAN</button><button class="type-btn lan ' + (net.type === 'lan' ? 'active' : '') + '" onclick="setNetType(' + idx + ',\'lan\')">LAN</button><button class="type-btn vlan ' + (net.type === 'vlan' ? 'active' : '') + '" onclick="setNetType(' + idx + ',\'vlan\')">VLAN</button></div></div>';
        }).join('');
    }

    window.setNetType = function(idx, type) {
        state.networks[idx].type = type;
        renderNetworkList(state.networks);
    };

    window.saveNetworkClassification = async function() {
        try {
            const res = await fetch(API.networkConfig, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ networks: state.networks })
            });
            const data = await res.json();
            notify(data.success ? 'success' : 'error', data.success ? 'Network config saved' : (data.error || 'Save failed'));
        } catch (err) {
            notify('error', 'Failed to save network config');
        }
    };

    async function loadNetworkConfig() {
        try {
            const res = await fetch(API.networkConfig);
            const data = await res.json();

            if (data.success && data.networks && data.networks.length > 0) {
                state.networks = data.networks;
                renderNetworkList(data.networks);
                document.getElementById('networks-list').classList.remove('hidden');
                document.getElementById('network-actions').classList.remove('hidden');
                document.getElementById('no-networks-msg').classList.add('hidden');
            }
        } catch (err) {
            // No saved config
        }
    }

    // Internal Device Scan
    window.scanInternalDevices = async function() {
        const btn = document.getElementById('scan-internal-btn');
        const progressDiv = document.getElementById('devices-scan-progress');
        const statusText = document.getElementById('devices-scan-status');
        const noDevMsg = document.getElementById('no-devices-msg');
        const summaryDiv = document.getElementById('devices-summary');
        const tableContainer = document.getElementById('devices-table-container');
        const consoleDiv = document.getElementById('internal-scan-console');
        const hostsList = document.getElementById('discovered-hosts-list');

        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        progressDiv.classList.remove('hidden');
        noDevMsg.classList.add('hidden');
        summaryDiv.classList.add('hidden');
        tableContainer.classList.add('hidden');
        statusText.textContent = 'Starting scan...';
        consoleDiv.innerHTML = '';
        hostsList.innerHTML = '<div class="no-hosts-yet">Waiting for host discovery...</div>';
        state.internalLogCount = 0;

        try {
            const res = await fetch(API.scan.internal, { method: 'POST' });
            const data = await res.json();

            if (data.success) {
                pollInternalScan();
            } else {
                notify('error', data.error || 'Failed to start scan');
                resetInternalScanUI();
            }
        } catch (err) {
            notify('error', 'Failed to start internal scan');
            resetInternalScanUI();
        }
    };

    window.cancelInternalScan = async function() {
        try {
            await fetch(API.scan.internalCancel, { method: 'POST' });
            notify('info', 'Scan cancelled');
            resetInternalScanUI();
        } catch (err) {
            notify('error', 'Failed to cancel scan');
        }
    };

    function pollInternalScan() {
        if (state.internalPoll) clearInterval(state.internalPoll);

        state.internalPoll = setInterval(async () => {
            try {
                const res = await fetch(API.scan.internalStatus);
                const data = await res.json();

                updateInternalScanUI(data);

                if (['completed', 'failed', 'idle'].includes(data.status)) {
                    clearInterval(state.internalPoll);
                    state.internalPoll = null;

                    if (data.status === 'completed') {
                        notify('success', 'Internal scan completed');
                        renderDeviceResults(data.devices || []);
                    } else if (data.status === 'failed') {
                        notify('error', 'Scan failed: ' + (data.error || 'Unknown'));
                    }
                    resetInternalScanUI();
                }
            } catch (err) {
                console.error('Internal poll error:', err);
            }
        }, 1500);
    }

    function updateInternalScanUI(data) {
        document.getElementById('devices-scan-status').textContent = data.current_step || 'Scanning...';
        document.getElementById('devices-progress-text').textContent = data.current_step || 'Scanning...';
        document.getElementById('devices-hosts-progress').textContent = (data.scanned_hosts || 0) + ' / ' + (data.total_hosts || 0) + ' hosts';

        const pct = data.total_hosts > 0 ? Math.round((data.scanned_hosts / data.total_hosts) * 100) : 0;
        document.getElementById('devices-progress-fill').style.width = pct + '%';

        // Update console
        if (data.logs && data.logs.length > state.internalLogCount) {
            const consoleDiv = document.getElementById('internal-scan-console');
            data.logs.slice(state.internalLogCount).forEach(log => {
                const line = document.createElement('div');
                line.className = 'console-line console-' + log.level;
                line.innerHTML = '<span class="console-time">[' + log.timestamp + ']</span>' + escapeHtml(log.message);
                consoleDiv.appendChild(line);
            });
            consoleDiv.scrollTop = consoleDiv.scrollHeight;
            state.internalLogCount = data.logs.length;
        }

        // Update discovered hosts
        if (data.discovered_hosts && data.discovered_hosts.length > 0) {
            const hostsList = document.getElementById('discovered-hosts-list');
            hostsList.innerHTML = data.discovered_hosts.map(h => {
                const statusClass = h.status === 'completed' ? 'completed' : 'pending';
                const portsLabel = h.status === 'completed' ? (h.open_ports || 0) + ' ports' : 'scanning...';
                const portsClass = h.status === 'completed' ? '' : 'scanning';
                return '<div class="discovered-host ' + statusClass + '"><span class="host-ip">' + h.ip + '</span><span class="host-name">' + (h.hostname || '') + '</span><span class="host-ports ' + portsClass + '">' + portsLabel + '</span></div>';
            }).join('');
        }
    }

    function renderDeviceResults(devices) {
        const summaryDiv = document.getElementById('devices-summary');
        const tableContainer = document.getElementById('devices-table-container');
        const tbody = document.getElementById('devices-table-body');

        const totalPorts = devices.reduce((sum, d) => sum + (d.open_ports ? d.open_ports.length : 0), 0);
        const activeDevices = devices.filter(d => d.status === 'active').length;

        document.getElementById('total-devices-count').textContent = devices.length;
        document.getElementById('active-devices-count').textContent = activeDevices;
        document.getElementById('total-ports-count').textContent = totalPorts;

        summaryDiv.classList.remove('hidden');
        tableContainer.classList.remove('hidden');

        tbody.innerHTML = devices.map(d => {
            const statusClass = d.status === 'active' ? 'status-active' : 'status-inactive';
            const ports = (d.open_ports || []).slice(0, 10).map(p => {
                const critPorts = [21, 22, 23, 3389, 5900];
                const isCrit = critPorts.includes(p);
                return '<span class="port-badge' + (isCrit ? ' critical' : '') + '">' + p + '</span>';
            }).join('') + (d.open_ports && d.open_ports.length > 10 ? '<span class="port-badge">+' + (d.open_ports.length - 10) + '</span>' : '');

            return '<tr><td style="font-family:var(--ff-mono)">' + d.ip + '</td><td>' + (d.hostname || '-') + '</td><td style="font-family:var(--ff-mono);font-size:.8rem">' + (d.mac || '-') + '</td><td>' + (d.network || d.vlan || '-') + '</td><td class="' + statusClass + '">' + d.status + '</td><td><div class="port-list">' + (ports || '-') + '</div></td></tr>';
        }).join('');
    }

    function resetInternalScanUI() {
        const btn = document.getElementById('scan-internal-btn');
        btn.disabled = false;
        btn.innerHTML = '<i class="fas fa-search"></i> Scan Internal Networks';
        document.getElementById('devices-scan-progress').classList.add('hidden');
    }

    // Utilities
    function notify(type, message) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast ' + type;
        toast.innerHTML = '<div>' + message + '</div>';
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

})();
