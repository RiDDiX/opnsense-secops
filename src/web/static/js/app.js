/**
 * OPNsense Security Auditor - Dashboard Controller
 * Real-time security audit with live progress tracking
 */
(function() {
    'use strict';

    const API = {
        config: '/api/config',
        testConnection: '/api/connection/test',
        scan: {
            start: '/api/scan/start',
            status: '/api/scan/status',
            cancel: '/api/scan/cancel'
        },
        results: '/api/results/latest',
        rawData: '/api/data/raw',
        history: '/api/reports/history',
        ignoreFinding: '/api/ignore-list/add-finding',
        internalScan: '/api/scan/internal/status'
    };

    let state = {
        scanning: false,
        pollInterval: null,
        results: null,
        config: null,
        scanStartTime: null,
        lastLogIndex: 0,
        currentFinding: null,
        reportFile: null
    };

    // Initialize
    document.addEventListener('DOMContentLoaded', init);

    function init() {
        setupNavigation();
        setupEventListeners();
        loadConfig();
        loadLatestResults();
        checkScanStatus();
    }

    // Navigation
    function setupNavigation() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                const view = item.dataset.view;
                switchView(view);
            });
        });

        document.querySelectorAll('[data-view]').forEach(link => {
            link.addEventListener('click', (e) => {
                if (link.tagName === 'A') e.preventDefault();
                switchView(link.dataset.view);
            });
        });
    }

    function switchView(viewName) {
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

        const navItem = document.querySelector(`[data-view="${viewName}"]`);
        const view = document.getElementById(`view-${viewName}`);

        if (navItem) navItem.classList.add('active');
        if (view) view.classList.add('active');

        updateViewTitle(viewName);
    }

    function updateViewTitle(viewName) {
        const titles = {
            dashboard: 'Security Dashboard',
            findings: 'Alle Findings',
            firewall: 'Firewall Analyse',
            dns: 'DNS Sicherheit',
            system: 'System Sicherheit',
            network: 'Netzwerk-Geräte',
            config: 'Konfiguration'
        };
        document.getElementById('view-title').textContent = titles[viewName] || viewName;
    }

    // Event Listeners
    function setupEventListeners() {
        document.getElementById('btn-start-scan').addEventListener('click', startScan);
        document.getElementById('btn-cancel-scan').addEventListener('click', cancelScan);
        document.getElementById('btn-refresh').addEventListener('click', () => loadLatestResults());
        document.getElementById('btn-test-connection').addEventListener('click', testConnection);
        document.getElementById('btn-save-config').addEventListener('click', saveConfig);
        document.getElementById('modal-close').addEventListener('click', closeModal);
        document.querySelector('.modal-backdrop').addEventListener('click', closeModal);
        document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

        // Filters
        document.getElementById('filter-severity').addEventListener('change', applyFilters);
        document.getElementById('filter-category').addEventListener('change', applyFilters);
        document.getElementById('filter-search').addEventListener('input', applyFilters);

        // Download report
        document.getElementById('btn-download-report').addEventListener('click', downloadReport);

        // Exclude finding from modal
        document.getElementById('btn-exclude-finding').addEventListener('click', excludeCurrentFinding);

        // Device search
        const deviceSearch = document.getElementById('device-search');
        if (deviceSearch) deviceSearch.addEventListener('input', filterDevices);
    }

    // Config Management
    async function loadConfig() {
        try {
            const res = await fetch(API.config);
            const data = await res.json();
            if (data.success && data.opnsense) {
                state.config = data.opnsense;
                document.getElementById('cfg-host').value = data.opnsense.host || '';
                document.getElementById('cfg-apikey').value = data.opnsense.api_key || '';
                document.getElementById('cfg-apisecret').value = data.opnsense.api_secret || '';
                document.getElementById('opnsense-host').textContent = data.opnsense.host || 'Nicht konfiguriert';
                updateConnectionStatus(false);
            }
        } catch (err) {
            console.error('Config load failed:', err);
        }
    }

    async function saveConfig() {
        const config = {
            host: document.getElementById('cfg-host').value,
            api_key: document.getElementById('cfg-apikey').value,
            api_secret: document.getElementById('cfg-apisecret').value
        };

        try {
            const res = await fetch(API.config, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ opnsense: config })
            });
            const data = await res.json();
            if (data.success) {
                showConnectionResult('Konfiguration gespeichert', 'success');
                state.config = config;
                document.getElementById('opnsense-host').textContent = config.host;
            } else {
                showConnectionResult(data.error || 'Speichern fehlgeschlagen', 'error');
            }
        } catch (err) {
            showConnectionResult('Netzwerkfehler: ' + err.message, 'error');
        }
    }

    async function testConnection() {
        const btn = document.getElementById('btn-test-connection');
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Teste...';

        const config = {
            host: document.getElementById('cfg-host').value,
            api_key: document.getElementById('cfg-apikey').value,
            api_secret: document.getElementById('cfg-apisecret').value
        };

        try {
            const res = await fetch(API.testConnection, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });
            const data = await res.json();
            if (data.success) {
                showConnectionResult(`Verbunden! OPNsense ${data.version || ''}`, 'success');
                updateConnectionStatus(true);
            } else {
                showConnectionResult(data.error || 'Verbindung fehlgeschlagen', 'error');
                updateConnectionStatus(false);
            }
        } catch (err) {
            showConnectionResult('Netzwerkfehler: ' + err.message, 'error');
            updateConnectionStatus(false);
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="fas fa-plug"></i> Verbindung testen';
        }
    }

    function showConnectionResult(msg, type) {
        const el = document.getElementById('connection-result');
        el.textContent = msg;
        el.className = 'connection-result ' + type;
        el.classList.remove('hidden');
    }

    function updateConnectionStatus(online) {
        const el = document.getElementById('connection-status');
        const dot = el.querySelector('.status-dot');
        const text = el.querySelector('span:last-child');
        if (online) {
            dot.classList.add('online');
            text.textContent = 'Verbunden';
        } else {
            dot.classList.remove('online');
            text.textContent = 'Nicht verbunden';
        }
    }

    // Scan Management
    async function startScan() {
        if (state.scanning) return;

        state.scanning = true;
        state.scanStartTime = Date.now();
        state.lastLogIndex = 0;
        showScanPanel();
        clearScanLog();
        addScanLog('info', 'Security Scan wird gestartet...');

        try {
            const res = await fetch(API.scan.start, { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                addScanLog('success', 'Scan erfolgreich gestartet');
                startScanPolling();
            } else {
                addScanLog('error', 'Start fehlgeschlagen: ' + (data.error || 'Unbekannter Fehler'));
                hideScanPanel();
                state.scanning = false;
            }
        } catch (err) {
            addScanLog('error', 'Netzwerkfehler: ' + err.message);
            hideScanPanel();
            state.scanning = false;
        }
    }

    async function cancelScan() {
        try {
            await fetch(API.scan.cancel, { method: 'POST' });
            addScanLog('warning', 'Scan wird abgebrochen...');
        } catch (err) {
            console.error('Cancel failed:', err);
        }
    }

    function startScanPolling() {
        if (state.pollInterval) clearInterval(state.pollInterval);
        state.pollInterval = setInterval(pollScanStatus, 500);
    }

    function stopScanPolling() {
        if (state.pollInterval) {
            clearInterval(state.pollInterval);
            state.pollInterval = null;
        }
    }

    async function pollScanStatus() {
        try {
            const res = await fetch(API.scan.status);
            const data = await res.json();

            updateScanProgress(data);

            // Process new log entries since last poll
            if (data.logs && data.logs.length > state.lastLogIndex) {
                const newLogs = data.logs.slice(state.lastLogIndex);
                newLogs.forEach(log => addScanLogEntry(log));
                state.lastLogIndex = data.logs.length;
            }

            if (data.status === 'completed') {
                stopScanPolling();
                state.scanning = false;
                addScanLog('success', 'Scan abgeschlossen!');
                setTimeout(() => {
                    hideScanPanel();
                    loadLatestResults();
                }, 1500);
            } else if (data.status === 'failed' || data.status === 'cancelled') {
                stopScanPolling();
                state.scanning = false;
                addScanLog('error', data.error || 'Scan abgebrochen');
                setTimeout(hideScanPanel, 2000);
            }
        } catch (err) {
            console.error('Poll failed:', err);
        }
    }

    async function checkScanStatus() {
        try {
            const res = await fetch(API.scan.status);
            const data = await res.json();
            if (data.status === 'running') {
                state.scanning = true;
                state.scanStartTime = Date.now();
                showScanPanel();
                startScanPolling();
            }
        } catch (err) {
            console.error('Status check failed:', err);
        }
    }

    function updateScanProgress(data) {
        const progress = data.progress || 0;
        document.getElementById('scan-progress-fill').style.width = progress + '%';
        document.getElementById('scan-progress-text').textContent = progress + '%';
        
        const currentCheck = document.getElementById('scan-current-check');
        currentCheck.innerHTML = `<i class="fas fa-circle-notch fa-spin"></i> <span>${data.current_step || 'Verarbeite...'}</span>`;

        // Update duration
        if (state.scanStartTime) {
            const duration = Math.floor((Date.now() - state.scanStartTime) / 1000);
            document.getElementById('stat-duration').textContent = duration + 's';
        }
    }

    function showScanPanel() {
        document.getElementById('scan-panel').classList.remove('hidden');
        document.getElementById('btn-start-scan').disabled = true;
    }

    function hideScanPanel() {
        document.getElementById('scan-panel').classList.add('hidden');
        document.getElementById('btn-start-scan').disabled = false;
    }

    function clearScanLog() {
        document.getElementById('scan-log').innerHTML = '';
    }

    function addScanLog(level, message) {
        const time = new Date().toLocaleTimeString('de-DE');
        addScanLogEntry({ timestamp: time, level, message });
    }

    function addScanLogEntry(log) {
        const logEl = document.getElementById('scan-log');
        const entry = document.createElement('div');
        entry.className = 'log-entry ' + log.level;
        entry.dataset.logId = `${log.timestamp}-${log.message.substring(0,20)}`;
        entry.innerHTML = `
            <span class="log-time">${log.timestamp}</span>
            <span class="log-msg">${escapeHtml(log.message)}</span>
        `;
        logEl.appendChild(entry);
        logEl.scrollTop = logEl.scrollHeight;
    }

    // Results
    async function loadLatestResults() {
        try {
            const res = await fetch(API.results);
            const data = await res.json();
            if (data.success && data.results) {
                state.results = data.results;
                state.reportFile = data.report_file || null;
                renderDashboard(data.results);
                renderFindings(data.results);
                renderFirewallView(data.results);
                renderDnsView(data.results);
                renderSystemView(data.results);
                renderNetworkDevices(data.results);
                updateConnectionStatus(true);
                loadScanHistory();
                // Show download button if we have results
                const dlBtn = document.getElementById('btn-download-report');
                if (dlBtn) dlBtn.style.display = state.reportFile ? '' : 'none';
            }
        } catch (err) {
            console.error('Load results failed:', err);
        }
    }

    function renderDashboard(results) {
        // Security Score
        const score = results.security_score || 0;
        const grade = results.security_grade || '--';
        
        document.getElementById('security-score').textContent = score;
        document.getElementById('security-grade').textContent = grade;
        
        // Animate score ring
        const circle = document.getElementById('score-circle');
        const circumference = 2 * Math.PI * 45;
        const offset = circumference - (score / 100) * circumference;
        circle.style.strokeDashoffset = offset;

        // Set color based on score
        let color = '#ff6b6b';
        if (score >= 80) color = '#69db7c';
        else if (score >= 60) color = '#ffd43b';
        else if (score >= 40) color = '#ffa94d';
        circle.style.stroke = color;
        document.getElementById('security-grade').style.color = color;

        // Category Scores
        const catScores = results.category_scores || {};
        setBreakdownScore('firewall', catScores.firewall || 0);
        setBreakdownScore('dns', catScores.dns || 0);
        setBreakdownScore('system', catScores.system || 0);
        setBreakdownScore('vpn', catScores.vpn || 0);

        // Severity counts
        const counts = countSeverities(results);
        document.getElementById('count-critical').textContent = counts.critical;
        document.getElementById('count-high').textContent = counts.high;
        document.getElementById('count-medium').textContent = counts.medium;
        document.getElementById('count-low').textContent = counts.low;

        // Stats
        document.getElementById('stat-fw-rules').textContent = results.statistics?.firewall_rules || '--';
        document.getElementById('stat-nat-rules').textContent = results.statistics?.nat_rules || '--';
        document.getElementById('stat-interfaces').textContent = results.statistics?.interfaces || '--';
        document.getElementById('stat-last-scan').textContent = formatTimestamp(results.scan_timestamp);

        // Top findings
        renderTopFindings(results);
    }

    function setBreakdownScore(category, score) {
        const bar = document.getElementById(`score-${category}`);
        const val = document.getElementById(`score-${category}-val`);
        if (bar) {
            bar.style.width = score + '%';
            let color = '#ff6b6b';
            if (score >= 80) color = '#69db7c';
            else if (score >= 60) color = '#ffd43b';
            else if (score >= 40) color = '#ffa94d';
            bar.style.background = color;
        }
        if (val) val.textContent = score + '%';
    }

    function countSeverities(results) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        const allFindings = getAllFindings(results);
        allFindings.forEach(f => {
            const sev = (f.severity || '').toLowerCase();
            if (counts[sev] !== undefined) counts[sev]++;
        });
        return counts;
    }

    function getAllFindings(results) {
        return [
            ...(results.firewall_findings || []),
            ...(results.port_findings || []),
            ...(results.dns_findings || []),
            ...(results.system_findings || []),
            ...(results.vulnerability_findings || []),
            ...(results.vlan_findings || [])
        ];
    }

    function renderTopFindings(results) {
        const container = document.getElementById('top-findings-list');
        const allFindings = sortBySeverity(getAllFindings(results))
            .filter(f => ['critical', 'high'].includes((f.severity || '').toLowerCase()))
            .slice(0, 5);

        if (allFindings.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <i class="fas fa-check-circle"></i>
                    <p>Keine kritischen Findings</p>
                </div>
            `;
            return;
        }

        container.innerHTML = allFindings.map((f, i) => renderFindingItem(f, 'top_' + i)).join('');
        attachFindingListeners(container);
    }

    function sortBySeverity(findings) {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return [...findings].sort((a, b) => {
            return (severityOrder[(a.severity || '').toLowerCase()] || 4) - 
                   (severityOrder[(b.severity || '').toLowerCase()] || 4);
        });
    }

    function renderFindings(results) {
        const container = document.getElementById('all-findings-list');
        const allFindings = sortBySeverity(getAllFindings(results));

        if (allFindings.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <i class="fas fa-search"></i>
                    <p>Keine Findings vorhanden</p>
                </div>
            `;
            return;
        }

        container.innerHTML = allFindings.map((f, i) => renderFindingItem(f, 'all_' + i)).join('');
        attachFindingListeners(container);
    }

    function renderFindingItem(finding, key) {
        const severity = (finding.severity || 'low').toLowerCase();
        const title = finding.issue || finding.check || 'Unbekanntes Finding';
        const desc = finding.reason || finding.description || '';
        const path = finding.opnsense_path || '';

        // Store finding in global map, keyed by unique ID
        if (!window._findingsMap) window._findingsMap = {};
        window._findingsMap[key] = finding;

        return `
            <div class="finding-item ${severity}" data-finding-key="${key}">
                <div class="finding-severity-bar"></div>
                <span class="finding-badge">${severity}</span>
                <div class="finding-content">
                    <h4>${escapeHtml(title)}</h4>
                    <p>${escapeHtml(desc.substring(0, 120))}${desc.length > 120 ? '...' : ''}</p>
                    ${path ? `<div class="finding-path"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(path)}</div>` : ''}
                </div>
                <div class="finding-arrow"><i class="fas fa-chevron-right"></i></div>
            </div>
        `;
    }

    function getCategory(finding) {
        if (finding.rule_id || finding.rule_description) return 'Firewall';
        if (finding.wan_exposed || finding.details?.wan_exposed) return 'Firewall';
        if (finding.check?.includes('dns') || finding.check?.includes('unbound')) return 'DNS';
        if (finding.check?.includes('ssh') || finding.check?.includes('webgui') || finding.check?.includes('ids')) return 'System';
        if (finding.category?.toLowerCase().includes('vpn') || finding.check?.includes('vpn') || finding.check?.includes('wg_')) return 'VPN';
        if (finding.vlan_id !== undefined) return 'VLAN';
        if (finding.cve_id) return 'Vulnerability';
        return 'System';
    }

    function attachFindingListeners(container) {
        container.querySelectorAll('.finding-item').forEach(item => {
            item.addEventListener('click', () => {
                const key = item.dataset.findingKey;
                const finding = window._findingsMap && window._findingsMap[key];
                if (finding) showFindingDetail(finding);
            });
        });
    }

    function showFindingDetail(finding) {
        state.currentFinding = finding;
        const modal = document.getElementById('finding-modal');
        const title = document.getElementById('modal-title');
        const body = document.getElementById('modal-body');

        const severity = (finding.severity || 'low').toLowerCase();
        title.innerHTML = `<span class="finding-badge ${severity}" style="margin-right:10px">${severity.toUpperCase()}</span> ${escapeHtml(finding.issue || finding.check || 'Finding')}`;

        body.innerHTML = `
            ${finding.opnsense_path ? `
                <div class="detail-path">
                    <i class="fas fa-directions"></i> ${escapeHtml(finding.opnsense_path)}
                </div>
            ` : ''}
            
            <div class="detail-section">
                <h4>Problem</h4>
                <p>${escapeHtml(finding.reason || finding.description || 'Keine Details verfügbar')}</p>
            </div>
            
            <div class="detail-section">
                <h4>Lösung</h4>
                <p>${escapeHtml(finding.solution || 'Keine Lösung angegeben')}</p>
            </div>
            
            ${finding.implementation_steps ? `
                <div class="detail-section">
                    <h4>Umsetzung</h4>
                    <ol style="margin-left:20px; line-height:1.8">
                        ${finding.implementation_steps.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
                    </ol>
                </div>
            ` : ''}
            
            ${finding.details || finding.rule_details ? `
                <div class="detail-section">
                    <h4>Technische Details</h4>
                    <pre>${escapeHtml(JSON.stringify(finding.details || finding.rule_details, null, 2))}</pre>
                </div>
            ` : ''}
        `;

        modal.classList.remove('hidden');
    }

    function closeModal() {
        document.getElementById('finding-modal').classList.add('hidden');
    }

    // Firewall View
    function renderFirewallView(results) {
        const fwFindings = results.firewall_findings || [];
        const stats = results.statistics || {};

        document.getElementById('fw-total-rules').textContent = stats.firewall_rules || '--';
        document.getElementById('fw-problem-rules').textContent = fwFindings.length;
        
        const anyRules = fwFindings.filter(f => 
            f.issue?.toLowerCase().includes('any-to-any') || 
            f.check?.includes('any_to_any')
        ).length;
        document.getElementById('fw-any-rules').textContent = anyRules;

        const container = document.getElementById('fw-rules-list');
        if (fwFindings.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <i class="fas fa-check-circle"></i>
                    <p>Keine Firewall-Probleme gefunden</p>
                </div>
            `;
        } else {
            const sorted = sortBySeverity(fwFindings);
            container.innerHTML = sorted.map((f, i) => renderFindingItem(f, 'fw_' + i)).join('');
            attachFindingListeners(container);
        }
    }

    // DNS View
    function renderDnsView(results) {
        const dnsConfig = results.dns_config || {};
        const unbound = dnsConfig.unbound || {};

        const setStatus = (id, enabled) => {
            const el = document.getElementById(id);
            el.textContent = enabled ? 'Aktiviert' : 'Deaktiviert';
            el.className = 'status-value ' + (enabled ? 'enabled' : 'disabled');
        };

        setStatus('dns-dnssec', unbound.dnssec === '1' || unbound.dnssec === true);
        setStatus('dns-dot', unbound.dot === '1' || unbound.dot === true);
        setStatus('dns-rebind', unbound.private_domain === '1' || unbound.private_domain === true);

        // DNS Servers
        const servers = [
            ...(dnsConfig.system_dns || []),
            ...(dnsConfig.forward_servers || []).map(s => s.ip)
        ].filter(Boolean);

        const serverList = document.querySelector('#dns-servers-list .server-list');
        if (servers.length > 0) {
            serverList.innerHTML = servers.map(s => `
                <div class="status-card" style="margin-bottom:8px">
                    <div class="status-icon"><i class="fas fa-server"></i></div>
                    <div class="status-info">
                        <span class="status-value" style="font-family:var(--font-mono)">${escapeHtml(s)}</span>
                    </div>
                </div>
            `).join('');
        }
    }

    // System View
    function renderSystemView(results) {
        const sysFindings = results.system_findings || [];
        const container = document.getElementById('system-checks');

        if (sysFindings.length === 0) {
            container.innerHTML = `
                <div class="no-data" style="grid-column: 1/-1">
                    <i class="fas fa-check-circle"></i>
                    <p>Alle System-Checks bestanden</p>
                </div>
            `;
        } else {
            window._sysFindings = sysFindings;
            container.innerHTML = sysFindings.map((f, i) => `
                <div class="status-card" style="cursor:pointer" data-sys-index="${i}">
                    <div class="status-icon" style="background:${getSeverityBg(f.severity)};color:${getSeverityColor(f.severity)}">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="status-info">
                        <span class="status-label">${escapeHtml(f.category || 'System')}</span>
                        <span class="status-value">${escapeHtml(f.issue || f.check)}</span>
                    </div>
                </div>
            `).join('');
            container.querySelectorAll('[data-sys-index]').forEach(card => {
                card.addEventListener('click', () => {
                    const idx = parseInt(card.dataset.sysIndex, 10);
                    if (window._sysFindings[idx]) showFindingDetail(window._sysFindings[idx]);
                });
            });
        }
    }

    function getSeverityColor(sev) {
        const colors = { critical: '#ff6b6b', high: '#ffa94d', medium: '#ffd43b', low: '#69db7c' };
        return colors[(sev || '').toLowerCase()] || '#69db7c';
    }

    function getSeverityBg(sev) {
        const bgs = { 
            critical: 'rgba(255,107,107,0.1)', 
            high: 'rgba(255,169,77,0.1)', 
            medium: 'rgba(255,212,59,0.1)', 
            low: 'rgba(105,219,124,0.1)' 
        };
        return bgs[(sev || '').toLowerCase()] || 'rgba(105,219,124,0.1)';
    }

    // Filters
    function applyFilters() {
        if (!state.results) return;

        const severity = document.getElementById('filter-severity').value;
        const category = document.getElementById('filter-category').value;
        const search = document.getElementById('filter-search').value.toLowerCase();

        let findings = sortBySeverity(getAllFindings(state.results));

        if (severity !== 'all') {
            findings = findings.filter(f => (f.severity || '').toLowerCase() === severity);
        }
        if (category !== 'all') {
            findings = findings.filter(f => {
                const cat = getCategory(f).toLowerCase();
                return cat.includes(category);
            });
        }
        if (search) {
            findings = findings.filter(f => 
                (f.issue || '').toLowerCase().includes(search) ||
                (f.reason || '').toLowerCase().includes(search) ||
                (f.solution || '').toLowerCase().includes(search)
            );
        }

        const container = document.getElementById('all-findings-list');
        if (findings.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <i class="fas fa-search"></i>
                    <p>Keine Ergebnisse für Filter</p>
                </div>
            `;
        } else {
            container.innerHTML = findings.map((f, i) => renderFindingItem(f, 'filter_' + i)).join('');
            attachFindingListeners(container);
        }
    }

    // Utilities
    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function formatTimestamp(ts) {
        if (!ts) return '--';
        try {
            const date = new Date(ts);
            return date.toLocaleString('de-DE', { 
                day: '2-digit', 
                month: '2-digit', 
                hour: '2-digit', 
                minute: '2-digit' 
            });
        } catch {
            return ts;
        }
    }

    // === Report Download ===
    async function downloadReport() {
        if (!state.reportFile) return;
        try {
            window.open(`/api/reports/${state.reportFile}/html`, '_blank');
        } catch (err) {
            console.error('Download failed:', err);
        }
    }

    // === Exclude Finding ===
    async function excludeCurrentFinding() {
        if (!state.currentFinding) return;
        const reason = prompt('Grund f\u00fcr Ausschluss (optional):', 'Bewusst akzeptiertes Risiko');
        if (reason === null) return; // cancelled
        try {
            const res = await fetch(API.ignoreFinding, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ finding: state.currentFinding, reason: reason || 'Manuell ausgeschlossen' })
            });
            const data = await res.json();
            if (data.success) {
                closeModal();
                const badge = document.createElement('div');
                badge.className = 'scan-log';
                badge.style.cssText = 'position:fixed;bottom:20px;right:20px;background:#69db7c;color:#1a1a2e;padding:12px 20px;border-radius:8px;z-index:10000;font-weight:600';
                badge.textContent = '\u2713 Finding ausgeschlossen';
                document.body.appendChild(badge);
                setTimeout(() => badge.remove(), 3000);
            } else {
                alert('Fehler: ' + (data.error || 'Unbekannt'));
            }
        } catch (err) {
            alert('Fehler: ' + err.message);
        }
    }

    // === Scan History ===
    async function loadScanHistory() {
        try {
            const res = await fetch(API.history);
            const data = await res.json();
            if (data.success && data.history && data.history.length >= 2) {
                renderScanHistory(data.history);
            }
        } catch (err) {
            console.error('Load history failed:', err);
        }
    }

    function renderScanHistory(history) {
        const section = document.getElementById('scan-history-section');
        if (!section) return;
        section.style.display = '';

        // Render visual bar chart
        const chartEl = document.getElementById('history-chart');
        const maxScore = 100;
        const barWidth = Math.max(30, Math.min(60, Math.floor(600 / history.length)));
        
        let barsHtml = history.map((h, i) => {
            const score = h.score || 0;
            const height = Math.max(4, (score / maxScore) * 120);
            let color = '#ff6b6b';
            if (score >= 80) color = '#69db7c';
            else if (score >= 60) color = '#ffd43b';
            else if (score >= 40) color = '#ffa94d';
            const label = h.timestamp ? new Date(h.timestamp).toLocaleDateString('de-DE', {day:'2-digit',month:'2-digit'}) : `#${i+1}`;
            return `
                <div class="history-bar-col" style="text-align:center;flex:0 0 ${barWidth}px">
                    <div style="font-size:11px;color:var(--text-secondary);margin-bottom:4px">${score}</div>
                    <div style="height:${height}px;background:${color};border-radius:4px 4px 0 0;margin:0 4px;transition:height 0.3s"></div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:4px">${label}</div>
                </div>
            `;
        }).join('');

        chartEl.innerHTML = `
            <div style="display:flex;align-items:flex-end;justify-content:center;min-height:160px;padding:10px 0">
                ${barsHtml}
            </div>
        `;

        // Render table
        const tableEl = document.getElementById('history-table');
        tableEl.innerHTML = `
            <table class="devices-table" style="margin-top:12px">
                <thead><tr>
                    <th>Datum</th><th>Score</th><th>Grade</th>
                    <th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
                    <th>Gesamt</th>
                </tr></thead>
                <tbody>
                    ${history.slice().reverse().map(h => `
                        <tr>
                            <td>${h.timestamp ? new Date(h.timestamp).toLocaleString('de-DE', {day:'2-digit',month:'2-digit',year:'2-digit',hour:'2-digit',minute:'2-digit'}) : '--'}</td>
                            <td><strong>${h.score || 0}</strong></td>
                            <td><span class="finding-badge ${(h.grade||'F').toLowerCase() <= 'b' ? 'low' : (h.grade||'F') <= 'D' ? 'medium' : 'critical'}" style="font-size:11px">${h.grade || 'F'}</span></td>
                            <td>${h.critical || 0}</td>
                            <td>${h.high || 0}</td>
                            <td>${h.medium || 0}</td>
                            <td>${h.low || 0}</td>
                            <td>${h.total_findings || 0}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    // === Network Devices ===
    function flattenNetworkMap(networkMap) {
        // network_map format: { "192.168.1.0/24": { "VLAN10": [ {ip, hostname, mac, ...} ] } }
        const devices = [];
        if (!networkMap || typeof networkMap !== 'object') return devices;
        for (const [network, vlans] of Object.entries(networkMap)) {
            if (typeof vlans !== 'object') continue;
            for (const [vlan, devList] of Object.entries(vlans)) {
                if (!Array.isArray(devList)) continue;
                devList.forEach(d => {
                    devices.push({ ...d, network: network, vlan: vlan || '' });
                });
            }
        }
        return devices;
    }

    function renderNetworkDevices(results) {
        // Prefer flat devices array, fall back to flattening network_map
        let devices = results.devices || [];
        if (devices.length === 0 && results.network_map) {
            devices = flattenNetworkMap(results.network_map);
        }
        const tbody = document.getElementById('devices-tbody');
        if (!tbody) return;

        // Update stats
        const totalDevices = devices.length;
        const totalPorts = devices.reduce((sum, d) => sum + (d.open_ports ? (Array.isArray(d.open_ports) ? d.open_ports.length : d.open_ports) : 0), 0);
        const networks = new Set(devices.map(d => d.network).filter(Boolean));
        
        document.getElementById('stat-total-devices').textContent = totalDevices || '--';
        document.getElementById('stat-total-open-ports').textContent = totalPorts || '--';
        document.getElementById('stat-total-networks').textContent = networks.size || '--';

        if (devices.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="no-data-cell">Keine Ger\u00e4te gefunden. Starte einen Netzwerk-Scan.</td></tr>';
            return;
        }

        // Sort by IP
        const sorted = [...devices].sort((a, b) => {
            const ipA = (a.ip || '').split('.').map(n => parseInt(n) || 0);
            const ipB = (b.ip || '').split('.').map(n => parseInt(n) || 0);
            for (let i = 0; i < 4; i++) { if (ipA[i] !== ipB[i]) return ipA[i] - ipB[i]; }
            return 0;
        });

        window._allDevices = sorted;
        tbody.innerHTML = sorted.map(d => renderDeviceRow(d)).join('');
    }

    function renderDeviceRow(d) {
        const ports = Array.isArray(d.open_ports) ? d.open_ports : [];
        const portStr = ports.length > 0 
            ? ports.slice(0, 8).map(p => `<span class="port-tag">${p}</span>`).join('') + (ports.length > 8 ? ` <span class="port-tag">+${ports.length-8}</span>` : '')
            : '<span style="color:var(--text-muted)">keine</span>';
        const statusDot = d.status === 'active' ? 'online' : 'offline';
        return `
            <tr class="device-row">
                <td><span class="status-dot ${statusDot}"></span></td>
                <td style="font-family:var(--font-mono)">${escapeHtml(d.ip || '')}</td>
                <td>${escapeHtml(d.hostname || '--')}</td>
                <td style="font-family:var(--font-mono);font-size:12px">${escapeHtml(d.mac || '--')}</td>
                <td>${escapeHtml(d.network || '--')}</td>
                <td>${portStr}</td>
            </tr>
        `;
    }

    function filterDevices() {
        const search = (document.getElementById('device-search')?.value || '').toLowerCase();
        const tbody = document.getElementById('devices-tbody');
        if (!window._allDevices || !tbody) return;

        const filtered = search 
            ? window._allDevices.filter(d => 
                (d.ip || '').toLowerCase().includes(search) ||
                (d.hostname || '').toLowerCase().includes(search) ||
                (d.mac || '').toLowerCase().includes(search) ||
                (d.network || '').toLowerCase().includes(search)
            )
            : window._allDevices;

        tbody.innerHTML = filtered.length > 0 
            ? filtered.map(d => renderDeviceRow(d)).join('')
            : '<tr><td colspan="6" class="no-data-cell">Keine Ger\u00e4te f\u00fcr Suche gefunden</td></tr>';
    }

    // Expose for inline handlers
    window.showFindingDetail = showFindingDetail;

})();
