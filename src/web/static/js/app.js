// OPNsense Security Auditor dashboard
(function () {
    'use strict';

    // CSRF mirror: copy cookie to header for state changing methods
    const _origFetch = window.fetch.bind(window);
    function readCookie(name) {
        const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[$()*+?.\\^|]/g, '\\$&') + '=([^;]*)'));
        return m ? decodeURIComponent(m[1]) : '';
    }
    window.fetch = function (input, init) {
        init = init || {};
        const method = (init.method || 'GET').toUpperCase();
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
            init.headers = Object.assign({}, init.headers || {});
            const tok = readCookie('secops_csrf');
            if (tok) init.headers['X-CSRF-Token'] = tok;
            init.credentials = init.credentials || 'same-origin';
        }
        return _origFetch(input, init);
    };

    const API = {
        config: '/api/config',
        connection: '/api/connection/test',
        scanStart: '/api/scan/start',
        scanStatus: '/api/scan/status',
        scanCancel: '/api/scan/cancel',
        results: '/api/results/latest',
        history: '/api/reports/history',
        clearHistory: '/api/reports/clear',
        ignoreFinding: '/api/ignore-list/add-finding',
        ignoreList: '/api/ignore-list',
        ignoreAdd: '/api/ignore-list/add',
        ignoreRemove: '/api/ignore-list/remove',
        schedule: '/api/schedule',
        suggestionApply: '/api/suggestions/apply',
        networks: '/api/networks/fetch',
        networksSelected: '/api/config/networks',
        scanInternalStart: '/api/scan/internal',
        scanInternalStatus: '/api/scan/internal/status',
        scanInternalCancel: '/api/scan/internal/cancel',
    };

    const state = {
        results: null,
        reportFile: null,
        findings: [],
        findingsById: new Map(),
        devices: [],
        scanPoll: null,
        netPoll: null,
        scanRunning: false,
        scanStarted: 0,
        lang: 'en',
        langPref: 'auto',
        translations: {},
    };

    // ---------- i18n ----------
    const LANG_KEY = 'secops_lang';
    const SUPPORTED = ['en', 'de'];

    function detectBrowserLang() {
        const cands = []
            .concat(navigator.languages || [])
            .concat(navigator.language ? [navigator.language] : []);
        for (const c of cands) {
            const head = String(c || '').toLowerCase().split('-')[0];
            if (SUPPORTED.includes(head)) return head;
        }
        return 'en';
    }
    function readLangPref() {
        const v = localStorage.getItem(LANG_KEY);
        if (v === 'en' || v === 'de' || v === 'auto') return v;
        return 'auto';
    }
    function effectiveLang(pref) {
        if (pref === 'en' || pref === 'de') return pref;
        return detectBrowserLang();
    }
    function t(key, fallback) {
        const dict = state.translations[state.lang] || {};
        if (dict[key] != null) return dict[key];
        const en = state.translations.en || {};
        if (en[key] != null) return en[key];
        return fallback != null ? fallback : key;
    }
    async function loadTranslations(lang) {
        if (state.translations[lang]) return;
        try {
            const r = await fetch('/api/translations/' + encodeURIComponent(lang));
            if (!r.ok) return;
            const data = await r.json();
            if (data && data.success && data.translations) {
                state.translations[lang] = data.translations;
            }
        } catch (e) { /* ignore */ }
    }
    function applyI18n(root) {
        root = root || document;
        document.documentElement.lang = state.lang;
        root.querySelectorAll('[data-i18n]').forEach((el) => {
            const key = el.getAttribute('data-i18n');
            if (!key) return;
            el.textContent = t(key);
        });
        root.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
            const key = el.getAttribute('data-i18n-placeholder');
            if (key) el.setAttribute('placeholder', t(key));
        });
        root.querySelectorAll('[data-i18n-title]').forEach((el) => {
            const key = el.getAttribute('data-i18n-title');
            if (key) el.setAttribute('title', t(key));
        });
        root.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
            const key = el.getAttribute('data-i18n-aria-label');
            if (key) el.setAttribute('aria-label', t(key));
        });
        document.querySelectorAll('.lang-btn').forEach((b) => {
            b.classList.toggle('active', b.dataset.lang === state.lang);
        });
        const cfgLang = document.getElementById('cfg-language');
        if (cfgLang) cfgLang.value = state.langPref;
        const titleEl = document.getElementById('view-title');
        if (titleEl && titleEl.dataset.i18n) titleEl.textContent = t(titleEl.dataset.i18n);
    }
    async function setLanguage(pref) {
        const newPref = (pref === 'en' || pref === 'de' || pref === 'auto') ? pref : 'auto';
        localStorage.setItem(LANG_KEY, newPref);
        state.langPref = newPref;
        state.lang = effectiveLang(newPref);
        await loadTranslations(state.lang);
        applyI18n();
        // Re-render dynamic content with new strings.
        if (state.results) {
            renderDashboard();
            renderFindings();
            renderFirewall();
            renderDns();
            renderSystem();
            renderCerts();
            renderDevices(state.devices);
        }
    }

    const $ = (id) => document.getElementById(id);
    const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

    function escapeHtml(s) {
        const d = document.createElement('div');
        d.textContent = s == null ? '' : String(s);
        return d.innerHTML;
    }
    function fmtTime(iso) {
        if (!iso) return '--';
        try {
            const d = new Date(iso);
            return d.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
        } catch (e) { return iso; }
    }
    function durationSince(ms) {
        const sec = Math.max(0, Math.floor((Date.now() - ms) / 1000));
        if (sec < 60) return sec + 's';
        return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
    }
    function severityKey(sev) {
        return (sev || '').toString().toLowerCase();
    }

    function toast(level, msg) {
        const stack = $('toast-stack');
        if (!stack) return;
        const el = document.createElement('div');
        el.className = 'toast ' + level;
        el.textContent = msg;
        stack.appendChild(el);
        setTimeout(() => el.remove(), 5000);
    }

    async function apiGet(url) {
        const res = await fetch(url, { credentials: 'same-origin' });
        if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
        return res.json();
    }
    async function apiPost(url, body) {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: body == null ? '{}' : JSON.stringify(body),
        });
        if (!res.ok) throw new Error(res.status + ' ' + res.statusText);
        return res.json();
    }

    // ---------- view router ----------
    function setView(name) {
        $$('.nav-item').forEach((n) => n.classList.toggle('active', n.dataset.view === name));
        $$('.view').forEach((v) => v.classList.toggle('active', v.id === 'view-' + name));
        const titleKey = 'title.' + (name === 'dashboard' ? 'overview' : name);
        const titleEl = $('view-title');
        if (titleEl) {
            titleEl.dataset.i18n = titleKey;
            titleEl.textContent = t(titleKey, name);
        }
        if (name === 'config') {
            loadIgnoreList();
            loadNetworksSelected();
        }
    }
    function bindNav() {
        document.addEventListener('click', (e) => {
            const item = e.target.closest('[data-view]');
            if (!item) return;
            e.preventDefault();
            setView(item.dataset.view);
        });
    }

    // ---------- config ----------
    async function loadConfig() {
        try {
            const data = await apiGet(API.config);
            if (!data.success) return;
            const cfg = data.opnsense || {};
            $('cfg-host').value = cfg.host || '';
            // Server returns masked '***' or empty if unset.
            $('cfg-apikey').value = cfg.api_key_set ? '***' : '';
            $('cfg-apisecret').value = cfg.api_secret_set ? '***' : '';
            $('cfg-insecure-tls').checked = !!cfg.insecure_tls;
            $('opnsense-host').textContent = cfg.host || '--';
            updateConnDot(!!cfg.host && cfg.api_key_set);
        } catch (e) {
            toast('error', t('toast.config_load_failed'));
        }
    }

    async function saveConfig() {
        const cfg = {
            host: $('cfg-host').value.trim(),
            api_key: $('cfg-apikey').value === '***' ? '' : $('cfg-apikey').value,
            api_secret: $('cfg-apisecret').value === '***' ? '' : $('cfg-apisecret').value,
            insecure_tls: $('cfg-insecure-tls').checked,
        };
        try {
            const data = await apiPost(API.config, { opnsense: cfg });
            if (data.success) {
                toast('success', t('toast.config_saved'));
                loadConfig();
            } else {
                toast('error', data.error || t('toast.save_failed'));
            }
        } catch (e) {
            toast('error', t('toast.save_failed'));
        }
    }

    async function testConnection() {
        const out = $('connection-result');
        out.classList.remove('hidden', 'ok', 'err');
        out.textContent = '...';
        try {
            const body = {
                host: $('cfg-host').value.trim(),
                api_key: $('cfg-apikey').value === '***' ? '' : $('cfg-apikey').value,
                api_secret: $('cfg-apisecret').value === '***' ? '' : $('cfg-apisecret').value,
                insecure_tls: $('cfg-insecure-tls').checked,
            };
            const data = await apiPost(API.connection, body);
            if (data.success) {
                out.classList.add('ok');
                out.textContent = t('toast.connection_ok') + ' ' + (data.version ? 'OPNsense ' + data.version : '');
                updateConnDot(true);
            } else {
                out.classList.add('err');
                out.textContent = data.error || t('toast.connection_failed');
                updateConnDot(false);
            }
        } catch (e) {
            out.classList.add('err');
            out.textContent = t('toast.connection_failed');
            updateConnDot(false);
        }
    }

    function updateConnDot(online) {
        const wrap = $('connection-status');
        if (!wrap) return;
        const dot = wrap.querySelector('.dot');
        const txt = wrap.querySelector('.conn-text');
        if (online) {
            dot.classList.remove('offline'); dot.classList.add('online');
            txt.textContent = t('conn.online');
        } else {
            dot.classList.remove('online'); dot.classList.add('offline');
            txt.textContent = t('conn.offline');
        }
    }

    // ---------- scan ----------
    async function startScan() {
        try {
            const data = await apiPost(API.scanStart);
            if (!data.success) {
                toast('error', data.error || t('toast.scan_start_failed'));
                return;
            }
            state.scanRunning = true;
            state.scanStarted = Date.now();
            showScanPanel();
            startScanPolling();
        } catch (e) {
            toast('error', t('toast.scan_start_failed'));
        }
    }

    async function cancelScan() {
        try { await apiPost(API.scanCancel); } catch (e) { /* ignore */ }
    }

    function showScanPanel() {
        $('scan-panel').classList.remove('hidden');
        $('btn-start-scan').disabled = true;
        $('scan-log').textContent = '';
    }
    function hideScanPanel() {
        $('scan-panel').classList.add('hidden');
        $('btn-start-scan').disabled = false;
    }

    function startScanPolling() {
        stopScanPolling();
        state.scanPoll = setInterval(pollScan, 1500);
        pollScan();
    }
    function stopScanPolling() {
        if (state.scanPoll) { clearInterval(state.scanPoll); state.scanPoll = null; }
    }

    async function pollScan() {
        try {
            const data = await apiGet(API.scanStatus);
            if (!data.success) return;
            applyScanStatus(data);
            const done = ['completed', 'failed', 'cancelled', 'idle'].includes(data.status);
            if (done) {
                stopScanPolling();
                state.scanRunning = false;
                hideScanPanel();
                if (data.status === 'completed') toast('success', t('toast.scan_done'));
                else if (data.status === 'failed') toast('error', t('toast.scan_failed'));
                else if (data.status === 'cancelled') toast('warning', t('toast.scan_cancelled'));
                loadResults();
                loadHistory();
            }
        } catch (e) { /* keep polling */ }
    }

    function applyScanStatus(data) {
        const pct = Math.max(0, Math.min(100, parseInt(data.progress || 0, 10)));
        $('scan-progress-fill').style.width = pct + '%';
        $('scan-progress-text').textContent = pct + '%';
        $('scan-current-check').textContent = data.current_step || '';
        $('stat-rules-checked').textContent = data.rules_checked ?? 0;
        $('stat-findings').textContent = data.findings_count ?? 0;
        $('stat-duration').textContent = state.scanStarted ? durationSince(state.scanStarted) : '0s';
        renderLogs($('scan-log'), data.logs || []);
    }

    function renderLogs(container, logs) {
        container.innerHTML = logs.map((l) => {
            const lvl = (l.level || 'info').toLowerCase();
            return '<div class="log-entry ' + escapeHtml(lvl) + '">'
                 + '<span class="ts">' + escapeHtml(l.timestamp || '') + '</span>'
                 + '<span class="lvl">' + escapeHtml(lvl) + '</span>'
                 + '<span class="msg">' + escapeHtml(l.message || '') + '</span>'
                 + '</div>';
        }).join('');
        container.scrollTop = container.scrollHeight;
    }

    // ---------- results / dashboard ----------
    async function loadResults() {
        try {
            const data = await apiGet(API.results);
            if (!data.success) {
                $('top-findings-list').innerHTML = '<p class="empty">' + escapeHtml(t('empty.no_scan')) + '</p>';
                return;
            }
            state.results = data.results || {};
            state.reportFile = data.report_file || null;
            const findings = collectFindings(state.results);
            state.findings = findings;
            state.findingsById = new Map(findings.map((f) => [f.rule_id || f.check || f.cve_id || randomId(), f]));
            renderDashboard();
            renderFindings();
            renderFirewall();
            renderDns();
            renderSystem();
            renderCerts();
            renderDevices(state.results.devices || []);
            $('btn-download-report').classList.toggle('hidden', !state.reportFile);
            $('opnsense-host').textContent = state.results.opnsense_host || '--';
        } catch (e) {
            // 404 first run is fine
        }
    }

    function randomId() { return 'tmp_' + Math.random().toString(36).slice(2, 10); }

    function collectFindings(r) {
        const buckets = [
            ['firewall', r.firewall_findings],
            ['dns', r.dns_findings],
            ['system', r.system_findings],
            ['vlan', r.vlan_findings],
            ['ipv6', r.ipv6_findings],
            ['gateway', r.gateway_findings],
            ['radvd', r.radvd_findings],
            ['port', r.port_findings],
            ['vulnerability', r.vulnerability_findings],
            ['certificate', r.certificate_findings],
        ];
        const out = [];
        for (const [cat, list] of buckets) {
            if (!Array.isArray(list)) continue;
            for (const f of list) {
                out.push(Object.assign({}, f, { _category: cat }));
            }
        }
        return out;
    }

    function renderDashboard() {
        const r = state.results || {};
        const sum = r.summary || {};
        $('count-critical').textContent = sum.critical || 0;
        $('count-high').textContent = sum.high || 0;
        $('count-medium').textContent = sum.medium || 0;
        $('count-low').textContent = sum.low || 0;
        const stats = r.statistics || {};
        $('stat-fw-rules').textContent = stats.firewall_rules ?? '--';
        $('stat-nat-rules').textContent = stats.nat_rules ?? '--';
        $('stat-interfaces').textContent = stats.interfaces ?? '--';
        $('stat-last-scan').textContent = fmtTime(r.scan_timestamp);

        const score = parseInt(r.security_score || 0, 10);
        $('security-score').textContent = isNaN(score) ? '--' : score;
        $('security-grade').textContent = r.security_grade || '--';
        const circ = 282.7;
        const offset = circ - (circ * Math.max(0, Math.min(100, score)) / 100);
        const ring = $('score-circle');
        ring.style.strokeDashoffset = offset;
        ring.style.stroke = scoreColor(score);

        const cats = r.category_scores || {};
        for (const k of ['firewall', 'dns', 'system', 'vpn']) {
            const pct = typeof cats[k] === 'number' ? cats[k] : null;
            const fill = $('score-' + k);
            const val = $('score-' + k + '-val');
            if (pct == null) {
                if (fill) fill.style.width = '0%';
                if (val) val.textContent = '--';
            } else {
                if (fill) {
                    fill.style.width = Math.max(0, Math.min(100, pct)) + '%';
                    fill.style.background = scoreColor(pct);
                }
                if (val) val.textContent = pct;
            }
        }

        renderTopFindings();
    }

    function scoreColor(s) {
        if (s >= 90) return getCss('--ok');
        if (s >= 70) return getCss('--warn');
        if (s >= 0) return getCss('--err');
        return getCss('--accent');
    }
    function getCss(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    function renderTopFindings() {
        const top = state.findings
            .filter((f) => ['CRITICAL', 'HIGH'].includes(severityKey(f.severity).toUpperCase()))
            .slice(0, 6);
        const c = $('top-findings-list');
        if (!top.length) {
            c.innerHTML = '<p class="empty">' + escapeHtml(t('empty.no_critical')) + '</p>';
            return;
        }
        c.innerHTML = top.map(rowHtml).join('');
    }

    function rowHtml(f) {
        const sev = severityKey(f.severity || 'low');
        const id = f.rule_id || f.check || f.cve_id || '';
        const issue = f.issue || f.title || f.check || 'Finding';
        const cat = f._category || f.category || '';
        return '<div class="finding-row" data-finding-id="' + escapeHtml(id) + '">'
             + '<span class="sev-tag sev-' + sev + '">' + escapeHtml(sev) + '</span>'
             + '<div class="finding-main">'
             + '<div class="finding-issue">' + escapeHtml(issue) + '</div>'
             + '<div class="finding-meta">'
             + (cat ? '<span class="cat">' + escapeHtml(cat) + '</span>' : '')
             + (f.opnsense_path ? '<span>' + escapeHtml(f.opnsense_path) + '</span>' : '')
             + '</div>'
             + '</div>'
             + '<div class="finding-aside">' + escapeHtml(id.slice(0, 12)) + '</div>'
             + '</div>';
    }

    // ---------- findings list ----------
    function renderFindings() {
        applyFilter();
    }

    function applyFilter() {
        const sevSel = $('filter-severity').value;
        const catSel = $('filter-category').value;
        const q = $('filter-search').value.trim().toLowerCase();
        const filtered = state.findings.filter((f) => {
            const sev = severityKey(f.severity);
            if (sevSel !== 'all' && sev !== sevSel) return false;
            if (catSel !== 'all' && (f._category || '') !== catSel) return false;
            if (q) {
                const hay = [
                    f.issue, f.title, f.check, f.reason, f.description,
                    f.solution, f.opnsense_path, f.rule_id, f.cve_id,
                ].map((x) => (x || '').toString().toLowerCase()).join(' ');
                if (!hay.includes(q)) return false;
            }
            return true;
        });
        const c = $('all-findings-list');
        if (!filtered.length) {
            c.innerHTML = '<p class="empty">' + escapeHtml(t('empty.no_filter_match')) + '</p>';
        } else {
            c.innerHTML = filtered.map(rowHtml).join('');
        }
        $('filter-count').textContent = filtered.length + ' ' + t('filter.results_count');
    }

    // ---------- firewall view ----------
    function renderFirewall() {
        const fw = (state.results || {}).firewall_findings || [];
        const stats = (state.results || {}).statistics || {};
        $('fw-total-rules').textContent = stats.firewall_rules ?? '--';
        $('fw-problem-rules').textContent = fw.length;
        $('fw-any-rules').textContent = fw.filter((f) => /any/i.test(f.issue || '')).length;
        const c = $('fw-rules-list');
        c.innerHTML = fw.length
            ? fw.map((f) => Object.assign({}, f, { _category: 'firewall' })).map(rowHtml).join('')
            : '<p class="empty">' + escapeHtml(t('empty.no_findings')) + '</p>';
    }

    // ---------- dns view ----------
    function renderDns() {
        const r = state.results || {};
        const dnsCfg = (r.dns_config || {}).unbound || {};
        $('dns-dnssec').textContent = truthLabel(dnsCfg.dnssec);
        $('dns-dot').textContent = truthLabel(dnsCfg.dot);
        $('dns-rebind').textContent = truthLabel(dnsCfg.private_domain);
        const servers = dnsCfg.forwarders || (r.dns_config || {}).forward_servers || [];
        const c = $('dns-servers-list');
        if (!servers.length) {
            c.innerHTML = '<p class="empty">' + escapeHtml(t('empty.no_dns_forwarders')) + '</p>';
        } else {
            c.innerHTML = servers.map((s) =>
                '<div class="ignore-row">'
                + '<span class="mono">' + escapeHtml(s.ip || '') + ':' + escapeHtml(s.port || '53') + (s.dot ? ' (DoT)' : '') + '</span>'
                + '<span class="reason">' + escapeHtml(s.domain || '') + '</span>'
                + '</div>'
            ).join('');
        }
    }
    function truthLabel(v) {
        const s = (v == null ? '' : String(v)).toLowerCase();
        return ['1', 'true', 'yes', 'on', 'enabled'].includes(s) ? t('value.active') : t('value.inactive');
    }

    // ---------- system view ----------
    function renderSystem() {
        const sys = (state.results || {}).system_findings || [];
        const c = $('system-checks');
        c.innerHTML = sys.length
            ? sys.map((f) => Object.assign({}, f, { _category: 'system' })).map(rowHtml).join('')
            : '<p class="empty">' + escapeHtml(t('empty.no_findings')) + '</p>';
    }

    // ---------- certs view ----------
    function renderCerts() {
        const list = (state.results || {}).certificate_findings || [];
        const c = $('cert-list');
        c.innerHTML = list.length
            ? list.map((f) => Object.assign({}, f, { _category: 'certificate' })).map(rowHtml).join('')
            : '<p class="empty">' + escapeHtml(t('empty.no_findings')) + '</p>';
    }

    // ---------- devices ----------
    function renderDevices(devices) {
        state.devices = devices || [];
        const tbody = $('devices-tbody');
        const stats = (state.results || {}).statistics || {};
        $('stat-total-devices').textContent = stats.total_devices ?? state.devices.length;
        $('stat-total-open-ports').textContent = stats.total_open_ports ?? state.devices.reduce((a, d) => a + ((d.open_ports || []).length), 0);
        $('stat-total-networks').textContent = Object.keys(stats.devices_by_network || {}).length || '--';
        if (!state.devices.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-cell">' + escapeHtml(t('empty.no_devices')) + '</td></tr>';
            return;
        }
        tbody.innerHTML = filteredDevices().map(deviceRow).join('');
    }
    function filteredDevices() {
        const q = ($('device-search').value || '').toLowerCase().trim();
        if (!q) return state.devices;
        return state.devices.filter((d) =>
            (d.ip || '').toLowerCase().includes(q) ||
            (d.hostname || '').toLowerCase().includes(q) ||
            (d.mac || '').toLowerCase().includes(q)
        );
    }
    function deviceRow(d) {
        const status = d.status === 'active' ? '<span class="s-on">on</span>' : '<span class="s-off">off</span>';
        const ports = (d.open_ports || []).slice(0, 12)
            .map((p) => '<span class="port-tag">' + escapeHtml(String(p)) + '</span>').join('');
        return '<tr>'
             + '<td>' + status + '</td>'
             + '<td class="mono">' + escapeHtml(d.ip || '') + '</td>'
             + '<td>' + escapeHtml(d.hostname || '--') + '</td>'
             + '<td class="mono">' + escapeHtml(d.mac || '--') + '</td>'
             + '<td class="mono">' + escapeHtml(d.network || '') + '</td>'
             + '<td class="mono">' + escapeHtml(d.vlan || '') + '</td>'
             + '<td>' + ports + '</td>'
             + '</tr>';
    }

    // ---------- internal scan ----------
    async function startInternalScan() {
        try {
            const data = await apiPost(API.scanInternalStart, {});
            if (!data.success) { toast('error', data.error || t('toast.internal_scan_start_failed')); return; }
            $('net-scan-panel').classList.remove('hidden');
            $('btn-network-scan').classList.add('hidden');
            $('btn-network-scan-cancel').classList.remove('hidden');
            startNetPolling();
        } catch (e) {
            toast('error', t('toast.internal_scan_start_failed'));
        }
    }
    async function cancelInternalScan() {
        try { await apiPost(API.scanInternalCancel, {}); } catch (e) { /* ignore */ }
    }
    function startNetPolling() {
        stopNetPolling();
        state.netPoll = setInterval(pollNet, 2000);
        pollNet();
    }
    function stopNetPolling() {
        if (state.netPoll) { clearInterval(state.netPoll); state.netPoll = null; }
    }
    async function pollNet() {
        try {
            const data = await apiGet(API.scanInternalStatus);
            if (!data.success) return;
            const total = parseInt(data.total_hosts || 0, 10);
            const done = parseInt(data.scanned_hosts || 0, 10);
            const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
            $('net-scan-fill').style.width = pct + '%';
            $('net-scan-step').textContent = (data.current_step || '') + (total > 0 ? ' (' + done + '/' + total + ')' : '');
            renderLogs($('net-scan-log'), data.logs || []);
            if (Array.isArray(data.devices)) renderDevices(data.devices);
            const finished = ['completed', 'failed', 'cancelled', 'idle'].includes(data.status);
            if (finished) {
                stopNetPolling();
                $('btn-network-scan').classList.remove('hidden');
                $('btn-network-scan-cancel').classList.add('hidden');
                if (data.status === 'completed') toast('success', t('toast.internal_scan_done'));
                else if (data.status === 'failed') toast('error', t('toast.internal_scan_failed'));
                else if (data.status === 'cancelled') toast('warning', t('toast.internal_scan_cancelled'));
            }
        } catch (e) { /* keep polling */ }
    }

    // ---------- networks selection ----------
    async function loadNetworksSelected() {
        try {
            const data = await apiGet(API.networksSelected);
            const list = $('networks-list');
            const networks = (data.networks || []);
            if (!networks.length) {
                list.innerHTML = '<p class="empty">' + escapeHtml(t('empty.networks_unset')) + '</p>';
                return;
            }
            list.innerHTML = networks.map((n) =>
                '<div class="network-row">'
                + '<label class="checkbox"><input type="checkbox" data-cidr="' + escapeHtml(n.network || '') + '"' + (n.enabled !== false ? ' checked' : '') + '> ' + escapeHtml(n.name || n.network || '') + '</label>'
                + '<span class="cidr">' + escapeHtml(n.network || '') + '</span>'
                + '</div>'
            ).join('');
        } catch (e) { /* ignore */ }
    }
    async function fetchNetworks() {
        try {
            const data = await apiGet(API.networks);
            if (!data.success) { toast('error', data.error || t('toast.networks_load_failed')); return; }
            const list = $('networks-list');
            const nets = data.networks || [];
            if (!nets.length) {
                list.innerHTML = '<p class="empty">' + escapeHtml(t('empty.networks_unset')) + '</p>';
                return;
            }
            list.innerHTML = nets.map((n) =>
                '<div class="network-row">'
                + '<label class="checkbox"><input type="checkbox" data-cidr="' + escapeHtml(n.network || '') + '" data-name="' + escapeHtml(n.name || '') + '" checked> ' + escapeHtml(n.name || n.network || '') + '</label>'
                + '<span class="cidr">' + escapeHtml(n.network || '') + '</span>'
                + '</div>'
            ).join('');
            toast('success', t('toast.networks_loaded_pre') + ' ' + nets.length + ' ' + t('toast.networks_loaded_suf'));
        } catch (e) {
            toast('error', t('toast.networks_load_failed'));
        }
    }
    async function saveNetworks() {
        const rows = $$('#networks-list input[type="checkbox"]');
        const selected = rows.map((r) => ({
            network: r.dataset.cidr || '',
            name: r.dataset.name || '',
            enabled: r.checked,
        }));
        try {
            const data = await apiPost(API.networksSelected, { networks: selected });
            if (data.success) toast('success', t('toast.networks_saved'));
            else toast('error', data.error || t('toast.save_failed'));
        } catch (e) {
            toast('error', t('toast.save_failed'));
        }
    }

    // ---------- ignore list ----------
    async function loadIgnoreList() {
        try {
            const data = await apiGet(API.ignoreList);
            const list = $('ignore-list');
            const groups = data.ignore_list || {};
            const flat = [];
            for (const [cat, items] of Object.entries(groups)) {
                (items || []).forEach((it, idx) => flat.push({ category: cat, index: idx, item: it }));
            }
            if (!flat.length) {
                list.innerHTML = '<p class="empty">' + escapeHtml(t('empty.no_exceptions')) + '</p>';
                return;
            }
            list.innerHTML = flat.map(({ category, index, item }) => {
                const id = item.rule_id || item.cve_id || item.check || (item.host && item.port ? item.host + ':' + item.port : '') || item.description || '';
                return '<div class="ignore-row">'
                    + '<span class="mono">[' + escapeHtml(category) + '] ' + escapeHtml(id) + '</span>'
                    + '<span class="reason">' + escapeHtml(item.reason || '') + '</span>'
                    + '<button class="btn ghost sm" data-ignore-remove="' + escapeHtml(category + ':' + index) + '">x</button>'
                    + '</div>';
            }).join('');
        } catch (e) { /* ignore */ }
    }
    async function removeIgnore(token) {
        const [category, idxStr] = (token || '').split(':');
        const index = parseInt(idxStr, 10);
        if (!category || isNaN(index)) return;
        try {
            const data = await apiPost(API.ignoreRemove, { category, index });
            if (data.success) { toast('success', t('toast.exception_removed')); loadIgnoreList(); }
            else toast('error', data.error || t('toast.exception_failed'));
        } catch (e) {
            toast('error', t('toast.exception_failed'));
        }
    }

    // ---------- history ----------
    async function loadHistory() {
        try {
            const data = await apiGet(API.history);
            if (!data.success) return;
            const hist = data.history || [];
            const sec = $('scan-history-section');
            if (hist.length < 2) { sec.classList.add('hidden'); return; }
            sec.classList.remove('hidden');
            const max = Math.max(...hist.map((h) => h.score || 0), 100);
            $('history-chart').innerHTML = hist.map((h) => {
                const cls = h.critical > 0 ? 'crit' : (h.high > 0 ? 'warn' : 'ok');
                const height = Math.max(4, ((h.score || 0) / max) * 100);
                return '<div class="hist-bar ' + cls + '" style="height:' + height + '%" title="' + escapeHtml(h.timestamp || '') + ' - Score ' + (h.score || 0) + '"></div>';
            }).join('');
            $('history-table').innerHTML = hist.slice().reverse().slice(0, 30).map((h) =>
                '<div class="history-row">'
                + '<span class="ts">' + escapeHtml(fmtTime(h.timestamp)) + '</span>'
                + '<span>' + (h.score || 0) + '</span>'
                + '<span>' + (h.total_findings || 0) + '</span>'
                + '</div>'
            ).join('');
        } catch (e) { /* ignore */ }
    }
    async function clearHistory() {
        if (!confirm(t('modal.confirm_clear'))) return;
        try {
            const data = await apiPost(API.clearHistory);
            if (data.success) {
                toast('success', (data.deleted || 0) + ' ' + t('toast.history_cleared_suf'));
                loadResults(); loadHistory();
            }
        } catch (e) {
            toast('error', t('toast.history_clear_failed'));
        }
    }

    // ---------- schedule ----------
    async function loadSchedule() {
        try {
            const data = await apiGet(API.schedule);
            if (!data.success) return;
            const s = data.schedule || {};
            $('schedule-enabled').checked = !!s.enabled;
            $('schedule-interval').value = String(s.interval_hours || 24);
            const nextEl = $('schedule-next-run');
            if (s.next_run) {
                nextEl.removeAttribute('data-i18n');
                nextEl.textContent = fmtTime(s.next_run);
            } else {
                nextEl.setAttribute('data-i18n', 'form.next_run_unset');
                nextEl.textContent = t('form.next_run_unset');
            }
        } catch (e) { /* ignore */ }
    }
    async function saveSchedule() {
        const body = {
            enabled: $('schedule-enabled').checked,
            interval_hours: parseInt($('schedule-interval').value, 10) || 24,
        };
        try {
            const data = await apiPost(API.schedule, body);
            if (data.success) { toast('success', t('toast.schedule_saved')); loadSchedule(); }
            else toast('error', data.error || t('toast.save_failed'));
        } catch (e) {
            toast('error', t('toast.save_failed'));
        }
    }

    // ---------- modal ----------
    function openModal(findingId) {
        const f = state.findingsById.get(findingId);
        if (!f) return;
        $('modal-title').textContent = f.issue || f.title || f.check || 'Finding';
        const sev = severityKey(f.severity);
        const sections = [];
        if (f.opnsense_path) {
            sections.push(section(t('modal.path'), '<span class="path-tag">' + escapeHtml(f.opnsense_path) + '</span>'));
        }
        if (f.current_value || f.recommended_value) {
            sections.push(section(t('modal.compare'),
                '<div class="compare-grid">'
                + '<div class="compare-cell bad"><div class="label">' + escapeHtml(t('modal.current')) + '</div><div class="value">' + escapeHtml(f.current_value || '') + '</div></div>'
                + '<div class="compare-cell good"><div class="label">' + escapeHtml(t('modal.recommended')) + '</div><div class="value">' + escapeHtml(f.recommended_value || '') + '</div></div>'
                + '</div>'));
        }
        if (f.reason || f.description) {
            sections.push(section(t('modal.reason'), '<p>' + escapeHtml(f.reason || f.description) + '</p>'));
        }
        if (f.solution) {
            sections.push(section(t('modal.solution'), '<p>' + escapeHtml(f.solution) + '</p>'));
        }
        const steps = (f.implementation_steps || []).filter((s) => s);
        if (steps.length) {
            sections.push(section(t('modal.steps'), '<ol>' + steps.map((s) => '<li>' + escapeHtml(s) + '</li>').join('') + '</ol>'));
        }
        const details = f.details || f.rule_details || null;
        if (details) {
            sections.push(section(t('modal.details'), '<pre>' + escapeHtml(JSON.stringify(details, null, 2)) + '</pre>'));
        }
        if (f.suggested_rule) {
            sections.push(section(t('modal.suggestion'),
                '<pre>' + escapeHtml(JSON.stringify(f.suggested_rule, null, 2)) + '</pre>'
                + '<button class="btn primary sm" id="apply-suggestion-btn">' + escapeHtml(t('btn.apply_rule')) + '</button>'
                + '<div class="status-line" id="apply-suggestion-status"></div>'));
        }
        $('modal-body').innerHTML = '<div class="row-flex"><span class="sev-tag sev-' + sev + '">' + escapeHtml(sev) + '</span><span class="spacer"></span></div>' + sections.join('');
        $('finding-modal').classList.remove('hidden');
        $('finding-modal').dataset.findingId = (f.rule_id || f.check || f.cve_id || '');
    }
    function section(title, html) {
        return '<div class="modal-section"><h4>' + escapeHtml(title) + '</h4>' + html + '</div>';
    }
    function closeModal() {
        $('finding-modal').classList.add('hidden');
        $('finding-modal').dataset.findingId = '';
    }

    async function applySuggestion(findingId) {
        const status = $('apply-suggestion-status');
        const btn = $('apply-suggestion-btn');
        if (!status || !btn) return;
        btn.disabled = true;
        status.textContent = '...';
        try {
            const data = await apiPost(API.suggestionApply, { finding_id: findingId, confirm: true });
            if (data.success) status.textContent = t('toast.connection_ok') + ' ' + (data.uuid || '');
            else status.textContent = (data.error || 'error');
        } catch (e) {
            status.textContent = t('toast.exception_failed');
        } finally {
            btn.disabled = false;
        }
    }

    async function excludeCurrent() {
        const id = $('finding-modal').dataset.findingId;
        if (!id) return;
        const f = state.findingsById.get(id);
        if (!f) return;
        const reason = prompt(t('modal.exclude_prompt')) || '';
        try {
            const data = await apiPost(API.ignoreFinding, { finding: f, reason });
            if (data.success) { toast('success', t('toast.exception_added')); closeModal(); loadResults(); }
            else toast('error', data.error || t('toast.exception_failed'));
        } catch (e) {
            toast('error', t('toast.exception_failed'));
        }
    }

    function downloadReport() {
        if (!state.reportFile) return;
        window.open('/api/reports/' + encodeURIComponent(state.reportFile) + '/html', '_blank', 'noopener');
    }

    // ---------- event delegation ----------
    function bindEvents() {
        document.addEventListener('click', (e) => {
            const fid = e.target.closest('[data-finding-id]');
            if (fid) { openModal(fid.dataset.findingId); return; }
            const remove = e.target.closest('[data-ignore-remove]');
            if (remove) { removeIgnore(remove.dataset.ignoreRemove); return; }
        });

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });

        $('modal-close').addEventListener('click', closeModal);
        document.querySelector('#finding-modal .modal-backdrop').addEventListener('click', closeModal);

        // Apply suggestion is bound via delegation since the button is dynamic.
        document.addEventListener('click', (e) => {
            if (e.target && e.target.id === 'apply-suggestion-btn') {
                const id = $('finding-modal').dataset.findingId;
                applySuggestion(id);
            }
        });

        $('btn-start-scan').addEventListener('click', startScan);
        $('btn-cancel-scan').addEventListener('click', cancelScan);
        $('btn-refresh').addEventListener('click', () => { loadResults(); loadHistory(); });
        $('btn-download-report').addEventListener('click', downloadReport);
        $('btn-test-connection').addEventListener('click', testConnection);
        $('btn-save-config').addEventListener('click', saveConfig);
        $('btn-save-schedule').addEventListener('click', saveSchedule);
        $('btn-clear-history').addEventListener('click', clearHistory);
        $('btn-network-scan').addEventListener('click', startInternalScan);
        $('btn-network-scan-cancel').addEventListener('click', cancelInternalScan);
        $('btn-fetch-networks').addEventListener('click', fetchNetworks);
        $('btn-save-networks').addEventListener('click', saveNetworks);
        $('btn-exclude-finding').addEventListener('click', excludeCurrent);
        $('filter-severity').addEventListener('change', applyFilter);
        $('filter-category').addEventListener('change', applyFilter);
        $('filter-search').addEventListener('input', applyFilter);
        $('device-search').addEventListener('input', () => renderDevices(state.devices));

        $$('.lang-btn').forEach((b) => {
            b.addEventListener('click', () => setLanguage(b.dataset.lang));
        });
        const cfgLang = $('cfg-language');
        if (cfgLang) cfgLang.addEventListener('change', () => setLanguage(cfgLang.value));
    }

    async function init() {
        // Language must be ready before any DOM rendering reads strings.
        state.langPref = readLangPref();
        state.lang = effectiveLang(state.langPref);
        await loadTranslations(state.lang);
        if (state.lang !== 'en') await loadTranslations('en');
        applyI18n();

        bindNav();
        bindEvents();
        loadConfig();
        loadResults();
        loadHistory();
        loadSchedule();
        // If a scan is running on the server, attach polling.
        apiGet(API.scanStatus).then((d) => {
            if (d && d.success && (d.status === 'running' || d.status === 'cancelling')) {
                state.scanRunning = true;
                state.scanStarted = Date.now();
                showScanPanel();
                startScanPolling();
            }
        }).catch(() => {});
    }

    document.addEventListener('DOMContentLoaded', init);
})();
