// VulnScan AI – Main Frontend Logic
// Đồ án: Công cụ Đánh giá Lỗ hổng Phần mềm kết hợp AI & CVE Database

'use strict';

// ── Global state ─────────────────────────────────────────────────────────────
const _state = {
    binary:   null,   // last PE analysis result
    packages: null,   // last package analysis result
    search:   null,   // last search/CPE result
};

// ── Tab management ────────────────────────────────────────────────────────────
function showTab(name, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(`${name}-tab`).classList.add('active');
    if (btn) btn.classList.add('active');
    _hideSharedResults();
    document.getElementById('error').style.display = 'none';
}

function _hideSharedResults() {
    document.getElementById('results').style.display  = 'none';
    document.getElementById('loading').style.display  = 'none';
}

// ── File upload wiring ────────────────────────────────────────────────────────
function _wireUpload(boxId, inputId, nameId, infoId) {
    const box   = document.getElementById(boxId);
    const input = document.getElementById(inputId);

    box.addEventListener('dragover', e => {
        e.preventDefault();
        box.style.borderColor = '#10b981';
        box.style.background  = '#f0fdf4';
    });
    box.addEventListener('dragleave', () => {
        box.style.borderColor = '';
        box.style.background  = '';
    });
    box.addEventListener('drop', e => {
        e.preventDefault();
        box.style.borderColor = '';
        box.style.background  = '';
        if (e.dataTransfer.files.length) _selectFile(e.dataTransfer.files[0], nameId, infoId, input);
    });
    box.addEventListener('click', () => input.click());
    input.addEventListener('change', e => {
        if (e.target.files.length) _selectFile(e.target.files[0], nameId, infoId, input);
    });
}

function _selectFile(file, nameId, infoId, input) {
    document.getElementById(nameId).textContent =
        `\uD83D\uDCC4 ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    document.getElementById(infoId).style.display = 'block';
    const dt = new DataTransfer();
    dt.items.add(file);
    input.files = dt.files;
}

document.addEventListener('DOMContentLoaded', () => {
    _wireUpload('binaryUploadBox', 'binaryFileInput', 'binaryFileName', 'binaryFileInfo');
    _wireUpload('pkgUploadBox',    'pkgFileInput',    'pkgFileName',    'pkgFileInfo');

    fetch('/api/status').then(r => r.json()).then(d => {
        console.log('[VulnScan] Status:', d);
    }).catch(() => {});
});

// ── Unified analyze() ─────────────────────────────────────────────────────────
async function analyzeFile(type) {
    const inputId  = type === 'binary' ? 'binaryFileInput' : 'pkgFileInput';
    const loadId   = type === 'binary' ? 'binaryLoading'   : 'pkgLoading';
    const errId    = type === 'binary' ? 'binaryError'      : 'pkgError';
    const errMsgId = type === 'binary' ? 'binaryErrorMsg'   : 'pkgErrorMsg';
    const resId    = type === 'binary' ? 'binaryResults'    : 'pkgResults';

    const file = document.getElementById(inputId).files[0];
    if (!file) { _showError(errMsgId, errId, 'Vui lòng chọn file trước.'); return; }

    document.getElementById(loadId).style.display = 'block';
    document.getElementById(errId).style.display  = 'none';
    document.getElementById(resId).style.display  = 'none';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res  = await fetch('/api/analyze', { method: 'POST', body: formData });
        const data = await res.json();
        document.getElementById(loadId).style.display = 'none';

        if (!data.success && !data.analysis_type) {
            _showError(errMsgId, errId, data.error || 'Phân tích thất bại.');
            return;
        }

        if (data.analysis_type === 'binary') {
            _state.binary = data;
            _renderBinaryResults(data);
        } else if (data.analysis_type === 'packages') {
            _state.packages = data;
            _renderPackageResults(data);
        } else {
            _showError(errMsgId, errId, data.error || 'Loại file không hỗ trợ.');
        }
    } catch (err) {
        document.getElementById(loadId).style.display = 'none';
        _showError(errMsgId, errId, `Lỗi mạng: ${err.message}`);
    }
}

function _showError(msgId, errId, msg) {
    document.getElementById(msgId).textContent = msg;
    document.getElementById(errId).style.display = 'block';
}

// ── Search ────────────────────────────────────────────────────────────────────
async function searchSoftware() {
    const name    = document.getElementById('softwareName').value.trim();
    const version = document.getElementById('softwareVersion').value.trim();
    if (!name) { showError('Vui lòng nhập tên phần mềm'); return; }

    showLoading(); hideError(); hideResults();

    try {
        const res  = await fetch('/api/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ software_name: name, version }),
        });
        const data = await res.json();
        hideLoading();
        if (data.success) { _state.search = data; displayResults(data); }
        else showError(data.error || 'Không tìm thấy kết quả');
    } catch (err) {
        hideLoading();
        showError(`Lỗi: ${err.message}`);
    }
}

// ── CPE Query ─────────────────────────────────────────────────────────────────
async function queryCPE() {
    const cpe = document.getElementById('cpeString').value.trim();
    if (!cpe) { showError('Vui lòng nhập CPE string'); return; }

    showLoading(); hideError(); hideResults();

    try {
        const res  = await fetch('/api/query-cpe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cpe }),
        });
        const data = await res.json();
        hideLoading();
        if (data.success) { _state.search = data; displayResults(data); }
        else showError(data.error || 'Query thất bại');
    } catch (err) {
        hideLoading();
        showError(`Lỗi: ${err.message}`);
    }
}

function setExample(name, ver) {
    document.getElementById('softwareName').value    = name;
    document.getElementById('softwareVersion').value = ver;
}

function setCPE(el) {
    document.getElementById('cpeString').value = el.textContent.trim();
}

// ── Shared search/CPE results ─────────────────────────────────────────────────
function displayResults(data) {
    document.getElementById('results').style.display = 'block';
    document.getElementById('resultCPE').textContent  = data.cpe || 'N/A';

    const s = data.statistics || {};
    document.getElementById('statTotal').textContent    = s.total_cves || 0;
    document.getElementById('statCritical').textContent = (s.by_severity || {}).CRITICAL || 0;
    document.getElementById('statHigh').textContent     = (s.by_severity || {}).HIGH     || 0;
    document.getElementById('statMedium').textContent   = (s.by_severity || {}).MEDIUM   || 0;
    document.getElementById('statLow').textContent      = (s.by_severity || {}).LOW      || 0;
    document.getElementById('statAvgCVSS').textContent  = (s.avg_cvss || 0).toFixed(1);

    _renderAiPanel(data.ai_analysis, {
        panel: 'aiAnalysisPanel', badge: 'aiOverallRiskBadge',
        summary: 'aiRiskSummary', threats: 'aiTopThreats',
        recs: 'aiRecommendations', vectors: 'aiAttackVectors',
    });

    const listEl = document.getElementById('cveList');
    listEl.innerHTML = '';
    const vulns = data.vulnerabilities || [];
    if (!vulns.length) {
        listEl.innerHTML = '<p style="text-align:center; padding:40px; color:#10b981;"><i class="fas fa-check-circle"></i> Không tìm thấy CVE nào!</p>';
    } else {
        vulns.forEach(cve => listEl.appendChild(_createCVEItem(cve)));
    }

    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

// ── Binary / PE results renderer ─────────────────────────────────────────────
function _renderBinaryResults(data) {
    _renderRiskBanner(data.risk || {});
    _renderFileInfo(data);
    _renderPEHeader(data.pe_info);
    _renderComponents(data.components);
    _renderSections(data.sections);
    _renderImports(data.imports);
    _renderStrings(data.strings);
    _renderPECVEs(data);
    document.getElementById('binaryResults').style.display = 'block';
    document.getElementById('binaryResults').scrollIntoView({ behavior: 'smooth' });
}

function _renderRiskBanner(risk) {
    const COLORS = {
        CLEAN:    { bg: '#d1fae5', border: '#10b981', text: '#065f46' },
        LOW:      { bg: '#dbeafe', border: '#3b82f6', text: '#1e3a8a' },
        MEDIUM:   { bg: '#fef3c7', border: '#f59e0b', text: '#78350f' },
        HIGH:     { bg: '#fee2e2', border: '#ef4444', text: '#7f1d1d' },
        CRITICAL: { bg: '#fce7f3', border: '#db2777', text: '#831843' },
    };
    const level  = risk.level || 'CLEAN';
    const c      = COLORS[level] || COLORS.CLEAN;
    const banner = document.getElementById('riskBanner');
    banner.style.background  = c.bg;
    banner.style.borderColor = c.border;
    banner.style.color       = c.text;
    document.getElementById('riskLevel').textContent = level;
    document.getElementById('riskScore').textContent = `Risk Score: ${risk.score || 0} / 100`;
    document.getElementById('riskFactors').innerHTML =
        (risk.factors || []).map(f => `<div class="risk-factor-item">&bull; ${_esc(f)}</div>`).join('');
}

function _renderFileInfo(data) {
    document.getElementById('peInfoName').textContent   = data.filename || '-';
    const fi = data.file_info || {};
    document.getElementById('peInfoSize').textContent   = fi.size_human || '-';
    document.getElementById('peInfoMD5').textContent    = fi.md5    || '-';
    document.getElementById('peInfoSHA256').textContent = fi.sha256 || '-';
}

function _renderPEHeader(peInfo) {
    const tbl = document.getElementById('peHeaderTable');
    if (!peInfo) {
        tbl.innerHTML = '<tr><td colspan="2" style="color:#9ca3af">Không phải PE file hoặc không đọc được header</td></tr>';
        return;
    }
    const rows = [
        ['Architecture', peInfo.machine],
        ['Compiled',     peInfo.compile_time],
        ['Subsystem',    peInfo.subsystem],
        ['Type',         peInfo.is_dll ? 'DLL' : 'EXE'],
        ['Entry Point',  peInfo.entry_point],
        ['Image Base',   peInfo.image_base],
        ['Sections',     peInfo.num_sections],
        ['TLS Callbacks', peInfo.has_tls ? 'CÓ (đáng ngờ)' : 'Không'],
    ];
    tbl.innerHTML = rows.map(([k, v]) =>
        `<tr><td>${_esc(k)}</td><td>${_esc(String(v ?? '-'))}</td></tr>`
    ).join('');
}

function _renderComponents(components) {
    const card = document.getElementById('componentsCard');
    const body = document.getElementById('componentsBody');
    if (!components || !components.length) { card.style.display = 'none'; return; }

    card.style.display = 'block';
    body.innerHTML = `
        <p style="color:#6b7280; font-size:13px; margin-bottom:10px;">
            <i class="fas fa-info-circle"></i>
            ${components.length} thư viện nhúng được phát hiện. Mỗi thư viện có thể có CVE riêng độc lập với phần mềm chính.
        </p>
        <div class="components-grid">
        ${components.map(c => {
            const ver = c.version ? `v${_esc(c.version)}` : 'version không rõ';
            return `<div class="component-card">
                <div class="component-name">${_esc(c.name)}</div>
                <div class="component-version">${ver}</div>
                <div class="component-source">Phát hiện qua: ${_esc(c.source || 'string scan')}</div>
            </div>`;
        }).join('')}
        </div>`;
}

function _renderSections(sections) {
    const el = document.getElementById('peSectionsBody');
    if (!sections || !sections.length) {
        el.innerHTML = '<p style="color:#9ca3af; padding:10px">Không có section</p>';
        return;
    }
    const rows = sections.map(s => {
        const pct   = Math.min((s.entropy / 8) * 100, 100).toFixed(0);
        const color = s.entropy > 7.0 ? '#ef4444' : s.entropy > 6.0 ? '#f59e0b' : '#10b981';
        const flags = [
            s.executable    ? '<span class="sec-flag exec">X</span>' : '',
            s.writable      ? '<span class="sec-flag write">W</span>' : '',
            s.readable      ? '<span class="sec-flag read">R</span>' : '',
            s.high_entropy  ? '<span class="sec-flag danger">HIGH ENTROPY</span>' : '',
            s.suspicious_name ? '<span class="sec-flag danger">ODD NAME</span>' : '',
        ].join('');
        return `<tr>
            <td class="sec-name">${_esc(s.name || '(none)')}</td>
            <td>${_fmtBytes(s.virtual_size)}</td>
            <td>
                <div class="entropy-bar-wrap">
                    <div class="entropy-bar" style="width:${pct}%;background:${color}"></div>
                </div>
                <span style="font-size:12px;color:${color}">${s.entropy.toFixed(2)}</span>
            </td>
            <td>${flags}</td>
        </tr>`;
    }).join('');
    el.innerHTML = `<table class="sections-table">
        <thead><tr><th>Name</th><th>Size</th><th>Entropy</th><th>Flags</th></tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

function _renderImports(imports) {
    const el = document.getElementById('peImportsBody');
    if (!imports || !(imports.suspicious || []).length) {
        el.innerHTML = '<p style="color:#10b981; padding:10px"><i class="fas fa-check-circle"></i> Không phát hiện API đáng ngờ.</p>';
        return;
    }
    const bycat = imports.by_category || {};
    const blocks = Object.entries(bycat).map(([cat, entries]) => {
        const risk    = (entries[0]?.risk || 'LOW').toLowerCase();
        const apiList = entries.map(e =>
            `<span class="api-badge risk-${risk}">${_esc(e.function)}</span>`
        ).join(' ');
        return `<div class="import-category">
            <div class="import-cat-header">
                <span class="import-cat-name">${_esc(cat)}</span>
                <span class="risk-badge risk-${risk}">${entries[0]?.risk || ''}</span>
                <span class="import-count">${entries.length} API</span>
            </div>
            <div class="api-list">${apiList}</div>
        </div>`;
    }).join('');
    el.innerHTML = `<p class="imports-summary">
        <strong>${imports.total_dlls} DLLs</strong>, <strong>${imports.total_functions} functions</strong>
        &mdash; <strong style="color:#ef4444">${imports.suspicious.length} đáng ngờ</strong>
    </p>${blocks}`;
}

function _renderStrings(strings) {
    const el = document.getElementById('peStringsBody');
    if (!strings || !Object.keys(strings).length) {
        el.innerHTML = '<p style="color:#9ca3af; padding:10px">Không tìm thấy chuỗi đặc biệt.</p>';
        return;
    }
    el.innerHTML = Object.entries(strings).map(([cat, items]) => `
        <div class="string-category">
            <div class="string-cat-header">${_esc(cat)} <span class="import-count">${items.length}</span></div>
            <div class="string-items">${items.map(s => `<div class="string-item">${_esc(s)}</div>`).join('')}</div>
        </div>`
    ).join('');
}

function _renderPECVEs(data) {
    const cpe     = data.cpe;
    const cpeInfo = data.cpe_info || {};
    const vulns   = data.vulnerabilities || [];
    const stats   = data.cve_statistics  || {};
    const listEl  = document.getElementById('peCVEList');
    const statsEl = document.getElementById('peCVEStats');

    if (!cpe) {
        listEl.innerHTML = `<p style="color:#f59e0b; padding:10px;">
            <i class="fas fa-exclamation-triangle"></i>
            ${_esc(data.cpe_error || 'Không xác định được phiên bản phần mềm từ file này.')}
        </p>`;
        statsEl.style.display = 'none';
        document.getElementById('peCPEInfo').style.display = 'none';
        document.getElementById('peCPEBadge').style.display = 'none';
        return;
    }

    document.getElementById('peCPEBadge').textContent = cpe;
    document.getElementById('peCPEBadge').style.display = 'inline';
    document.getElementById('peCPEString').textContent  = cpe;
    document.getElementById('peCPEMeta').textContent    = [
        cpeInfo.vendor  ? `Vendor: ${cpeInfo.vendor}`   : '',
        cpeInfo.product ? `Product: ${cpeInfo.product}` : '',
        cpeInfo.version ? `Version: ${cpeInfo.version}` : '',
        cpeInfo.extraction_method ? `(${cpeInfo.extraction_method})` : '',
    ].filter(Boolean).join('  |  ');
    document.getElementById('peCPEInfo').style.display = 'block';

    if (!vulns.length) {
        listEl.innerHTML = '<p style="color:#10b981; padding:10px;"><i class="fas fa-check-circle"></i> Không tìm thấy CVE nào cho phiên bản này.</p>';
        statsEl.style.display = 'none';
        return;
    }

    const sev = stats.by_severity || {};
    document.getElementById('peCVETotal').textContent    = stats.total_cves || vulns.length;
    document.getElementById('peCVECritical').textContent = sev.CRITICAL || 0;
    document.getElementById('peCVEHigh').textContent     = sev.HIGH     || 0;
    document.getElementById('peCVEMedium').textContent   = sev.MEDIUM   || 0;
    document.getElementById('peCVELow').textContent      = sev.LOW      || 0;
    document.getElementById('peCVEAvg').textContent      = (stats.avg_cvss || 0).toFixed(1);
    statsEl.style.display = 'grid';

    _renderAiPanel(data.ai_analysis, {
        panel: 'peAiPanel', badge: 'peAiRiskBadge',
        summary: 'peAiSummary', threats: 'peAiThreats',
        recs: 'peAiRecs', vectors: 'peAiVectors',
    });

    listEl.innerHTML = '';
    vulns.forEach(cve => listEl.appendChild(_createCVEItem(cve)));
}

// ── Package results renderer ──────────────────────────────────────────────────
function _renderPackageResults(data) {
    const ecosystem = data.ecosystem || '';
    const total     = data.total_packages || 0;
    const unique    = data.total_unique_cves || 0;

    // Summary banner
    const summaryEl = document.getElementById('pkgSummaryHeader');
    summaryEl.innerHTML = `
        <div class="pkg-summary">
            <div class="pkg-eco-badge eco-${ecosystem.toLowerCase()}">${_esc(ecosystem.toUpperCase())}</div>
            <div class="pkg-summary-stats">
                <span><i class="fas fa-box-open"></i> <strong>${total}</strong> packages</span>
                <span><i class="fas fa-bug"></i> <strong>${unique}</strong> unique CVEs</span>
                <span><i class="fas fa-file"></i> ${_esc(data.filename || '')}</span>
            </div>
        </div>`;

    _renderAiPanel(data.ai_analysis, {
        panel: 'pkgAiPanel', badge: 'pkgAiRiskBadge',
        summary: 'pkgAiSummary', threats: 'pkgAiThreats',
        recs: 'pkgAiRecs', vectors: 'pkgAiVectors',
    });

    const listEl = document.getElementById('pkgPackagesList');
    listEl.innerHTML = '';

    const packages = data.packages || [];
    packages.forEach(pkg => {
        listEl.appendChild(_createPackageCard(pkg));
    });

    document.getElementById('pkgResults').style.display = 'block';
    document.getElementById('pkgResults').scrollIntoView({ behavior: 'smooth' });
}

function _createPackageCard(pkg) {
    const div  = document.createElement('div');
    div.className = 'pkg-card';

    const cves  = pkg.cves || [];
    const stats = pkg.statistics || {};
    const sev   = stats.by_severity || {};
    const hasCVE = cves.length > 0;

    // Severity color for card left border
    const maxSev = hasCVE
        ? (sev.CRITICAL > 0 ? 'critical' : sev.HIGH > 0 ? 'high' : sev.MEDIUM > 0 ? 'medium' : 'low')
        : 'clean';

    div.classList.add(`pkg-card-${maxSev}`);

    div.innerHTML = `
        <div class="pkg-card-header">
            <div class="pkg-name">
                <span class="pkg-eco eco-${_esc(pkg.ecosystem)}">${_esc(pkg.ecosystem)}</span>
                <strong>${_esc(pkg.name)}</strong>
                ${pkg.version ? `<span class="pkg-ver">v${_esc(pkg.version)}</span>` : ''}
            </div>
            <div class="pkg-card-stats">
                ${hasCVE ? `
                    ${sev.CRITICAL ? `<span class="pkg-sev-dot critical">${sev.CRITICAL} Critical</span>` : ''}
                    ${sev.HIGH     ? `<span class="pkg-sev-dot high">${sev.HIGH} High</span>`   : ''}
                    ${sev.MEDIUM   ? `<span class="pkg-sev-dot medium">${sev.MEDIUM} Med</span>` : ''}
                    <span style="color:#6b7280; font-size:12px;">${cves.length} CVE${cves.length > 1 ? 's' : ''}</span>
                ` : '<span style="color:#10b981; font-size:13px;"><i class="fas fa-check-circle"></i> No CVEs</span>'}
            </div>
        </div>
        ${pkg.cpe ? `<div class="pkg-cpe"><code>${_esc(pkg.cpe)}</code></div>` : ''}
        ${hasCVE ? `<div class="pkg-cve-list">${cves.map(c => _createCVEItem(c).outerHTML).join('')}</div>` : ''}
    `;

    // Make CVEs clickable
    div.querySelectorAll('.cve-item').forEach((el, i) => {
        el.addEventListener('click', () => showCVEDetailModal(cves[i]));
    });

    return div;
}

// ── CVE item ──────────────────────────────────────────────────────────────────
function _createCVEItem(cve) {
    const div      = document.createElement('div');
    const severity = (cve.severity || 'none').toLowerCase();
    div.className  = `cve-item ${severity}`;

    const shortDesc = (cve.description || 'Không có mô tả').substring(0, 240) +
                      ((cve.description || '').length > 240 ? '...' : '');

    // Unified AI severity badge
    const aiSev = cve.ai_severity;
    let aiBadge = '';
    if (aiSev) {
        const conf   = aiSev.confidence ? ` ${(aiSev.confidence * 100).toFixed(0)}%` : '';
        const models = aiSev.models_used ? aiSev.models_used.join('+') : aiSev.source;
        aiBadge = `<span class="badge ai-sev-badge ai-sev-${aiSev.predicted_severity.toLowerCase()}"
            title="AI Ensemble (${_esc(models)})">
            AI: ${_esc(aiSev.predicted_severity)}${conf}
        </span>`;
    }

    // Unified relevance badge (only for PE analysis)
    const rel = cve.relevance;
    let relBadge = '';
    if (rel && rel.method !== 'none') {
        relBadge = `<span class="relevance-badge rel-${rel.label.toLowerCase()}"
            title="Relevance (${_esc(rel.method)}): score ${rel.score}">
            <span class="relevance-dot"></span>
            Relevance: ${_esc(rel.label)}
        </span>`;
    }

    div.innerHTML = `
        <div class="cve-header">
            <span class="cve-id">${_esc(cve.cve_id)}</span>
            <div class="cve-badges">
                <span class="badge ${severity}">${_esc(cve.severity || 'N/A')}</span>
                <span class="badge cvss-badge">CVSS ${cve.cvss_score || 'N/A'}</span>
                ${aiBadge}
            </div>
        </div>
        ${relBadge ? `<div class="cve-relevance-row">${relBadge}</div>` : ''}
        <p class="cve-summary">${_esc(shortDesc)}</p>
        <div class="cve-links">
            ${(cve.references || []).slice(0, 2).map(ref =>
                `<a href="${_esc(ref)}" target="_blank" onclick="event.stopPropagation()">
                    <i class="fas fa-external-link-alt"></i> Ref
                </a>`
            ).join(' ')}
        </div>`;

    div.style.cursor = 'pointer';
    div.addEventListener('click', () => showCVEDetailModal(cve));
    return div;
}

// ── AI Panel renderer ─────────────────────────────────────────────────────────
const _AI_COLORS = {
    CRITICAL: { bg: '#fce7f3', border: '#db2777', badge: '#db2777' },
    HIGH:     { bg: '#fff7ed', border: '#f97316', badge: '#f97316' },
    MEDIUM:   { bg: '#fefce8', border: '#eab308', badge: '#eab308' },
    LOW:      { bg: '#f0fdf4', border: '#22c55e', badge: '#22c55e' },
};

function _renderAiPanel(ai, ids) {
    const panel = document.getElementById(ids.panel);
    if (!panel) return;
    if (!ai || !ai.success) { panel.style.display = 'none'; return; }

    const c = _AI_COLORS[ai.overall_risk] || _AI_COLORS.MEDIUM;
    panel.style.borderColor = c.border;
    panel.style.background  = c.bg;
    panel.style.display     = 'block';

    const badge = document.getElementById(ids.badge);
    if (badge) {
        badge.textContent      = ai.overall_risk;
        badge.style.background = c.badge;
        badge.style.color      = '#fff';
    }

    const s = document.getElementById(ids.summary);
    if (s) s.textContent = ai.risk_summary || '';

    const t = document.getElementById(ids.threats);
    if (t) t.innerHTML = (ai.top_threats || []).map(x => `<li>${_esc(x)}</li>`).join('');

    const r = document.getElementById(ids.recs);
    if (r) r.innerHTML = (ai.recommendations || []).map(x => `<li>${_esc(x)}</li>`).join('');

    const v = document.getElementById(ids.vectors);
    if (v) v.innerHTML = (ai.key_attack_vectors || []).map(x =>
        `<span class="ai-vector-tag">${_esc(x)}</span>`
    ).join('');
}

// ── CVE Detail Modal ──────────────────────────────────────────────────────────
function showCVEDetailModal(cve) {
    document.getElementById('modal-cve-id').textContent      = cve.cve_id || '';
    document.getElementById('modal-published').textContent   = (cve.published || 'N/A').substring(0, 10);
    document.getElementById('modal-severity').textContent    = cve.severity || 'N/A';
    document.getElementById('modal-cvss').textContent        = `${cve.cvss_score || 'N/A'} (${cve.cvss_version || 'N/A'})`;
    document.getElementById('modal-cna').textContent         = cve.cna || 'N/A';
    document.getElementById('modal-description').textContent = cve.description || '—';

    // AI section
    const aiSec  = document.getElementById('modal-ai-section');
    const aiSev  = document.getElementById('modal-ai-severity');
    const relSec = document.getElementById('modal-relevance-section');
    const ctxEl  = document.getElementById('modal-ctx-reasons');

    const hasAISev = cve.ai_severity;
    const hasRel   = cve.relevance;

    if (hasAISev || hasRel) {
        aiSec.style.display = 'block';

        if (hasAISev) {
            const a = cve.ai_severity;
            const conf = a.confidence ? ` (${(a.confidence * 100).toFixed(0)}% confidence)` : '';
            const models = (a.models_used || [a.source]).join(' + ');
            aiSev.innerHTML = `
                <div class="modal-ai-row">
                    <strong>AI Predicted Severity:</strong>
                    <span class="badge ai-sev-badge ai-sev-${a.predicted_severity.toLowerCase()}">${_esc(a.predicted_severity)}</span>
                    ${conf}
                    <small style="color:#6b7280; margin-left:8px;">Models: ${_esc(models)}</small>
                </div>
                ${a.ensemble_scores ? `<div class="modal-ensemble">
                    ${Object.entries(a.ensemble_scores).map(([s, v]) =>
                        `<span class="ens-score sev-${s.toLowerCase()}">${s}: ${(v*100).toFixed(0)}%</span>`
                    ).join(' ')}
                </div>` : ''}`;
        } else {
            aiSev.innerHTML = '';
        }

        if (hasRel) {
            const rel = cve.relevance;
            relSec.innerHTML = `<div class="modal-ai-row" style="margin-top:8px;">
                <strong>Relevance to Software:</strong>
                <span class="badge rel-badge rel-${rel.label.toLowerCase()}">${rel.label}</span>
                <small style="color:#6b7280; margin-left:8px;">score ${rel.score} (${rel.method})</small>
            </div>`;
            ctxEl.innerHTML = rel.reasons && rel.reasons.length
                ? `<div style="margin-top:8px;"><strong>Lý do:</strong><ul style="margin-top:4px; padding-left:20px;">
                    ${rel.reasons.map(r => `<li style="margin:3px 0; color:#4b5563;">${_esc(r)}</li>`).join('')}
                </ul></div>`
                : '';
        } else {
            relSec.innerHTML = '';
            ctxEl.innerHTML  = '';
        }
    } else {
        aiSec.style.display = 'none';
    }

    // References
    document.getElementById('modal-references').innerHTML =
        (cve.references || []).map(r =>
            `<a href="${_esc(r)}" target="_blank">${_esc(r)}</a><br>`
        ).join('');

    document.getElementById('cve-detail-modal').style.display = 'block';
}

function closeModal() {
    document.getElementById('cve-detail-modal').style.display = 'none';
}
window.addEventListener('click', e => {
    const m = document.getElementById('cve-detail-modal');
    if (e.target === m) m.style.display = 'none';
});

// ── Export ────────────────────────────────────────────────────────────────────
function exportCurrentJSON(type) {
    const data = _state[type];
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `vulnscan-${type}-${Date.now()}.json`;
    a.click();
}

function exportCSV() {
    const data = _state.search;
    if (!data || !data.vulnerabilities) return;
    let csv = 'CVE ID,Severity,CVSS Score,AI Severity,AI Confidence,Description\n';
    data.vulnerabilities.forEach(cve => {
        const ai   = cve.ai_severity || {};
        const desc = (cve.description || '').replace(/"/g, '""');
        csv += `"${cve.cve_id}","${cve.severity}",${cve.cvss_score},"${ai.predicted_severity || ''}",${(ai.confidence || 0).toFixed(2)},"${desc}"\n`;
    });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = `vulnscan-${Date.now()}.csv`;
    a.click();
}

// ── UI helpers ────────────────────────────────────────────────────────────────
function showLoading()  { document.getElementById('loading').style.display = 'block'; }
function hideLoading()  { document.getElementById('loading').style.display = 'none'; }
function showError(msg) {
    document.getElementById('errorMessage').textContent = msg;
    document.getElementById('error').style.display = 'block';
}
function hideError()    { document.getElementById('error').style.display   = 'none'; }
function hideResults()  { document.getElementById('results').style.display = 'none'; }

function _esc(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function _fmtBytes(n) {
    if (!n) return '0 B';
    if (n < 1024)       return `${n} B`;
    if (n < 1048576)    return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
}
