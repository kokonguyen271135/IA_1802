// frontend/static/js/main.js

// Global variables
let currentResults = null;

// Tab switching
function showTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    event.target.closest('.tab-btn').classList.add('active');
    
    // Hide results and errors
    hideResults();
    hideError();
}

// File upload handling
const uploadBox = document.getElementById('uploadBox');
const fileInput = document.getElementById('fileInput');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');

// Drag and drop
uploadBox.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadBox.style.borderColor = '#10b981';
    uploadBox.style.background = '#f0fdf4';
});

uploadBox.addEventListener('dragleave', () => {
    uploadBox.style.borderColor = '#2563eb';
    uploadBox.style.background = 'transparent';
});

uploadBox.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadBox.style.borderColor = '#2563eb';
    uploadBox.style.background = 'transparent';
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});

// File input change
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

function handleFileSelect(file) {
    fileName.textContent = `📄 ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
    fileInfo.style.display = 'block';
    fileInput.files = createFileList(file);
}

function createFileList(file) {
    const dataTransfer = new DataTransfer();
    dataTransfer.items.add(file);
    return dataTransfer.files;
}

// Scan file
async function scanFile() {
    const file = fileInput.files[0];
    
    if (!file) {
        showError('Please select a file first');
        return;
    }
    
    showLoading();
    hideError();
    hideResults();
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        hideLoading();
        
        if (data.success) {
            displayResults(data);
        } else {
            showError(data.error || 'Failed to scan file');
        }
        
    } catch (error) {
        hideLoading();
        showError(`Error: ${error.message}`);
    }
}

// Search software
async function searchSoftware() {
    const softwareName = document.getElementById('softwareName').value.trim();
    const softwareVersion = document.getElementById('softwareVersion').value.trim();
    
    if (!softwareName) {
        showError('Please enter a software name');
        return;
    }
    
    showLoading();
    hideError();
    hideResults();
    
    try {
        const response = await fetch('/api/search', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                software_name: softwareName,
                version: softwareVersion
            })
        });
        
        const data = await response.json();
        
        hideLoading();
        
        if (data.success) {
            displayResults(data);
        } else {
            showError(data.error || 'Failed to search software');
        }
        
    } catch (error) {
        hideLoading();
        showError(`Error: ${error.message}`);
    }
}

// Query CPE
async function queryCPE() {
    const cpeString = document.getElementById('cpeString').value.trim();
    
    if (!cpeString) {
        showError('Please enter a CPE string');
        return;
    }
    
    showLoading();
    hideError();
    hideResults();
    
    try {
        const response = await fetch('/api/query-cpe', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                cpe: cpeString
            })
        });
        
        const data = await response.json();
        
        hideLoading();
        
        if (data.success) {
            displayResults(data);
        } else {
            showError(data.error || 'Failed to query CPE');
        }
        
    } catch (error) {
        hideLoading();
        showError(`Error: ${error.message}`);
    }
}

// Set example
function setExample(name, version) {
    document.getElementById('softwareName').value = name;
    document.getElementById('softwareVersion').value = version;
}

// Display results
function displayResults(data) {
    currentResults = data;

    // Show results section
    document.getElementById('results').style.display = 'block';

    // Display CPE
    document.getElementById('resultCPE').textContent = data.cpe || 'N/A';

    // Display statistics
    const stats = data.statistics;
    document.getElementById('statTotal').textContent = stats.total_cves;
    document.getElementById('statCritical').textContent = stats.by_severity.CRITICAL || 0;
    document.getElementById('statHigh').textContent = stats.by_severity.HIGH || 0;
    document.getElementById('statMedium').textContent = stats.by_severity.MEDIUM || 0;
    document.getElementById('statLow').textContent = stats.by_severity.LOW || 0;
    document.getElementById('statAvgCVSS').textContent = stats.avg_cvss.toFixed(1);

    // ── AI Analysis panel ──────────────────────────────────────────────────
    renderAiPanel(data.ai_analysis, 'aiAnalysisPanel', 'aiOverallRiskBadge',
                  'aiRiskSummary', 'aiTopThreats', 'aiRecommendations', 'aiAttackVectors');

    // Display CVE list
    const cveList = document.getElementById('cveList');
    cveList.innerHTML = '';

    if (data.vulnerabilities.length === 0) {
        cveList.innerHTML = '<p style="text-align: center; padding: 40px; color: #10b981;">No vulnerabilities found!</p>';
        return;
    }

    data.vulnerabilities.forEach(cve => {
        const cveItem = createCVEItem(cve);
        cveList.appendChild(cveItem);
    });

    // Scroll to results
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

// ── AI panel renderer ──────────────────────────────────────────────────────
const AI_RISK_COLORS = {
    CRITICAL: { bg: '#fce7f3', border: '#db2777', text: '#831843', badge: '#db2777' },
    HIGH:     { bg: '#fff7ed', border: '#f97316', text: '#7c2d12', badge: '#f97316' },
    MEDIUM:   { bg: '#fefce8', border: '#eab308', text: '#713f12', badge: '#eab308' },
    LOW:      { bg: '#f0fdf4', border: '#22c55e', text: '#14532d', badge: '#22c55e' },
};

function renderAiPanel(ai, panelId, riskBadgeId, summaryId, threatsId, recsId, vectorsId) {
    const panel = document.getElementById(panelId);
    if (!panel) return;

    if (!ai || !ai.success) {
        panel.style.display = 'none';
        return;
    }

    const colors = AI_RISK_COLORS[ai.overall_risk] || AI_RISK_COLORS.MEDIUM;

    // Style the panel border
    panel.style.borderColor = colors.border;
    panel.style.background  = colors.bg;

    // Overall risk badge
    const badge = document.getElementById(riskBadgeId);
    if (badge) {
        badge.textContent = ai.overall_risk;
        badge.style.background = colors.badge;
        badge.style.color = '#fff';
    }

    // Risk summary
    const summaryEl = document.getElementById(summaryId);
    if (summaryEl) summaryEl.textContent = ai.risk_summary || '';

    // Top threats
    const threatsEl = document.getElementById(threatsId);
    if (threatsEl) {
        threatsEl.innerHTML = (ai.top_threats || [])
            .map(t => `<li>${escapeHtml(t)}</li>`).join('');
    }

    // Recommendations
    const recsEl = document.getElementById(recsId);
    if (recsEl) {
        recsEl.innerHTML = (ai.recommendations || [])
            .map(r => `<li>${escapeHtml(r)}</li>`).join('');
    }

    // Attack vectors
    const vectorsEl = document.getElementById(vectorsId);
    if (vectorsEl) {
        vectorsEl.innerHTML = (ai.key_attack_vectors || [])
            .map(v => `<span class="ai-vector-tag">${escapeHtml(v)}</span>`).join('');
    }

    panel.style.display = 'block';
}

// // Create CVE item HTML
// function createCVEItem(cve) {
//     const div = document.createElement('div');
//     div.className = `cve-item ${cve.severity.toLowerCase()}`;
    
//     div.innerHTML = `
//         <div class="cve-header">
//             <span class="cve-id">${cve.cve_id}</span>
//             <div class="cve-badges">
//                 <span class="badge ${cve.severity.toLowerCase()}">${cve.severity}</span>
//                 <span class="badge cvss-badge">CVSS ${cve.cvss_score}</span>
//             </div>
//         </div>
//         <p class="cve-summary">${cve.description || 'No description available'}</p>
//         <div class="cve-links">
//             ${cve.references.map(ref => `<a href="${ref}" target="_blank"><i class="fas fa-external-link-alt"></i> Reference</a>`).join('')}
//         </div>
//     `;
    
//     return div;
// }
// function createCVEItem(cve) {
//     const description = (cve.description || 'No description available');
//     const shortDesc = description.length > 250 
//         ? description.substring(0, 247) + '...' 
//         : description;

//     const div = document.createElement('div');
//     div.className = `cve-item ${cve.severity.toLowerCase()}`;
    
//     div.innerHTML = `
//         <div class="cve-header">
//             <span class="cve-id">${cve.cve_id}</span>
//             <div class="cve-badges">
//                 <span class="badge ${cve.severity.toLowerCase()}">${cve.severity}</span>
//                 <span class="badge cvss-badge">CVSS ${cve.cvss_score}</span>
//             </div>
//         </div>
//         <p class="cve-description">${shortDesc}</p>
//         <div class="cve-links">
//             ${cve.references.map(ref => `<a href="${ref}" target="_blank"><i class="fas fa-external-link-alt"></i> Reference</a>`).join('')}
//         </div>
//     `;
    
//     // Bonus: click để xem full description
//     if (description.length > 250) {
//         div.querySelector('.cve-description').addEventListener('click', () => {
//             alert(description); // hoặc mở modal đẹp hơn
//         });
//         div.querySelector('.cve-description').style.cursor = 'pointer';
//     }
    
//     return div;
// }

function createCVEItem(cve) {
    const div = document.createElement('div');
    div.className = `cve-item ${(cve.severity || 'none').toLowerCase()}`;

    // Truncate description
    const shortDesc = (cve.description || 'No description').substring(0, 250) +
                      ((cve.description || '').length > 250 ? '...' : '');

    // ── AI Relevance badges ───────────────────────────────────────
    const secbertBadge = buildRelevanceBadge(
        cve.secbert_relevance,
        'SecBERT',
        cve.secbert_relevance ? (cve.secbert_relevance.model || 'SecBERT').split('/').pop() : ''
    );
    const ctxBadge = buildRelevanceBadge(
        cve.contextual_relevance,
        'Context',
        'rule-based'
    );

    // ML severity prediction badge
    let mlBadge = '';
    if (cve.ml_prediction && cve.ml_prediction.predicted_severity) {
        const ml = cve.ml_prediction;
        const conf = ml.confidence ? ` (${(ml.confidence * 100).toFixed(0)}%)` : '';
        mlBadge = `<span class="badge ml-badge" title="ML: ${escapeHtml(ml.source || 'TF-IDF+LR')}">
            ML: ${escapeHtml(ml.predicted_severity)}${conf}
        </span>`;
    }

    const hasBadges = secbertBadge || ctxBadge || mlBadge;

    div.innerHTML = `
        <div class="cve-header">
            <span class="cve-id">${escapeHtml(cve.cve_id)}</span>
            <div class="cve-badges">
                <span class="badge ${(cve.severity || 'none').toLowerCase()}">${escapeHtml(cve.severity || 'N/A')}</span>
                <span class="badge cvss-badge">CVSS ${cve.cvss_score || 'N/A'}</span>
                ${mlBadge}
            </div>
        </div>
        ${hasBadges ? `<div class="cve-relevance-row">${secbertBadge}${ctxBadge}</div>` : ''}
        <p class="cve-summary">${escapeHtml(shortDesc)}</p>
        <div class="cve-links">
            ${(cve.references || []).map(ref =>
                `<a href="${escapeHtml(ref)}" target="_blank">
                    <i class="fas fa-external-link-alt"></i> Reference
                </a>`
            ).join(' • ')}
        </div>
    `;

    div.style.cursor = 'pointer';
    div.addEventListener('click', () => showCVEDetailModal(cve));

    return div;
}

// Export JSON
function exportJSON() {
    if (!currentResults) return;
    
    const dataStr = JSON.stringify(currentResults, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `vulnerability-scan-${Date.now()}.json`;
    link.click();
}

// Export CSV
function exportCSV() {
    if (!currentResults || !currentResults.vulnerabilities) return;
    
    // CSV header
    let csv = 'CVE ID,Severity,CVSS Score,Summary\n';
    
    // CSV rows
    currentResults.vulnerabilities.forEach(cve => {
        const summary = cve.summary.replace(/"/g, '""');
        csv += `"${cve.cve_id}","${cve.severity}",${cve.cvss_score},"${summary}"\n`;
    });
    
    const dataBlob = new Blob([csv], { type: 'text/csv' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(dataBlob);
    link.download = `vulnerability-scan-${Date.now()}.csv`;
    link.click();
}

// UI helpers
function showLoading() {
    document.getElementById('loading').style.display = 'block';
}

function hideLoading() {
    document.getElementById('loading').style.display = 'none';
}

function showError(message) {
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('error').style.display = 'block';
}

function hideError() {
    document.getElementById('error').style.display = 'none';
}

function hideResults() {
    document.getElementById('results').style.display = 'none';
}

// ============================================================
// PE STATIC ANALYSIS
// ============================================================

let currentPEResults = null;

// --- Run analysis ---
async function analyzePE() {
    const file = fileInput.files[0];
    if (!file) { showPEError('Please select a file first.'); return; }

    document.getElementById('peLoading').style.display  = 'block';
    document.getElementById('peResults').style.display  = 'none';
    document.getElementById('peError').style.display    = 'none';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res  = await fetch('/api/pe-analyze', { method: 'POST', body: formData });
        const data = await res.json();

        document.getElementById('peLoading').style.display = 'none';

        if (data.success) {
            currentPEResults = data;
            renderPEResults(data);
        } else {
            showPEError(data.error || 'Analysis failed.');
        }
    } catch (err) {
        document.getElementById('peLoading').style.display = 'none';
        showPEError(`Network error: ${err.message}`);
    }
}

function showPEError(msg) {
    document.getElementById('peErrorMessage').textContent = msg;
    document.getElementById('peError').style.display      = 'block';
    document.getElementById('peLoading').style.display    = 'none';
}

// --- Render all results ---
function renderPEResults(data) {
    renderRiskBanner(data.risk);
    renderFileInfo(data);
    renderPEHeader(data.pe_info);
    renderCodeBERTAnalysis(data.codebert_analysis, data.behavior_profile_text);
    renderSections(data.sections);
    renderImports(data.imports);
    renderStrings(data.strings);
    renderPECVEs(data);
    document.getElementById('peResults').style.display = 'block';
    document.getElementById('peResults').scrollIntoView({ behavior: 'smooth' });
}

// CVE section inside PE Analysis tab
function renderPECVEs(data) {
    const cpe         = data.cpe;
    const cpeInfo     = data.cpe_info || {};
    const vulns       = data.vulnerabilities || [];
    const stats       = data.cve_statistics || {};
    const cpeError    = data.cpe_error;

    const listEl      = document.getElementById('peCVEList');
    const statsEl     = document.getElementById('peCVEStats');
    const cpeInfoEl   = document.getElementById('peCPEInfo');
    const cpeBadge    = document.getElementById('peCPEBadge');

    // --- No CPE extracted ---
    if (!cpe) {
        const reason = cpeError
            ? `CPE extraction failed: ${cpeError}`
            : (cpeInfo.error || 'Could not identify software version from this file.');
        listEl.innerHTML = `<p style="color:#f59e0b; padding:10px;">
            <i class="fas fa-exclamation-triangle"></i>&nbsp;
            ${escapeHtml(reason)}
        </p>`;
        statsEl.style.display  = 'none';
        cpeInfoEl.style.display = 'none';
        cpeBadge.style.display  = 'none';
        return;
    }

    // --- Show CPE ---
    cpeBadge.textContent    = cpe;
    cpeBadge.style.display  = 'inline';
    document.getElementById('peCPEString').textContent = cpe;
    const meta = [
        cpeInfo.vendor  ? `Vendor: ${cpeInfo.vendor}`   : '',
        cpeInfo.product ? `Product: ${cpeInfo.product}` : '',
        cpeInfo.version ? `Version: ${cpeInfo.version}` : '',
        cpeInfo.extraction_method ? `(via ${cpeInfo.extraction_method})` : '',
    ].filter(Boolean).join('  |  ');
    document.getElementById('peCPEMeta').textContent = meta;
    cpeInfoEl.style.display = 'block';

    // --- No CVEs found ---
    if (vulns.length === 0) {
        listEl.innerHTML = `<p style="color:#10b981; padding:10px;">
            <i class="fas fa-check-circle"></i>&nbsp;No known CVEs found for this software version.
        </p>`;
        statsEl.style.display = 'none';
        return;
    }

    // --- Stats ---
    const sev = stats.by_severity || {};
    document.getElementById('peCVETotal').textContent    = stats.total_cves || vulns.length;
    document.getElementById('peCVECritical').textContent = sev.CRITICAL || 0;
    document.getElementById('peCVEHigh').textContent     = sev.HIGH     || 0;
    document.getElementById('peCVEMedium').textContent   = sev.MEDIUM   || 0;
    document.getElementById('peCVELow').textContent      = sev.LOW      || 0;
    document.getElementById('peCVEAvg').textContent      = (stats.avg_cvss || 0).toFixed(1);
    statsEl.style.display = 'grid';

    // --- AI Analysis panel (PE tab) ---
    renderAiPanel(data.ai_analysis, 'peAiPanel', 'peAiOverallRiskBadge',
                  'peAiRiskSummary', 'peAiTopThreats', 'peAiRecommendations', 'peAiAttackVectors');

    // --- CVE list ---
    listEl.innerHTML = '';
    const header = document.createElement('h3');
    header.style.cssText = 'margin-bottom:16px; color:#1f2937;';
    header.innerHTML = `<i class="fas fa-list"></i> Vulnerabilities
        <span style="font-size:13px; font-weight:400; color:#6b7280; margin-left:8px;">
            (showing ${vulns.length} of ${stats.total_cves || vulns.length})
        </span>`;
    listEl.appendChild(header);

    vulns.forEach(cve => {
        listEl.appendChild(createCVEItem(cve));
    });
}

// ============================================================
// CODEBERT DEEP BEHAVIOR ANALYSIS
// ============================================================

const CODEBERT_SEVERITY_COLORS = {
    CRITICAL: '#dc2626',
    HIGH:     '#f97316',
    MEDIUM:   '#eab308',
    LOW:      '#22c55e',
    MINIMAL:  '#9ca3af',
};

const CONFIDENCE_COLORS = {
    high:   '#10b981',
    medium: '#f59e0b',
    low:    '#f97316',
    none:   '#9ca3af',
};

function renderCodeBERTAnalysis(cb, profileText) {
    const card = document.getElementById('codebertCard');
    const secbertCard = document.getElementById('secbertProfileCard');
    if (!card) return;

    // ── SecBERT profile text ──────────────────────────────────────
    if (profileText && secbertCard) {
        document.getElementById('secbertProfileText').textContent = profileText;
        secbertCard.style.display = 'block';
    } else if (secbertCard) {
        secbertCard.style.display = 'none';
    }

    if (!cb || !cb.available) {
        card.style.display = 'none';
        return;
    }

    card.style.display = 'block';

    // ── Score bar ─────────────────────────────────────────────────
    const score = cb.codebert_score || 0;
    const pct = Math.round(score * 100);
    const barColor = score >= 0.75 ? '#dc2626'
                   : score >= 0.55 ? '#f97316'
                   : score >= 0.35 ? '#eab308'
                   : score >= 0.15 ? '#22c55e'
                   : '#9ca3af';

    const bar = document.getElementById('codebertBar');
    if (bar) {
        bar.style.width = `${pct}%`;
        bar.style.background = barColor;
    }
    const scoreVal = document.getElementById('codebertScoreValue');
    if (scoreVal) scoreVal.textContent = score.toFixed(3);

    const confEl = document.getElementById('codebertConfidence');
    if (confEl) {
        const conf = cb.confidence || 'none';
        confEl.textContent = `Confidence: ${conf.toUpperCase()}`;
        confEl.style.color = CONFIDENCE_COLORS[conf] || '#9ca3af';
    }

    // ── Behavior summary ──────────────────────────────────────────
    const sumEl = document.getElementById('codebertSummary');
    if (sumEl) sumEl.textContent = cb.behavior_summary || '';

    // ── Detected patterns ─────────────────────────────────────────
    const patternsEl = document.getElementById('codebertPatterns');
    if (!patternsEl) return;

    const detected = cb.detected_patterns || [];
    const allScores = cb.all_scores || [];

    if (detected.length === 0 && allScores.length === 0) {
        patternsEl.innerHTML = '<p style="color:#10b981; padding:8px 0;"><i class="fas fa-check-circle"></i> No malware behavior patterns detected.</p>';
        return;
    }

    // Detected patterns (above threshold)
    let html = '';
    if (detected.length > 0) {
        html += `<div class="codebert-section-title">
            <i class="fas fa-exclamation-triangle" style="color:#ef4444"></i>
            Detected Behavior Patterns (similarity ≥ ${0.60})
        </div>`;
        html += '<div class="codebert-patterns-grid">';
        detected.forEach(p => {
            const color = CODEBERT_SEVERITY_COLORS[p.severity] || '#9ca3af';
            const simPct = Math.round(p.similarity * 100);
            html += `
            <div class="codebert-pattern-card detected">
                <div class="pattern-header">
                    <span class="pattern-name">${escapeHtml(p.pattern)}</span>
                    <span class="pattern-severity-badge" style="background:${color}">${escapeHtml(p.severity)}</span>
                    <span class="pattern-mitre">MITRE ${escapeHtml(p.mitre || '')}</span>
                </div>
                <div class="pattern-sim-bar-wrap">
                    <div class="pattern-sim-bar" style="width:${simPct}%; background:${color}"></div>
                    <span class="pattern-sim-val">${p.similarity.toFixed(3)}</span>
                </div>
                <p class="pattern-desc">${escapeHtml(p.description)}</p>
            </div>`;
        });
        html += '</div>';
    }

    // Top-5 all scores (collapsible)
    if (allScores.length > 0) {
        html += `<details class="codebert-all-scores">
            <summary>All Pattern Similarity Scores (top ${Math.min(allScores.length, 10)})</summary>
            <div class="all-scores-table-wrap">
            <table class="all-scores-table">
                <thead><tr><th>Pattern</th><th>Severity</th><th>MITRE</th><th>Similarity</th></tr></thead>
                <tbody>`;
        allScores.forEach(p => {
            const color = CODEBERT_SEVERITY_COLORS[p.severity] || '#9ca3af';
            const isDetected = p.similarity >= 0.60;
            html += `<tr class="${isDetected ? 'score-row-detected' : ''}">
                <td>${escapeHtml(p.pattern)}</td>
                <td><span style="color:${color};font-weight:600">${escapeHtml(p.severity)}</span></td>
                <td><code>${escapeHtml(p.mitre || '')}</code></td>
                <td>
                    <span style="color:${color};font-weight:700">${p.similarity.toFixed(4)}</span>
                    ${isDetected ? ' <span class="detected-tick">✓</span>' : ''}
                </td>
            </tr>`;
        });
        html += '</tbody></table></div></details>';
    }

    patternsEl.innerHTML = html;
}


// ============================================================
// CVE RELEVANCE BADGE HELPERS
// ============================================================

const RELEVANCE_COLORS = {
    CRITICAL: { bg: '#fde8e8', border: '#dc2626', text: '#7f1d1d', dot: '#dc2626' },
    HIGH:     { bg: '#fff3e6', border: '#f97316', text: '#7c2d12', dot: '#f97316' },
    MEDIUM:   { bg: '#fefce8', border: '#eab308', text: '#713f12', dot: '#eab308' },
    LOW:      { bg: '#f0fdf4', border: '#22c55e', text: '#14532d', dot: '#22c55e' },
    MINIMAL:  { bg: '#f3f4f6', border: '#9ca3af', text: '#374151', dot: '#9ca3af' },
};

function buildRelevanceBadge(relevance, label, modelShort) {
    if (!relevance) return '';
    const lvl = relevance.label || 'MINIMAL';
    const score = relevance.score || 0;
    const c = RELEVANCE_COLORS[lvl] || RELEVANCE_COLORS.MINIMAL;
    return `<span class="relevance-badge"
        style="background:${c.bg}; border-color:${c.border}; color:${c.text};"
        title="${escapeHtml(label)}: ${lvl} (score=${score.toFixed(3)}) — ${escapeHtml(modelShort)}">
        <span class="relevance-dot" style="background:${c.dot}"></span>
        ${escapeHtml(label)}: ${lvl}
    </span>`;
}


// Risk banner
const RISK_COLORS = {
    CLEAN:    { bg: '#d1fae5', border: '#10b981', text: '#065f46' },
    LOW:      { bg: '#dbeafe', border: '#3b82f6', text: '#1e3a8a' },
    MEDIUM:   { bg: '#fef3c7', border: '#f59e0b', text: '#78350f' },
    HIGH:     { bg: '#fee2e2', border: '#ef4444', text: '#7f1d1d' },
    CRITICAL: { bg: '#fce7f3', border: '#db2777', text: '#831843' },
};

function renderRiskBanner(risk) {
    const level   = risk.level || 'CLEAN';
    const score   = risk.score || 0;
    const factors = risk.factors || [];
    const colors  = RISK_COLORS[level] || RISK_COLORS.CLEAN;

    const banner = document.getElementById('riskBanner');
    banner.style.background   = colors.bg;
    banner.style.borderColor  = colors.border;
    banner.style.color        = colors.text;

    document.getElementById('riskLevel').textContent = level;
    document.getElementById('riskScore').textContent = `Risk Score: ${score} / 100`;

    const factorsEl = document.getElementById('riskFactors');
    factorsEl.innerHTML = factors.map(f => `<div class="risk-factor-item">&#8226; ${escapeHtml(f)}</div>`).join('');
}

// File info
function renderFileInfo(data) {
    document.getElementById('peInfoName').textContent   = data.filename || '-';
    const fi = data.file_info || {};
    document.getElementById('peInfoSize').textContent   = fi.size_human || '-';
    document.getElementById('peInfoMD5').textContent    = fi.md5   || '-';
    document.getElementById('peInfoSHA1').textContent   = fi.sha1  || '-';
    document.getElementById('peInfoSHA256').textContent = fi.sha256 || '-';
}

// PE header
function renderPEHeader(peInfo) {
    const tbl = document.getElementById('peHeaderTable');
    if (!peInfo) {
        tbl.innerHTML = '<tr><td colspan="2" style="color:#9ca3af">Not a valid PE file or header parse failed</td></tr>';
        return;
    }
    const rows = [
        ['Machine',       peInfo.machine],
        ['Compiled',      peInfo.compile_time],
        ['Subsystem',     peInfo.subsystem],
        ['File Type',     peInfo.is_dll ? 'DLL' : 'EXE'],
        ['Entry Point',   peInfo.entry_point],
        ['Image Base',    peInfo.image_base],
        ['Sections',      peInfo.num_sections],
        ['TLS Callbacks', peInfo.has_tls ? 'YES (suspicious)' : 'No'],
        ['Debug Info',    peInfo.has_debug ? 'Present' : 'Stripped'],
    ];
    tbl.innerHTML = rows.map(([k, v]) =>
        `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v ?? '-'))}</td></tr>`
    ).join('');
}

// Sections
function renderSections(sections) {
    const container = document.getElementById('peSectionsBody');
    if (!sections || sections.length === 0) {
        container.innerHTML = '<p style="color:#9ca3af;padding:10px">No sections found</p>';
        return;
    }

    const rows = sections.map(s => {
        const entropyPct  = Math.min((s.entropy / 8) * 100, 100).toFixed(0);
        const entropyColor = s.entropy > 7.0 ? '#ef4444' : s.entropy > 6.0 ? '#f59e0b' : '#10b981';
        const flags = [
            s.executable ? '<span class="sec-flag exec">X</span>' : '',
            s.writable   ? '<span class="sec-flag write">W</span>' : '',
            s.readable   ? '<span class="sec-flag read">R</span>'  : '',
            s.high_entropy    ? '<span class="sec-flag danger">HIGH ENTROPY</span>' : '',
            s.suspicious_name ? '<span class="sec-flag danger">ODD NAME</span>'    : '',
        ].join('');
        return `
        <tr>
            <td class="sec-name">${escapeHtml(s.name || '(none)')}</td>
            <td>${formatBytes(s.virtual_size)}</td>
            <td>
                <div class="entropy-bar-wrap">
                    <div class="entropy-bar" style="width:${entropyPct}%;background:${entropyColor}"></div>
                </div>
                <span style="font-size:12px;color:${entropyColor}">${s.entropy.toFixed(2)}</span>
            </td>
            <td>${flags}</td>
        </tr>`;
    }).join('');

    container.innerHTML = `
    <table class="sections-table">
        <thead><tr><th>Name</th><th>Virtual Size</th><th>Entropy</th><th>Flags</th></tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

// Suspicious imports
function renderImports(imports) {
    const container = document.getElementById('peImportsBody');
    if (!imports || !imports.suspicious || imports.suspicious.length === 0) {
        container.innerHTML = '<p style="color:#10b981;padding:10px">No suspicious imports detected.</p>';
        return;
    }

    const byCategory = imports.by_category || {};
    const catBlocks  = Object.entries(byCategory).map(([cat, entries]) => {
        const riskClass = (entries[0]?.risk || 'LOW').toLowerCase();
        const apiList   = entries.map(e =>
            `<span class="api-badge risk-${riskClass}">${escapeHtml(e.function)}</span>`
        ).join(' ');
        return `
        <div class="import-category">
            <div class="import-cat-header">
                <span class="import-cat-name">${escapeHtml(cat)}</span>
                <span class="risk-badge risk-${riskClass}">${entries[0]?.risk || ''}</span>
                <span class="import-count">${entries.length} API(s)</span>
            </div>
            <div class="api-list">${apiList}</div>
        </div>`;
    }).join('');

    container.innerHTML = `
    <p class="imports-summary">
        Total: <strong>${imports.total_dlls} DLLs</strong>, <strong>${imports.total_functions} functions</strong>
        &mdash; <strong style="color:#ef4444">${imports.suspicious.length} suspicious</strong>
    </p>
    ${catBlocks}`;
}

// Extracted strings
function renderStrings(strings) {
    const container = document.getElementById('peStringsBody');
    if (!strings || Object.keys(strings).length === 0) {
        container.innerHTML = '<p style="color:#9ca3af;padding:10px">No notable strings found.</p>';
        return;
    }

    const blocks = Object.entries(strings).map(([cat, items]) => {
        const itemList = items.map(s =>
            `<div class="string-item">${escapeHtml(s)}</div>`
        ).join('');
        return `
        <div class="string-category">
            <div class="string-cat-header">${escapeHtml(cat)} <span class="import-count">${items.length}</span></div>
            <div class="string-items">${itemList}</div>
        </div>`;
    }).join('');

    container.innerHTML = blocks;
}

// Export
function exportPEJSON() {
    if (!currentPEResults) return;
    const blob = new Blob([JSON.stringify(currentPEResults, null, 2)], { type: 'application/json' });
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `pe-analysis-${currentPEResults.filename || 'result'}-${Date.now()}.json`;
    a.click();
}

// Utility helpers
function formatBytes(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ============================================================
// Initialize
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    console.log('CVE-CPE Vulnerability Scanner initialized');
    
    // Load database stats
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => {
            console.log('Database loaded:', data);
        })
        .catch(err => {
            console.error('Failed to load database stats:', err);
        });
});

function showCVEDetailModal(cve) {
    let modal = document.getElementById('cve-detail-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'cve-detail-modal';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <span class="close-btn" onclick="closeModal()">&times;</span>
                <h2 id="modal-cve-id"></h2>
                <div class="modal-meta">
                    <p><strong>Published:</strong> <span id="modal-published"></span></p>
                    <p><strong>CNA / Source:</strong> <span id="modal-cna"></span></p>
                    <p><strong>Severity:</strong> <span id="modal-severity"></span></p>
                    <p><strong>CVSS:</strong> <span id="modal-cvss"></span></p>
                </div>
                <!-- AI Relevance section -->
                <div id="modal-ai-section" style="display:none; margin:16px 0;">
                    <h3><i class="fas fa-brain"></i> AI Relevance to This File</h3>
                    <div id="modal-ai-badges" style="margin:8px 0;"></div>
                    <div id="modal-ctx-reasons"></div>
                </div>
                <h3>Description</h3>
                <p id="modal-description"></p>
                <h3>References</h3>
                <div id="modal-references"></div>
                <button class="btn btn-primary" onclick="closeModal()">Close</button>
            </div>
        `;
        document.body.appendChild(modal);
    }

    document.getElementById('modal-cve-id').textContent = cve.cve_id;
    document.getElementById('modal-published').textContent = (cve.published || 'N/A').substring(0, 10);
    document.getElementById('modal-cna').textContent = cve.cna || 'Unknown';
    document.getElementById('modal-severity').textContent = cve.severity;
    document.getElementById('modal-cvss').textContent = `${cve.cvss_score} (${cve.cvss_version || 'N/A'})`;
    document.getElementById('modal-description').textContent = cve.description || 'No description from NVD.';

    // ── AI Relevance section ──────────────────────────────────────
    const aiSection = document.getElementById('modal-ai-section');
    const aiBadgesEl = document.getElementById('modal-ai-badges');
    const ctxReasonsEl = document.getElementById('modal-ctx-reasons');

    const hasSec = cve.secbert_relevance;
    const hasCtx = cve.contextual_relevance;

    if (hasSec || hasCtx) {
        aiSection.style.display = 'block';
        let badgesHtml = '';
        if (hasSec) {
            badgesHtml += buildRelevanceBadge(hasSec, 'SecBERT Semantic', hasSec.model || 'SecBERT');
            badgesHtml += `<span style="margin-left:12px; color:#6b7280; font-size:13px;">
                score: ${hasSec.score.toFixed(4)}
            </span>`;
        }
        if (hasCtx) {
            badgesHtml += '&nbsp;';
            badgesHtml += buildRelevanceBadge(hasCtx, 'Contextual', 'rule-based');
            badgesHtml += `<span style="margin-left:12px; color:#6b7280; font-size:13px;">
                score: ${hasCtx.score.toFixed(3)}
            </span>`;
        }
        aiBadgesEl.innerHTML = badgesHtml;

        // Contextual reasons
        if (hasCtx && hasCtx.reasons && hasCtx.reasons.length > 0) {
            ctxReasonsEl.innerHTML = `
                <div style="margin-top:10px;">
                    <strong style="color:#374151;">Why this CVE is relevant:</strong>
                    <ul style="margin-top:6px; padding-left:20px; color:#4b5563;">
                        ${hasCtx.reasons.map(r => `<li style="margin:4px 0;">${escapeHtml(r)}</li>`).join('')}
                    </ul>
                </div>`;
        } else {
            ctxReasonsEl.innerHTML = '';
        }
    } else {
        aiSection.style.display = 'none';
    }

    // References
    const refsDiv = document.getElementById('modal-references');
    refsDiv.innerHTML = (cve.references || []).map(ref =>
        `<a href="${escapeHtml(ref)}" target="_blank">${escapeHtml(ref)}</a><br>`
    ).join('');

    modal.style.display = 'block';
}

// Đóng modal khi click ngoài hoặc nút close
function closeModal() {
    const modal = document.getElementById('cve-detail-modal');
    if (modal) modal.style.display = 'none';
}

// Đóng khi click ngoài modal
window.addEventListener('click', (event) => {
    const modal = document.getElementById('cve-detail-modal');
    if (event.target === modal) {
        closeModal();
    }
});