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

    // AI severity prediction badges (3 models compared)
    let mlBadge = '';
    if (cve.bert_prediction && cve.bert_prediction.predicted_severity) {
        const b = cve.bert_prediction;
        const conf = b.confidence ? ` ${(b.confidence * 100).toFixed(0)}%` : '';
        mlBadge += `<span class="badge ml-badge bert-badge"
            title="Fine-tuned BERT (${escapeHtml(b.model || 'DistilBERT')})">
            BERT: ${escapeHtml(b.predicted_severity)}${conf}</span> `;
    } else if (cve.ml_prediction && cve.ml_prediction.predicted_severity) {
        const ml = cve.ml_prediction;
        const conf = ml.confidence ? ` ${(ml.confidence * 100).toFixed(0)}%` : '';
        mlBadge += `<span class="badge ml-badge"
            title="Baseline: TF-IDF + Logistic Regression">
            ML: ${escapeHtml(ml.predicted_severity)}${conf}</span> `;
    }
    if (cve.zero_shot_prediction && cve.zero_shot_prediction.predicted_severity) {
        const zs = cve.zero_shot_prediction;
        const conf = zs.confidence ? ` ${(zs.confidence * 100).toFixed(0)}%` : '';
        mlBadge += `<span class="badge ml-badge zs-badge"
            title="Zero-shot NLI (${escapeHtml(zs.model || 'BART-MNLI')}) — no training data">
            NLI: ${escapeHtml(zs.predicted_severity)}${conf}</span>`;
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
            ${(cve.references || []).slice(0, 3).map(ref =>
                `<a href="${escapeHtml(ref)}" target="_blank">
                    <i class="fas fa-external-link-alt"></i> Reference
                </a>`
            ).join(' • ')}
            ${(cve.references || []).length > 3 ? `<span class="ref-more">+${(cve.references || []).length - 3} more</span>` : ''}
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
// ============================================================
// XGBOOST ML CLASSIFIER
// ============================================================

function renderMlClassifier(ml) {
    const card = document.getElementById('mlClassifierCard');
    if (!card) return;
    if (!ml || !ml.success) { card.style.display = 'none'; return; }

    card.style.display = 'block';

    const COLORS = { MALICIOUS: '#dc2626', SUSPICIOUS: '#ea580c', CLEAN: '#16a34a' };
    const verdict = ml.verdict || 'UNKNOWN';
    const prob    = ml.probability || 0;
    const color   = COLORS[verdict] || '#6b7280';

    // Verdict badge
    const badge = document.getElementById('mlVerdictBadge');
    if (badge) {
        badge.textContent = verdict;
        badge.style.background = color;
        badge.style.color = '#fff';
    }

    // Probability display
    const probEl = document.getElementById('mlProbValue');
    if (probEl) {
        probEl.textContent = Math.round(prob * 100) + '%';
        probEl.style.color = color;
    }
    const barEl = document.getElementById('mlProbBar');
    if (barEl) {
        barEl.style.width      = Math.round(prob * 100) + '%';
        barEl.style.background = color;
    }

    // Top features (feature importance bars)
    const featEl = document.getElementById('mlTopFeatures');
    if (featEl && ml.top_features) {
        const maxImp = Math.max(...ml.top_features.map(f => f.importance), 0.0001);
        featEl.innerHTML = ml.top_features.slice(0, 8).map(f => {
            const barW   = Math.round((f.importance / maxImp) * 100);
            const active = f.value > 0 ? color : '#374151';
            return `<div style="display:flex; align-items:center; gap:8px; margin-bottom:5px;">
                <span style="font-size:11px; color:#94a3b8; width:200px; white-space:nowrap;
                    overflow:hidden; text-overflow:ellipsis; flex-shrink:0;">
                    ${escapeHtml(f.feature)}</span>
                <div style="flex:1; background:#1e293b; border-radius:3px; height:14px; overflow:hidden;">
                    <div style="width:${barW}%; background:${active}; height:100%; border-radius:3px;"></div>
                </div>
                <span style="font-size:11px; color:#6b7280; width:36px; text-align:right; flex-shrink:0;">
                    ${f.value}</span>
            </div>`;
        }).join('');
    }

    // Model metadata row
    const infoEl = document.getElementById('mlModelInfo');
    if (infoEl && ml.model_info) {
        const m = ml.model_info;
        const chips = [
            m.train_samples ? `Trained on ${m.train_samples.toLocaleString()} samples` : null,
            m.val_auc       ? `Val AUC: ${m.val_auc}` : null,
            m.data_source   ? `Data: ${m.data_source}` : null,
            m.xgboost_version ? `XGBoost ${m.xgboost_version}` : null,
        ].filter(Boolean);
        infoEl.innerHTML = chips.map(c =>
            `<span style="background:#1e293b; padding:2px 8px; border-radius:6px;">${escapeHtml(c)}</span>`
        ).join('');
    }
}

// ============================================================
// AI BINARY CODE ANALYSIS (disassembly → Claude reads assembly)
// ============================================================

function renderAiCodeAnalysis(codeAnalysis) {
    const card = document.getElementById('aiCodeAnalysisCard');
    if (!card) return;

    if (!codeAnalysis || !codeAnalysis.success) {
        card.style.display = 'none';
        return;
    }

    card.style.display = 'block';

    // Risk badge
    const riskBadge = document.getElementById('aiCodeRiskBadge');
    if (riskBadge) {
        const r = codeAnalysis.code_risk || 'UNKNOWN';
        const rColors = { CRITICAL:'#dc2626', HIGH:'#ea580c', MEDIUM:'#d97706', LOW:'#16a34a', CLEAN:'#059669' };
        riskBadge.textContent = r;
        riskBadge.style.background = rColors[r] || '#374151';
        riskBadge.style.color = '#fff';
    }

    // Arch + instruction count
    const archEl = document.getElementById('aiCodeArch');
    if (archEl) archEl.textContent = `[${escapeHtml(codeAnalysis.arch || '')}]`;
    const instrEl = document.getElementById('aiCodeInstrCount');
    if (instrEl && codeAnalysis.instructions_analyzed)
        instrEl.textContent = `${codeAnalysis.instructions_analyzed} instructions analyzed`;

    // Entry point analysis
    const epEl = document.getElementById('aiCodeEntryPoint');
    if (epEl) epEl.textContent = codeAnalysis.entry_point_analysis || '';

    // Overall verdict
    const verdictEl = document.getElementById('aiCodeVerdict');
    if (verdictEl) verdictEl.textContent = codeAnalysis.overall_code_verdict || '';

    // Per-API code findings
    const findingsSection = document.getElementById('aiCodeFindingsSection');
    const findingsEl = document.getElementById('aiCodeFindings');
    const findings = codeAnalysis.code_findings || [];
    if (findingsEl && findings.length > 0) {
        findingsSection.style.display = 'block';
        findingsEl.innerHTML = findings.map(f => `
            <div style="
                background:#1a1a2e; border:1px solid #4c1d95; border-radius:8px;
                padding:12px; margin-bottom:8px;">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
                    <code style="
                        background:#2e1065; color:#c4b5fd; padding:2px 8px;
                        border-radius:4px; font-size:12px;">${escapeHtml(f.api || '')}</code>
                    ${f.mitre ? `<span style="font-size:11px; color:#7c3aed; border:1px solid #4c1d95;
                        padding:1px 6px; border-radius:8px;">${escapeHtml(f.mitre)}</span>` : ''}
                </div>
                <div style="color:#a5b4fc; font-size:13px; margin-bottom:4px;">
                    <strong>Pattern:</strong> ${escapeHtml(f.code_pattern || '')}
                </div>
                ${f.vulnerability ? `<div style="color:#f87171; font-size:12px; font-style:italic;">
                    <i class="fas fa-exclamation-triangle"></i> ${escapeHtml(f.vulnerability)}
                </div>` : ''}
            </div>`
        ).join('');
    } else if (findingsSection) {
        findingsSection.style.display = 'none';
    }

    // Hardcoded artifacts
    const hardSection = document.getElementById('aiHardcodedSection');
    const hardList = document.getElementById('aiHardcodedList');
    const artifacts = codeAnalysis.hardcoded_artifacts || [];
    if (hardList && artifacts.length > 0) {
        hardSection.style.display = 'block';
        hardList.innerHTML = artifacts.map(a =>
            `<li style="color:#fcd34d; font-size:13px; margin-bottom:3px;">${escapeHtml(a)}</li>`
        ).join('');
    } else if (hardSection) {
        hardSection.style.display = 'none';
    }

    // Obfuscation techniques
    const obfSection = document.getElementById('aiObfuscationSection');
    const obfList = document.getElementById('aiObfuscationList');
    const obf = codeAnalysis.obfuscation_techniques || [];
    if (obfList && obf.length > 0) {
        obfSection.style.display = 'block';
        obfList.innerHTML = obf.map(o =>
            `<li style="color:#fdba74; font-size:13px; margin-bottom:3px;">${escapeHtml(o)}</li>`
        ).join('');
    } else if (obfSection) {
        obfSection.style.display = 'none';
    }
}

// ============================================================
// SECURITY MITIGATIONS + AI COMPREHENSIVE ASSESSMENT
// ============================================================

const MITIGATION_LABELS = {
    aslr:            { label: 'ASLR',             icon: 'fa-random' },
    high_entropy_va: { label: 'High-Entropy VA',  icon: 'fa-random' },
    dep_nx:          { label: 'DEP / NX',          icon: 'fa-ban' },
    cfg:             { label: 'CFG',               icon: 'fa-shield-alt' },
    safe_seh:        { label: 'SafeSEH',           icon: 'fa-layer-group' },
    force_integrity: { label: 'Code Integrity',   icon: 'fa-lock' },
    stack_canary:    { label: 'Stack Canary (GS)', icon: 'fa-fish' },
    authenticode:    { label: 'Authenticode',      icon: 'fa-certificate' },
    appcontainer:    { label: 'AppContainer',      icon: 'fa-box' },
};

const POSTURE_COLORS = {
    STRONG:   { bg: '#065f46', border: '#059669', text: '#6ee7b7' },
    MODERATE: { bg: '#78350f', border: '#d97706', text: '#fcd34d' },
    WEAK:     { bg: '#7c2d12', border: '#ea580c', text: '#fdba74' },
    CRITICAL: { bg: '#7f1d1d', border: '#dc2626', text: '#fca5a5' },
};

function renderSecurityAssessment(mitigations, aiAssessment) {
    const card = document.getElementById('securityAssessmentCard');
    if (!card) return;

    // Need at least mitigation data to show anything
    if (!mitigations || !mitigations.flags) {
        card.style.display = 'none';
        return;
    }

    card.style.display = 'block';

    // ── Posture badge ──────────────────────────────────────────────────────
    const postureLevel = mitigations.posture_level || 'UNKNOWN';
    const postureScore = mitigations.posture_score || 0;
    const badge = document.getElementById('postureScoreBadge');
    const pc = POSTURE_COLORS[postureLevel] || { bg: '#1e293b', border: '#475569', text: '#94a3b8' };
    if (badge) {
        badge.textContent = `Security Posture: ${postureLevel} (${postureScore}/100)`;
        badge.style.background  = pc.bg;
        badge.style.border      = `1px solid ${pc.border}`;
        badge.style.color       = pc.text;
    }

    // ── Mitigation flags grid ──────────────────────────────────────────────
    const grid = document.getElementById('mitigationFlagsGrid');
    if (grid) {
        const flags = mitigations.flags || {};
        grid.innerHTML = Object.entries(MITIGATION_LABELS).map(([key, meta]) => {
            const present = flags[key];
            const color = present ? '#065f46' : '#7f1d1d';
            const border = present ? '#059669' : '#dc2626';
            const textCol = present ? '#6ee7b7' : '#fca5a5';
            const iconName = present ? 'fa-check-circle' : 'fa-times-circle';
            return `<div style="
                background:${color}; border:1px solid ${border}; border-radius:8px;
                padding:8px 12px; text-align:center; font-size:12px;">
                <i class="fas ${iconName}" style="color:${textCol}; margin-right:4px;"></i>
                <span style="color:${textCol}; font-weight:600;">${meta.label}</span>
            </div>`;
        }).join('');
    }

    // ── Missing mitigations list ───────────────────────────────────────────
    const missingSection = document.getElementById('missingMitigationsSection');
    const missingList    = document.getElementById('missingMitigationsList');
    const missing = mitigations.missing || [];
    if (missingList && missing.length > 0) {
        missingSection.style.display = 'block';
        missingList.innerHTML = missing.map(m => {
            const riskColor = m.risk === 'HIGH' ? '#f87171' : m.risk === 'MEDIUM' ? '#fbbf24' : '#6b7280';
            return `<div style="
                background:#111827; border-left:3px solid ${riskColor};
                padding:10px 14px; margin-bottom:8px; border-radius:0 8px 8px 0;">
                <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                    <strong style="color:${riskColor};">${escapeHtml(m.name)}</strong>
                    <span style="font-size:11px; color:#6b7280;">${escapeHtml(m.cwe || '')}</span>
                    <span style="font-size:11px; padding:1px 6px; border-radius:8px;
                                 background:${riskColor}22; color:${riskColor};">${m.risk}</span>
                </div>
                <div style="color:#9ca3af; font-size:13px; margin-bottom:4px;">${escapeHtml(m.description || '')}</div>
                <div style="color:#6b7280; font-size:12px; font-style:italic;">${escapeHtml(m.impact || '')}</div>
            </div>`;
        }).join('');
    } else if (missingSection) {
        missingSection.style.display = 'none';
    }

    // ── AI Security Assessment panel ───────────────────────────────────────
    const aiPanel = document.getElementById('aiSecurityAssessmentPanel');
    if (!aiPanel) return;

    if (!aiAssessment || !aiAssessment.success) {
        aiPanel.style.display = 'none';
        return;
    }

    aiPanel.style.display = 'block';

    // Overall risk badge
    const riskLabel = document.getElementById('aiOverallRiskLabel');
    if (riskLabel) {
        const r = aiAssessment.overall_risk || 'UNKNOWN';
        const rColors = { CRITICAL:'#dc2626', HIGH:'#ea580c', MEDIUM:'#d97706', LOW:'#16a34a', CLEAN:'#059669' };
        riskLabel.textContent = r;
        riskLabel.style.background = rColors[r] || '#374151';
    }

    // Exploitability text
    const expText = document.getElementById('aiExploitabilityText');
    if (expText) expText.textContent = aiAssessment.exploitability_assessment || '';

    // Behavioral summary
    const behSummary = document.getElementById('aiBehavioralSummary');
    if (behSummary) {
        const profile = aiAssessment.behavioral_profile || '';
        const summary = aiAssessment.behavioral_summary || '';
        const profileColors = {
            legitimate:         '#6ee7b7',
            potentially_unwanted: '#fcd34d',
            suspicious:         '#fdba74',
            malware_like:       '#fca5a5',
        };
        const pColor = profileColors[profile] || '#9ca3af';
        behSummary.innerHTML = `<span style="font-weight:700; color:${pColor}; margin-right:8px;">
            [${escapeHtml(profile.toUpperCase().replace('_',' '))}]
        </span>${escapeHtml(summary)}`;
    }

    // Attack surface list
    const attackSurface = document.getElementById('aiAttackSurface');
    if (attackSurface) {
        const items = aiAssessment.attack_surface || [];
        attackSurface.innerHTML = items.map(t =>
            `<li style="margin-bottom:4px; font-size:13px; color:#e2e8f0;">${escapeHtml(t)}</li>`
        ).join('') || '<li style="color:#6b7280;">None detected</li>';
    }

    // MITRE techniques
    const mitreEl = document.getElementById('aiMitreTechniques');
    if (mitreEl) {
        const items = aiAssessment.mitre_techniques || [];
        mitreEl.innerHTML = items.map(t =>
            `<li style="margin-bottom:4px; font-size:13px; color:#e2e8f0;">${escapeHtml(t)}</li>`
        ).join('') || '<li style="color:#6b7280;">None identified</li>';
    }

    // Remediation
    const remEl = document.getElementById('aiRemediationPriority');
    if (remEl) {
        const items = aiAssessment.remediation_priority || [];
        remEl.innerHTML = items.map((t, i) =>
            `<li style="margin-bottom:4px; font-size:13px; color:#e2e8f0;">
                <strong style="color:#34d399;">${i + 1}.</strong> ${escapeHtml(t)}
            </li>`
        ).join('') || '<li style="color:#6b7280;">No actions needed</li>';
    }

    // CWE findings
    const cweSection = document.getElementById('aiCweFindings');
    const cweList    = document.getElementById('aiCweList');
    const cwes = aiAssessment.cwe_findings || [];
    if (cweList && cwes.length > 0) {
        cweSection.style.display = 'block';
        cweList.innerHTML = cwes.map(cwe =>
            `<span style="
                background:#1e293b; border:1px solid #475569; color:#93c5fd;
                padding:3px 10px; border-radius:12px; font-size:12px; font-family:monospace;">
                ${escapeHtml(cwe)}
            </span>`
        ).join('');
    } else if (cweSection) {
        cweSection.style.display = 'none';
    }
}

function renderPEResults(data) {
    // Primary: risk + CVEs + components + AI behavior
    renderRiskBanner(data.ai_risk || data.risk);
    renderMlClassifier(data.ml_classification);
    renderAiCodeAnalysis(data.ai_code_analysis);
    renderSecurityAssessment(data.security_mitigations, data.ai_security_assessment);
    renderPECVEs(data);
    renderComponents(data.components);
    renderCodeBERTAnalysis(data.codebert_analysis, data.behavior_profile_text);

    // Technical details (inside collapsed section in HTML)
    renderFileInfo(data);
    renderPEHeader(data.pe_info);
    renderSections(data.sections);
    renderImports(data.imports);
    renderStrings(data.strings);

    document.getElementById('peResults').style.display = 'block';
    document.getElementById('peResults').scrollIntoView({ behavior: 'smooth' });
}

function toggleTechDetails() {
    const body = document.getElementById('techDetailsBody');
    const icon = document.getElementById('techDetailsIcon');
    if (!body) return;
    const visible = body.style.display !== 'none';
    body.style.display = visible ? 'none' : 'block';
    icon.className = visible ? 'fas fa-chevron-right' : 'fas fa-chevron-down';
}

// Embedded component detection results
function renderComponents(components) {
    const card = document.getElementById('componentsCard');
    const body = document.getElementById('componentsBody');
    if (!card || !body) return;

    if (!components || components.length === 0) {
        card.style.display = 'none';
        return;
    }

    card.style.display = 'block';
    const cards = components.map(c => {
        const ver = c.version ? `v${escapeHtml(c.version)}` : 'version unknown';
        const cpe = c.cpe_vendor && c.cpe_product
            ? `cpe:2.3:a:${escapeHtml(c.cpe_vendor)}:${escapeHtml(c.cpe_product)}:${escapeHtml(c.version || '*')}:*:*:*:*:*:*:*`
            : '';
        return `
        <div class="component-card">
            <div class="component-name">${escapeHtml(c.name)}</div>
            <div class="component-version">${ver}</div>
            <div class="component-source">Detected via: ${escapeHtml(c.source || 'string scan')}</div>
            ${cpe ? `<div class="component-cpe">${escapeHtml(cpe)}</div>` : ''}
        </div>`;
    }).join('');

    body.innerHTML = `
        <p style="color:#6b7280; font-size:13px; margin-bottom:10px;">
            <i class="fas fa-info-circle"></i>
            ${components.length} embedded component(s) detected. Each may have its own CVEs independent of the main software.
        </p>
        <div class="components-grid">${cards}</div>`;
}

// Helpers for renderPECVEs
function _renderPECVEStats(stats, vulns, statsEl) {
    const sev = stats.by_severity || {};
    document.getElementById('peCVETotal').textContent    = stats.total_cves || vulns.length;
    document.getElementById('peCVECritical').textContent = sev.CRITICAL || 0;
    document.getElementById('peCVEHigh').textContent     = sev.HIGH     || 0;
    document.getElementById('peCVEMedium').textContent   = sev.MEDIUM   || 0;
    document.getElementById('peCVELow').textContent      = sev.LOW      || 0;
    document.getElementById('peCVEAvg').textContent      = (stats.avg_cvss || 0).toFixed(1);
    statsEl.style.display = 'grid';
}

function _renderPECVEList(listEl, vulns, stats, title) {
    const header = document.createElement('h3');
    header.style.cssText = 'margin-bottom:16px; color:#1f2937;';
    header.innerHTML = `<i class="fas fa-list"></i> ${title}
        <span style="font-size:13px; font-weight:400; color:#6b7280; margin-left:8px;">
            (showing ${vulns.length} of ${stats.total_cves || vulns.length})
        </span>`;
    listEl.appendChild(header);
    vulns.forEach(cve => listEl.appendChild(createCVEItem(cve)));
}

// CVE section inside PE Analysis tab
function _renderPECVEStats(stats, vulns, statsEl) {
    const sev = stats.by_severity || {};
    document.getElementById('peCVETotal').textContent    = stats.total_cves || vulns.length;
    document.getElementById('peCVECritical').textContent = sev.CRITICAL || 0;
    document.getElementById('peCVEHigh').textContent     = sev.HIGH     || 0;
    document.getElementById('peCVEMedium').textContent   = sev.MEDIUM   || 0;
    document.getElementById('peCVELow').textContent      = sev.LOW      || 0;
    document.getElementById('peCVEAvg').textContent      = (stats.avg_cvss || 0).toFixed(1);
    statsEl.style.display = 'grid';
}

function _renderPECVEList(listEl, vulns, stats, title) {
    const header = document.createElement('h3');
    header.style.cssText = 'margin-bottom:16px; color:#1f2937;';
    header.innerHTML = `<i class="fas fa-list"></i> ${title}
        <span style="font-size:13px; font-weight:400; color:#6b7280; margin-left:8px;">
            (showing ${vulns.length} of ${stats.total_cves || vulns.length})
        </span>`;
    listEl.appendChild(header);
    vulns.forEach(cve => listEl.appendChild(createCVEItem(cve)));
}

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
        const cweAnalysis   = data.cwe_analysis || {};
        const predictedCWEs = cweAnalysis.predicted_cwes || [];
        const cweSource     = cweAnalysis.prediction_method || '';

        const reason = cpeError
            ? `CPE extraction failed: ${cpeError}`
            : (cpeInfo.error || 'Could not identify software version from this file.');
        cpeInfoEl.style.display = 'none';
        cpeBadge.style.display  = 'none';

        listEl.innerHTML = '';
        const banner = document.createElement('p');
        banner.style.cssText = 'color:#f59e0b; padding:10px;';
        banner.innerHTML = `<i class="fas fa-exclamation-triangle"></i>&nbsp;${escapeHtml(reason)}`;
        listEl.appendChild(banner);

        // CWE prediction badges
        const cwePredicted = (data.cwe_analysis && data.cwe_analysis.predicted_cwes) || [];
        if (cwePredicted.length > 0) {
            const badgeWrap = document.createElement('div');
            badgeWrap.style.cssText = 'margin:8px 0 12px;';
            badgeWrap.innerHTML = '<strong style="font-size:13px;">Predicted CWEs:</strong> ';
            cwePredicted.forEach(c => {
                const color = CODEBERT_SEVERITY_COLORS[c.label] || '#9ca3af';
                badgeWrap.innerHTML += `<span style="display:inline-block; background:${color};
                    color:#fff; border-radius:4px; padding:2px 8px; margin:2px; font-size:12px;">
                    ${escapeHtml(c.cwe_id || c.label)}</span>`;
            });
            listEl.appendChild(badgeWrap);
        }

        if (vulns.length > 0) {
            _renderPECVEStats(stats, vulns, statsEl);
            _renderPECVEList(listEl, vulns, stats, 'Predicted CVEs');
        } else {
            statsEl.style.display = 'none';
        }
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
    _renderPECVEStats(stats, vulns, statsEl);

    // --- AI Analysis panel (PE tab) ---
    renderAiPanel(data.ai_analysis, 'peAiPanel', 'peAiOverallRiskBadge',
                  'peAiRiskSummary', 'peAiTopThreats', 'peAiRecommendations', 'peAiAttackVectors');

    // --- CVE list ---
    listEl.innerHTML = '';
    _renderPECVEList(listEl, vulns, stats, 'Vulnerabilities');
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

function renderCodeBERTAnalysis(cb) {
    const card = document.getElementById('codebertCard');
    const secbertCard = document.getElementById('secbertProfileCard');
    if (!card) return;

    // ── SecBERT profile text (ẩn — profile quá generic, không hiển thị) ──
    if (secbertCard) secbertCard.style.display = 'none';

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
    const isAI    = risk.method === 'ai_relevance';

    const banner = document.getElementById('riskBanner');
    banner.style.background   = colors.bg;
    banner.style.borderColor  = colors.border;
    banner.style.color        = colors.text;

    const isAI = risk.method === 'ai_relevance';
    document.getElementById('riskLevel').textContent = level;
    document.getElementById('riskScore').textContent = isAI ? `AI Risk Score: ${score} / 100` : `Risk Score: ${score} / 100`;

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
    const allRefs = cve.references || [];
    const maxShow = 5;
    const visibleRefs = allRefs.slice(0, maxShow);
    const hiddenRefs  = allRefs.slice(maxShow);
    refsDiv.innerHTML = visibleRefs.map(ref =>
        `<a href="${escapeHtml(ref)}" target="_blank">${escapeHtml(ref)}</a><br>`
    ).join('') + (hiddenRefs.length > 0 ? `
        <div id="refs-hidden" style="display:none">${hiddenRefs.map(ref =>
            `<a href="${escapeHtml(ref)}" target="_blank">${escapeHtml(ref)}</a><br>`
        ).join('')}</div>
        <a href="#" id="refs-toggle" onclick="
            var h=document.getElementById('refs-hidden');
            var t=document.getElementById('refs-toggle');
            if(h.style.display==='none'){h.style.display='block';t.textContent='Show less';}
            else{h.style.display='none';t.textContent='Show ${hiddenRefs.length} more...';}
            return false;
        " style="color:#4fc3f7;font-size:0.85em;">Show ${hiddenRefs.length} more...</a>
    ` : '');

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