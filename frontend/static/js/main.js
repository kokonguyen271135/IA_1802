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
    div.className = `cve-item ${cve.severity.toLowerCase()}`;
    
    // Cắt ngắn description cho list (nếu dài)
    const shortDesc = (cve.description || 'No description').substring(0, 250) + 
                      ((cve.description || '').length > 250 ? '...' : '');
    
    div.innerHTML = `
        <div class="cve-header">
            <span class="cve-id">${cve.cve_id}</span>
            <div class="cve-badges">
                <span class="badge ${cve.severity.toLowerCase()}">${cve.severity}</span>
                <span class="badge cvss-badge">CVSS ${cve.cvss_score}</span>
            </div>
        </div>
        <p class="cve-summary">${shortDesc}</p>
        <div class="cve-links">
            ${cve.references.map(ref => 
                `<a href="${ref}" target="_blank"><i class="fas fa-external-link-alt"></i> Reference</a>`
            ).join(' • ')}
        </div>
    `;
    
    // Làm cho toàn bộ item clickable để mở modal
    div.style.cursor = 'pointer';
    div.addEventListener('click', () => {
        showCVEDetailModal(cve);
    });
    
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

// Initialize
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
    // Tạo modal nếu chưa có
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
                <h3>Description</h3>
                <p id="modal-description"></p>
                <h3>References</h3>
                <div id="modal-references"></div>
                <button class="btn btn-primary" onclick="closeModal()">Đóng</button>
            </div>
        `;
        document.body.appendChild(modal);
    }

    // Đổ dữ liệu vào modal
    document.getElementById('modal-cve-id').textContent = cve.cve_id;
    document.getElementById('modal-published').textContent = (cve.published || 'N/A').substring(0, 10);
    document.getElementById('modal-cna').textContent = cve.cna || 'Unknown';
    document.getElementById('modal-severity').textContent = cve.severity;
    document.getElementById('modal-cvss').textContent = `${cve.cvss_score} (${cve.cvss_version || 'N/A'})`;
    document.getElementById('modal-description').textContent = cve.description || 'No description from NVD.';
    
    // References
    const refsDiv = document.getElementById('modal-references');
    refsDiv.innerHTML = cve.references.map(ref => 
        `<a href="${ref}" target="_blank">${ref}</a><br>`
    ).join('');
    
    // Hiển thị modal
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