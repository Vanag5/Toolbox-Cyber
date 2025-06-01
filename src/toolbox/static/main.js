// Utility functions
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.querySelector('.container').prepend(alertDiv);
    setTimeout(() => alertDiv.remove(), 5000);
}

function formatDate(dateStr) {
    return new Date(dateStr).toLocaleString();
}

function getSeverityClass(severity) {
    const severityLevel = parseFloat(severity);
    if (severityLevel >= 9.0) return 'critical';
    if (severityLevel >= 7.0) return 'high';
    if (severityLevel >= 4.0) return 'medium';
    if (severityLevel >= 0.1) return 'low';
    return 'info';
}

// Scan management
class ScanManager {
    constructor() {
        this.activeScanId = null;
        this.updateInterval = null;
    }

    startScan(endpoint, data) {
        console.log('startScan called with endpoint:', endpoint, 'and data:', data);
        fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                this.activeScanId = data.scan_id;
                showAlert('Scan started successfully', 'success');
                console.log("Appel monitorProgress pour scan_id:", this.activeScanId);
                this.monitorProgress();
                const resultsModal = document.getElementById('resultsModal');
                if (resultsModal) {
                    const modal = new bootstrap.Modal(resultsModal);
                    modal.show();
                }
            } else {
                showAlert(data.message || 'Failed to start scan', 'danger');
            }
        })
        .catch(error => {
            showAlert('Error starting scan: ' + error, 'danger');
        });
    }

    monitorProgress() {
    if (!this.activeScanId) return;
    console.log("Polling lancé pour scan_id:", this.activeScanId);    
    const progressBar = document.querySelector('.progress-bar');
    const statusDiv = document.getElementById('scanStatus');
    const downloadBtn = document.getElementById('downloadResultsBtn');

    this.updateInterval = setInterval(() => {
        fetch(`/scan/nmap/${this.activeScanId}/status`)
            .then(response => response.json())
            .then(data => {
                console.log("Réponse status scan :", data);
                if (data.status === 'success') {
                    progressBar.style.width = `${data.progress}%`;
                    progressBar.textContent = `${data.progress}%`;
                    statusDiv.textContent = data.message;
                    
                    // Arrête le polling dès que 100% atteint
                    if (data.progress === 100) {
                        this.stopMonitoring();
                    }
                    // Active le bouton si le scan est terminé et report_id existe
                    if (data.scan_status === 'completed' && data.report_id) {
                        if (downloadBtn) {
                            downloadBtn.disabled = false;
                            downloadBtn.onclick = () => {
                                window.open(`/scan/nmap/${this.activeScanId}/report`, '_blank');
                            };
                        }
                        this.stopMonitoring();
                        // Optionnel : charger les résultats si tu veux remplir un tableau
                        // this.loadResults();
                    }
                }
            })
            .catch(error => {
                showAlert('Error monitoring scan: ' + error, 'danger');
                this.stopMonitoring();
            });
    }, 5000);
}

    stopMonitoring() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
            this.updateInterval = null;
        }
    }

    loadResults() {
        if (!this.activeScanId) return;

        fetch(`/scan/nmap/${this.activeScanId}/report`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    this.updateResultsTable(data.report);
                    showAlert('Scan completed successfully', 'success');
                    const downloadBtn = document.getElementById('downloadResultsBtn');
                    if (downloadBtn) {
                        downloadBtn.disabled = false;
                        // Stocke les résultats pour le téléchargement
                        downloadBtn.dataset.results = JSON.stringify(data.report);
                    }
                } else {
                    showAlert(data.message || 'Failed to load results', 'warning');
                }
            })
            .catch(error => {
                showAlert('Error loading results: ' + error, 'danger');
            });
    }

    updateResultsTable(vulnerabilities) {
        const tbody = document.getElementById('vulnerabilityTable').querySelector('tbody');
        tbody.innerHTML = '';

        vulnerabilities.forEach(vuln => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>
                    <span class="badge severity-${getSeverityClass(vuln.severity)}">
                        ${vuln.severity}
                    </span>
                </td>
                <td>${vuln.name}</td>
                <td>${vuln.port || 'N/A'}</td>
                <td>${this.formatCVEList(vuln.cve)}</td>
                <td>${formatDate(vuln.detected_at)}</td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="showVulnerabilityDetails(${JSON.stringify(vuln)})">
                        Details
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    formatCVEList(cveList) {
        if (!cveList || !cveList.length) return 'N/A';
        return cveList.map(cve => `
            <a href="https://nvd.nist.gov/vuln/detail/${cve}" target="_blank" class="badge bg-secondary">
                ${cve}
            </a>
        `).join(' ');
    }

    startSqlmapScan(data) {
        fetch('/scan/sqlmap', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        })
        .then(res => res.json())
        .then(data => {
            if (data.task_id) {
                this.activeScanId = data.task_id;
                showAlert('SQLMap scan started', 'success');
                this.pollSqlmapResult();
                const resultsModal = document.getElementById('resultsModal');
                    if (resultsModal) {
                        const modal = new bootstrap.Modal(resultsModal);
                        modal.show();
                    }
            } else {
                showAlert(data.error || 'Failed to start SQLMap scan', 'danger');
            }
        })
        .catch(err => showAlert('Error starting SQLMap scan: ' + err, 'danger'));
    }

    pollSqlmapResult() {
    if (!this.activeScanId) return;

    const progressBar = document.querySelector('.progress-bar');
    const statusDiv = document.getElementById('scanStatus');
    const downloadBtn = document.getElementById('downloadResultsBtn');
    const scanResults = document.getElementById('scanResults');
    const scanTypeBadge = document.getElementById('scanType');
    const scanTargetBadge = document.getElementById('scanTarget');

    // Affiche le type de scan et la cible dans la modale
    scanTypeBadge.textContent = 'SQLMap Scan';
    scanTargetBadge.textContent = document.getElementById('sqlmapTarget').value;

    this.updateInterval = setInterval(() => {
        fetch(`/scan/sqlmap/result/${this.activeScanId}`)
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    // Pas encore prêt, on affiche un message et on continue le polling
                    statusDiv.textContent = 'Scan en cours...';
                    progressBar.style.width = '50%';  // Tu peux adapter la valeur
                    progressBar.textContent = 'En cours';
                    console.log('Waiting for SQLMap result...');
                } else {
                    // Résultat prêt, on affiche tout
                    statusDiv.textContent = 'Scan terminé';
                    progressBar.style.width = '100%';
                    progressBar.textContent = '100%';

                    // Affiche le résultat brut dans la modale
                    scanResults.textContent = data.output || JSON.stringify(data, null, 2);

                    // Active le bouton téléchargement
                    if (downloadBtn) {
                        downloadBtn.disabled = false;
                        // Par exemple : ouvre un fichier / endpoint spécifique ou télécharge les données
                        downloadBtn.onclick = () => {
                            // Si tu as une route pour récupérer un rapport au format fichier
                            window.open(`/scan/sqlmap/${this.activeScanId}/report`, '_blank');
                            // Sinon, tu peux aussi générer un fichier à la volée (plus complexe)
                        };
                    }

                    // Stop le polling car le scan est terminé
                    this.stopMonitoring();
                }
            })
            .catch(err => {
                showAlert('Error polling SQLMap result: ' + err, 'danger');
                this.stopMonitoring();
            });
    }, 5000); 
}
}

// Initialize scan manager
const scanManager = new ScanManager();

// API endpoints
const API_ENDPOINTS = {
    vulnerabilityScan: '/scan/vulnerability/scan',
    networkDiscovery: '/scan/network/discover',
    portScan: '/scan/ports',
    scanStatus: '/scan/nmap/<scan_id>/status',      
    scanReport: '/scan/nmap/<scan_id>/report',       
    sqlmap: '/scan/sqlmap'
};

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    const downloadBtn = document.getElementById('downloadResultsBtn');
    if (downloadBtn) downloadBtn.disabled = true;

    function handleFormSubmit(formId, endpoint, dataExtractor, customStartFn) {
        const form = document.getElementById(formId);
        if (form) {
            form.addEventListener('submit', e => {
                e.preventDefault();
                const formData = dataExtractor();
                if (typeof customStartFn === 'function') {
                    customStartFn(formData);
                } else {
                    scanManager.startScan(endpoint, formData);
                }
            });
        }
    }    
    const forms = [
     
        { id: 'networkScanForm', endpoint: API_ENDPOINTS.networkDiscovery, dataExtractor: () => ({
            target: document.getElementById('networkTarget').value,
            scan_type: document.getElementById('networkScanType').value
        }) },
        { id: 'portScanForm', endpoint: API_ENDPOINTS.portScan, dataExtractor: () => ({
            target: document.getElementById('portTarget').value,
            ports: document.getElementById('portRange').value,
            scan_type: document.getElementById('portScanType').value
        }) },
        {  id: 'vulnerabilityScanForm',
            endpoint: API_ENDPOINTS.vulnerabilityScan,
            dataExtractor: () => ({
                target: document.getElementById('vulnerabilityTarget').value
            }) },
        { id: 'nmapForm', endpoint: '/scan/nmap', dataExtractor: () => ({
        target: document.getElementById('nmapTarget').value,
        options: document.getElementById('nmapOptions').value === 'custom'
            ? document.getElementById('nmapCustomOptions').value
            : document.getElementById('nmapOptions').value
        }) },
        { id: 'sqlmapForm', endpoint: '/scan/sqlmap', dataExtractor: () => ({
        url: document.getElementById('sqlmapTarget').value,
        level: parseInt(document.getElementById('sqlmapLevel').value),
        risk: parseInt(document.getElementById('sqlmapRisk').value),
        additional_args: document.getElementById('sqlmapArgs').value,
        options: document.getElementById('sqlmapArgs').value
        }) 
        }
    ];

    forms.forEach(({ id, endpoint, dataExtractor }) => {
        if (id === 'sqlmapForm') {
            handleFormSubmit(id, endpoint, dataExtractor, (formData) => {
                scanManager.startSqlmapScan(formData);
            });
        } else {
            handleFormSubmit(id, endpoint, dataExtractor);
        }
    });
    const enableFormsCrawl = document.getElementById('enableFormsCrawl');
    const sqlmapArgsInput = document.getElementById('sqlmapArgs');
    let previousSqlmapArgs = '';

    if (enableFormsCrawl && sqlmapArgsInput) {
        enableFormsCrawl.addEventListener('change', () => {
            if (enableFormsCrawl.checked) {
                previousSqlmapArgs = sqlmapArgsInput.value;
                sqlmapArgsInput.value = '--forms --crawl=2';
            } else {
                sqlmapArgsInput.value = previousSqlmapArgs;
            }
        });
    }
});