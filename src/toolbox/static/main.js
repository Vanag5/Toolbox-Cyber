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
        this.scanType = null;  // Ajouté pour tracker le type de scan actif
    }

    startHydraScan(data) {
        this.startScan('/scan/hydra', data, 'hydra');
    }

    startScan(endpoint, data, scanType = 'nmap') {
        console.log('startScan called with endpoint:', endpoint, 'and data:', data, 'type:', scanType);
        this.scanType = scanType;
        fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                this.activeScanId = data.scan_id;
                showAlert('Scan started successfully', 'success');
                console.log("Appel monitorProgress pour scan_id :", this.activeScanId);
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
            showAlert('Error starting scan : ' + error, 'danger');
        });
    }

    monitorProgress() {
        if (!this.activeScanId || !this.scanType) return;

        console.log("Polling lancé pour scan_id :", this.activeScanId, "type :", this.scanType);

        const progressBar = document.querySelector('.progress-bar');
        const statusDiv = document.getElementById('scanStatus');
        const downloadBtn = document.getElementById('downloadResultsBtn');
        const hydraResultsTable = document.getElementById('hydraResultsTable');
        const scanResults = document.getElementById('scanResults');
        const scanTypeBadge = document.getElementById('scanType');
        const scanTargetBadge = document.getElementById('scanTarget');

        // Détermine endpoint selon type de scan
        let statusEndpoint = '';
        if (this.scanType === 'nmap') {
            statusEndpoint = `/scan/nmap/${this.activeScanId}`;
        } else if (this.scanType === 'hydra') {
            statusEndpoint = `/scan/hydra/status/${encodeURIComponent(this.activeScanId)}`;
        } else {
            statusEndpoint = `/scan/status/${this.activeScanId}`;
            return;
        }

        // Affiche le type de scan et la cible dans la modale
        scanTypeBadge.textContent = this.scanType === 'nmap' ? 'Nmap Scan' : 'Hydra Scan';
        if (this.scanType === 'nmap') {
            const targetInput = document.getElementById('nmapTarget');
            scanTargetBadge.textContent = targetInput ? targetInput.value : '';
        } else if (this.scanType === 'hydra') {
            const targetInput = document.getElementById('hydraTarget');
            scanTargetBadge.textContent = targetInput ? targetInput.value : '';
        }

        // Reset bouton download au départ (désactivé)
        if (downloadBtn) {
            downloadBtn.disabled = true;
            downloadBtn.onclick = null;
        }
        if (hydraResultsTable) hydraResultsTable.style.display = 'none';
        if (scanResults) scanResults.style.display = 'block';

        this.updateInterval = setInterval(() => {
            fetch(statusEndpoint)
            .then(response => response.json())
            .then(data => {
                console.log("Réponse status scan :", data);
                if (data.status === 'success') {
                    progressBar.style.width = `${data.progress}%`;
                    progressBar.textContent = `${data.progress}%`;
                    statusDiv.textContent = data.message;

                    if (data.scan && data.scan.current_status === 'completed' && data.report_id) {
                        // Active le bouton de téléchargement selon type
                        if (downloadBtn) {
                            downloadBtn.disabled = false;
                            if (this.scanType === 'nmap') {
                                downloadBtn.onclick = () => {
                                    window.open(`/scan/nmap/${this.activeScanId}/report`, '_blank');
                                };
                            } else if (this.scanType === 'hydra') {
                                downloadBtn.onclick = () => {
                                    window.open(`/scan/hydra/${this.activeScanId}/report`, '_blank');
                                };
                            }
                        }

                        // Si hydra, afficher les résultats dans le tableau
                        if (this.scanType === 'hydra' && data.scan && data.scan.results) {
                            if (scanResults) scanResults.style.display = 'none';
                            if (hydraResultsTable) {
                                hydraResultsTable.style.display = 'table';
                                this.updateHydraResultsTable(data.scan.results);
                            }
                        }

                        this.stopMonitoring();
                    }
                }
            })
            .catch(error => {
                showAlert('Error monitoring scan : ' + error, 'danger');
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

    updateHydraResultsTable(results) {
        const tbody = document.getElementById('hydraResultsTable').querySelector('tbody');
        tbody.innerHTML = '';

        results.forEach(result => {
            const tr = document.createElement('tr');
            const success = !!result.success;  // Converti en booléen sûr
            tr.innerHTML = `
                <td>${result.host || 'N/A'}</td>
                <td>${result.login || 'N/A'}</td>
                <td>${result.password || 'N/A'}</td>
                <td>
                    <span class="badge bg-${success ? 'success' : 'danger'}">
                        ${success ? 'Yes' : 'No'}
                    </span>
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
        .catch(err => showAlert('Error starting SQLMap scan : ' + err, 'danger'));
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
                showAlert('Error polling SQLMap result : ' + err, 'danger');
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
        { id: 'vulnerabilityScanForm', endpoint: API_ENDPOINTS.vulnerabilityScan, dataExtractor: () => ({
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
        }) },
        { id: 'hydraForm', 
            endpoint: '/scan/hydra', dataExtractor: () => ({
            target: document.getElementById('hydraTarget').value,
            service: document.getElementById('hydraService').value,
            username: document.getElementById('hydraUser').value,
            password: document.getElementById('hydraPass').value,
            formPath: document.getElementById('hydraHttpForm').value
        }), 
        }     
    ];

    forms.forEach(({ id, endpoint, dataExtractor }) => {
        if (id === 'sqlmapForm') {
            handleFormSubmit(id, endpoint, dataExtractor, (formData) => {
                scanManager.startSqlmapScan(formData);
            });
        } else if (id === 'hydraForm') {
            handleFormSubmit(id, endpoint, dataExtractor, (formData) => {
                scanManager.startHydraScan(formData);
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
