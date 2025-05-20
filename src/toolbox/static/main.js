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
                this.monitorProgress();
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

        const progressBar = document.querySelector('.progress-bar');
        const statusDiv = document.getElementById('scanStatus');

        this.updateInterval = setInterval(() => {
            fetch(`${API_ENDPOINTS.scanStatus}/${this.activeScanId}`)
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        progressBar.style.width = `${data.progress}%`;
                        progressBar.textContent = `${data.progress}%`;
                        statusDiv.textContent = data.message;

                        if (data.scan_status === 'Done') {
                            this.stopMonitoring();
                            this.loadResults();
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

        fetch(`${API_ENDPOINTS.scanReport}/${this.activeScanId}`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    this.updateResultsTable(data.report);
                    showAlert('Scan completed successfully', 'success');
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
}

// Initialize scan manager
const scanManager = new ScanManager();

// API endpoints
const API_ENDPOINTS = {
    vulnerabilityScan: '/scan/vulnerability/scan',
    networkDiscovery: '/scan/network/discover',
    portScan: '/scan/ports',
    scanStatus: '/scan/vulnerability/scan/status',
    scanReport: '/scan/vulnerability/report'
};

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    function handleFormSubmit(formId, endpoint, dataExtractor) {
        const form = document.getElementById(formId);
        if (form) {
            form.addEventListener('submit', e => {
                e.preventDefault();
                const formData = dataExtractor();
                scanManager.startScan(endpoint, formData);
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
            })
        }
    ];

    forms.forEach(({ id, endpoint, dataExtractor }) => {
        handleFormSubmit(id, endpoint, dataExtractor);
    });
});

