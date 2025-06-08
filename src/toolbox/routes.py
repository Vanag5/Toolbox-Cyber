from flask import Blueprint, jsonify, request, render_template, current_app
from datetime import datetime
import time
from .network_discovery import NetworkDiscovery
from .service_enum import ServiceEnumerator
from .logger import logger
import traceback
from concurrent.futures import ThreadPoolExecutor
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from io import BytesIO
from flask import send_file
from reportlab.lib.units import inch
import os
import uuid
from typing import Dict
from datetime import timedelta
from .pdf_utils import generate_pdf_report
from toolbox.models import ScanResult, SQLMapScanResult, ZAPScanResult, TimelineEvent
import json
from flask_login import login_required
from .tasks import run_sqlmap_scan
from celery.result import AsyncResult
from toolbox.celery import celery
from .hydra_scanner import HydraScanner
from .tasks import run_hydra_scan, run_zap_scan
from toolbox import db
from .zap_scanner import ZAPScanner
from reportlab.platypus import PageBreak
import re
from .utils import log_event

main_bp = Blueprint('main', __name__)
report_bp = Blueprint('report', __name__, url_prefix='/report')
scan_bp = Blueprint('scan', __name__, url_prefix='/scan')

# Global state
active_scans = {}  # Store active scans
scan_reports = {}  # Store scan reports

# Initialize components
net_discovery = NetworkDiscovery()
service_enumerator = ServiceEnumerator()

@main_bp.before_request
def log_request_info():
    """Log request information and start timer for response time tracking"""
    request.start_time = time.time()

@main_bp.after_request
def log_request_complete(response):
    """Log completed request information"""
    # Calculate response time
    total_time = time.time() - getattr(request, 'start_time', time.time())

    # Log access information
    logger.log_access(
        request_method=request.method,
        endpoint=request.endpoint,
        source_ip=request.remote_addr,
        status_code=response.status_code,
        response_time=round(total_time * 1000, 2)  # Convert to milliseconds
    )

    return response

@main_bp.route('/')
@login_required
def index():
    return render_template('index.html')

@main_bp.route('/api/status')
def api_status():
    return jsonify({
        'status': 'ok',
        'message': 'Pentest Toolbox API is running'
    })

@main_bp.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'pentest-toolbox'
    })

@main_bp.route('/scans')
def scans():
    return render_template('scans.html')

@main_bp.route('/reports')
def reports():
    return render_template('reports.html')

@main_bp.route('/api/scans')
def api_scans():
    """Get list of all scans"""
    try:
        scans = []
        for scan_id, scan_info in active_scans.items():
            scans.append({
                'id': scan_id,
                'target': scan_info.get('target', ''),
                'type': scan_info.get('type', ''),
                'status': scan_info.get('status', 'unknown'),
                'start_time': scan_info.get('start_time', ''),
                'end_time': scan_info.get('end_time', '')
            })
        return jsonify({
            'status': 'success',
            'scans': scans
        })
    except Exception as e:
        logger.log_error(
            error_type='scan_status_error',
            error_message=str(e)
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@main_bp.route('/api/reports')
def api_reports():
    """Get list of all reports"""
    try:
        reports = []
        for scan in ScanResult.query.all():
            reports.append({
                'id': scan.scan_id,
                'scan_type': scan.scan_type,
                'target': scan.target,
                'timestamp': scan.timestamp.isoformat(),
                'summary': json.loads(scan.summary_json) if scan.summary_json else {}
            })
        return jsonify({
            'status': 'success',
            'reports': reports
        })
    except Exception as e:
        logger.log_error(
            error_type='api_reports_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scan_bp.route('/network/discover', methods=['POST'])
def discover_network():
    """Endpoint to perform network discovery"""
    data = request.get_json()
    if not data or 'target_network' not in data:
        return jsonify({'error': 'target_network is required'}), 400
    try:
        results = net_discovery.scan_network(data['target_network'])

        # Log the scan
        logger.log_scan(
            scan_type='network_discovery',
            target=data['target_network'],
            results=results
        )
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'results': results
        })
    except Exception as e:
        logger.log_error(
            error_type='network_discovery_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scan_bp.route('/port/scan', methods=['POST'])
def scan_ports():
    port_scanner = current_app.port_scanner
    """Endpoint to perform port scanning"""
    data = request.get_json()
    if not data or 'target' not in data or 'scan_type' not in data:
        return jsonify({'error': 'target and scan_type are required'}), 400
    try:
        target = data['target']
        scan_type = data['scan_type']
        ports = data.get('ports', '')
        scan_id = f"portscan_{target}_{int(time.time())}"
        # Start scan asynchronously
        def run_scan():
            try:
                if scan_type == 'quick':
                    results = port_scanner.quick_scan(
                        target, ports or "1-1024")
                elif scan_type == 'comprehensive':
                    results = port_scanner.comprehensive_scan(
                        target, ports or "1-65535")
                elif scan_type == 'udp':
                    results = port_scanner.udp_scan(
                        target, ports or "53,67,68,69,123,161,162")
                else:
                    active_scans[scan_id]['status'] = 'failed'
                    active_scans[scan_id]['error'] = 'Invalid scan type'
                    return
                # Store results
                scan_reports[scan_id] = {
                    'scan_type': f'port_scan_{scan_type}',
                    'target': target,
                    'timestamp': datetime.now().isoformat(),
                    'results': [vars(r) for r in results],
                    'summary': {
                        'total_ports': len(results),
                        'open_ports': len([r for r in results if r.state == 'open'])
                    }
                }
                # Update scan status
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['end_time'] = datetime.now().isoformat()
                # Log the scan
                logger.log_scan(
                    scan_type=f'port_scan_{scan_type}',
                    target=target,
                    results=[vars(r) for r in results]
                )
            except Exception as e:
                active_scans[scan_id]['status'] = 'failed'
                active_scans[scan_id]['error'] = str(e)
                logger.log_error(
                    error_type='port_scan_error',
                    error_message=str(e),
                    stack_trace=traceback.format_exc()
                )
        # Store initial scan info
        active_scans[scan_id] = {
            'target': target,
            'type': f'port_scan_{scan_type}',
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'end_time': None
        }
        # Start scan in background
        executor = ThreadPoolExecutor(max_workers=1)
        executor.submit(run_scan)
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'message': f'Port scan started for {target}'
        })
    except Exception as e:
        logger.log_error(
            error_type='port_scan_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scan_bp.route('/service/enumerate', methods=['POST'])
def enumerate_services():
    """Endpoint to perform service enumeration"""
    data = request.get_json()
    if not data or 'target' not in data or 'ports' not in data:
        return jsonify({'error': 'target and ports are required'}), 400
    try:
        target = data['target']
        ports = data['ports']
        results = {}
        for port_info in ports:
            port = port_info['port']
            service = port_info['service']
            result = service_enumerator.enumerate_service(
                target, port, service)
            results[f"{port}/{service}"] = vars(result)
        # Log the enumeration
        logger.log_scan(
            scan_type='service_enumeration',
            target=target,
            results=results
        )
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'results': results
        })
    except Exception as e:
        logger.log_error(
            error_type='service_enum_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
       
    except Exception as e:
        logger.log_error(
            error_type='openvas_scan_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scan_bp.route('/nmap', methods=['POST'])
def nmap_scan():
    port_scanner = current_app.port_scanner 
    """Endpoint to perform Nmap scan"""
    # Try to get JSON data, fall back to form data
    data = request.get_json(silent=True) or request.form

    if not data or 'target' not in data:
        return jsonify({'error': 'target is required'}), 400
    try:
        target = data['target']
        scan_type = data.get('scan_type', 'quick')
        options = data.get('options', '')
        if scan_type == 'quick':
            scan_options = '-F -sV'  # Fast scan with version detection
        elif scan_type == 'comprehensive':
            scan_options = '-sV -sC -A'  # Comprehensive scan
        elif scan_type == 'custom':
            scan_options = options
        else:
            return jsonify({'error': 'Invalid scan_type'}), 400
        # Start the scan
        scan_id = port_scanner.start_nmap_scan(target, scan_options)
        # Store in active_scans for the web interface
        active_scans[scan_id] = {
            'target': target,
            'type': f'nmap_{scan_type}',
            'status': 'running',
            'start_time': datetime.now().isoformat()
        }
        # Log the scan initiation
        logger.log_scan(
            scan_type=f'nmap_{scan_type}',
            target=target,
            results={'status': 'initiated', 'scan_id': scan_id}
        )
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'message': 'Nmap scan started successfully'
        }), 201
    except Exception as e:
        logger.log_error(
            error_type='nmap_scan_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scan_bp.route('/nmap/<scan_id>/status', methods=['GET'], endpoint='nmap_scan_status')
def nmap_scan_status(scan_id):
    current_app.port_scanner.load_active_scans()
    scan_data = current_app.port_scanner.active_scans.get(scan_id)
    logger.log_debug(f"DEBUG: scan_data progress après reload: {scan_data.get('progress')}")
    if not scan_data:
        logger.log_error(
            error_type='scan_status_error',
            error_message=f'Scan not found: {scan_id}'
        )
        return jsonify({
            'status': 'error',
            'message': 'Scan not found',
            'scan_id': scan_id
        }), 404
    
    current_app.port_scanner.load_active_scans()
    scan_data = current_app.port_scanner.active_scans.get(scan_id)
    try:
        logger.log_debug(f"Received status request for scan ID: {scan_id}")
        logger.log_debug(f"Scan data for {scan_id}: {scan_data}")
        estimated_completion = None
        progress = scan_data.get('progress', {})
        progress_percentage = progress.get('percentage', 0)
        if scan_data.get('status') == 'running':
            start_time = datetime.fromisoformat(
                scan_data.get('start_time', datetime.now().isoformat()))
            estimated_completion = (
                start_time + timedelta(minutes=2)).isoformat()
        response = {
            'status': 'success',
            'scan': {
                'id': scan_id,
                'target': scan_data.get('target', 'Unknown'),
                'type': scan_data.get('type', 'nmap'),
                'current_status': scan_data.get('status', 'unknown'),
                'start_time': scan_data.get('start_time', 'N/A'),
                'estimated_completion': estimated_completion,
                'progress': scan_data.get('progress', {
                    'total_hosts': 1,
                    'scanned_hosts': 0,
                    'current_host': None,
                    'percentage': 0
                }),
            },
            'report_id': None,
            'progress': scan_data.get('progress', {}).get('percentage', 0),
            'scan_status': scan_data.get('status', 'unknown'),
            'message': f"Scan {scan_data.get('status', 'en cours')}, {scan_data.get('progress', {}).get('percentage', 0)}%"
        }
        if scan_data.get('status') == 'completed':
            report_data = {
                'target': scan_data.get('target', '127.0.0.1'),
                'scan_type': scan_data.get('type', 'nmap'),
                'timestamp': scan_data.get('end_time', datetime.now().isoformat()),
                'results': scan_data.get('results', []),
                'summary': {
                    'total_ports': len(scan_data.get('results', [])),
                    'open_ports': len([r for r in scan_data.get('results', []) if r.get('state') == 'open'])
                }
            }
            try:
                report_path = generate_nmap_pdf_report(report_data)
                report_id = f"report_{scan_id}"
                scan_data['report_path'] = report_path
                current_app.port_scanner.active_scans[scan_id] = scan_data
                response['report_id'] = report_id
                logger.log_debug(
                    f"Report generated for scan {scan_id}: {report_path}")
            except Exception as report_error:
                logger.log_error(
                    error_type='report_generation_error',
                    error_message=str(report_error),
                    additional_info={
                        'scan_id': scan_id,
                        'scan_data': scan_data
                    },
                    stack_trace=traceback.format_exc()
                )
                response['report_generation_error'] = str(report_error)
        logger.log_debug(f"Réponse status pour {scan_id}: {response}")
        return jsonify(response)
    except Exception as e:
        logger.log_error(
            error_type='scan_status_error',
            error_message=str(e)
        )
        return jsonify({
            'status': 'error',
            'message': str(e),
            'scan_id': scan_id
        }), 500

@scan_bp.route('/nmap/<scan_id>/report', methods=['GET'])
def download_nmap_report(scan_id):   
    try:
        scan = ScanResult.query.filter_by(scan_id=scan_id).first()
        if not scan:
            return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
        scan_data = {
            'scan_type': scan.scan_type,
            'target': scan.target,
            'timestamp': scan.timestamp.isoformat(),
            'results': json.loads(scan.results_json),
            'summary': json.loads(scan.summary_json) if scan.summary_json else {}
        }
        report_path = generate_pdf_report(scan_data)
        log_event('report_generated', f'Rapport généré pour le scan {scan_id}', scan_id)
        return send_file(report_path, as_attachment=True, download_name=f"nmap_scan_report_{scan_id}.pdf")
    
    except Exception as e:
        log_event('error', f'Erreur lors de la génération du rapport : {str(e)}', scan_id)
        logger.log_error(
            error_type='report_download_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({'status': 'error', 'message': str(e)}), 500

@scan_bp.route('/nmap/<scan_id>/report', methods=['GET'], endpoint='download_nmap_report_legacy')
def download_nmap_report_legacy(scan_id):
    """
    DEPRECATED: Legacy function for downloading Nmap scan reports
    """
    try:
        # Get scan data
        scan_data = active_scans[scan_id]
        # Check if scan is completed
        if scan_data.get('status') != 'completed':
            return jsonify({
                'status': 'error',
                'message': 'Scan is not yet completed'
            }), 400
        # Check if report path exists
        if 'report_path' not in scan_data or not os.path.exists(scan_data['report_path']):
            # If no report, generate one
            report_data = {
                'target': scan_data.get('target', '127.0.0.1'),
                'scan_type': scan_data.get('type', 'nmap'),
                'timestamp': scan_data.get('end_time', datetime.now().isoformat()),
                'results': scan_data.get('results', []),
                'summary': {
                    'total_ports': len(scan_data.get('results', [])),
                    'open_ports': len([r for r in scan_data.get('results', []) if r.get('state') == 'open'])
                }
            }
            report_path = generate_nmap_pdf_report(report_data)
            scan_data['report_path'] = report_path
            active_scans[scan_id] = scan_data
        # Return the PDF file
        return send_file(
            scan_data['report_path'],
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"nmap_scan_report_{scan_id}.pdf"
        )
    except Exception as e:
        # Log the error
        logger.log_error(
            error_type='nmap_report_download_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        # Return error response
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scan_bp.route('/logs/<log_type>', methods=['GET'])
def get_logs(log_type):
    """
    Retrieve logs by type
    Valid log types: security, scan, error, access, audit
    """
    valid_types = ['security', 'scan', 'error', 'access', 'audit']
    if log_type not in valid_types:
        return jsonify({'error': f'Invalid log type. Must be one of: {", ".join(valid_types)}'}), 400
    try:
        limit = int(request.args.get('limit', 100))
        logs = logger.get_recent_logs(log_type, limit)
        # Log the access to logs
        logger.log_audit(
            user=request.remote_addr,
            action='view_logs',
            resource=log_type,
            status='success'
        )
        return jsonify({
            'status': 'success',
            'log_type': log_type,
            'count': len(logs),
            'logs': logs
        })
    except Exception as e:
        logger.log_error(
            error_type='log_retrieval_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

def generate_nmap_pdf_report(scan_data: Dict, output_dir: str = '/app/scan_reports') -> str:
    """
    Generate a PDF report for an Nmap scan
    :param scan_data: Dictionary containing scan information
    :param output_dir: Directory to save the PDF report
    :return: Path to the generated PDF report
    """
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    # Generate unique filename
    report_filename = f"{output_dir}/nmap_scan_{uuid.uuid4().hex[:8]}.pdf"
    # Create PDF document
    doc = SimpleDocTemplate(report_filename, pagesize=letter,
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    # Prepare report content
    content = []
    styles = getSampleStyleSheet()
    # Title
    title = Paragraph(
        f"Nmap Scan Report for {scan_data.get('target', 'Unknown Target')}", styles['Title'])
    content.append(title)
    # Scan Details
    details = [
        ['Scan Type', scan_data.get('scan_type', 'Unknown')],
        ['Target', scan_data.get('target', 'Unknown')],
        ['Timestamp', scan_data.get('timestamp', 'Unknown')]
    ]
    details_table = Table(details, colWidths=[2*inch, 4*inch])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    content.append(details_table)
    # Results Table
    results = scan_data.get('results', [])
    if results:
        # Prepare results for table
        results_data = [['Port', 'State', 'Service', 'Version']]
        for result in results:
            results_data.append([
                str(result.get('port', 'N/A')),
                result.get('state', 'N/A'),
                result.get('service', 'N/A'),
                result.get('version', 'N/A')
            ])
        results_table = Table(results_data, colWidths=[
                              1*inch, 1*inch, 2*inch, 2*inch])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(Paragraph("Scan Results", styles['Heading2']))
        content.append(results_table)
    # Summary
    summary = scan_data.get('summary', {})
    summary_text = Paragraph(
        f"Total Ports Scanned: {summary.get('total_ports', 0)}<br/>" +
        f"Open Ports: {summary.get('open_ports', 0)}",
        styles['Normal']
    )
    content.append(summary_text)
    # Build PDF
    doc.build(content)
    return report_filename

def get_scan_status(scan_id):
    """
    DEPRECATED: Use the blueprint route instead
    Get the status of a scan and generate a report if completed
    """
    try:
        # Retrieve scan from active scans
        if scan_id not in active_scans:
            return jsonify({'error': 'Scan not found', 'status': 'error'}), 404
        scan_data = active_scans[scan_id]
        # Check if scan is completed and has results
        if scan_data.get('status') == 'completed' and scan_data.get('results'):
            # Prepare report data
            report_data = {
                'target': scan_data.get('target', '127.0.0.1'),
                'scan_type': scan_data.get('type', 'nmap'),
                'timestamp': scan_data.get('end_time', datetime.now().isoformat()),
                'results': scan_data.get('results', []),
                'summary': {
                    'total_ports': len(scan_data.get('results', [])),
                    'open_ports': len([r for r in scan_data.get('results', []) if r.get('state') == 'open'])
                }
            }
            # Generate PDF report
            report_path = generate_nmap_pdf_report(report_data)
            # Generate a unique report ID
            report_id = f"report_{scan_id}"
            # Store report path in active scans
            scan_data['report_path'] = report_path
            active_scans[scan_id] = scan_data
            # Return status with report ID
            return jsonify({
                'status': 'success',
                'scan': scan_data,
                'report_id': report_id
            })
        # Return scan status if not completed
        return jsonify({
            'status': 'success',
            'scan': scan_data,
            'report_id': None
        })
    except Exception as e:
        logger.log_error(
            error_type='scan_status_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scan_bp.route('/sqlmap/status/<task_id>', methods=['GET'])
def sqlmap_status(task_id):
    task_result = AsyncResult(task_id, app=celery)
    response = {
        "task_id": task_id,
        "state": task_result.state,
        "info": task_result.info  # peut contenir message ou progression
    }
    return jsonify(response)

@scan_bp.route('/sqlmap/result/<sqlmap_id>', methods=['GET'])
def get_result(sqlmap_id):
    result = SQLMapScanResult.query.filter_by(task_id=sqlmap_id, task_type='sqlmap').first()
    if result:
        return jsonify({
            "url": result.target_url,
            "output": result.raw_output,
            "timestamp": result.timestamp.isoformat()
        })
    return jsonify({"error": "Not found"}), 404

@scan_bp.route('/sqlmap', methods=['POST'])
def sqlmap_scan():
    try:
        data = request.get_json()
        url = data.get("url")
        method = data.get("method", "GET")
        post_data = data.get("data")
        level = int(data.get("level", 1))
        risk = int(data.get("risk", 1))
        additional_args = data.get("additional_args", "")
        enable_forms_crawl = data.get("enableFormsCrawl", False)

        if not url:
            return jsonify({"error": "URL is required"}), 400

        task = run_sqlmap_scan.delay(
            url=url,
            method=method.upper(),
            data=post_data,
            level=level,
            risk=risk,
            additional_args=additional_args,
            enable_forms_crawl=enable_forms_crawl,
            use_tamper=True
        )

        return jsonify({
            "message": "SQLMap scan launched",
            "task_id": task.id
        }), 202

    except Exception as e:
        current_app.logger.exception("Erreur lors du lancement du scan SQLMap")
        return jsonify({"error": str(e)}), 500


@scan_bp.route('/sqlmap/<task_id>/report', methods=['GET'])
def download_sqlmap_report(task_id):
    try:
        # Exemple : recherche du scan SQLMap en base
        scan = SQLMapScanResult.query.filter_by(task_id=task_id).first()
        if not scan:
            return jsonify({'status': 'error', 'message': 'Scan not found'}), 404

        if getattr(scan, 'results_json', None):
            try:
                results = json.loads(scan.results_json)
            except json.JSONDecodeError:
                results = []
        else:
            # On tente de parser raw_output (chaîne JSON brute) si disponible
            if scan.raw_output:
                try:
                    results = json.loads(scan.raw_output)
                except json.JSONDecodeError:
                    results = []
            else:
                results = []

        scan_data = {
            'scan_type': 'sqlmap',
            'target': scan.target_url,
            'timestamp': scan.timestamp.isoformat(),
            'results': results,
            'summary': {
                'total_vulnerabilities': len(results),
                'dbms_list': list({r.get('dbms', 'Inconnu') for r in results if isinstance(results, list) and r.get('dbms')})
            }
        }

        # Fonction à créer similaire à generate_pdf_report mais pour SQLMap
        report_path = generate_sqlmap_pdf_report(scan_data)
        log_event('report_generated', f'Rapport généré pour le scan {task_id}', task_id)
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"sqlmap_scan_report_{task_id}.pdf"
        )

    except Exception as e:
        log_event('error', f'Erreur lors de la génération du rapport : {str(e)}', task_id)
        logger.log_error(
            error_type='sqlmap_report_download_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
def generate_sqlmap_pdf_report(scan_data: dict, output_dir: str = '/app/scan_reports') -> str:
    """
    Generate a PDF report for a SQLMap scan
    :param scan_data: Dictionary containing scan information (target, timestamp, results, summary)
    :param output_dir: Directory to save the PDF report
    :return: Path to the generated PDF report
    """
    os.makedirs(output_dir, exist_ok=True)
    report_filename = f"{output_dir}/sqlmap_scan_{uuid.uuid4().hex[:8]}.pdf"
    doc = SimpleDocTemplate(report_filename, pagesize=letter,
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    content = []
    styles = getSampleStyleSheet()

    # Title
    title = Paragraph(f"SQLMap Scan Report for {scan_data.get('target', 'Unknown Target')}", styles['Title'])
    content.append(title)

    # Scan Details
    details = [
        ['Scan Type', scan_data.get('scan_type', 'Unknown')],
        ['Target', scan_data.get('target', 'Unknown')],
        ['Timestamp', scan_data.get('timestamp', 'Unknown')]
    ]
    details_table = Table(details, colWidths=[2*inch, 4*inch])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    content.append(details_table)

    # Results Table (adapted to typical SQLMap output)
    results = scan_data.get('results', [])
    if results:
        results_data = [['Parameter', 'Vulnerability Type', 'Payload Example', 'DBMS']]
        for res in results:
            results_data.append([
                res.get('parameter', 'N/A'),
                res.get('vulnerability', 'N/A'),
                res.get('payload', 'N/A'),
                res.get('dbms', 'N/A')
            ])
        results_table = Table(results_data, colWidths=[1.5*inch, 3*inch, 2*inch, 1*inch])
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(Paragraph("Detected Vulnerabilities", styles['Heading2']))
        content.append(results_table)

    # Summary (optionnel, selon ce que tu stockes)
    summary = scan_data.get('summary', {})
    summary_text = Paragraph(
        f"Total Vulnerabilities Found: {summary.get('total_vulnerabilities', len(results))}<br/>" +
        f"DBMS Detected: {', '.join(summary.get('dbms_list', [])) if summary.get('dbms_list') else 'N/A'}",
        styles['Normal']
    )
    content.append(summary_text)

    doc.build(content)
    return report_filename


@scan_bp.route('/hydra', methods=['POST'])
def hydra_scan():
    """Endpoint to perform Hydra brute force scan"""
    try:
        data = request.get_json()
        if not data or 'target' not in data or 'service' not in data:
            return jsonify({'error': 'target and service are required'}), 400
        
        target = data['target']
        service = data['service']  # ex. : ssh, http-post-form, ftp
        username = data.get('username')
        password = data.get('password')
        user_list = data.get('user_list')  # Chemin vers un fichier de liste d'utilisateurs
        pass_list = data.get('pass_list')  # Chemin vers un fichier de liste de mots de passe
        options = data.get('options', {})  # Options supplémentaires (ex. : {'-t': 4} pour 4 threads)
        
        import os

        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'wordlists'))

        if user_list:
            user_list_path = os.path.join(base_path, user_list)
        else:
            user_list_path = None

        if pass_list:
            pass_list_path = os.path.join(base_path, pass_list)
        else:
            pass_list_path = None


        form_path = None
        if service == 'http-post-form':
            form_path = data.get('formPath')
            if not form_path:
                return jsonify({'error': 'formPath is required for service http-post-form'}), 400

        scan_id = f"hydra_{target}_{int(datetime.now().timestamp())}"
        
        import os

        if user_list_path and not os.path.isfile(user_list_path):
            return jsonify({'error': f'user_list file not found: {user_list_path}'}), 400

        if pass_list_path and not os.path.isfile(pass_list_path):
            return jsonify({'error': f'pass_list file not found: {pass_list_path}'}), 400

        #Start scan asynchronously via Celery
        task = run_hydra_scan.delay(target, service, username, password, user_list_path, pass_list_path, options, form_path)

        # Store initial scan info
        active_scans[scan_id] = {
            'target': target,
            'type': f'hydra_{service}',
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'task_id': task.id   # <-- ici tu stockes l'ID de la tâche Celery
        }
                
        # Log scan initiation
        logger.log_scan(
            scan_type=f'hydra_{service}',
            target=target,
            results={'status': 'initiated', 'scan_id': scan_id}
        )
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'task_id': task.id,
            'message': f'Hydra scan started for {target} on {service}'
        }), 202
    except Exception as e:
        logger.log_error(
            error_type='hydra_scan_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@scan_bp.route('/hydra/status/<path:scan_id>', methods=['GET'])
def hydra_scan_status(scan_id):
    """Check the status of an Hydra scan"""
    try:
        scan_data = active_scans.get(scan_id)
        if not scan_data:
            logger.log_error(
                error_type='hydra_scan_status_error',
                error_message=f'Scan not found: {scan_id}'
            )
            return jsonify({
                'status': 'error',
                'message': 'Scan not found',
                'scan_id': scan_id
            }), 404
        
        # Check Celery task status
        task_id = scan_data.get('task_id')
        task_result = AsyncResult(task_id, app=celery)
        
        response = {
            'status': 'success',
            'scan': {
                'id': scan_id,
                'target': scan_data.get('target', 'Unknown'),
                'type': scan_data.get('type', 'hydra'),
                'current_status': scan_data.get('status', 'unknown'),
                'start_time': scan_data.get('start_time', 'N/A'),
                'end_time': scan_data.get('end_time', 'N/A'),
                'task_status': task_result.state,
                'task_info': task_result.info if task_result.info else {}
            },
            'report_id': None
        }
        
        if task_result.state == 'SUCCESS':
            scan_data['status'] = 'completed'
            scan_data['end_time'] = datetime.now().isoformat()
            active_scans[scan_id] = scan_data

            result = task_result.result
            response['scan']['results'] = result.get('results', [])
            response['report_id'] = f"report_{scan_id}"

            existing = ScanResult.query.filter_by(scan_id=scan_id).first()
            if not existing:
                try:
                    new_scan = ScanResult(
                        scan_id=scan_id,
                        scan_type=scan_data.get('type', 'hydra'),
                        target=scan_data.get('target'),
                        timestamp=datetime.now(),
                        results_json=json.dumps(result.get('results', [])),
                        summary_json=json.dumps(result.get('summary', {}))
                    )
                    db.session.add(new_scan)
                    db.session.commit()

                    logger.info(f"Hydra scan {scan_id} enregistré en base.")
                except Exception as db_error:
                    logger.log_error(
                        error_type='db_insert_error',
                        error_message=str(db_error),
                        stack_trace=traceback.format_exc()
                    )

        return jsonify(response)

    except Exception as e:
        logger.log_error(
            error_type='hydra_scan_status_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e),
            'scan_id': scan_id
        }), 500


@scan_bp.route('/hydra/<path:scan_id>/report', methods=['GET'])
def download_hydra_report(scan_id):
    """Download Hydra scan report as PDF"""
    try:
        scan = ScanResult.query.filter_by(scan_id=scan_id).first()
        if not scan:
            return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
        
        scan_data = {
            'scan_type': scan.scan_type,
            'target': scan.target,
            'timestamp': scan.timestamp.isoformat(),
            'results': json.loads(scan.results_json) if scan.results_json else [],
            'summary': json.loads(scan.summary_json) if scan.summary_json else {}
        }
        
        report_path = generate_hydra_pdf_report(scan_data)
        log_event('report_generated', f'Rapport généré pour le scan {scan_id}', scan_id)
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"hydra_scan_report_{scan_id}.pdf"
        )
    except Exception as e:
        log_event('error', f'Erreur lors de la génération du rapport : {str(e)}', scan_id)
        logger.log_error(
            error_type='hydra_report_download_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    
def generate_hydra_pdf_report(scan_data: dict, output_dir: str = '/app/scan_reports') -> str:
    """Generate a PDF report for hydra"""
    os.makedirs(output_dir, exist_ok=True)
    report_filename = f"{output_dir}/{scan_data.get('scan_type', 'scan')}_{uuid.uuid4().hex[:8]}.pdf"
    doc = SimpleDocTemplate(report_filename, pagesize=letter,
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    content = []
    styles = getSampleStyleSheet()

    # Title
    title = Paragraph(f"{scan_data.get('scan_type', 'Scan')} Report for {scan_data.get('target', 'Unknown Target')}", styles['Title'])
    content.append(title)

    # Scan Details
    details = [
        ['Scan Type', scan_data.get('scan_type', 'Unknown')],
        ['Target', scan_data.get('target', 'Unknown')],
        ['Timestamp', scan_data.get('timestamp', 'Unknown')]
    ]
    details_table = Table(details, colWidths=[2*inch, 4*inch])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    content.append(details_table)

    # Results Table
    results = scan_data.get('results', [])
    if results:
        if 'hydra' in scan_data.get('scan_type', '').lower():
            results_data = [['Host', 'Login', 'Password', 'Success']]
            for result in results:
                results_data.append([
                    result.get('host', 'N/A'),
                    result.get('login', 'N/A'),
                    result.get('password', 'N/A'),
                    str(result.get('success', 'N/A'))
                ])
            col_widths = [1.5*inch, 1.5*inch, 2*inch, 1*inch]
        else:
            results_data = [['Key', 'Value']]
            for result in results:
                for k, v in result.items():
                    results_data.append([str(k), str(v)])
            col_widths = [2*inch, 4*inch]

        results_table = Table(results_data, colWidths=col_widths)
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(Paragraph("Scan Results", styles['Heading2']))
        content.append(results_table)

    # Summary
    summary = scan_data.get('summary', {})
    summary_text = Paragraph(
        f"Total Items: {summary.get('total_attempts', summary.get('total_ports', summary.get('total_hosts', len(results))))}<br/>"
        f"Successful/Open: {summary.get('successful_logins', summary.get('open_ports', summary.get('total_vulnerabilities', 0)))}",
        styles['Normal']
    )
    content.append(summary_text)

    doc.build(content)
    return report_filename    

@scan_bp.route('/zap', methods=['POST'])
def zap_scan():
    try:
        data = request.get_json()
        url = data.get('url')
        scan_type = data.get('scan_type', 'spider')  # spider ou active
        level = data.get('level', 'Default')

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        scan_id = f"zap_{url}_{int(datetime.now().timestamp())}"
        task = run_zap_scan.delay(scan_id, url, scan_type, level)

        active_scans[scan_id] = {
            'target': url,
            'type': f'zap_{scan_type}',
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'task_id': task.id
        }

        logger.log_scan(
            scan_type=f'zap_{scan_type}',
            target=url,
            results={'status': 'initiated', 'scan_id': scan_id}
        )

        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'task_id': task.id,
            'message': f'ZAP {scan_type} scan started for {url}'
        }), 202
    except Exception as e:
        logger.log_error(
            error_type='zap_scan_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({'status': 'error', 'message': str(e)}), 500

@scan_bp.route('/zap/<path:scan_id>/status', methods=['GET'])
def zap_scan_status(scan_id):
    try:
        from urllib.parse import unquote
        decoded_id = unquote(scan_id)

        scan_data = active_scans.get(decoded_id)
        if not scan_data:
            logger.log_error(
                error_type='zap_scan_status_error',
                error_message=f'Scan not found: {decoded_id}'
            )
            return jsonify({
                'status': 'error',
                'message': 'Scan not found',
                'scan_id': decoded_id
            }), 404

        task_id     = scan_data.get('task_id')
        task_result = AsyncResult(task_id, app=celery)

        response = {
            'status':   'success',
            'progress': 0,
            'message':  '',
            'scan': {
                'id':             decoded_id,
                'target':         scan_data.get('target', ''),
                'type':           scan_data.get('type', 'zap'),
                'current_status': scan_data.get('status', 'unknown'),
                'start_time':     scan_data.get('start_time', ''),
                'end_time':       scan_data.get('end_time', ''),
                'task_status':    task_result.state,
                'task_info':      task_result.info or {}
            },
            'report_id': None
        }

        # Si le task envoie des informations de progression
        if task_result.state == 'PROGRESS' and isinstance(task_result.info, dict):
            response['progress'] = task_result.info.get('progress', 0)
            response['message']  = task_result.info.get('message', '')

        # Si le task est terminé avec succès
        if task_result.state == 'SUCCESS':
            log_event('scan_completed', f'Scan terminé avec succès', decoded_id)
            scan_data['status']   = 'completed'
            scan_data['end_time'] = datetime.now().isoformat()
            active_scans[decoded_id] = scan_data

            result = task_result.result or {}
            response['scan']['results'] = result.get('results', [])
            response['report_id']       = f"report_{decoded_id}"

        # → On renvoie TOUJOURS la réponse, qu’on soit ici en PENDING, FAILURE, PROGRESS ou SUCCESS.
        return jsonify(response)

    except Exception as e:
        logger.log_error(
            error_type='zap_scan_status_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e),
            'scan_id': scan_id
        }), 500


@scan_bp.route('/zap/<path:scan_id>/report', methods=['GET'])
def download_zap_report(scan_id):
    try:
        scan = ZAPScanResult.query.filter_by(scan_id=scan_id).first()
        if not scan:
            return jsonify({'status': 'error', 'message': 'Scan not found'}), 404

        scan_data = {
            'scan_type': scan.scan_type,
            'target': scan.target_url,
            'timestamp': scan.timestamp.isoformat(),
            'results': json.loads(scan.results_json) if scan.results_json else [],
            'summary': json.loads(scan.summary_json) if scan.summary_json else {}
        }

        report_path = generate_zap_pdf_report(scan_data)
        logger.info(f"PDF path: {report_path}")
        logger.info(f"Existe: {os.path.exists(report_path)}")
        if os.path.exists(report_path):
            logger.info(f"Taille du fichier: {os.path.getsize(report_path)} octets")
        log_event('report_generated', f'Rapport généré pour le scan {scan_id}', scan_id)
        return send_file(
            report_path,
            as_attachment=True,
            download_name=f"zap_scan_report_{scan_id}.pdf"
        )
        
    except Exception as e:
        log_event('error', f'Erreur lors de la génération du rapport : {str(e)}', scan_id)
        logger.log_error(
            error_type='zap_report_download_error',
            error_message=str(e),
            stack_trace=traceback.format_exc()
        )
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
        
def generate_zap_pdf_report(scan_data: dict, output_dir: str = '/app/scan_reports') -> str:
    import re

    os.makedirs(output_dir, exist_ok=True)
    report_filename = f"{output_dir}/zap_scan_{uuid.uuid4().hex[:8]}.pdf"
    doc = SimpleDocTemplate(report_filename, pagesize=letter,
                            rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    content = []
    styles = getSampleStyleSheet()

    # Title
    title = Paragraph(
        f"{scan_data.get('scan_type', 'ZAP Scan')} Report for {scan_data.get('target', 'Unknown Target')}",
        styles['Title']
    )
    content.append(title)
    content.append(Spacer(1, 12))

    # Scan Details
    details = [
        ['Scan Type', scan_data.get('scan_type', 'Unknown')],
        ['Target', scan_data.get('target', 'Unknown')],
        ['Timestamp', scan_data.get('timestamp', 'Unknown')]
    ]
    details_table = Table(details, colWidths=[2*inch, 4*inch])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    content.append(details_table)
    content.append(Spacer(1, 12))

    # Safe cell style with strong wrapping
    cell_style = ParagraphStyle(
        name='TableCell',
        fontSize=6,
        leading=8,
        wordWrap='CJK',
        allowWidows=0,
        allowOrphans=0,
        spaceAfter=2,
    )

    def wrap_cell(text, max_len=300):
        if not text:
            return Paragraph('', cell_style)

        text = str(text)

        # Remove invisible/invalid characters
        text = re.sub(r'[^\x20-\x7E\u00A0-\uFFFF]+', '', text)

        # Limit line length to avoid huge rows
        text = text.replace('\n', '<br/>').replace('\r', '')

        # Truncate if needed
        if len(text) > max_len:
            text = text[:max_len] + '...'

        # Add spaces in long continuous strings
        text = re.sub(r'([^\s]{50})', r'\1 ', text)

        return Paragraph(text, cell_style)

    # Results Table
    results = scan_data.get('results', [])
    if results:
        content.append(Paragraph("Scan Results", styles['Heading2']))

        # Header row
        raw_data = [['Alert', 'Risk', 'URI', 'Parameter', 'Solution']]

        # Limit number of rows to avoid overflow
        MAX_ROWS = 100
        for result in results[:MAX_ROWS]:
            raw_data.append([
                result.get('alert', 'N/A'),
                result.get('risk', 'N/A'),
                result.get('uri', 'N/A'),
                result.get('param', 'N/A'),
                result.get('solution', 'N/A')
            ])

        # Calculate column widths based on header (safe default)
        colWidths = [1.5*inch, 0.8*inch, 2*inch, 1*inch, 2*inch]

        # Apply secure wrapping to each cell
        results_data = [[wrap_cell(cell) for cell in row] for row in raw_data]

        results_table = Table(results_data, colWidths=colWidths)
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black)
        ]))

        content.append(results_table)
        content.append(Spacer(1, 12))

    # Summary
    summary = scan_data.get('summary', {})
    summary_text = Paragraph(
        f"Total Alerts: {summary.get('total_alerts', 0)}<br/>"
        f"High Risk: {summary.get('risk_levels', {}).get('High', 0)}<br/>"
        f"Medium Risk: {summary.get('risk_levels', {}).get('Medium', 0)}<br/>"
        f"Low Risk: {summary.get('risk_levels', {}).get('Low', 0)}<br/>"
        f"Informational: {summary.get('risk_levels', {}).get('Informational', 0)}",
        styles['Normal']
    )
    content.append(summary_text)

    doc.build(content)
    return report_filename


@scan_bp.route('/tasks/<task_id>', methods=['GET'])
def get_task_status(task_id):
    try:
        task = AsyncResult(task_id, app=celery)
        response = {
            'task_id': task_id,
            'state': task.state,
            'info': task.info if task.info else None
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
@scan_bp.route('/events', methods=['GET'])
def get_timeline_events():
    events = TimelineEvent.query.order_by(TimelineEvent.timestamp.desc()).limit(100).all()
    return jsonify([e.to_dict() for e in events])    