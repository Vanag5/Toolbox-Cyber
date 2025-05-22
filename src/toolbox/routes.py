from flask import (
    Blueprint, jsonify, request, render_template, send_file
)
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from typing import Dict
import traceback
import time
import os
import uuid

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from gvm.protocols.gmp import Gmp

from .network_discovery import NetworkDiscovery
from .port_scanner import PortScanner
from .service_enum import ServiceEnumerator
from .logger import logger
from .pdf_utils import generate_pdf_report
from .scanner import get_vuln_scanner

main_bp = Blueprint('main', __name__)
report_bp = Blueprint('report', __name__, url_prefix='/report')
scan_bp = Blueprint('scan', __name__, url_prefix='/scan')

active_scans = {}
scan_reports = {}

net_discovery = NetworkDiscovery()
port_scanner = PortScanner()
service_enumerator = ServiceEnumerator()


@main_bp.before_request
def log_request_info():
    request.start_time = time.time()


@main_bp.after_request
def log_request_complete(response):
    total_time = time.time() - getattr(request, 'start_time', time.time())
    logger.log_access(
        request_method=request.method,
        endpoint=request.endpoint,
        source_ip=request.remote_addr,
        status_code=response.status_code,
        response_time=round(total_time * 1000, 2)
    )
    return response


@main_bp.route('/')
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
    try:
        scans = [
            {
                'id': sid,
                'target': sinfo.get('target', ''),
                'type': sinfo.get('type', ''),
                'status': sinfo.get('status', 'unknown'),
                'start_time': sinfo.get('start_time', ''),
                'end_time': sinfo.get('end_time', '')
            }
            for sid, sinfo in active_scans.items()
        ]
        return jsonify({'status': 'success', 'scans': scans})
    except Exception as e:
        logger.log_error('api_scans_error', str(e), traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500


@main_bp.route('/api/reports')
def api_reports():
    try:
        reports = [
            {
                'id': rid,
                'scan_type': rinfo.get('scan_type', ''),
                'target': rinfo.get('target', ''),
                'timestamp': rinfo.get('timestamp', ''),
                'summary': rinfo.get('summary', {})
            }
            for rid, rinfo in scan_reports.items()
        ]
        return jsonify({'status': 'success', 'reports': reports})
    except Exception as e:
        logger.log_error('api_reports_error', str(e), traceback.format_exc())
        return jsonify({'status': 'error', 'message': str(e)}), 500
