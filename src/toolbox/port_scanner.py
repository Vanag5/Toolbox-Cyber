import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional
import logging
from dataclasses import dataclass
from enum import Enum
import subprocess
import time
from datetime import datetime, timedelta
from libnmap.parser import NmapParser
from .models import ScanResult
from toolbox import db
import uuid

scan_id = str(uuid.uuid4())  # Génère un identifiant unique pour chaque scan
# Ensure Nmap is imported
try:
    import nmap
except ImportError:
    def install_nmap():
        """Install python-nmap if not already installed"""
        subprocess.check_call(
            [sys.executable, '-m', 'pip', 'install', 'python-nmap'])
    try:
        install_nmap()
        import nmap
    except Exception as e:
        logging.error(f"Failed to import or install python-nmap: {e}")
        nmap = None

class ScanType(Enum):
    TCP_SYN = "-sS"
    TCP_CONNECT = "-sT"
    UDP = "-sU"
    VERSION = "-sV"
    AGGRESSIVE = "-A"

@dataclass
class PortScanResult:
    host: str
    port: int
    state: str
    service: str
    version: Optional[str] = None
    protocol: str = "tcp"
    product: Optional[str] = ""
    extrainfo: Optional[str] = ""
    banner: Optional[str] = ""
    cpe: Optional[str] = ""
    scripts: Optional[list] = None

class PortScanner:
    def __init__(self, threads: int = 10, app=None):
        if nmap is None:
            raise RuntimeError("Nmap is not installed or failed to import")
        self.nm = nmap.PortScanner()
        self.app=app
        self.threads = threads
        self.logger = logging.getLogger(__name__)
        self.executor = ThreadPoolExecutor(max_workers=threads)
        self.active_scans = {}  # Store active scan states
        self.scans_cache_file = '/src/scan_cache.json'
        self.load_active_scans()

    def load_active_scans(self):
        """Load active scans from a persistent cache file"""
        try:
            if os.path.exists(self.scans_cache_file):
                with open(self.scans_cache_file, 'r') as f:
                    self.active_scans = json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading scan cache: {e}")
            self.active_scans = {}

    def save_active_scans(self):
        """Save active scans to a persistent cache file"""
        try:
            with open(self.scans_cache_file, 'w') as f:
                json.dump(self.active_scans, f)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            self.logger.error(f"Error saving scan cache: {e}")

    def quick_scan(self, target: str, ports: str = "1-1024") -> List[PortScanResult]:
        """
        Perform a quick TCP SYN scan of common ports
        """
        try:
            self.nm.scan(
                target, ports, arguments=f"{ScanType.TCP_SYN.value} -T4")
            return self._parse_scan_results(target)
        except Exception as e:
            self.logger.error(f"Quick scan failed for {target}: {str(e)}")
            return []

    def comprehensive_scan(self, target: str, ports: str = "1-65535") -> List[PortScanResult]:
        """
        Perform a comprehensive scan including version detection
        """
        try:
            args = f"{ScanType.TCP_SYN.value} {ScanType.VERSION.value} {ScanType.AGGRESSIVE.value} -T4"
            self.nm.scan(target, ports, arguments=args)
            return self._parse_scan_results(target)
        except Exception as e:
            self.logger.error(
                f"Comprehensive scan failed for {target}: {str(e)}")
            return []

    def udp_scan(self, target: str, ports: str = "53,67,68,69,123,161,162") -> List[PortScanResult]:
        """
        Perform UDP port scan on common UDP services
        """
        try:
            self.nm.scan(target, ports, arguments=f"{ScanType.UDP.value} -T4")
            return self._parse_scan_results(target, protocol="udp")
        except Exception as e:
            self.logger.error(f"UDP scan failed for {target}: {str(e)}")
            return []

    def _parse_scan_results(self, target: str, protocol: str = "tcp") -> List[PortScanResult]:
        """
        Parse Nmap scan results for a given target
        :param target: Target IP or hostname to parse results for
        :param protocol: Protocol to filter (default: tcp)
        :return: List of PortScanResult objects
        """
        try:
            # Use libnmap to parse results
            parsed_report = NmapParser.parse_fromfile(
                f"/tmp/nmap_scan_{target}.xml")
            # Prepare list to store results
            results = []
            # Track scan progress
            total_hosts = len(parsed_report.hosts)
            scanned_hosts = 0
            # Find the corresponding scan ID
            current_scan_id = None
            for scan_id, scan_data in self.active_scans.items():
                if scan_data.get('target') == target:
                    current_scan_id = scan_id
                    break
            # Iterate through scanned hosts
            for host in parsed_report.hosts:
                try:
                    # Update current scan progress
                    scanned_hosts += 1
                    # Filter services by protocol
                    host_results = [
                        PortScanResult(
                            host=host.address,
                            port=service.port,
                            state=service.state,
                            service=service.service,
                            version=getattr(service, 'version', '') or '',
                            protocol=service.protocol
                        )
                        for service in host.services
                        if service.protocol.lower() == protocol.lower()
                    ]
                    results.extend(host_results)
                    # Update active scan progress if applicable
                    if current_scan_id:
                        # Forcefully update progress in active_scans
                        self.active_scans[current_scan_id]['progress'] = {
                            'total_hosts': total_hosts,
                            'scanned_hosts': scanned_hosts,
                            'current_host': host.address,
                            'estimated_completion_time': datetime.now().isoformat(),
                            'percentage': int((scanned_hosts / total_hosts) * 100)
                        }
                        # Ensure the scan status is updated
                        if self.active_scans[current_scan_id]['status'] == 'running':
                            self.active_scans[current_scan_id]['status'] = 'completed'
                except Exception as host_error:
                    self.logger.error(
                        f"Error parsing host results: {host_error}")
            return results
        except Exception as e:
            self.logger.error(
                f"Error parsing scan results for {target}: {str(e)}")
            return []

    def vulnerability_scan(self, target: str, ports: str) -> Dict:
        """
        Perform vulnerability scanning using NSE scripts
        """
        try:
            # Using common NSE scripts for vulnerability detection
            args = f"{ScanType.TCP_SYN.value} {ScanType.VERSION.value} --script=vuln,auth,default -T4"
            self.nm.scan(target, ports, arguments=args)
            results = {}
            if target in self.nm.all_hosts():
                if 'script' in self.nm[target]:
                    results['vulnerabilities'] = self.nm[target]['script']
            return results
        except Exception as e:
            self.logger.error(
                f"Vulnerability scan failed for {target}: {str(e)}")
            return {}

    def start_nmap_scan(self, target: str, options: str) -> str:
        """
        Start an asynchronous Nmap scan
        Returns a scan ID that can be used to check the status
        """
        try:
            # Détermine le type de scan
            scan_type = 'nmap_quick'
            if '-sV' in options:
                scan_type = 'nmap_version'
            elif '-A' in options:
                scan_type = 'nmap_aggressive'
            elif '-sU' in options:
                scan_type = 'nmap_udp'
            # Si aucune option n'est passée, force un scan version sur 80 et 443
            if not options.strip():
                options = "-sV -p 80,443"
            elif "-Pn" not in options:
                options = options.strip() + " -Pn"    
            # Génère un scan_id unique
            scan_id = f"nmap_{target}_{int(time.time())}_{hash(target + options)}"
            # Initialise l'état du scan
            scan_state = {
                'target': target,
                'options': options,
                'status': 'initializing',
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'results': [],
                'type': scan_type,
                'error': None,
                'progress': {
                    'total_hosts': 1,
                    'scanned_hosts': 0,
                    'current_host': target,
                    'estimated_completion_time': None,
                    'percentage': 0
                }
            }
            if not hasattr(self, 'active_scans') or not isinstance(self.active_scans, dict):
                self.active_scans = {}
            self.active_scans[scan_id] = scan_state
            # Log pour vérifier les options utilisées
            self.logger.info(f"Scan initiated: {scan_id} (Type: {scan_type})")
            self.logger.info(f"Options Nmap utilisées pour {scan_id}: {options}")
            # Start the scan in a separate thread
            def run_scan():
                try:
                    # Update scan status
                    self.active_scans[scan_id]['status'] = 'running'
                    scan_start_time = datetime.now()
                    max_scan_duration = timedelta(minutes=2)
                    xml_output_path = f"/tmp/nmap_scan_{target}.xml"
                    nmap_cmd = f"timeout 120s nmap {target} {options} -v -oX \"{xml_output_path}\""
                    max_scan_duration = timedelta(minutes=2)
                    # Create a shared state for progress tracking
                    process = subprocess.Popen(
                        nmap_cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        universal_newlines=True
                    )
                    while process.poll() is None:
                        elapsed_time = datetime.now() - scan_start_time
                        progress_percentage = min(99, int(
                            (elapsed_time.total_seconds() / max_scan_duration.total_seconds()) * 100))
                        self.active_scans[scan_id]['progress'] = {
                            'total_hosts': 1,
                            'scanned_hosts': 1,  # Toujours 1 ici pour localhost
                            'current_host': target,
                            'estimated_completion_time': (scan_start_time + max_scan_duration).isoformat(),
                            'percentage': progress_percentage
                        }   
                        self.save_active_scans()
                        time.sleep(2)  # Mets à jour toutes les 2 secondes
                    self.logger.info(f"Sortie de la boucle Nmap pour {scan_id}")
                    # À la fin du scan
                    stdout, stderr = process.communicate()
                    results = []
                    try:
                        from libnmap.parser import NmapParser
                        parsed_report = NmapParser.parse_fromfile(xml_output_path)
                        for host in parsed_report.hosts:
                            for service in host.services:
                                results.append(PortScanResult(
                                    host=host.address,
                                    port=service.port,
                                    state=service.state,
                                    service=service.service,
                                    version=getattr(service, 'version', '') or '',
                                    protocol=service.protocol,
                                    product=getattr(service, 'product', ''),
                                    extrainfo=getattr(service, 'extrainfo', ''),
                                    banner=getattr(service, 'banner', ''),
                                    cpe=getattr(service, 'cpe', ''),
                                    scripts=[s.output for s in getattr(service, 'scripts_results', [])],
                               ))
                    except Exception as parse_error:
                        self.logger.error(f"Failed to parse Nmap XML: {parse_error}")
                        results = []    
                    self.logger.info(f"Fin du traitement du scan {scan_id}")
                except Exception as e:
                    import traceback
                    self.logger.error(traceback.format_exc())
                    self.active_scans[scan_id].update({
                        'status': 'failed',
                        'end_time': datetime.now().isoformat(),
                        'error': str(e),
                        'results': [],
                        'progress': {
                        'total_hosts': 1,
                        'scanned_hosts': 0,
                        'current_host': None,
                        'estimated_completion_time': None,
                        'percentage': 0
                        }
                    })
                else:
                    self.logger.info(f"[DEBUG] Progress juste avant save_active_scans: {self.active_scans[scan_id]['progress']}")
                    self.active_scans[scan_id].update({
                        'status': 'completed',
                        'end_time': datetime.now().isoformat(),
                        'results': [vars(r) for r in results],
                        'progress': {
                            'total_hosts': 1,
                            'scanned_hosts': 1,
                            'current_host': None,
                            'estimated_completion_time': datetime.now().isoformat(),
                            'percentage': 100
                        }
                    })
                    self.logger.info(f"[DEBUG] Progress après passage à 100%: {self.active_scans[scan_id]['progress']}")
                    self.save_active_scans()
                    self.logger.info(f"Appel de save_scan_result pour {scan_id}")
                    save_scan_result(self.app, scan_id, target, scan_type, results)
                    self.logger.info(f"save_scan_result appelé pour {scan_id}")
                    self.logger.info(f"Scan completed successfully: {scan_id}")    
                finally:
                    # Toujours sauvegarder l'état, succès ou erreur
                    if self.active_scans[scan_id]['status'] == 'completed':
                        if 'progress' in self.active_scans[scan_id]:
                            self.active_scans[scan_id]['progress']['percentage'] = 100
                        else:
                            self.active_scans[scan_id]['progress'] = {'percentage': 100}
                    self.logger.info(f"[DEBUG] Juste avant save_active_scans: status={self.active_scans[scan_id]['status']} progress={self.active_scans[scan_id]['progress']}")
                    self.save_active_scans()
            # Submit scan to thread pool
            self.executor.submit(run_scan)
            # Save active scans immediately
            self.save_active_scans()
            return scan_id
        except Exception as e:
            error_msg = f"Failed to start Nmap scan for {target}: {str(e)}"
            self.logger.error(error_msg)
            # Log full traceback
            import traceback
            self.logger.error(traceback.format_exc())
            raise RuntimeError(error_msg)

    def get_scan_status(self, scan_id: str) -> Dict:
        """Get the status and results of a scan with comprehensive logging"""
        # Ensure active_scans is loaded
        self.load_active_scans()
        # Log all available scan IDs for debugging
        self.logger.info(
            f"Available scan IDs: {list(self.active_scans.keys())}")
        if scan_id not in self.active_scans:
            self.logger.warning(f"Scan not found: {scan_id}")
            return {'status': 'not_found'}
        current_scan = self.active_scans[scan_id]
        # Force complete status if scan has been running too long
        if current_scan['status'] == 'running':
            current_scan['status'] = 'completed'
            current_scan['end_time'] = datetime.now().isoformat()
            current_scan['progress'] = {
                'total_hosts': current_scan['progress'].get('total_hosts', 1),
                'scanned_hosts': current_scan['progress'].get('scanned_hosts', 1),
                'current_host': None,
                'estimated_completion_time': datetime.now().isoformat(),
                'percentage': 100
            }
            # Parse results and convert to list of dictionaries
            raw_results = self._parse_scan_results(current_scan['target'])
            current_scan['results'] = [
                {
                    'protocol': getattr(result, 'protocol', 'unknown'),
                    'port': getattr(result, 'port', 0),
                    'state': getattr(result, 'state', 'unknown'),
                    'service': getattr(result, 'service', 'unknown'),
                    'version': getattr(result, 'version', 'unknown')
                } for result in raw_results
            ]
            self.save_active_scans()
        # Log scan status for debugging
        self.logger.info(
            f"Scan status for {scan_id}: {current_scan['status']}")
        return current_scan

def save_scan_result(app, scan_id, target, scan_type, results):
    logger = logging.getLogger("toolbox.port_scanner")
    logger.info(f"[DEBUG] Flask app id in save_scan_result: {id(app)}")
    with app.app_context():
        try:
            logger.info(f"[DEBUG] save_scan_result appelé pour {scan_id} ({len(results)} résultats)")
            print("scan_id:", scan_id)
            print("scan_id length:", len(scan_id))
            print("target:", target)
            print("scan_type:", scan_type)
            print("results_json:", json.dumps([vars(r) for r in results]))
            print("summary_json:", json.dumps({
                'total_ports': len(results),
                'open_ports': len([r for r in results if getattr(r, 'state', None) == 'open'])
            }))
            print("timestamp:", datetime.utcnow())
            scan_result = ScanResult(
                scan_id=scan_id,
                target=target,
                scan_type=scan_type,
                results_json=json.dumps([vars(r) for r in results]),
                summary_json=json.dumps({
                    'total_ports': len(results),
                    'open_ports': len([r for r in results if getattr(r, 'state', None) == 'open'])
                }),
                timestamp=datetime.utcnow()
            )
            db.session.add(scan_result)
            print("ScanResult fields:", scan_result.scan_id, scan_result.target, scan_result.scan_type, scan_result.timestamp)
            db.session.commit()
            logger.info(f"[DEBUG] Scan {scan_id} enregistré en base")
        except Exception as e:
            import traceback
            logger.error(f"[ERROR] save_scan_result: {e}")
            logger.error(traceback.format_exc())
            print(traceback.format_exc())