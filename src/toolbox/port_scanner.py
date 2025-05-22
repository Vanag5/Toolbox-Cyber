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


class PortScanner:
    def __init__(self, threads: int = 10):
        if nmap is None:
            raise RuntimeError("Nmap is not installed or failed to import")
        self.nm = nmap.PortScanner()
        self.threads = threads
        self.logger = logging.getLogger(__name__)
        self.executor = ThreadPoolExecutor(max_workers=threads)
        self.active_scans = {}  # Store active scan states
        self.scans_cache_file = '/app/scan_cache.json'
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
            # Determine scan type based on options
            scan_type = 'nmap_quick'
            if '-sV' in options:
                scan_type = 'nmap_version'
            elif '-A' in options:
                scan_type = 'nmap_aggressive'
            elif '-sU' in options:
                scan_type = 'nmap_udp'

            # Generate a unique scan ID with more robust generation
            scan_id = f"nmap_{target}_{int(time.time())}_{hash(target + options)}"

            # Initialize scan state with comprehensive error handling
            scan_state = {
                'target': target,
                'options': options,
                'status': 'initializing',
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'results': [],  # Always initialize as empty list
                'type': scan_type,  # Explicit scan type
                'error': None,
                'progress': {
                    'total_hosts': 1,  # Default for localhost
                    'scanned_hosts': 0,
                    'current_host': target,
                    'estimated_completion_time': None,
                    'percentage': 0
                }
            }

            # Ensure active_scans is a dictionary
            if not hasattr(self, 'active_scans') or not isinstance(self.active_scans, dict):
                self.active_scans = {}

            # Store scan state
            self.active_scans[scan_id] = scan_state

            # Logging for debugging
            self.logger.info(f"Scan initiated: {scan_id} (Type: {scan_type})")

            # Start the scan in a separate thread
            def run_scan():
                try:
                    # Update scan status
                    self.active_scans[scan_id]['status'] = 'running'

                    # Prepare progress tracking
                    scan_start_time = datetime.now()
                    max_scan_duration = timedelta(minutes=2)

                    # Create a shared state for progress tracking
                    progress_state = {
                        'start_time': scan_start_time,
                        'max_duration': max_scan_duration,
                        'scan_id': scan_id
                    }

                    # Periodic progress update function
                    def update_progress(state):
                        try:
                            # Calculate progress based on elapsed time
                            elapsed_time = datetime.now() - state['start_time']
                            progress_percentage = min(100, int(
                                (elapsed_time.total_seconds() / state['max_duration'].total_seconds()) * 100))

                            # Update active scan progress
                            if state['scan_id'] in self.active_scans:
                                # Forcefully update progress
                                self.active_scans[state['scan_id']]['progress'] = {
                                    'total_hosts': 1,
                                    'scanned_hosts': 0,
                                    'current_host': target,
                                    'estimated_completion_time': (state['start_time'] + state['max_duration']).isoformat(),
                                    'percentage': progress_percentage
                                }

                                self.logger.info(
                                    f"Scan progress update: {progress_percentage}%")

                                # Persist changes
                                self.save_active_scans()
                        except Exception as progress_error:
                            self.logger.error(
                                f"Error updating scan progress: {progress_error}")

                    # Create a timer to update progress periodically
                    import threading
                    progress_timer = threading.Timer(
                        5, update_progress, args=(progress_state,))
                    progress_timer.start()

                    try:
                        # Perform the scan with a timeout
                        import subprocess
                        from libnmap.parser import NmapParser

                        # Construct Nmap command with timeout
                        import os
                        xml_output_path = f"/tmp/nmap_scan_{target}.xml"
                        nmap_cmd = f"timeout 120s nmap {target} {options} -v -oX \"{xml_output_path}\""

                        self.logger.info(f"Executing Nmap command: {nmap_cmd}")

                        # Run the scan using subprocess
                        process = subprocess.Popen(
                            nmap_cmd,
                            shell=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True
                        )

                        # Capture output
                        stdout, stderr = process.communicate()

                        self.logger.info(f"Nmap stdout: {stdout}")
                        self.logger.info(f"Nmap stderr: {stderr}")

                        # Check return code
                        if process.returncode != 0:
                            raise Exception(f"Nmap scan failed: {stderr}")

                        # Parse the output manually
                        try:
                            parsed_report = NmapParser.parse_fromfile(
                                xml_output_path)
                        except Exception as parse_error:
                            self.logger.error(
                                f"Failed to parse Nmap XML: {parse_error}")
                            raise

                        # Convert parsed results to our format
                        results = []
                        for host in parsed_report.hosts:
                            for service in host.services:
                                results.append(PortScanResult(
                                    host=host.address,
                                    port=service.port,
                                    state=service.state,
                                    service=service.service,
                                    version=getattr(
                                        service, 'version', '') or '',
                                    protocol=service.protocol
                                ))

                        # Clean up XML file
                        try:
                            os.remove(xml_output_path)
                        except Exception as cleanup_error:
                            self.logger.warning(
                                f"Failed to remove XML file: {cleanup_error}")

                    except subprocess.TimeoutExpired:
                        # Handle timeout
                        self.logger.warning(
                            f"Nmap scan for {target} timed out")
                        results = []
                    finally:
                        # Stop the progress timer
                        progress_timer.cancel()

                    # Update scan state
                    self.active_scans[scan_id].update({
                        'status': 'completed',
                        'end_time': datetime.now().isoformat(),
                        # Convert to dict for JSON serialization
                        'results': [vars(r) for r in results],
                        'progress': {
                            'total_hosts': 1,
                            'scanned_hosts': 1,
                            'current_host': None,
                            'estimated_completion_time': datetime.now().isoformat(),
                            'percentage': 100
                        }
                    })

                    self.logger.info(f"Scan completed successfully: {scan_id}")

                    # Save active scans after completion
                    self.save_active_scans()

                except Exception as e:
                    error_msg = str(e)
                    self.logger.error(f"Scan failed for {target}: {error_msg}")

                    # Log full traceback
                    import traceback
                    self.logger.error(traceback.format_exc())

                    self.active_scans[scan_id].update({
                        'status': 'failed',
                        'end_time': datetime.now().isoformat(),
                        'error': error_msg,
                        'results': [],  # Ensure results is always a list
                        'progress': {
                            'total_hosts': 1,
                            'scanned_hosts': 0,
                            'current_host': None,
                            'estimated_completion_time': None,
                            'percentage': 0
                        }
                    })
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
        if not hasattr(self, 'active_scans') or not isinstance(self.active_scans, dict):
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

            # Parse results and convert to list of dictionaries
            raw_results = self._parse_scan_results('target')
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
