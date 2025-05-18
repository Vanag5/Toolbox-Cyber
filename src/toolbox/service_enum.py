import socket
import ssl
from typing import Dict, List, Optional
import requests
from dataclasses import dataclass
import logging
from concurrent.futures import ThreadPoolExecutor
import re
from urllib.parse import urlparse

@dataclass
class ServiceInfo:
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    details: Optional[Dict] = None

class ServiceEnumerator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._common_web_paths = [
            "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/admin", "/login", "/wp-admin", "/phpmyadmin"
        ]

    def enumerate_service(self, host: str, port: int, service_name: str) -> ServiceInfo:
        """
        Enumerate specific service based on port and known service name
        """
        try:
            if service_name in ["http", "https"]:
                return self._enumerate_web_service(host, port, service_name == "https")
            elif service_name == "ssh":
                return self._enumerate_ssh(host, port)
            elif service_name == "ftp":
                return self._enumerate_ftp(host, port)
            elif service_name == "smtp":
                return self._enumerate_smtp(host, port)
            else:
                return self._enumerate_generic_service(host, port)
        except Exception as e:
            self.logger.error(f"Service enumeration failed for {host}:{port} ({service_name}): {str(e)}")
            return ServiceInfo(name=service_name)

    def _enumerate_web_service(self, host: str, port: int, is_https: bool) -> ServiceInfo:
        """
        Enumerate web service details including server software, headers, and basic structure
        """
        protocol = "https" if is_https else "http"
        base_url = f"{protocol}://{host}:{port}"
        details = {
            "headers": {},
            "endpoints": {},
            "technologies": []
        }

        try:
            # Test common paths
            for path in self._common_web_paths:
                url = f"{base_url}{path}"
                try:
                    response = requests.get(url, timeout=5, verify=False)
                    details["endpoints"][path] = {
                        "status": response.status_code,
                        "size": len(response.content)
                    }
                    
                    # Capture headers from root path only
                    if path == "/":
                        details["headers"] = dict(response.headers)
                        server = response.headers.get("Server", "")
                        powered_by = response.headers.get("X-Powered-By", "")
                        
                        # Detect technologies
                        if "nginx" in server.lower():
                            details["technologies"].append("Nginx")
                        if "apache" in server.lower():
                            details["technologies"].append("Apache")
                        if "php" in powered_by.lower():
                            details["technologies"].append(f"PHP ({powered_by})")
                        
                except requests.RequestException:
                    continue

            return ServiceInfo(
                name="http" if not is_https else "https",
                version=details["headers"].get("Server", "Unknown"),
                banner=str(details["headers"]),
                details=details
            )
        except Exception as e:
            self.logger.error(f"Web service enumeration failed for {base_url}: {str(e)}")
            return ServiceInfo(name="http" if not is_https else "https")

    def _enumerate_ssh(self, host: str, port: int) -> ServiceInfo:
        """
        Enumerate SSH service details
        """
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                version = re.search(r'SSH-\d+\.\d+-([^\s]+)', banner)
                return ServiceInfo(
                    name="ssh",
                    version=version.group(1) if version else None,
                    banner=banner
                )
        except Exception as e:
            self.logger.error(f"SSH enumeration failed for {host}:{port}: {str(e)}")
            return ServiceInfo(name="ssh")

    def _enumerate_ftp(self, host: str, port: int) -> ServiceInfo:
        """
        Enumerate FTP service details
        """
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                version = re.search(r'FTP|FileZilla|vsftpd|ProFTPD', banner)
                return ServiceInfo(
                    name="ftp",
                    version=version.group(0) if version else None,
                    banner=banner
                )
        except Exception as e:
            self.logger.error(f"FTP enumeration failed for {host}:{port}: {str(e)}")
            return ServiceInfo(name="ftp")

    def _enumerate_smtp(self, host: str, port: int) -> ServiceInfo:
        """
        Enumerate SMTP service details
        """
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                # Try EHLO command
                sock.send(b'EHLO example.com\r\n')
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                version = re.search(r'ESMTP|Postfix|Exim|Sendmail', response)
                return ServiceInfo(
                    name="smtp",
                    version=version.group(0) if version else None,
                    banner=banner,
                    details={"extended_info": response}
                )
        except Exception as e:
            self.logger.error(f"SMTP enumeration failed for {host}:{port}: {str(e)}")
            return ServiceInfo(name="smtp")

    def _enumerate_generic_service(self, host: str, port: int) -> ServiceInfo:
        """
        Attempt to enumerate unknown service details
        """
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                # Send a generic probe
                sock.send(b'\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return ServiceInfo(
                    name="unknown",
                    banner=banner
                )
        except Exception as e:
            self.logger.error(f"Generic service enumeration failed for {host}:{port}: {str(e)}")
            return ServiceInfo(name="unknown")
