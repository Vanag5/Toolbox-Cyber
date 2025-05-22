import nmap
from scapy.all import ARP, Ether, srp
from typing import List, Dict
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


class NetworkDiscovery:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def discover_hosts(self, target_network: str) -> List[Dict[str, str]]:
        """
        Discover live hosts in the network using ARP scanning
        Args:
            target_network: Network range in CIDR notation (e.g., '192.168.1.0/24')
        Returns:
            List of dictionaries containing IP and MAC addresses of discovered hosts
        """
        try:
            # Create ARP request packet
            arp = ARP(pdst=target_network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send packet and get response
            result = srp(packet, timeout=3, verbose=False)[0]

            # Process responses
            hosts = []
            for sent, received in result:
                hosts.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
            return hosts
        except Exception as e:
            logging.error(f"Error in host discovery: {str(e)}")
            return []

    def scan_ports(self, target_ip: str, ports: str = "21-23,25,53,80,443,445,3389") -> Dict[str, Dict]:
        """
        Perform port scanning on a target IP
        Args:
            target_ip: IP address to scan
            ports: Ports to scan (default: common ports)
        Returns:
            Dictionary containing scan results
        """
        try:
            self.nm.scan(target_ip, ports, arguments='-sS -sV -n -Pn')
            return self.nm[target_ip] if target_ip in self.nm.all_hosts() else {}
        except Exception as e:
            logging.error(f"Error in port scanning: {str(e)}")
            return {}

    def get_os_info(self, target_ip: str) -> str:
        """
        Attempt to determine the operating system of the target
        Args:
            target_ip: Target IP address
        Returns:
            String containing OS information or unknown
        """
        try:
            self.nm.scan(target_ip, arguments='-O')
            if 'osmatch' in self.nm[target_ip]:
                matches = self.nm[target_ip]['osmatch']
                if matches and len(matches) > 0:
                    return matches[0]['name']
        except Exception as e:
            logging.error(f"Error in OS detection: {str(e)}")
        return "Unknown"

    def scan_network(self, target_network: str) -> Dict[str, Dict]:
        """
        Perform a comprehensive network scan
        Args:
            target_network: Network range in CIDR notation
        Returns:
            Dictionary containing complete scan results
        """
        results = {}
        try:
            # First discover hosts
            hosts = self.discover_hosts(target_network)

            # Then scan each host
            for host in hosts:
                ip = host['ip']
                results[ip] = {
                    'mac': host['mac'],
                    'ports': self.scan_ports(ip),
                    'os': self.get_os_info(ip)
                }

            return results
        except Exception as e:
            logging.error(f"Error in network scanning: {str(e)}")
            return results
