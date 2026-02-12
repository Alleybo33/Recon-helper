#!/usr/bin/env python3
"""
Port Scanning Module
Supports: Nmap (quick & full scans), Masscan
"""

import os
import json
import xml.etree.ElementTree as ET
from typing import List, Dict
from modules.utils import CommandExecutor, FileManager, ProgressTracker


class PortScanner:
    """Port scanning with Nmap and Masscan"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        self.tracker = ProgressTracker(logger)
        
        # Create scan directory
        self.scan_dir = os.path.join(output_dir, "port_scans")
        self.file_manager.create_directory(self.scan_dir)
    
    def run_quick_scan(self, input_file: str) -> str:
        """Run quick Nmap scan on top ports"""
        self.tracker.start_phase("Quick Port Scan (Nmap)")
        
        output_base = os.path.join(self.scan_dir, "nmap_quick")
        
        try:
            nmap_config = self.config.get('port_scanning', {}).get('nmap', {}).get('quick_scan', {})
            top_ports = nmap_config.get('top_ports', 1000)
            timing = nmap_config.get('timing', 'T4')
            
            cmd = f"nmap -sS -{timing} --top-ports {top_ports} -iL {input_file} -oA {output_base}"
            
            self.logger.info(f"Running quick scan on top {top_ports} ports...")
            self.executor.run(cmd, timeout=3600)
            
            # Parse results
            stats = self._parse_nmap_xml(f"{output_base}.xml")
            
            self.tracker.end_phase("Quick Port Scan (Nmap)", {
                'Hosts scanned': stats.get('hosts_up', 0),
                'Open ports found': stats.get('open_ports', 0),
                'Output files': f"{output_base}.*"
            })
            
            return output_base
        
        except Exception as e:
            self.logger.error(f"Quick scan failed: {e}")
            return ""
    
    def run_full_scan(self, input_file: str, ports: str = None) -> str:
        """Run full Nmap scan on specific ports"""
        self.tracker.start_phase("Full Port Scan (Nmap)")
        
        output_base = os.path.join(self.scan_dir, "nmap_full_web")
        
        try:
            full_config = self.config.get('port_scanning', {}).get('nmap', {}).get('full_scan', {})
            
            if not ports:
                ports = full_config.get('ports', '8000,8080,8443,8888,9000,3000,8081')
            
            scripts = full_config.get('scripts', 'default')
            version = '-sV' if full_config.get('version_detection', True) else ''
            os_detect = '-O' if full_config.get('os_detection', False) else ''
            
            cmd = f"nmap -sC {version} {os_detect} -p {ports} -iL {input_file} -oA {output_base}"
            
            self.logger.info(f"Running full scan on ports: {ports}...")
            self.executor.run(cmd, timeout=7200)
            
            # Parse results
            stats = self._parse_nmap_xml(f"{output_base}.xml")
            
            self.tracker.end_phase("Full Port Scan (Nmap)", {
                'Hosts scanned': stats.get('hosts_up', 0),
                'Services identified': stats.get('services', 0),
                'Ports scanned': ports,
                'Output files': f"{output_base}.*"
            })
            
            return output_base
        
        except Exception as e:
            self.logger.error(f"Full scan failed: {e}")
            return ""
    
    def run_masscan(self, input_file: str) -> str:
        """Run Masscan for fast port discovery"""
        self.logger.info("Running Masscan (fast scan)...")
        
        output_file = os.path.join(self.scan_dir, "masscan_results.txt")
        
        try:
            masscan_config = self.config.get('port_scanning', {}).get('masscan', {})
            rate = masscan_config.get('rate', 1000)
            ports = masscan_config.get('ports', '1-65535')
            
            # Read targets
            targets = ' '.join(self.file_manager.read_file_lines(input_file))
            
            cmd = f"masscan {targets} -p{ports} --rate={rate} -oL {output_file}"
            
            self.executor.run(cmd, timeout=3600)
            
            count = self.file_manager.count_lines(output_file)
            self.logger.info(f"Masscan found {count} open ports")
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Masscan failed: {e}")
            return ""
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict:
        """Parse Nmap XML output"""
        stats = {
            'hosts_up': 0,
            'hosts_down': 0,
            'open_ports': 0,
            'services': 0,
            'hosts': []
        }
        
        try:
            if not os.path.exists(xml_file):
                return stats
            
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('.//host'):
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    stats['hosts_up'] += 1
                    
                    host_info = {
                        'ip': '',
                        'hostname': '',
                        'ports': []
                    }
                    
                    # Get IP
                    addr = host.find('.//address[@addrtype="ipv4"]')
                    if addr is not None:
                        host_info['ip'] = addr.get('addr', '')
                    
                    # Get hostname
                    hostname = host.find('.//hostname')
                    if hostname is not None:
                        host_info['hostname'] = hostname.get('name', '')
                    
                    # Get ports
                    for port in host.findall('.//port'):
                        state = port.find('state')
                        if state is not None and state.get('state') == 'open':
                            stats['open_ports'] += 1
                            
                            port_info = {
                                'port': port.get('portid'),
                                'protocol': port.get('protocol'),
                                'service': '',
                                'version': ''
                            }
                            
                            service = port.find('service')
                            if service is not None:
                                stats['services'] += 1
                                port_info['service'] = service.get('name', '')
                                port_info['version'] = service.get('version', '')
                            
                            host_info['ports'].append(port_info)
                    
                    if host_info['ports']:
                        stats['hosts'].append(host_info)
                else:
                    stats['hosts_down'] += 1
        
        except Exception as e:
            self.logger.error(f"Error parsing Nmap XML: {e}")
        
        return stats
    
    def extract_web_services(self, nmap_output: str) -> str:
        """Extract hosts with web services"""
        self.logger.info("Extracting web services...")
        
        web_services_file = os.path.join(self.output_dir, "web_services.txt")
        web_ports = "80|443|8000|8080|8443|8888|3000|8081|8082|9000|9090|9443|10000"
        
        try:
            # Parse XML for web services
            xml_file = f"{nmap_output}.xml"
            if not os.path.exists(xml_file):
                return ""
            
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            web_hosts = []
            
            for host in root.findall('.//host'):
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    addr = host.find('.//address[@addrtype="ipv4"]')
                    ip = addr.get('addr', '') if addr is not None else ''
                    
                    hostname_elem = host.find('.//hostname')
                    hostname = hostname_elem.get('name', '') if hostname_elem is not None else ip
                    
                    for port in host.findall('.//port'):
                        port_num = port.get('portid')
                        state = port.find('state')
                        
                        if state is not None and state.get('state') == 'open':
                            service = port.find('service')
                            service_name = service.get('name', '') if service is not None else ''
                            
                            # Check if it's a web service
                            if port_num in web_ports.split('|') or 'http' in service_name.lower():
                                protocol = 'https' if 'ssl' in service_name.lower() or port_num in ['443', '8443', '9443'] else 'http'
                                url = f"{protocol}://{hostname}:{port_num}"
                                web_hosts.append(url)
            
            # Write to file
            self.file_manager.write_file_lines(web_services_file, sorted(set(web_hosts)))
            
            self.logger.info(f"Extracted {len(web_hosts)} web services to {web_services_file}")
            
            return web_services_file
        
        except Exception as e:
            self.logger.error(f"Web service extraction failed: {e}")
            return ""
    
    def generate_port_summary(self, nmap_output: str) -> str:
        """Generate a summary report of port scan results"""
        summary_file = os.path.join(self.scan_dir, "port_summary.txt")
        
        try:
            stats = self._parse_nmap_xml(f"{nmap_output}.xml")
            
            with open(summary_file, 'w') as f:
                f.write("="*60 + "\n")
                f.write("PORT SCAN SUMMARY\n")
                f.write("="*60 + "\n\n")
                
                f.write(f"Hosts Up: {stats['hosts_up']}\n")
                f.write(f"Hosts Down: {stats['hosts_down']}\n")
                f.write(f"Total Open Ports: {stats['open_ports']}\n")
                f.write(f"Services Identified: {stats['services']}\n\n")
                
                f.write("-"*60 + "\n")
                f.write("HOST DETAILS\n")
                f.write("-"*60 + "\n\n")
                
                for host in stats['hosts']:
                    f.write(f"\nHost: {host['hostname'] or host['ip']}\n")
                    f.write(f"IP: {host['ip']}\n")
                    f.write(f"Open Ports: {len(host['ports'])}\n")
                    
                    for port in host['ports']:
                        f.write(f"  {port['port']}/{port['protocol']} - {port['service']} {port['version']}\n")
            
            self.logger.info(f"Port summary saved to {summary_file}")
            return summary_file
        
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            return ""


if __name__ == "__main__":
    # Test module
    from modules.utils import ReconLogger, ConfigLoader
    
    logger = ReconLogger("port_scanner", "logs").get_logger()
    config = ConfigLoader("config/config.yaml")
    
    scanner = PortScanner(config.config, logger, "output")
    
    # Test quick scan
    quick_results = scanner.run_quick_scan("output/resolvable_domains.txt")
    
    # Test full scan
    full_results = scanner.run_full_scan("output/resolvable_domains.txt")
    
    print(f"Scan results: {quick_results}, {full_results}")