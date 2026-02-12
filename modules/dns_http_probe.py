#!/usr/bin/env python3
"""
DNS Resolution and HTTP Probing Module
Supports: dnsx, massdns, httpx
"""

import os
import json
from typing import List, Dict, Set
from modules.utils import CommandExecutor, FileManager, ProgressTracker


class DNSResolver:
    """Resolve subdomains to IP addresses"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        self.tracker = ProgressTracker(logger)
    
    def resolve_with_dnsx(self, input_file: str) -> str:
        """Resolve domains using dnsx"""
        self.tracker.start_phase("DNS Resolution (dnsx)")
        
        output_file = os.path.join(self.output_dir, "resolvable_domains.txt")
        json_output = os.path.join(self.output_dir, "dnsx_results.json")
        
        try:
            dnsx_config = self.config.get('dns_resolution', {}).get('dnsx', {})
            threads = dnsx_config.get('threads', 50)
            retry = dnsx_config.get('retry', 2)
            timeout = dnsx_config.get('timeout', 10)
            
            # Run dnsx with A records and JSON output
            cmd = f"dnsx -l {input_file} -a -resp -json -t {threads} -retry {retry} -timeout {timeout} -o {json_output}"
            
            self.executor.run(cmd, timeout=600)
            
            # Extract just the domains that resolved
            if self.file_manager.file_exists(json_output):
                resolved = set()
                with open(json_output, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            if 'host' in data and 'a' in data:
                                resolved.add(data['host'])
                        except json.JSONDecodeError:
                            continue
                
                # Write resolved domains
                self.file_manager.write_file_lines(output_file, sorted(resolved))
                
                initial_count = self.file_manager.count_lines(input_file)
                resolved_count = len(resolved)
                
                self.tracker.end_phase("DNS Resolution (dnsx)", {
                    'Initial domains': initial_count,
                    'Resolved domains': resolved_count,
                    'Resolution rate': f"{(resolved_count/initial_count*100):.2f}%" if initial_count > 0 else "0%",
                    'Output file': output_file
                })
                
                return output_file
        
        except Exception as e:
            self.logger.error(f"dnsx failed: {e}")
        
        return input_file
    
    def resolve_with_massdns(self, input_file: str) -> str:
        """Resolve domains using massdns (alternative)"""
        self.logger.info("Running massdns...")
        output_file = os.path.join(self.output_dir, "massdns_resolved.txt")
        
        try:
            # Requires massdns and resolvers.txt
            cmd = f"massdns -r /usr/share/massdns/lists/resolvers.txt -t A -o S {input_file} | grep -oE '^[^[:space:]]+' > {output_file}"
            
            self.executor.run(cmd, timeout=600)
            
            if self.file_manager.file_exists(output_file):
                count = self.file_manager.count_lines(output_file)
                self.logger.info(f"massdns resolved {count} domains")
                return output_file
        
        except Exception as e:
            self.logger.error(f"massdns failed: {e}")
        
        return input_file


class HTTPProber:
    """Probe for live HTTP/HTTPS services"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        self.tracker = ProgressTracker(logger)
    
    def probe_with_httpx(self, input_file: str) -> Dict[str, str]:
        """Probe URLs using httpx"""
        self.tracker.start_phase("HTTP Probing (httpx)")
        
        output_file = os.path.join(self.output_dir, "live_http.txt")
        json_output = os.path.join(self.output_dir, "httpx_results.json")
        urls_file = os.path.join(self.output_dir, "live_urls.txt")
        
        try:
            httpx_config = self.config.get('http_probing', {}).get('httpx', {})
            threads = httpx_config.get('threads', 50)
            timeout = httpx_config.get('timeout', 10)
            retry = httpx_config.get('retry', 2)
            ports = httpx_config.get('ports', '80,443,8080,8443')
            
            # Build httpx command
            cmd_parts = [
                f"httpx -l {input_file}",
                f"-threads {threads}",
                f"-timeout {timeout}",
                f"-retries {retry}",
                f"-ports {ports}",
                "-status-code",
                "-title",
                "-tech-detect",
                "-web-server",
                "-content-length",
                "-json",
                "-silent",
                f"-o {json_output}"
            ]
            
            if httpx_config.get('follow_redirects', True):
                cmd_parts.append("-follow-redirects")
            
            cmd = ' '.join(cmd_parts)
            
            self.executor.run(cmd, timeout=1800)
            
            if self.file_manager.file_exists(json_output):
                # Parse JSON output
                urls = []
                results_data = []
                
                with open(json_output, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            url = data.get('url', '')
                            if url:
                                urls.append(url)
                                results_data.append(data)
                        except json.JSONDecodeError:
                            continue
                
                # Write URLs only
                self.file_manager.write_file_lines(urls_file, urls)
                
                # Create readable summary
                with open(output_file, 'w') as f:
                    for data in results_data:
                        url = data.get('url', '')
                        status = data.get('status_code', 'N/A')
                        title = data.get('title', 'N/A')
                        server = data.get('webserver', 'N/A')
                        tech = ','.join(data.get('tech', []))
                        
                        f.write(f"{url} [{status}] [{title}] [{server}] [{tech}]\n")
                
                initial_count = self.file_manager.count_lines(input_file)
                live_count = len(urls)
                
                # Count by status code
                status_counts = {}
                for data in results_data:
                    status = str(data.get('status_code', 'unknown'))
                    status_counts[status] = status_counts.get(status, 0) + 1
                
                self.tracker.end_phase("HTTP Probing (httpx)", {
                    'Initial hosts': initial_count,
                    'Live URLs found': live_count,
                    'Success rate': f"{(live_count/initial_count*100):.2f}%" if initial_count > 0 else "0%",
                    'Status codes': str(status_counts),
                    'URLs file': urls_file
                })
                
                return {
                    'urls_file': urls_file,
                    'json_file': json_output,
                    'summary_file': output_file
                }
        
        except Exception as e:
            self.logger.error(f"httpx failed: {e}")
        
        return {'urls_file': input_file}
    
    def extract_live_urls(self, httpx_output: str) -> str:
        """Extract just the URLs from httpx output"""
        urls_file = os.path.join(self.output_dir, "live_urls.txt")
        
        try:
            # If JSON output, parse it
            if httpx_output.endswith('.json'):
                urls = []
                with open(httpx_output, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            url = data.get('url', '')
                            if url:
                                urls.append(url)
                        except json.JSONDecodeError:
                            continue
                
                self.file_manager.write_file_lines(urls_file, urls)
            else:
                # Extract first column (URL)
                cmd = f"cat {httpx_output} | awk '{{print $1}}' > {urls_file}"
                self.executor.run(cmd)
            
            count = self.file_manager.count_lines(urls_file)
            self.logger.info(f"Extracted {count} live URLs to {urls_file}")
            
            return urls_file
        
        except Exception as e:
            self.logger.error(f"URL extraction failed: {e}")
            return httpx_output


class WebPortIdentifier:
    """Identify web services on non-standard ports"""
    
    def __init__(self, logger, output_dir: str):
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
    
    def extract_web_ports(self, nmap_output: str) -> str:
        """Extract hosts with web services on high-value ports"""
        self.logger.info("Identifying web services on non-standard ports...")
        
        web_ports_file = os.path.join(self.output_dir, "web_ports.txt")
        target_ports = "8080|8443|8888|3000|8000|9000|8081|8082|8090|8180|9090|9443|10000"
        
        try:
            # Extract from nmap gnmap output
            cmd = f"grep -E '{target_ports}' {nmap_output}.gnmap | awk '{{print $2}}' | sort -u > {web_ports_file}"
            
            self.executor.run(cmd, check=False)
            
            count = self.file_manager.count_lines(web_ports_file)
            self.logger.info(f"Found {count} hosts with web services on non-standard ports")
            
            return web_ports_file
        
        except Exception as e:
            self.logger.error(f"Web port extraction failed: {e}")
            return ""


if __name__ == "__main__":
    # Test module
    from modules.utils import ReconLogger, ConfigLoader
    
    logger = ReconLogger("dns_http_probe", "logs").get_logger()
    config = ConfigLoader("config/config.yaml")
    
    # Test DNS resolution
    resolver = DNSResolver(config.config, logger, "output")
    resolved = resolver.resolve_with_dnsx("output/all_subdomains.txt")
    
    # Test HTTP probing
    prober = HTTPProber(config.config, logger, "output")
    results = prober.probe_with_httpx(resolved)
    
    print(f"Results: {results}")