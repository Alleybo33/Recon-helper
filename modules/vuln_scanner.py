#!/usr/bin/env python3
"""
Vulnerability Scanning Module
Supports: Nuclei, Content Discovery (feroxbuster, ffuf), JS Analysis
"""

import os
import json
from typing import List, Dict
from modules.utils import CommandExecutor, FileManager, ProgressTracker


class VulnerabilityScanner:
    """Scan for vulnerabilities using Nuclei"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        self.tracker = ProgressTracker(logger)
        
        # Create vulnerability directory
        self.vuln_dir = os.path.join(output_dir, "vulnerabilities")
        self.file_manager.create_directory(self.vuln_dir)
    
    def scan_with_nuclei(self, urls_file: str) -> str:
        """Scan for vulnerabilities using Nuclei"""
        self.tracker.start_phase("Vulnerability Scanning (Nuclei)")
        
        output_file = os.path.join(self.vuln_dir, "nuclei_results.json")
        markdown_output = os.path.join(self.vuln_dir, "nuclei_report.md")
        
        try:
            nuclei_config = self.config.get('vulnerability_scanning', {}).get('nuclei', {})
            templates = nuclei_config.get('templates', 'cves,vulnerabilities,exposures')
            severity = nuclei_config.get('severity', 'critical,high,medium')
            threads = nuclei_config.get('threads', 25)
            rate_limit = nuclei_config.get('rate_limit', 150)
            bulk_size = nuclei_config.get('bulk_size', 25)
            timeout = nuclei_config.get('timeout', 5)
            retries = nuclei_config.get('retries', 1)
            
            # Update templates first
            self.logger.info("Updating Nuclei templates...")
            self.executor.run("nuclei -update-templates", timeout=300, check=False)
            
            # Build Nuclei command
            cmd_parts = [
                f"nuclei -l {urls_file}",
                f"-t {templates}",
                f"-severity {severity}",
                f"-c {threads}",
                f"-rate-limit {rate_limit}",
                f"-bulk-size {bulk_size}",
                f"-timeout {timeout}",
                f"-retries {retries}",
                "-json",
                f"-o {output_file}",
                "-markdown-export", markdown_output,
                "-stats",
                "-silent"
            ]
            
            cmd = ' '.join(cmd_parts)
            
            self.logger.info("Running Nuclei vulnerability scan...")
            self.logger.info(f"Templates: {templates}")
            self.logger.info(f"Severity: {severity}")
            
            self.executor.run(cmd, timeout=7200)
            
            # Parse results
            stats = self._parse_nuclei_results(output_file)
            
            url_count = self.file_manager.count_lines(urls_file)
            
            self.tracker.end_phase("Vulnerability Scanning (Nuclei)", {
                'URLs scanned': url_count,
                'Vulnerabilities found': stats.get('total', 0),
                'Critical': stats.get('critical', 0),
                'High': stats.get('high', 0),
                'Medium': stats.get('medium', 0),
                'Low': stats.get('low', 0),
                'Results file': output_file,
                'Report': markdown_output
            })
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {e}")
            return ""
    
    def _parse_nuclei_results(self, json_file: str) -> Dict:
        """Parse Nuclei JSON results"""
        stats = {
            'total': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'vulnerabilities': []
        }
        
        try:
            if not os.path.exists(json_file):
                return stats
            
            with open(json_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        stats['total'] += 1
                        
                        severity = data.get('info', {}).get('severity', 'info').lower()
                        
                        if severity in stats:
                            stats[severity] += 1
                        
                        vuln_info = {
                            'template': data.get('template-id', ''),
                            'name': data.get('info', {}).get('name', ''),
                            'severity': severity,
                            'host': data.get('host', ''),
                            'matched_at': data.get('matched-at', '')
                        }
                        
                        stats['vulnerabilities'].append(vuln_info)
                    
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            self.logger.error(f"Error parsing Nuclei results: {e}")
        
        return stats


class ContentDiscovery:
    """Discover hidden content and endpoints"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        self.tracker = ProgressTracker(logger)
        
        # Create content discovery directory
        self.content_dir = os.path.join(output_dir, "content_discovery")
        self.file_manager.create_directory(self.content_dir)
    
    def discover_with_feroxbuster(self, urls_file: str) -> str:
        """Discover content using Feroxbuster"""
        self.logger.info("Running Feroxbuster for content discovery...")
        
        output_file = os.path.join(self.content_dir, "feroxbuster_results.txt")
        
        try:
            ferox_config = self.config.get('content_discovery', {}).get('feroxbuster', {})
            threads = ferox_config.get('threads', 50)
            wordlist = ferox_config.get('wordlist', '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt')
            extensions = ferox_config.get('extensions', 'php,html,js,txt')
            depth = ferox_config.get('depth', 3)
            timeout = ferox_config.get('timeout', 10)
            
            # Read URLs
            urls = self.file_manager.read_file_lines(urls_file)
            
            # Run feroxbuster on each URL (limit to first 10 to avoid long runtime)
            all_results = []
            
            for url in urls[:10]:
                try:
                    url_output = os.path.join(self.content_dir, f"ferox_{url.replace('://', '_').replace('/', '_')}.txt")
                    
                    cmd = f"feroxbuster -u {url} -w {wordlist} -x {extensions} -t {threads} -d {depth} --timeout {timeout} -o {url_output} -q"
                    
                    self.logger.info(f"Scanning {url}...")
                    self.executor.run(cmd, timeout=1800, check=False)
                    
                    if self.file_manager.file_exists(url_output):
                        all_results.append(url_output)
                
                except Exception as e:
                    self.logger.warning(f"Feroxbuster failed for {url}: {e}")
            
            # Merge results
            if all_results:
                self.file_manager.merge_files(all_results, output_file, remove_duplicates=True)
            
            count = self.file_manager.count_lines(output_file)
            self.logger.info(f"Found {count} endpoints with Feroxbuster")
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Feroxbuster failed: {e}")
            return ""
    
    def discover_with_ffuf(self, urls_file: str) -> str:
        """Discover content using ffuf"""
        self.logger.info("Running ffuf for content discovery...")
        
        output_file = os.path.join(self.content_dir, "ffuf_results.json")
        
        try:
            ffuf_config = self.config.get('content_discovery', {}).get('ffuf', {})
            threads = ffuf_config.get('threads', 40)
            wordlist = ffuf_config.get('wordlist', '/usr/share/seclists/Discovery/Web-Content/common.txt')
            extensions = ffuf_config.get('extensions', 'php,html,js,txt')
            
            # Read URLs
            urls = self.file_manager.read_file_lines(urls_file)
            
            # Run ffuf on first few URLs
            for url in urls[:5]:
                try:
                    url_output = os.path.join(self.content_dir, f"ffuf_{url.replace('://', '_').replace('/', '_')}.json")
                    
                    cmd = f"ffuf -u {url}/FUZZ -w {wordlist} -e {extensions} -t {threads} -mc 200,204,301,302,307,401,403 -o {url_output} -of json -s"
                    
                    self.executor.run(cmd, timeout=900, check=False)
                
                except Exception as e:
                    self.logger.warning(f"ffuf failed for {url}: {e}")
            
            self.logger.info(f"ffuf results saved to {self.content_dir}")
            return output_file
        
        except Exception as e:
            self.logger.error(f"ffuf failed: {e}")
            return ""


class JSAnalyzer:
    """Analyze JavaScript files for endpoints and secrets"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        
        # Create JS analysis directory
        self.js_dir = os.path.join(output_dir, "js_analysis")
        self.file_manager.create_directory(self.js_dir)
    
    def collect_js_files(self, urls_file: str) -> str:
        """Collect JavaScript files using getJS"""
        self.logger.info("Collecting JavaScript files...")
        
        js_files = os.path.join(self.js_dir, "js_files.txt")
        
        try:
            cmd = f"getjs --input {urls_file} --output {js_files} --complete"
            
            self.executor.run(cmd, timeout=900, check=False)
            
            count = self.file_manager.count_lines(js_files)
            self.logger.info(f"Found {count} JavaScript files")
            
            return js_files
        
        except Exception as e:
            self.logger.error(f"getJS failed: {e}")
            return ""
    
    def analyze_with_linkfinder(self, js_files: str) -> str:
        """Analyze JS files with LinkFinder"""
        self.logger.info("Analyzing JavaScript with LinkFinder...")
        
        output_file = os.path.join(self.js_dir, "linkfinder_results.txt")
        
        try:
            # Read JS URLs
            js_urls = self.file_manager.read_file_lines(js_files)
            
            all_endpoints = set()
            
            for js_url in js_urls[:50]:  # Limit to avoid long runtime
                try:
                    result = self.executor.run(
                        f"python3 /opt/LinkFinder/linkfinder.py -i {js_url} -o cli",
                        timeout=60,
                        check=False
                    )
                    
                    if result.stdout:
                        endpoints = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                        all_endpoints.update(endpoints)
                
                except Exception:
                    continue
            
            # Save results
            self.file_manager.write_file_lines(output_file, sorted(all_endpoints))
            
            self.logger.info(f"Found {len(all_endpoints)} endpoints in JavaScript files")
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"LinkFinder failed: {e}")
            return ""


class ParameterDiscovery:
    """Discover parameters and test for vulnerabilities"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        
        # Create parameter directory
        self.param_dir = os.path.join(output_dir, "parameters")
        self.file_manager.create_directory(self.param_dir)
    
    def discover_with_arjun(self, urls_file: str) -> str:
        """Discover parameters using Arjun"""
        self.logger.info("Discovering parameters with Arjun...")
        
        output_file = os.path.join(self.param_dir, "arjun_results.json")
        
        try:
            arjun_config = self.config.get('additional_tools', {}).get('arjun', {})
            threads = arjun_config.get('threads', 5)
            
            cmd = f"arjun -i {urls_file} -t {threads} -oJ {output_file}"
            
            self.executor.run(cmd, timeout=1800, check=False)
            
            self.logger.info(f"Arjun results saved to {output_file}")
            return output_file
        
        except Exception as e:
            self.logger.error(f"Arjun failed: {e}")
            return ""


if __name__ == "__main__":
    # Test module
    from modules.utils import ReconLogger, ConfigLoader
    
    logger = ReconLogger("vuln_scanner", "logs").get_logger()
    config = ConfigLoader("config/config.yaml")
    
    # Test vulnerability scanning
    scanner = VulnerabilityScanner(config.config, logger, "output")
    nuclei_results = scanner.scan_with_nuclei("output/live_urls.txt")
    
    print(f"Nuclei results: {nuclei_results}")