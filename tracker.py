#!/usr/bin/env python3
"""
Main Recon Automation Tracker
Orchestrates the complete reconnaissance workflow
"""

import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

# Add modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import (
    ReconLogger,
    ConfigLoader,
    FileManager,
    ToolChecker,
    ProgressTracker,
    banner
)
from modules.subdomain_enum import SubdomainEnumerator
from modules.dns_http_probe import DNSResolver, HTTPProber, WebPortIdentifier
from modules.port_scanner import PortScanner
from modules.screenshot_tech import ScreenshotCapture, TechnologyDetector
from modules.vuln_scanner import (
    VulnerabilityScanner,
    ContentDiscovery,
    JSAnalyzer,
    ParameterDiscovery
)
from modules.reporting import ReportGenerator


class ReconTracker:
    """Main reconnaissance automation tracker"""
    
    def __init__(self, config_path: str = "config/config.yaml", target: str = None):
        """Initialize the tracker"""
        
        # Print banner
        banner()
        
        # Load configuration
        self.config = ConfigLoader(config_path)
        
        # Override target if provided
        if target:
            self.target = target
        else:
            self.target = self.config.get_target()
        
        # Setup logging
        self.logger = ReconLogger("recon_tracker", "logs").get_logger()
        
        # Setup directories
        self.output_dir = self._setup_output_directory()
        
        # Initialize utilities
        self.file_manager = FileManager(self.logger)
        self.tracker = ProgressTracker(self.logger)
        
        # Track timing
        self.start_time = datetime.now()
        self.end_time = None
        
        # Track results
        self.results = {
            'subdomain_file': '',
            'resolved_file': '',
            'live_urls_file': '',
            'nmap_quick': '',
            'nmap_full': '',
            'web_services_file': '',
            'screenshot_dir': '',
            'tech_results': '',
            'nuclei_results': '',
            'reports': {}
        }
        
        self.logger.info(f"Initialized Recon Tracker for target: {self.target}")
        self.logger.info(f"Output directory: {self.output_dir}")
    
    def _setup_output_directory(self) -> str:
        """Setup output directory structure"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_output = self.config.get_output_dir()
        
        output_dir = os.path.join(base_output, f"{self.target}_{timestamp}")
        
        # Create directory structure
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        return output_dir
    
    def check_dependencies(self) -> bool:
        """Check if required tools are installed"""
        self.logger.info("Checking dependencies...")
        
        tool_checker = ToolChecker(self.logger)
        
        required_tools = [
            'amass',
            'subfinder',
            'assetfinder',
            'dnsx',
            'httpx',
            'nmap',
            'gowitness',
            'whatweb',
            'nuclei'
        ]
        
        missing_tools = tool_checker.get_missing_tools(required_tools)
        
        if missing_tools:
            self.logger.error(f"Missing tools: {', '.join(missing_tools)}")
            self.logger.error("Please install missing tools before running")
            return False
        
        self.logger.info("✓ All required tools are installed")
        return True
    
    def run_full_scan(self):
        """Run complete reconnaissance workflow"""
        
        self.logger.info(f"Starting full reconnaissance scan on {self.target}")
        
        try:
            # Phase 1: Subdomain Enumeration
            self.results['subdomain_file'] = self._phase_subdomain_enum()
            
            # Phase 2: DNS Resolution
            self.results['resolved_file'] = self._phase_dns_resolution()
            
            # Phase 3: HTTP Probing
            self.results['live_urls_file'] = self._phase_http_probing()
            
            # Phase 4: Port Scanning
            self._phase_port_scanning()
            
            # Phase 5: Screenshot Capture
            self.results['screenshot_dir'] = self._phase_screenshots()
            
            # Phase 6: Technology Detection
            self.results['tech_results'] = self._phase_tech_detection()
            
            # Phase 7: Vulnerability Scanning
            self.results['nuclei_results'] = self._phase_vuln_scanning()
            
            # Phase 8: Generate Reports
            self.results['reports'] = self._phase_reporting()
            
            # Record end time
            self.end_time = datetime.now()
            
            # Print summary
            self._print_summary()
            
            self.logger.info("Reconnaissance scan completed successfully!")
            
        except KeyboardInterrupt:
            self.logger.warning("\n[!] Scan interrupted by user")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            raise
    
    def _phase_subdomain_enum(self) -> str:
        """Phase 1: Subdomain Enumeration"""
        enumerator = SubdomainEnumerator(
            target=self.target,
            config=self.config.config,
            logger=self.logger,
            output_dir=self.output_dir
        )
        
        return enumerator.run_all()
    
    def _phase_dns_resolution(self) -> str:
        """Phase 2: DNS Resolution"""
        resolver = DNSResolver(
            config=self.config.config,
            logger=self.logger,
            output_dir=self.output_dir
        )
        
        input_file = self.results['subdomain_file']
        
        if self.config.get('dns_resolution.enable_dnsx', True):
            return resolver.resolve_with_dnsx(input_file)
        else:
            return input_file
    
    def _phase_http_probing(self) -> str:
        """Phase 3: HTTP Probing"""
        prober = HTTPProber(
            config=self.config.config,
            logger=self.logger,
            output_dir=self.output_dir
        )
        
        input_file = self.results['resolved_file']
        
        probe_results = prober.probe_with_httpx(input_file)
        
        return probe_results.get('urls_file', '')
    
    def _phase_port_scanning(self):
        """Phase 4: Port Scanning"""
        scanner = PortScanner(
            config=self.config.config,
            logger=self.logger,
            output_dir=self.output_dir
        )
        
        input_file = self.results['resolved_file']
        
        # Quick scan
        if self.config.get('port_scanning.nmap.quick_scan.enable', True):
            self.results['nmap_quick'] = scanner.run_quick_scan(input_file)
        
        # Full scan on web ports
        if self.config.get('port_scanning.nmap.full_scan.enable', True):
            self.results['nmap_full'] = scanner.run_full_scan(input_file)
        
        # Extract web services
        if self.results['nmap_full']:
            self.results['web_services_file'] = scanner.extract_web_services(
                self.results['nmap_full']
            )
    
    def _phase_screenshots(self) -> str:
        """Phase 5: Screenshot Capture"""
        if not self.config.get('screenshots.enable_gowitness', True):
            self.logger.info("Screenshot capture disabled")
            return ""
        
        screenshotter = ScreenshotCapture(
            config=self.config.config,
            logger=self.logger,
            output_dir=self.output_dir
        )
        
        input_file = self.results['live_urls_file']
        
        return screenshotter.capture_with_gowitness(input_file)
    
    def _phase_tech_detection(self) -> str:
        """Phase 6: Technology Detection"""
        detector = TechnologyDetector(
            config=self.config.config,
            logger=self.logger,
            output_dir=self.output_dir
        )
        
        input_file = self.results['live_urls_file']
        
        # Whatweb
        if self.config.get('tech_detection.enable_whatweb', True):
            detector.detect_with_whatweb(input_file)
        
        # Webanalyze
        if self.config.get('tech_detection.enable_webanalyze', False):
            detector.detect_with_webanalyze(input_file)
        
        # Generate summary
        return detector.generate_tech_summary()
    
    def _phase_vuln_scanning(self) -> str:
        """Phase 7: Vulnerability Scanning"""
        if not self.config.get('vulnerability_scanning.enable_nuclei', True):
            self.logger.info("Vulnerability scanning disabled")
            return ""
        
        scanner = VulnerabilityScanner(
            config=self.config.config,
            logger=self.logger,
            output_dir=self.output_dir
        )
        
        input_file = self.results['live_urls_file']
        
        return scanner.scan_with_nuclei(input_file)
    
    def _phase_reporting(self) -> dict:
        """Phase 8: Generate Reports"""
        generator = ReportGenerator(
            logger=self.logger,
            output_dir=self.output_dir
        )
        
        # Set metadata
        generator.set_metadata(
            target=self.target,
            start_time=self.start_time,
            end_time=datetime.now()
        )
        
        # Gather statistics
        stats = self._gather_statistics()
        generator.add_section_data('statistics', stats)
        
        # Generate all reports
        return generator.generate_all_reports()
    
    def _gather_statistics(self) -> dict:
        """Gather statistics from all phases"""
        stats = {
            'total_subdomains': self.file_manager.count_lines(
                self.results.get('subdomain_file', '')
            ),
            'resolvable_domains': self.file_manager.count_lines(
                self.results.get('resolved_file', '')
            ),
            'live_urls': self.file_manager.count_lines(
                self.results.get('live_urls_file', '')
            ),
            'open_ports': 0,
            'vulnerabilities': 0,
            'technologies': 0
        }
        
        # Count vulnerabilities from Nuclei results
        nuclei_file = self.results.get('nuclei_results', '')
        if nuclei_file and os.path.exists(nuclei_file):
            stats['vulnerabilities'] = self.file_manager.count_lines(nuclei_file)
        
        return stats
    
    def _print_summary(self):
        """Print scan summary"""
        duration = (self.end_time - self.start_time).total_seconds()
        
        self.logger.info("\n" + "="*70)
        self.logger.info("SCAN SUMMARY")
        self.logger.info("="*70)
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Duration: {duration:.2f} seconds ({duration/60:.2f} minutes)")
        self.logger.info(f"Output Directory: {self.output_dir}")
        self.logger.info("")
        self.logger.info("Results:")
        self.logger.info(f"  - Subdomains: {self.file_manager.count_lines(self.results['subdomain_file'])}")
        self.logger.info(f"  - Resolvable: {self.file_manager.count_lines(self.results['resolved_file'])}")
        self.logger.info(f"  - Live URLs: {self.file_manager.count_lines(self.results['live_urls_file'])}")
        
        if self.results.get('nuclei_results'):
            vuln_count = self.file_manager.count_lines(self.results['nuclei_results'])
            self.logger.info(f"  - Vulnerabilities: {vuln_count}")
        
        self.logger.info("")
        self.logger.info("Reports:")
        for report_type, report_file in self.results.get('reports', {}).items():
            self.logger.info(f"  - {report_type.upper()}: {report_file}")
        
        self.logger.info("="*70 + "\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Advanced Reconnaissance Automation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tracker.py -t example.com
  python tracker.py -t example.com -c custom_config.yaml
  python tracker.py -t example.com --check-deps
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target domain (e.g., example.com)'
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config/config.yaml',
        help='Configuration file path (default: config/config.yaml)'
    )
    
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='Check dependencies and exit'
    )
    
    parser.add_argument(
        '--skip-deps-check',
        action='store_true',
        help='Skip dependency checking'
    )
    
    args = parser.parse_args()
    
    # Initialize tracker
    tracker = ReconTracker(
        config_path=args.config,
        target=args.target
    )
    
    # Check dependencies
    if args.check_deps:
        tracker.check_dependencies()
        sys.exit(0)
    
    if not args.skip_deps_check:
        if not tracker.check_dependencies():
            sys.exit(1)
    
    # Run full scan
    tracker.run_full_scan()


if __name__ == "__main__":
    main()