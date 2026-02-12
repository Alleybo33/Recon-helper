#!/usr/bin/env python3
"""
Subdomain Enumeration Module
Supports: Amass, Subfinder, Assetfinder, crt.sh, GitHub Subdomains
"""

import os
import json
import requests
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.utils import CommandExecutor, FileManager, ProgressTracker


class SubdomainEnumerator:
    """Enumerate subdomains using multiple tools"""
    
    def __init__(self, target: str, config: dict, logger, output_dir: str):
        self.target = target
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        self.tracker = ProgressTracker(logger)
        
        # Create output directory
        self.enum_dir = os.path.join(output_dir, "subdomain_enum")
        self.file_manager.create_directory(self.enum_dir)
        
        self.results = {
            'amass': set(),
            'subfinder': set(),
            'assetfinder': set(),
            'crtsh': set(),
            'github': set()
        }
    
    def run_all(self) -> str:
        """Run all enabled enumeration tools"""
        self.tracker.start_phase("Subdomain Enumeration")
        
        enum_config = self.config.get('subdomain_enum', {})
        
        # Run tools in parallel
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            if enum_config.get('enable_amass', True):
                futures.append(executor.submit(self.run_amass))
            
            if enum_config.get('enable_subfinder', True):
                futures.append(executor.submit(self.run_subfinder))
            
            if enum_config.get('enable_assetfinder', True):
                futures.append(executor.submit(self.run_assetfinder))
            
            if enum_config.get('enable_crtsh', True):
                futures.append(executor.submit(self.run_crtsh))
            
            if enum_config.get('enable_github_subdomains', True):
                futures.append(executor.submit(self.run_github_subdomains))
            
            # Wait for all to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Tool execution failed: {e}")
        
        # Merge all results
        merged_file = self.merge_results()
        
        # Track results
        total = sum(len(subs) for subs in self.results.values())
        unique = len(self.get_all_subdomains())
        
        self.tracker.end_phase("Subdomain Enumeration", {
            'Total subdomains found': total,
            'Unique subdomains': unique,
            'Output file': merged_file
        })
        
        return merged_file
    
    def run_amass(self) -> Set[str]:
        """Run Amass passive enumeration"""
        self.logger.info("Running Amass...")
        output_file = os.path.join(self.enum_dir, "amass.txt")
        
        try:
            amass_config = self.config.get('subdomain_enum', {}).get('amass', {})
            passive = "-passive" if amass_config.get('passive', True) else ""
            timeout = amass_config.get('timeout', 30)
            
            cmd = f"timeout {timeout}m amass enum {passive} -d {self.target} -o {output_file}"
            
            self.executor.run(cmd, timeout=timeout*60+60)
            
            if self.file_manager.file_exists(output_file):
                subs = set(self.file_manager.read_file_lines(output_file))
                self.results['amass'] = subs
                self.logger.info(f"Amass found {len(subs)} subdomains")
                return subs
            
        except Exception as e:
            self.logger.error(f"Amass failed: {e}")
        
        return set()
    
    def run_subfinder(self) -> Set[str]:
        """Run Subfinder"""
        self.logger.info("Running Subfinder...")
        output_file = os.path.join(self.enum_dir, "subfinder.txt")
        
        try:
            subfinder_config = self.config.get('subdomain_enum', {}).get('subfinder', {})
            threads = subfinder_config.get('threads', 10)
            timeout = subfinder_config.get('timeout', 10)
            
            cmd = f"subfinder -d {self.target} -silent -t {threads} -timeout {timeout} -o {output_file}"
            
            self.executor.run(cmd, timeout=timeout*60+60)
            
            if self.file_manager.file_exists(output_file):
                subs = set(self.file_manager.read_file_lines(output_file))
                self.results['subfinder'] = subs
                self.logger.info(f"Subfinder found {len(subs)} subdomains")
                return subs
            
        except Exception as e:
            self.logger.error(f"Subfinder failed: {e}")
        
        return set()
    
    def run_assetfinder(self) -> Set[str]:
        """Run Assetfinder"""
        self.logger.info("Running Assetfinder...")
        output_file = os.path.join(self.enum_dir, "assetfinder.txt")
        
        try:
            timeout = self.config.get('subdomain_enum', {}).get('assetfinder', {}).get('timeout', 10)
            
            cmd = f"assetfinder --subs-only {self.target} > {output_file}"
            
            self.executor.run(cmd, timeout=timeout*60)
            
            if self.file_manager.file_exists(output_file):
                subs = set(self.file_manager.read_file_lines(output_file))
                self.results['assetfinder'] = subs
                self.logger.info(f"Assetfinder found {len(subs)} subdomains")
                return subs
            
        except Exception as e:
            self.logger.error(f"Assetfinder failed: {e}")
        
        return set()
    
    def run_crtsh(self) -> Set[str]:
        """Query crt.sh Certificate Transparency logs"""
        self.logger.info("Querying crt.sh...")
        output_file = os.path.join(self.enum_dir, "crtsh.txt")
        
        try:
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle wildcard and multiple domains
                    for domain in name.split('\n'):
                        domain = domain.strip().replace('*.', '')
                        if domain and domain.endswith(self.target):
                            subdomains.add(domain)
                
                # Write to file
                self.file_manager.write_file_lines(output_file, sorted(subdomains))
                
                self.results['crtsh'] = subdomains
                self.logger.info(f"crt.sh found {len(subdomains)} subdomains")
                return subdomains
            else:
                self.logger.warning(f"crt.sh returned status code: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"crt.sh query failed: {e}")
        
        return set()
    
    def run_github_subdomains(self) -> Set[str]:
        """Run github-subdomains tool"""
        self.logger.info("Running GitHub Subdomains...")
        output_file = os.path.join(self.enum_dir, "github_subdomains.txt")
        
        try:
            github_token = self.config.get('api_keys', {}).get('github')
            
            if github_token:
                cmd = f"github-subdomains -d {self.target} -t {github_token} -o {output_file}"
            else:
                cmd = f"github-subdomains -d {self.target} -o {output_file}"
            
            self.executor.run(cmd, timeout=300)
            
            if self.file_manager.file_exists(output_file):
                subs = set(self.file_manager.read_file_lines(output_file))
                self.results['github'] = subs
                self.logger.info(f"GitHub Subdomains found {len(subs)} subdomains")
                return subs
            
        except Exception as e:
            self.logger.error(f"GitHub Subdomains failed: {e}")
        
        return set()
    
    def get_all_subdomains(self) -> Set[str]:
        """Get all unique subdomains from all tools"""
        all_subs = set()
        for subs in self.results.values():
            all_subs.update(subs)
        return all_subs
    
    def merge_results(self) -> str:
        """Merge all subdomain results into one file"""
        all_subdomains = self.get_all_subdomains()
        merged_file = os.path.join(self.output_dir, "all_subdomains.txt")
        
        # Sort and write
        sorted_subs = sorted(all_subdomains)
        self.file_manager.write_file_lines(merged_file, sorted_subs)
        
        self.logger.info(f"Merged {len(all_subdomains)} unique subdomains to {merged_file}")
        
        return merged_file
    
    def get_statistics(self) -> Dict:
        """Get statistics about subdomain enumeration"""
        return {
            'amass': len(self.results['amass']),
            'subfinder': len(self.results['subfinder']),
            'assetfinder': len(self.results['assetfinder']),
            'crtsh': len(self.results['crtsh']),
            'github': len(self.results['github']),
            'total_unique': len(self.get_all_subdomains())
        }


if __name__ == "__main__":
    # Test module
    from modules.utils import ReconLogger, ConfigLoader
    
    logger = ReconLogger("subdomain_enum", "logs").get_logger()
    config = ConfigLoader("config/config.yaml")
    
    enumerator = SubdomainEnumerator(
        target="example.com",
        config=config.config,
        logger=logger,
        output_dir="output"
    )
    
    merged_file = enumerator.run_all()
    print(f"Results saved to: {merged_file}")
    print(f"Statistics: {enumerator.get_statistics()}")