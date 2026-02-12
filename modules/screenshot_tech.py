#!/usr/bin/env python3
"""
Screenshot Capture and Technology Detection Module
Supports: Gowitness, EyeWitness, Wappalyzer, Whatweb, Webanalyze
"""

import os
import json
import subprocess
from typing import List, Dict
from modules.utils import CommandExecutor, FileManager, ProgressTracker


class ScreenshotCapture:
    """Capture screenshots of web applications"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        self.tracker = ProgressTracker(logger)
        
        # Create screenshot directory
        self.screenshot_dir = os.path.join(output_dir, "screenshots")
        self.file_manager.create_directory(self.screenshot_dir)
    
    def capture_with_gowitness(self, urls_file: str) -> str:
        """Capture screenshots using Gowitness"""
        self.tracker.start_phase("Screenshot Capture (Gowitness)")
        
        gowitness_dir = os.path.join(self.screenshot_dir, "gowitness_report")
        
        try:
            gowitness_config = self.config.get('screenshots', {}).get('gowitness', {})
            timeout = gowitness_config.get('timeout', 10)
            threads = gowitness_config.get('threads', 10)
            resolution = gowitness_config.get('resolution', '1440x900')
            fullpage = '--fullpage' if gowitness_config.get('fullpage', False) else ''
            
            cmd = f"gowitness file -f {urls_file} --timeout {timeout} --threads {threads} --resolution {resolution} {fullpage} --db-path {gowitness_dir}/gowitness.db --screenshot-path {gowitness_dir}/screenshots"
            
            self.logger.info(f"Capturing screenshots with Gowitness...")
            self.executor.run(cmd, timeout=3600)
            
            # Generate report
            report_cmd = f"gowitness report generate --db-path {gowitness_dir}/gowitness.db"
            self.executor.run(report_cmd, timeout=300)
            
            # Count screenshots
            screenshot_count = len([f for f in os.listdir(f"{gowitness_dir}/screenshots") 
                                   if f.endswith('.png')]) if os.path.exists(f"{gowitness_dir}/screenshots") else 0
            
            url_count = self.file_manager.count_lines(urls_file)
            
            self.tracker.end_phase("Screenshot Capture (Gowitness)", {
                'URLs processed': url_count,
                'Screenshots captured': screenshot_count,
                'Success rate': f"{(screenshot_count/url_count*100):.2f}%" if url_count > 0 else "0%",
                'Report directory': gowitness_dir
            })
            
            return gowitness_dir
        
        except Exception as e:
            self.logger.error(f"Gowitness failed: {e}")
            return ""
    
    def capture_with_eyewitness(self, urls_file: str) -> str:
        """Capture screenshots using EyeWitness"""
        self.logger.info("Running EyeWitness...")
        
        eyewitness_dir = os.path.join(self.screenshot_dir, "eyewitness_report")
        
        try:
            eyewitness_config = self.config.get('screenshots', {}).get('eyewitness', {})
            timeout = eyewitness_config.get('timeout', 30)
            threads = eyewitness_config.get('threads', 10)
            
            cmd = f"eyewitness -f {urls_file} --timeout {timeout} --threads {threads} -d {eyewitness_dir}"
            
            self.executor.run(cmd, timeout=3600)
            
            self.logger.info(f"EyeWitness report saved to {eyewitness_dir}")
            return eyewitness_dir
        
        except Exception as e:
            self.logger.error(f"EyeWitness failed: {e}")
            return ""


class TechnologyDetector:
    """Detect web technologies"""
    
    def __init__(self, config: dict, logger, output_dir: str):
        self.config = config
        self.logger = logger
        self.output_dir = output_dir
        self.executor = CommandExecutor(logger)
        self.file_manager = FileManager(logger)
        self.tracker = ProgressTracker(logger)
        
        # Create tech detection directory
        self.tech_dir = os.path.join(output_dir, "technology_detection")
        self.file_manager.create_directory(self.tech_dir)
    
    def detect_with_whatweb(self, urls_file: str) -> str:
        """Detect technologies using Whatweb"""
        self.tracker.start_phase("Technology Detection (Whatweb)")
        
        output_file = os.path.join(self.tech_dir, "whatweb_results.json")
        
        try:
            whatweb_config = self.config.get('tech_detection', {}).get('whatweb', {})
            aggression = whatweb_config.get('aggression', 3)
            
            cmd = f"whatweb -i {urls_file} --aggression {aggression} --log-json={output_file}"
            
            self.logger.info(f"Detecting technologies with Whatweb (aggression level {aggression})...")
            self.executor.run(cmd, timeout=1800)
            
            # Parse results
            tech_summary = self._parse_whatweb_results(output_file)
            
            url_count = self.file_manager.count_lines(urls_file)
            
            self.tracker.end_phase("Technology Detection (Whatweb)", {
                'URLs analyzed': url_count,
                'Unique technologies': len(tech_summary),
                'Results file': output_file
            })
            
            return output_file
        
        except Exception as e:
            self.logger.error(f"Whatweb failed: {e}")
            return ""
    
    def detect_with_webanalyze(self, urls_file: str) -> str:
        """Detect technologies using Webanalyze"""
        self.logger.info("Running Webanalyze...")
        
        output_file = os.path.join(self.tech_dir, "webanalyze_results.json")
        
        try:
            cmd = f"webanalyze -hosts {urls_file} -output json -crawl 1 > {output_file}"
            
            self.executor.run(cmd, timeout=1800)
            
            self.logger.info(f"Webanalyze results saved to {output_file}")
            return output_file
        
        except Exception as e:
            self.logger.error(f"Webanalyze failed: {e}")
            return ""
    
    def detect_with_wappalyzer(self, urls_file: str) -> str:
        """Detect technologies using Wappalyzer CLI"""
        self.logger.info("Running Wappalyzer...")
        
        output_file = os.path.join(self.tech_dir, "wappalyzer_results.json")
        
        try:
            # Read URLs
            urls = self.file_manager.read_file_lines(urls_file)
            
            # Wappalyzer processes one URL at a time
            results = []
            for url in urls[:50]:  # Limit to avoid rate limiting
                try:
                    result = subprocess.run(
                        f"wappalyzer {url}",
                        capture_output=True,
                        text=True,
                        shell=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0 and result.stdout:
                        try:
                            data = json.loads(result.stdout)
                            results.append({'url': url, 'technologies': data})
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    continue
            
            # Save results
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.logger.info(f"Wappalyzer analyzed {len(results)} URLs")
            return output_file
        
        except Exception as e:
            self.logger.error(f"Wappalyzer failed: {e}")
            return ""
    
    def _parse_whatweb_results(self, json_file: str) -> Dict:
        """Parse Whatweb JSON results"""
        tech_summary = {}
        
        try:
            if not os.path.exists(json_file):
                return tech_summary
            
            with open(json_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        
                        # Extract plugins (technologies)
                        plugins = data.get('plugins', {})
                        for tech_name in plugins.keys():
                            if tech_name not in tech_summary:
                                tech_summary[tech_name] = 0
                            tech_summary[tech_name] += 1
                    
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            self.logger.error(f"Error parsing Whatweb results: {e}")
        
        return tech_summary
    
    def generate_tech_summary(self) -> str:
        """Generate a summary of all detected technologies"""
        summary_file = os.path.join(self.tech_dir, "technology_summary.txt")
        
        try:
            all_tech = {}
            
            # Parse Whatweb results
            whatweb_file = os.path.join(self.tech_dir, "whatweb_results.json")
            if os.path.exists(whatweb_file):
                whatweb_tech = self._parse_whatweb_results(whatweb_file)
                for tech, count in whatweb_tech.items():
                    if tech not in all_tech:
                        all_tech[tech] = {'whatweb': 0, 'webanalyze': 0, 'total': 0}
                    all_tech[tech]['whatweb'] = count
                    all_tech[tech]['total'] += count
            
            # Write summary
            with open(summary_file, 'w') as f:
                f.write("="*60 + "\n")
                f.write("TECHNOLOGY DETECTION SUMMARY\n")
                f.write("="*60 + "\n\n")
                
                # Sort by frequency
                sorted_tech = sorted(all_tech.items(), key=lambda x: x[1]['total'], reverse=True)
                
                f.write(f"Total Technologies Detected: {len(sorted_tech)}\n\n")
                
                f.write("-"*60 + "\n")
                f.write("Top Technologies:\n")
                f.write("-"*60 + "\n\n")
                
                for tech, counts in sorted_tech[:20]:
                    f.write(f"{tech}: {counts['total']} occurrences\n")
                    if counts['whatweb'] > 0:
                        f.write(f"  - Whatweb: {counts['whatweb']}\n")
                    if counts['webanalyze'] > 0:
                        f.write(f"  - Webanalyze: {counts['webanalyze']}\n")
                    f.write("\n")
            
            self.logger.info(f"Technology summary saved to {summary_file}")
            return summary_file
        
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            return ""


if __name__ == "__main__":
    # Test module
    from modules.utils import ReconLogger, ConfigLoader
    
    logger = ReconLogger("screenshot_tech", "logs").get_logger()
    config = ConfigLoader("config/config.yaml")
    
    # Test screenshot capture
    screenshotter = ScreenshotCapture(config.config, logger, "output")
    gowitness_dir = screenshotter.capture_with_gowitness("output/live_urls.txt")
    
    # Test technology detection
    detector = TechnologyDetector(config.config, logger, "output")
    whatweb_results = detector.detect_with_whatweb("output/live_urls.txt")
    
    print(f"Results: {gowitness_dir}, {whatweb_results}")