#!/usr/bin/env python3
"""
Reporting Module
Generate reports in multiple formats: HTML, JSON, CSV, Markdown
"""

import os
import json
import csv
from datetime import datetime
from typing import Dict, List
from modules.utils import FileManager


class ReportGenerator:
    """Generate comprehensive reconnaissance reports"""
    
    def __init__(self, logger, output_dir: str):
        self.logger = logger
        self.output_dir = output_dir
        self.file_manager = FileManager(logger)
        
        # Create reports directory
        self.reports_dir = os.path.join(output_dir, "reports")
        self.file_manager.create_directory(self.reports_dir)
        
        self.report_data = {
            'metadata': {},
            'subdomains': {},
            'dns_resolution': {},
            'http_probing': {},
            'port_scanning': {},
            'screenshots': {},
            'technology': {},
            'vulnerabilities': {},
            'statistics': {}
        }
    
    def set_metadata(self, target: str, start_time: datetime, end_time: datetime):
        """Set report metadata"""
        self.report_data['metadata'] = {
            'target': target,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': str(end_time - start_time),
            'generated_at': datetime.now().isoformat()
        }
    
    def add_section_data(self, section: str, data: Dict):
        """Add data to a report section"""
        if section in self.report_data:
            self.report_data[section] = data
    
    def generate_all_reports(self):
        """Generate all report formats"""
        self.logger.info("Generating reports...")
        
        reports = {}
        
        # Generate JSON report
        json_file = self.generate_json_report()
        if json_file:
            reports['json'] = json_file
        
        # Generate HTML report
        html_file = self.generate_html_report()
        if html_file:
            reports['html'] = html_file
        
        # Generate Markdown report
        md_file = self.generate_markdown_report()
        if md_file:
            reports['markdown'] = md_file
        
        # Generate CSV summary
        csv_file = self.generate_csv_summary()
        if csv_file:
            reports['csv'] = csv_file
        
        self.logger.info(f"Generated {len(reports)} report formats")
        
        return reports
    
    def generate_json_report(self) -> str:
        """Generate JSON report"""
        json_file = os.path.join(self.reports_dir, "recon_report.json")
        
        try:
            with open(json_file, 'w') as f:
                json.dump(self.report_data, f, indent=2)
            
            self.logger.info(f"JSON report saved to {json_file}")
            return json_file
        
        except Exception as e:
            self.logger.error(f"JSON report generation failed: {e}")
            return ""
    
    def generate_html_report(self) -> str:
        """Generate HTML report"""
        html_file = os.path.join(self.reports_dir, "recon_report.html")
        
        try:
            metadata = self.report_data.get('metadata', {})
            stats = self.report_data.get('statistics', {})
            
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report - {metadata.get('target', 'Unknown')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        h1 {{
            color: #667eea;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #764ba2;
            margin-top: 30px;
        }}
        .metadata {{
            background: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .severity-critical {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .severity-high {{
            color: #f57c00;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #fbc02d;
            font-weight: bold;
        }}
        .severity-low {{
            color: #388e3c;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Reconnaissance Report</h1>
        
        <div class="metadata">
            <h3>Scan Information</h3>
            <p><strong>Target:</strong> {metadata.get('target', 'N/A')}</p>
            <p><strong>Start Time:</strong> {metadata.get('start_time', 'N/A')}</p>
            <p><strong>End Time:</strong> {metadata.get('end_time', 'N/A')}</p>
            <p><strong>Duration:</strong> {metadata.get('duration', 'N/A')}</p>
            <p><strong>Generated:</strong> {metadata.get('generated_at', 'N/A')}</p>
        </div>
        
        <h2>📊 Summary Statistics</h2>
        <div class="stat-grid">
            <div class="stat-card">
                <div class="stat-value">{stats.get('total_subdomains', 0)}</div>
                <div class="stat-label">Subdomains Found</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('resolvable_domains', 0)}</div>
                <div class="stat-label">Resolvable Domains</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('live_urls', 0)}</div>
                <div class="stat-label">Live URLs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('open_ports', 0)}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('vulnerabilities', 0)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{stats.get('technologies', 0)}</div>
                <div class="stat-label">Technologies</div>
            </div>
        </div>
        
        <h2>🌐 Subdomain Enumeration</h2>
        <p>Total unique subdomains discovered: <strong>{stats.get('total_subdomains', 0)}</strong></p>
        
        <h2>🔌 Port Scanning</h2>
        <p>Total open ports: <strong>{stats.get('open_ports', 0)}</strong></p>
        
        <h2>🛡️ Vulnerabilities</h2>
        <p>Total vulnerabilities found: <strong>{stats.get('vulnerabilities', 0)}</strong></p>
        {self._generate_vuln_table()}
        
        <h2>💻 Technologies Detected</h2>
        <p>Unique technologies: <strong>{stats.get('technologies', 0)}</strong></p>
        
        <h2>📁 Output Files</h2>
        <ul>
            <li>All Subdomains: <code>all_subdomains.txt</code></li>
            <li>Resolvable Domains: <code>resolvable_domains.txt</code></li>
            <li>Live URLs: <code>live_urls.txt</code></li>
            <li>Port Scans: <code>port_scans/</code></li>
            <li>Screenshots: <code>screenshots/</code></li>
            <li>Vulnerabilities: <code>vulnerabilities/</code></li>
        </ul>
    </div>
</body>
</html>
"""
            
            with open(html_file, 'w') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report saved to {html_file}")
            return html_file
        
        except Exception as e:
            self.logger.error(f"HTML report generation failed: {e}")
            return ""
    
    def generate_markdown_report(self) -> str:
        """Generate Markdown report"""
        md_file = os.path.join(self.reports_dir, "recon_report.md")
        
        try:
            metadata = self.report_data.get('metadata', {})
            stats = self.report_data.get('statistics', {})
            
            md_content = f"""# 🔍 Reconnaissance Report

## Scan Information

- **Target:** {metadata.get('target', 'N/A')}
- **Start Time:** {metadata.get('start_time', 'N/A')}
- **End Time:** {metadata.get('end_time', 'N/A')}
- **Duration:** {metadata.get('duration', 'N/A')}
- **Generated:** {metadata.get('generated_at', 'N/A')}

## 📊 Summary Statistics

| Metric | Count |
|--------|-------|
| Subdomains Found | {stats.get('total_subdomains', 0)} |
| Resolvable Domains | {stats.get('resolvable_domains', 0)} |
| Live URLs | {stats.get('live_urls', 0)} |
| Open Ports | {stats.get('open_ports', 0)} |
| Vulnerabilities | {stats.get('vulnerabilities', 0)} |
| Technologies | {stats.get('technologies', 0)} |

## 🌐 Subdomain Enumeration

Total unique subdomains discovered: **{stats.get('total_subdomains', 0)}**

### Tool Breakdown
- Amass: {stats.get('amass_count', 0)}
- Subfinder: {stats.get('subfinder_count', 0)}
- Assetfinder: {stats.get('assetfinder_count', 0)}
- crt.sh: {stats.get('crtsh_count', 0)}

## 🔌 Port Scanning

Total open ports found: **{stats.get('open_ports', 0)}**

## 🛡️ Vulnerabilities

Total vulnerabilities: **{stats.get('vulnerabilities', 0)}**

- Critical: {stats.get('critical_vulns', 0)}
- High: {stats.get('high_vulns', 0)}
- Medium: {stats.get('medium_vulns', 0)}
- Low: {stats.get('low_vulns', 0)}

## 💻 Technologies Detected

Total unique technologies: **{stats.get('technologies', 0)}**

## 📁 Output Files

- All Subdomains: `all_subdomains.txt`
- Resolvable Domains: `resolvable_domains.txt`
- Live URLs: `live_urls.txt`
- Port Scans: `port_scans/`
- Screenshots: `screenshots/`
- Vulnerabilities: `vulnerabilities/`
- Technology Detection: `technology_detection/`

## 🎯 Next Steps

1. Review critical and high severity vulnerabilities
2. Analyze screenshot gallery for interesting targets
3. Investigate technologies for known vulnerabilities
4. Perform manual testing on high-value targets
5. Check content discovery results for sensitive endpoints

---
*Generated by Recon Automation Framework v2.0*
"""
            
            with open(md_file, 'w') as f:
                f.write(md_content)
            
            self.logger.info(f"Markdown report saved to {md_file}")
            return md_file
        
        except Exception as e:
            self.logger.error(f"Markdown report generation failed: {e}")
            return ""
    
    def generate_csv_summary(self) -> str:
        """Generate CSV summary"""
        csv_file = os.path.join(self.reports_dir, "summary.csv")
        
        try:
            stats = self.report_data.get('statistics', {})
            
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Metric', 'Count'])
                
                for key, value in stats.items():
                    writer.writerow([key.replace('_', ' ').title(), value])
            
            self.logger.info(f"CSV summary saved to {csv_file}")
            return csv_file
        
        except Exception as e:
            self.logger.error(f"CSV summary generation failed: {e}")
            return ""
    
    def _generate_vuln_table(self) -> str:
        """Generate HTML table for vulnerabilities"""
        vulns = self.report_data.get('vulnerabilities', {}).get('details', [])
        
        if not vulns:
            return "<p>No vulnerabilities found.</p>"
        
        table_html = """
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Name</th>
                    <th>Host</th>
                    <th>Template</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for vuln in vulns[:50]:  # Limit to 50 for HTML
            severity = vuln.get('severity', 'info')
            severity_class = f"severity-{severity}"
            
            table_html += f"""
                <tr>
                    <td class="{severity_class}">{severity.upper()}</td>
                    <td>{vuln.get('name', 'N/A')}</td>
                    <td>{vuln.get('host', 'N/A')}</td>
                    <td><code>{vuln.get('template', 'N/A')}</code></td>
                </tr>
            """
        
        table_html += """
            </tbody>
        </table>
        """
        
        return table_html


if __name__ == "__main__":
    # Test module
    from modules.utils import ReconLogger
    
    logger = ReconLogger("reporting", "logs").get_logger()
    
    generator = ReportGenerator(logger, "output")
    
    # Set metadata
    start = datetime.now()
    end = datetime.now()
    generator.set_metadata("example.com", start, end)
    
    # Add statistics
    generator.add_section_data('statistics', {
        'total_subdomains': 150,
        'resolvable_domains': 120,
        'live_urls': 80,
        'open_ports': 45,
        'vulnerabilities': 12,
        'technologies': 25
    })
    
    # Generate reports
    reports = generator.generate_all_reports()
    print(f"Generated reports: {reports}")