# 🔍 Advanced Reconnaissance Automation Framework

A professional, production-grade reconnaissance and vulnerability scanning automation framework for penetration testing and bug bounty hunting.

## 🌟 Features

### Subdomain Enumeration
- **Amass** - OWASP's comprehensive subdomain discovery tool
- **Subfinder** - Fast passive subdomain discovery
- **Assetfinder** - Find domains and subdomains
- **crt.sh** - Certificate transparency logs
- **GitHub Subdomains** - GitHub code search for subdomains

### DNS Resolution & HTTP Probing
- **dnsx** - Fast DNS resolution with multiple features
- **httpx** - HTTP toolkit for probing live hosts
- Multi-port probing (80, 443, 8080, 8443, 8888, 3000, 8000, 9000, etc.)

### Port Scanning
- **Nmap** - Quick and full port scans with service detection
- **Masscan** - Ultra-fast port scanner (optional)
- Custom port lists for web services
- Automated web service identification

### Screenshot & Visualization
- **Gowitness** - Screenshot web applications
- **EyeWitness** - Alternative screenshot tool (optional)
- HTML report generation

### Technology Detection
- **Whatweb** - Web technology identification
- **Webanalyze** - Technology profiler
- **Wappalyzer** - Web technology detection (optional)

### Vulnerability Scanning
- **Nuclei** - Vulnerability scanner with 1000+ templates
- Configurable severity levels
- CVE detection
- Misconfiguration detection

### Content Discovery
- **Feroxbuster** - Fast content discovery
- **ffuf** - Web fuzzer
- Custom wordlists support

### JavaScript Analysis
- **LinkFinder** - Endpoint discovery in JS files
- **getJS** - JavaScript file collector
- Parameter extraction

### Reporting
- **HTML Reports** - Professional web-based reports
- **JSON Reports** - Machine-readable output
- **Markdown Reports** - Documentation-friendly
- **CSV Summaries** - Spreadsheet-compatible

## 📋 Requirements

### Operating System
- Linux (Kali Linux, Ubuntu, Debian recommended)
- macOS (with Homebrew)
- WSL2 on Windows

### Dependencies
- Python 3.8+
- Go 1.19+
- Git
- Chromium/Chrome (for screenshots)

## 🚀 Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/recon-automation.git
cd recon-automation

# Run installation script (requires sudo)
sudo bash install.sh
```

### Manual Installation

1. **Install Go**
```bash
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin:~/go/bin
```

2. **Install Tools**
```bash
# Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# dnsx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Gowitness
go install github.com/sensepost/gowitness@latest

# Feroxbuster
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# ffuf
go install github.com/ffuf/ffuf/v2@latest

# Additional tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/003random/getJS@latest

# Python tools
pip3 install arjun
```

3. **Install Python Dependencies**
```bash
pip3 install -r requirements.txt
```

4. **Install SecLists (Wordlists)**
```bash
sudo git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

## 📖 Usage

### Basic Usage

```bash
# Run full scan with default configuration
python tracker.py -t example.com

# Use CLI wrapper for quick scan
python cli.py -t example.com -m quick

# Stealth scan (passive only)
python cli.py -t example.com -m stealth

# Aggressive scan (all tools)
python cli.py -t example.com -m aggressive

# Custom configuration
python tracker.py -t example.com -c custom_config.yaml
```

### Scan Modes

#### Quick Mode
- Essential tools only
- Faster execution
- Good for initial reconnaissance

```bash
python cli.py -t example.com -m quick
```

#### Stealth Mode
- Passive reconnaissance only
- No active scanning
- OSINT-focused

```bash
python cli.py -t example.com -m stealth
```

#### Aggressive Mode
- All tools enabled
- Content discovery
- Vulnerability scanning
- Longest execution time

```bash
python cli.py -t example.com -m aggressive
```

### Check Dependencies

```bash
python tracker.py -t example.com --check-deps
```

## ⚙️ Configuration

The framework uses a YAML configuration file (`config/config.yaml`). You can customize:

### Subdomain Enumeration
```yaml
subdomain_enum:
  enable_amass: true
  enable_subfinder: true
  enable_assetfinder: true
  enable_crtsh: true
```

### Port Scanning
```yaml
port_scanning:
  nmap:
    quick_scan:
      enable: true
      top_ports: 1000
      timing: "T4"
    full_scan:
      enable: true
      ports: "8000,8080,8443,8888,9000,3000,8081"
```

### Vulnerability Scanning
```yaml
vulnerability_scanning:
  nuclei:
    templates: "cves,vulnerabilities,exposures,misconfigurations"
    severity: "critical,high,medium"
    threads: 25
```

## 📊 Output Structure

```
output/
└── example.com_20240128_143052/
    ├── all_subdomains.txt
    ├── resolvable_domains.txt
    ├── live_urls.txt
    ├── subdomain_enum/
    │   ├── amass.txt
    │   ├── subfinder.txt
    │   ├── assetfinder.txt
    │   └── crtsh.txt
    ├── port_scans/
    │   ├── nmap_quick.*
    │   └── nmap_full_web.*
    ├── screenshots/
    │   └── gowitness_report/
    ├── technology_detection/
    │   ├── whatweb_results.json
    │   └── technology_summary.txt
    ├── vulnerabilities/
    │   ├── nuclei_results.json
    │   └── nuclei_report.md
    └── reports/
        ├── recon_report.html
        ├── recon_report.json
        ├── recon_report.md
        └── summary.csv
```

## 🔧 Advanced Features

### API Keys Configuration

Add API keys in `config/config.yaml`:

```yaml
api_keys:
  shodan: "YOUR_SHODAN_API_KEY"
  censys_id: "YOUR_CENSYS_ID"
  censys_secret: "YOUR_CENSYS_SECRET"
  virustotal: "YOUR_VT_API_KEY"
  github: "YOUR_GITHUB_TOKEN"
```

### Custom Wordlists

```yaml
content_discovery:
  feroxbuster:
    wordlist: "/path/to/custom/wordlist.txt"
    extensions: "php,html,js,txt,json,xml"
```

### Performance Tuning

```yaml
performance:
  max_parallel_tasks: 5
  enable_rate_limiting: true
```

## 📝 Examples

### Example 1: Basic Reconnaissance
```bash
python tracker.py -t hackerone.com
```

### Example 2: Bug Bounty Program
```bash
# Quick initial recon
python cli.py -t target.com -m quick

# Review results, then run aggressive scan
python cli.py -t target.com -m aggressive
```

### Example 3: Red Team Engagement
```bash
# Stealth reconnaissance
python cli.py -t target.corp -m stealth

# Review and proceed with targeted scanning
python tracker.py -t target.corp -c redteam_config.yaml
```

## 🐛 Troubleshooting

### Common Issues

1. **Tools not found**
```bash
# Verify Go bin directory is in PATH
export PATH=$PATH:~/go/bin
```

2. **Permission errors**
```bash
# Some tools require sudo (e.g., masscan, nmap SYN scan)
sudo python tracker.py -t example.com
```

3. **Rate limiting**
```yaml
# Adjust in config.yaml
performance:
  enable_rate_limiting: true
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📜 License

This project is licensed under the MIT License - see LICENSE file for details.

## ⚠️ Legal Disclaimer

This tool is designed for legal security testing and research purposes only. Users must:

- Have explicit permission to test target systems
- Comply with all applicable laws and regulations
- Respect scope boundaries and rules of engagement
- Use responsibly and ethically

The authors assume no liability for misuse or damage caused by this tool.

## 🙏 Acknowledgments

This framework integrates and automates many excellent open-source tools:

- OWASP Amass
- ProjectDiscovery tools (Subfinder, dnsx, httpx, Nuclei)
- Tomnomnom's tools (Assetfinder, waybackurls)
- And many others

Thanks to all the security researchers and developers who created these tools.

## 📧 Contact

- GitHub Issues: [Report bugs or request features]
- Email: security@example.com

## 🔄 Updates

Check for updates regularly:
```bash
git pull origin main
sudo bash install.sh
```

---

**Happy Hunting! 🎯**