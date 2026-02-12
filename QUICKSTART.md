# 🚀 Quick Start Guide

Get started with Recon Automation Framework in 5 minutes!

## 📦 Installation

### One-Line Install (Ubuntu/Debian/Kali)

```bash
git clone https://github.com/yourusername/recon-automation.git && cd recon-automation && sudo bash install.sh
```

### What Gets Installed?

The installer will set up:
- ✅ Go programming language
- ✅ All reconnaissance tools (Amass, Subfinder, etc.)
- ✅ Python dependencies
- ✅ SecLists wordlists
- ✅ Symbolic links for easy access

## 🎯 First Scan

### Option 1: Using the Tracker (Full Control)

```bash
python tracker.py -t example.com
```

This runs a complete reconnaissance workflow with default settings.

### Option 2: Using the CLI (Recommended for Beginners)

```bash
# Quick scan (fastest)
python cli.py -t example.com -m quick

# Stealth scan (passive only)
python cli.py -t example.com -m stealth

# Aggressive scan (comprehensive)
python cli.py -t example.com -m aggressive
```

## 📊 Understanding the Output

After the scan completes, you'll find results in:

```
output/example.com_TIMESTAMP/
├── all_subdomains.txt          ← All discovered subdomains
├── resolvable_domains.txt      ← Domains that resolve to IPs
├── live_urls.txt               ← Active HTTP/HTTPS URLs
├── port_scans/                 ← Nmap scan results
├── screenshots/                ← Website screenshots
├── vulnerabilities/            ← Nuclei findings
└── reports/                    ← HTML, JSON, Markdown reports
```

## 🎨 View the Report

Open the HTML report in your browser:

```bash
# Find the report
cd output/example.com_*/reports/

# Open in browser
firefox recon_report.html
# or
google-chrome recon_report.html
```

## ⚙️ Quick Configuration Changes

Edit `config/config.yaml` to customize:

### Disable Screenshots (Faster Scans)
```yaml
screenshots:
  enable_gowitness: false
```

### Enable More Subdomain Tools
```yaml
subdomain_enum:
  enable_github_subdomains: true
  enable_shodan: true  # Requires API key
```

### Adjust Scan Speed
```yaml
port_scanning:
  nmap:
    quick_scan:
      timing: "T5"  # Faster (T4 is default, T5 is fastest)
```

## 🔑 Adding API Keys (Optional but Recommended)

Some tools work better with API keys. Add them to `config/config.yaml`:

```yaml
api_keys:
  github: "ghp_yourGitHubTokenHere"
  shodan: "yourShodanAPIKey"
  virustotal: "yourVTAPIKey"
```

### Getting API Keys

- **GitHub**: https://github.com/settings/tokens (free)
- **Shodan**: https://account.shodan.io/ (free tier available)
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey (free)

## 💡 Pro Tips

### 1. Start with Quick Scan
```bash
python cli.py -t target.com -m quick
```
Review results before running comprehensive scans.

### 2. Use Scope File for Multiple Targets
Create a file `targets.txt`:
```
subdomain1.example.com
subdomain2.example.com
subdomain3.example.com
```

Then modify config to use it:
```yaml
target:
  scope_file: "targets.txt"
```

### 3. Check Dependencies First
```bash
python tracker.py -t example.com --check-deps
```

### 4. Monitor Progress
Logs are saved in `logs/` directory:
```bash
tail -f logs/recon_tracker_*.log
```

## 🐛 Common First-Time Issues

### Issue: "Tool not found"
**Solution**: Make sure Go bin is in PATH:
```bash
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
```

### Issue: "Permission denied"
**Solution**: Some scans need sudo:
```bash
sudo python tracker.py -t example.com
```

### Issue: "Scan is slow"
**Solution**: 
1. Use quick mode: `python cli.py -t example.com -m quick`
2. Disable screenshots in config
3. Reduce thread counts in config

## 📚 Next Steps

1. ✅ Complete your first scan
2. 📖 Read the full [README.md](README.md)
3. ⚙️ Customize `config/config.yaml` for your needs
4. 🔍 Learn about individual modules in `modules/`
5. 🎯 Start bug bounty hunting or penetration testing!

## 🆘 Need Help?

- Check [README.md](README.md) for detailed documentation
- Review example configurations in `config/`
- Check logs in `logs/` directory
- Open an issue on GitHub

## ⚡ Quick Command Reference

```bash
# Check if everything is installed
python tracker.py -t test.com --check-deps

# Quick scan
python cli.py -t target.com -m quick

# Full scan
python tracker.py -t target.com

# Custom config
python tracker.py -t target.com -c my_config.yaml

# Skip dependency check
python tracker.py -t target.com --skip-deps-check
```

---

**Ready to start? Run your first scan now!**

```bash
python cli.py -t example.com -m quick
```