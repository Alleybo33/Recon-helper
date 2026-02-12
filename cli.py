#!/usr/bin/env python3
"""
CLI Wrapper for Recon Automation
Provides a user-friendly command-line interface
"""

import os
import sys
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import banner
from tracker import ReconTracker


def run_quick_scan(target: str):
    """Run a quick scan with minimal tools"""
    print("[*] Running quick scan...")
    tracker = ReconTracker(target=target)
    
    # Modify config for quick scan
    tracker.config.config['subdomain_enum']['enable_amass'] = True
    tracker.config.config['subdomain_enum']['enable_subfinder'] = True
    tracker.config.config['subdomain_enum']['enable_assetfinder'] = False
    tracker.config.config['subdomain_enum']['enable_crtsh'] = True
    
    tracker.config.config['port_scanning']['nmap']['quick_scan']['enable'] = True
    tracker.config.config['port_scanning']['nmap']['full_scan']['enable'] = False
    
    tracker.config.config['screenshots']['enable_gowitness'] = False
    tracker.config.config['vulnerability_scanning']['enable_nuclei'] = False
    
    tracker.run_full_scan()


def run_stealth_scan(target: str):
    """Run a stealthy scan (passive only)"""
    print("[*] Running stealth scan (passive only)...")
    tracker = ReconTracker(target=target)
    
    # Configure for passive only
    tracker.config.config['subdomain_enum']['enable_amass'] = True
    tracker.config.config['subdomain_enum']['amass']['passive'] = True
    tracker.config.config['subdomain_enum']['enable_subfinder'] = True
    tracker.config.config['subdomain_enum']['enable_assetfinder'] = True
    tracker.config.config['subdomain_enum']['enable_crtsh'] = True
    
    tracker.config.config['port_scanning']['enable_nmap'] = False
    tracker.config.config['screenshots']['enable_gowitness'] = False
    tracker.config.config['vulnerability_scanning']['enable_nuclei'] = False
    
    tracker.run_full_scan()


def run_aggressive_scan(target: str):
    """Run an aggressive scan with all tools"""
    print("[*] Running aggressive scan...")
    tracker = ReconTracker(target=target)
    
    # Enable everything
    tracker.config.config['subdomain_enum']['enable_amass'] = True
    tracker.config.config['subdomain_enum']['enable_subfinder'] = True
    tracker.config.config['subdomain_enum']['enable_assetfinder'] = True
    tracker.config.config['subdomain_enum']['enable_crtsh'] = True
    tracker.config.config['subdomain_enum']['enable_github_subdomains'] = True
    
    tracker.config.config['port_scanning']['nmap']['quick_scan']['enable'] = True
    tracker.config.config['port_scanning']['nmap']['full_scan']['enable'] = True
    
    tracker.config.config['screenshots']['enable_gowitness'] = True
    tracker.config.config['tech_detection']['enable_whatweb'] = True
    tracker.config.config['vulnerability_scanning']['enable_nuclei'] = True
    tracker.config.config['content_discovery']['enable_feroxbuster'] = True
    
    tracker.run_full_scan()


def main():
    """CLI main function"""
    banner()
    
    parser = argparse.ArgumentParser(
        description="Recon Automation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Modes:
  quick      - Quick scan with essential tools only
  stealth    - Passive/stealth reconnaissance only
  aggressive - Full scan with all tools enabled
  custom     - Use custom configuration file

Examples:
  python cli.py -t example.com -m quick
  python cli.py -t example.com -m stealth
  python cli.py -t example.com -m aggressive
  python cli.py -t example.com -m custom -c my_config.yaml
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target domain'
    )
    
    parser.add_argument(
        '-m', '--mode',
        choices=['quick', 'stealth', 'aggressive', 'custom'],
        default='quick',
        help='Scan mode (default: quick)'
    )
    
    parser.add_argument(
        '-c', '--config',
        help='Custom configuration file (for custom mode)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Custom output directory'
    )
    
    args = parser.parse_args()
    
    # Validate target
    if not args.target:
        print("[ERROR] Target domain is required")
        sys.exit(1)
    
    # Run appropriate scan mode
    try:
        if args.mode == 'quick':
            run_quick_scan(args.target)
        elif args.mode == 'stealth':
            run_stealth_scan(args.target)
        elif args.mode == 'aggressive':
            run_aggressive_scan(args.target)
        elif args.mode == 'custom':
            if not args.config:
                print("[ERROR] Custom mode requires -c/--config option")
                sys.exit(1)
            tracker = ReconTracker(config_path=args.config, target=args.target)
            tracker.run_full_scan()
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()