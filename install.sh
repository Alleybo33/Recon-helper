#!/bin/bash

# Recon Automation Framework - Installation Script
# This script installs all required tools and dependencies

set -e

echo "========================================"
echo "Recon Automation Framework - Installer"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Starting installation...${NC}"
echo ""

# Update system
echo -e "${YELLOW}[*] Updating system packages...${NC}"
apt-get update -y
apt-get upgrade -y

# Install basic dependencies
echo -e "${YELLOW}[*] Installing basic dependencies...${NC}"
apt-get install -y \
    git \
    wget \
    curl \
    python3 \
    python3-pip \
    build-essential \
    chromium-browser \
    jq \
    nmap \
    masscan

# Install Go (required for many tools)
echo -e "${YELLOW}[*] Installing Go...${NC}"
if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export PATH=$PATH:~/go/bin' >> /etc/profile
    source /etc/profile
fi

# Set Go paths
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:~/go/bin

# Install Amass
echo -e "${YELLOW}[*] Installing Amass...${NC}"
if ! command -v amass &> /dev/null; then
    go install -v github.com/owasp-amass/amass/v4/...@master
    cp ~/go/bin/amass /usr/local/bin/
fi

# Install Subfinder
echo -e "${YELLOW}[*] Installing Subfinder...${NC}"
if ! command -v subfinder &> /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    cp ~/go/bin/subfinder /usr/local/bin/
fi

# Install Assetfinder
echo -e "${YELLOW}[*] Installing Assetfinder...${NC}"
if ! command -v assetfinder &> /dev/null; then
    go install github.com/tomnomnom/assetfinder@latest
    cp ~/go/bin/assetfinder /usr/local/bin/
fi

# Install dnsx
echo -e "${YELLOW}[*] Installing dnsx...${NC}"
if ! command -v dnsx &> /dev/null; then
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    cp ~/go/bin/dnsx /usr/local/bin/
fi

# Install httpx
echo -e "${YELLOW}[*] Installing httpx...${NC}"
if ! command -v httpx &> /dev/null; then
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    cp ~/go/bin/httpx /usr/local/bin/
fi

# Install Nuclei
echo -e "${YELLOW}[*] Installing Nuclei...${NC}"
if ! command -v nuclei &> /dev/null; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    cp ~/go/bin/nuclei /usr/local/bin/
    
    # Update Nuclei templates
    nuclei -update-templates
fi

# Install Gowitness
echo -e "${YELLOW}[*] Installing Gowitness...${NC}"
if ! command -v gowitness &> /dev/null; then
    go install github.com/sensepost/gowitness@latest
    cp ~/go/bin/gowitness /usr/local/bin/
fi

# Install Whatweb
echo -e "${YELLOW}[*] Installing Whatweb...${NC}"
if ! command -v whatweb &> /dev/null; then
    apt-get install -y whatweb
fi

# Install Feroxbuster
echo -e "${YELLOW}[*] Installing Feroxbuster...${NC}"
if ! command -v feroxbuster &> /dev/null; then
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
    mv feroxbuster /usr/local/bin/
fi

# Install ffuf
echo -e "${YELLOW}[*] Installing ffuf...${NC}"
if ! command -v ffuf &> /dev/null; then
    go install github.com/ffuf/ffuf/v2@latest
    cp ~/go/bin/ffuf /usr/local/bin/
fi

# Install waybackurls
echo -e "${YELLOW}[*] Installing waybackurls...${NC}"
if ! command -v waybackurls &> /dev/null; then
    go install github.com/tomnomnom/waybackurls@latest
    cp ~/go/bin/waybackurls /usr/local/bin/
fi

# Install gau
echo -e "${YELLOW}[*] Installing gau...${NC}"
if ! command -v gau &> /dev/null; then
    go install github.com/lc/gau/v2/cmd/gau@latest
    cp ~/go/bin/gau /usr/local/bin/
fi

# Install getJS
echo -e "${YELLOW}[*] Installing getJS...${NC}"
if ! command -v getjs &> /dev/null; then
    go install github.com/003random/getJS@latest
    cp ~/go/bin/getJS /usr/local/bin/getjs
fi

# Install Arjun
echo -e "${YELLOW}[*] Installing Arjun...${NC}"
if ! command -v arjun &> /dev/null; then
    pip3 install arjun --break-system-packages
fi

# Install Python dependencies
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt --break-system-packages

# Install SecLists (wordlists)
echo -e "${YELLOW}[*] Installing SecLists...${NC}"
if [ ! -d "/usr/share/seclists" ]; then
    git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
fi

# Make scripts executable
echo -e "${YELLOW}[*] Setting permissions...${NC}"
chmod +x tracker.py
chmod +x cli.py

# Create symbolic links
echo -e "${YELLOW}[*] Creating symbolic links...${NC}"
ln -sf $(pwd)/tracker.py /usr/local/bin/recon-tracker
ln -sf $(pwd)/cli.py /usr/local/bin/recon-cli

echo ""
echo -e "${GREEN}========================================"
echo -e "Installation Complete!"
echo -e "========================================${NC}"
echo ""
echo -e "${GREEN}Usage:${NC}"
echo -e "  recon-tracker -t example.com"
echo -e "  recon-cli -t example.com -m quick"
echo -e "  recon-cli -t example.com -m aggressive"
echo ""
echo -e "${YELLOW}Note: You may need to log out and back in for PATH changes to take effect${NC}"
echo ""