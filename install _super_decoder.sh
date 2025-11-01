#!/bin/bash

echo -e "\033[1;36m"
echo "╔════════════════════════════════════════════════╗"
echo "║               SIMPLE DECODER BY ZYUS          ║"
echo "║     for any error or issue contact at         ║"
echo "║               IG/TG-@zyus_9                   ║"
echo "╚════════════════════════════════════════════════╝"
echo -e "\033[0m"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if running on Termux
if [ ! -d "/data/data/com.termux/files/usr" ]; then
    echo -e "${RED}[!] Error: This script is designed for Termux Android only!${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Updating packages...${NC}"
pkg update -y && pkg upgrade -y

echo -e "${YELLOW}[*] Installing dependencies...${NC}"
pkg install -y file coreutils

# Make scripts executable
chmod +x super_decoder.sh

# Create symlink for easy access
echo -e "${YELLOW}[*] Creating system-wide command...${NC}"
ln -sf $(pwd)/super_decoder.sh $PREFIX/bin/superdecode

echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════╗"
echo "║           Installation Complete!              ║"
echo "╠════════════════════════════════════════════════╣"
echo "║               SIMPLE DECODER BY ZYUS          ║"
echo "║     for any error or issue contact at         ║"
echo "║               IG/TG-@zyus_9                   ║"
echo "╠════════════════════════════════════════════════╣"
echo "║ Usage:                                        ║"
echo "║   superdecode filename        (anywhere)      ║"
echo "║   ./super_decoder.sh filename (this dir)      ║"
echo "║                                                ║"
echo "║ Examples:                                      ║"
echo "║   superdecode encoded.txt                      ║"
echo "║   superdecode --analyze secret.b64            ║"
echo "║   superdecode -o result.txt data.enc          ║"
echo "╚════════════════════════════════════════════════╝"
echo -e "${NC}"

# Test the installation
echo -e "${YELLOW}[*] Testing installation...${NC}"
if command -v superdecode &> /dev/null; then
    echo -e "${GREEN}[✓] Installation successful!${NC}"
    echo -e "${GREEN}[✓] You can now use 'superdecode' command from anywhere${NC}"
else
    echo -e "${RED}[!] Installation may have issues.${NC}"
    echo -e "${YELLOW}[!] Try running: source ~/.bashrc${NC}"
    echo -e "${YELLOW}[!] Or restart Termux${NC}"
fi
