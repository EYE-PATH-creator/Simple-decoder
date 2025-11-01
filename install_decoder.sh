#!/bin/bash

echo -e "\033[1;36m"
echo "╔════════════════════════════════════════════════╗"
echo "║               SIMPLE DECODER BY ZYUS          ║"
echo "║     for any error or issue contact at         ║"
echo "║               IG/TG-@zyus_9                   ║"
echo "╚════════════════════════════════════════════════╝"
echo -e "\033[0m"

# Check if running on Termux
if [ ! -d "/data/data/com.termux/files/usr" ]; then
    echo -e "\033[1;31m[!] Error: This script is designed for Termux Android only!\033[0m"
    exit 1
fi

# Update and install dependencies
echo -e "\033[1;33m[*] Updating packages...\033[0m"
pkg update -y && pkg upgrade -y

echo -e "\033[1;33m[*] Installing dependencies...\033[0m"
pkg install -y file coreutils

# Make scripts executable
chmod +x super_decoder.sh
chmod +x install_super_decoder.sh

# Create symlink for easy access
echo -e "\033[1;33m[*] Creating system-wide command...\033[0m"
ln -sf $(pwd)/super_decoder.sh $PREFIX/bin/superdecode

echo -e "\033[1;32m"
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
echo -e "\033[0m"
