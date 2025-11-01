#!/bin/bash

# Super Decoder Installer
# Installation script for super_decoder.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Installation directories
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="super_decoder.sh"
INSTALLED_NAME="superdecoder"
CONFIG_DIR="$HOME/.config/superdecoder"

# Function to print colored output
print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Display installer banner
display_banner() {
    echo -e "${PURPLE}"
    cat << "INSTALLBANNER"
╔════════════════════════════════════════════════════════════════╗
║                  SUPER DECODER INSTALLER                      ║
║                     BY ZYUS (@zyus_9)                         ║
╚════════════════════════════════════════════════════════════════╝
INSTALLBANNER
    echo -e "${NC}"
}

# Check if running as root for system-wide installation
check_privileges() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root for system-wide installation"
        return 0
    else
        # Check if we can write to /usr/local/bin without sudo
        if [ -w "$INSTALL_DIR" ]; then
            print_status "User has write access to $INSTALL_DIR"
            return 0
        else
            print_error "This installer needs root privileges for system-wide installation"
            print_status "Please run with sudo: sudo ./install_super_decode.sh"
            print_status "Or install locally with: ./install_super_decode.sh --local"
            exit 1
        fi
    fi
}

# Check dependencies
check_dependencies() {
    local deps=("base64" "xxd" "file" "sed" "grep" "awk" "python3")
    local missing=()
    
    print_status "Checking system dependencies..."
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        print_warning "Missing dependencies: ${missing[*]}"
        print_status "Attempting to install missing packages..."
        
        # Detect package manager and install
        if command -v pkg &> /dev/null; then
            # Termux
            pkg update > /dev/null 2>&1
            pkg install -y "${missing[@]}" > /dev/null 2>&1
        elif command -v apt &> /dev/null; then
            # Debian/Ubuntu
            sudo apt update > /dev/null 2>&1
            sudo apt install -y "${missing[@]}" > /dev/null 2>&1
        elif command -v yum &> /dev/null; then
            # RedHat/CentOS
            sudo yum install -y "${missing[@]}" > /dev/null 2>&1
        elif command -v pacman &> /dev/null; then
            # Arch
            sudo pacman -Sy --noconfirm "${missing[@]}" > /dev/null 2>&1
        else
            print_error "Cannot auto-install dependencies. Please install manually: ${missing[*]}"
            return 1
        fi
        
        # Verify installation
        for dep in "${missing[@]}"; do
            if command -v "$dep" &> /dev/null; then
                print_success "Installed: $dep"
            else
                print_error "Failed to install: $dep"
                return 1
            fi
        done
    else
        print_success "All dependencies satisfied"
    fi
}

# Backup existing installation
backup_existing() {
    if [[ -f "$INSTALL_DIR/$INSTALLED_NAME" ]]; then
        local backup_name="${INSTALLED_NAME}.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$INSTALL_DIR/$INSTALLED_NAME" "/tmp/$backup_name"
        print_status "Backed up existing installation to /tmp/$backup_name"
    fi
    
    if [[ -L "$INSTALL_DIR/sd" ]]; then
        local backup_name="sd.backup.$(date +%Y%m%d_%H%M%S)"
        cp "$INSTALL_DIR/sd" "/tmp/$backup_name" 2>/dev/null || true
    fi
}

# Install the script system-wide
install_system_wide() {
    local script_path=$(dirname "$0")/$SCRIPT_NAME
    
    if [[ ! -f "$script_path" ]]; then
        print_error "Main script $SCRIPT_NAME not found in current directory!"
        exit 1
    fi
    
    # Verify script is executable
    if [[ ! -x "$script_path" ]]; then
        print_status "Making script executable..."
        chmod +x "$script_path"
    fi
    
    # Copy script to install directory
    print_status "Installing to $INSTALL_DIR/$INSTALLED_NAME..."
    cp "$script_path" "$INSTALL_DIR/$INSTALLED_NAME"
    
    # Make executable
    chmod +x "$INSTALL_DIR/$INSTALLED_NAME"
    
    # Create symlink for easy access
    if [[ ! -L "$INSTALL_DIR/sd" ]]; then
        ln -s "$INSTALL_DIR/$INSTALLED_NAME" "$INSTALL_DIR/sd"
        print_success "Created shortcut: sd"
    fi
    
    print_success "Script installed to $INSTALL_DIR/$INSTALLED_NAME"
}

# Install locally for user
install_local() {
    local script_path=$(dirname "$0")/$SCRIPT_NAME
    local local_bin="$HOME/.local/bin"
    
    # Create local bin directory if it doesn't exist
    mkdir -p "$local_bin"
    
    if [[ ! -f "$script_path" ]]; then
        print_error "Main script $SCRIPT_NAME not found in current directory!"
        exit 1
    fi
    
    # Verify script is executable
    if [[ ! -x "$script_path" ]]; then
        print_status "Making script executable..."
        chmod +x "$script_path"
    fi
    
    # Copy script to local bin
    print_status "Installing to $local_bin/$INSTALLED_NAME..."
    cp "$script_path" "$local_bin/$INSTALLED_NAME"
    chmod +x "$local_bin/$INSTALLED_NAME"
    
    # Create symlink
    if [[ ! -L "$local_bin/sd" ]]; then
        ln -s "$local_bin/$INSTALLED_NAME" "$local_bin/sd"
        print_success "Created shortcut: sd"
    fi
    
    # Check if local bin is in PATH
    if [[ ":$PATH:" != *":$local_bin:"* ]]; then
        print_warning "Add to your ~/.bashrc or ~/.zshrc:"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\""
    fi
    
    print_success "Script installed to $local_bin/$INSTALLED_NAME"
}

# Verify installation
verify_installation() {
    if command -v "$INSTALLED_NAME" &> /dev/null || command -v sd &> /dev/null; then
        print_success "Installation verified - $INSTALLED_NAME is now available"
        return 0
    else
        print_error "Installation verification failed"
        return 1
    fi
}

# Create configuration directory
create_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_DIR/config" << EOF
# Super Decoder Configuration
# Default settings

MAX_LAYERS=50
TIMEOUT=30
AUTO_CLEANUP=true
LOG_LEVEL=INFO

EOF
    print_success "Configuration created in $CONFIG_DIR"
}

# Display usage information
show_usage() {
    echo
    print_status "Super Decoder v4.0.0 Installation Complete!"
    echo
    echo -e "${YELLOW}Usage Examples:${NC}"
    echo "  superdecoder encoded_file.txt"
    echo "  sd --analyze secret_message.b64"
    echo "  superdecoder --output result.txt --layers 25 encoded_data.txt"
    echo "  echo 'encoded_string' | superdecoder"
    echo
    echo -e "${YELLOW}Quick Start:${NC}"
    echo "  1. Analyze a file: sd --analyze filename"
    echo "  2. Decode a file: sd filename"
    echo "  3. Deep decode: sd --layers 100 complex_file"
    echo
    echo -e "${CYAN}For help: superdecoder --help${NC}"
    echo -e "${CYAN}Documentation: See README.md${NC}"
}

# Main installation process
main_install() {
    local install_type="$1"
    
    display_banner
    
    case "$install_type" in
        system)
            check_privileges
            check_dependencies
            backup_existing
            install_system_wide
            ;;
        local)
            check_dependencies
            install_local
            ;;
        *)
            print_error "Invalid installation type"
            exit 1
            ;;
    esac
    
    create_config
    
    if verify_installation; then
        show_usage
        print_success "Super Decoder installed successfully!"
        
        # Test run
        echo
        print_status "Testing installation..."
        if superdecoder --version &> /dev/null || sd --version &> /dev/null; then
            print_success "Test successful - Super Decoder is ready!"
        else
            print_warning "Installation test failed, but script is installed"
        fi
    else
        print_error "Installation failed!"
        exit 1
    fi
}

# Uninstall function
uninstall() {
    print_warning "Uninstalling Super Decoder..."
    
    # System-wide uninstall
    if [[ -f "$INSTALL_DIR/$INSTALLED_NAME" ]]; then
        rm -f "$INSTALL_DIR/$INSTALLED_NAME"
        print_status "Removed $INSTALL_DIR/$INSTALLED_NAME"
    fi
    
    if [[ -L "$INSTALL_DIR/sd" ]]; then
        rm -f "$INSTALL_DIR/sd"
        print_status "Removed symlink $INSTALL_DIR/sd"
    fi
    
    # Local uninstall
    local local_bin="$HOME/.local/bin"
    if [[ -f "$local_bin/$INSTALLED_NAME" ]]; then
        rm -f "$local_bin/$INSTALLED_NAME"
        print_status "Removed $local_bin/$INSTALLED_NAME"
    fi
    
    if [[ -L "$local_bin/sd" ]]; then
        rm -f "$local_bin/sd"
        print_status "Removed symlink $local_bin/sd"
    fi
    
    # Remove config
    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR"
        print_status "Removed configuration directory"
    fi
    
    print_success "Uninstallation complete"
}

# Parse command line arguments
case "${1:-}" in
    -u|--uninstall|uninstall)
        check_privileges
        uninstall
        exit 0
        ;;
    -l|--local|local)
        main_install "local"
        ;;
    -h|--help|help)
        display_banner
        echo "Super Decoder Installer"
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  -l, --local     Install for current user only"
        echo "  -u, --uninstall Remove the installation"
        echo "  -h, --help      Show this help message"
        echo
        echo "Examples:"
        echo "  sudo $0          # System-wide installation (default)"
        echo "  $0 --local       # User-local installation"
        echo "  $0 --uninstall   # Remove Super Decoder"
        exit 0
        ;;
    *)
        main_install "system"
        ;;
esac
