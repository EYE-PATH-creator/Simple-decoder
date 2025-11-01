#!/bin/bash

# Simple Decoder by ZYUS
# Ultimate Multi-Encoding Decoder for Termux
# Contact: IG/TG-@zyus_9

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
VERSION="3.0.0"
AUTHOR="ZYUS"
CONTACT="IG/TG-@zyus_9"
MAX_LAYERS=20

# Global variables
TEMP_DIR=""

# Cleanup function
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT INT TERM

# Display banner
display_banner() {
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║               SIMPLE DECODER BY ZYUS          ║"
    echo "║     for any error or issue contact at         ║"
    echo "║               IG/TG-@zyus_9                   ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}           Ultimate Multi-Encoding Decoder v$VERSION${NC}"
    echo ""
}

# Check dependencies
check_dependencies() {
    local deps=("file" "base64" "xxd" "sed" "grep" "awk")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Installing missing dependencies...${NC}"
        pkg update > /dev/null 2>&1
        pkg install -y "${missing[@]}" > /dev/null 2>&1
    fi
}

# Create temporary directory
create_temp_dir() {
    TEMP_DIR=$(mktemp -d)
    echo -e "${BLUE}[i] Temporary directory: $TEMP_DIR${NC}"
}

# Detect encodings in file
detect_encodings() {
    local file="$1"
    local encodings=()
    
    echo -e "${CYAN}[*] Analyzing file for encodings...${NC}"
    
    # Get basic file info
    local file_type=$(file -b "$file" 2>/dev/null || echo "unknown")
    local file_size=$(wc -c < "$file" 2>/dev/null || echo "0")
    
    echo -e "${BLUE}[i] File type: $file_type${NC}"
    echo -e "${BLUE}[i] File size: $file_size bytes${NC}"
    
    # Check for Base64
    if head -c 500 "$file" 2>/dev/null | grep -q -E '^[A-Za-z0-9+/]*={0,2}$'; then
        encodings+=("base64:90")
    fi
    
    # Check for Hex encoding
    local hex_check=$(head -c 500 "$file" | tr -d ' \n\r\t' | head -c 100)
    if echo "$hex_check" | grep -q -E '^[0-9A-Fa-f]*$'; then
        if [ $(( ${#hex_check} % 2 )) -eq 0 ]; then
            encodings+=("hex:85")
        fi
    fi
    
    # Check for URL encoding
    if head -c 500 "$file" 2>/dev/null | grep -q '%'; then
        encodings+=("url:80")
    fi
    
    # Check for ASCII text
    if file "$file" | grep -q 'ASCII text'; then
        encodings+=("ascii:95")
    fi
    
    # Check for ROT13
    if head -c 200 "$file" 2>/dev/null | grep -q -E '^[A-Za-z ]*$'; then
        encodings+=("rot13:50")
    fi
    
    # Check for Reverse text
    local first_line=$(head -1 "$file" 2>/dev/null)
    if [ -n "$first_line" ] && [ "${#first_line}" -gt 5 ]; then
        encodings+=("reverse:65")
    fi
    
    # Display detected encodings
    if [ ${#encodings[@]} -gt 0 ]; then
        echo -e "${GREEN}[+] Detected possible encodings:${NC}"
        for encoding in "${encodings[@]}"; do
            local enc_type=$(echo "$encoding" | cut -d':' -f1)
            local confidence=$(echo "$encoding" | cut -d':' -f2)
            echo -e "  ${GREEN}✓${NC} $enc_type (confidence: $confidence%)"
        done
    else
        echo -e "${YELLOW}[!] No specific encodings detected${NC}"
        encodings=("unknown:0")
    fi
    
    printf '%s\n' "${encodings[@]}"
}

# Base64 decoder
decode_base64() {
    local input_file="$1"
    local output_file="$2"
    
    if base64 -d "$input_file" > "$output_file" 2>/dev/null; then
        if [ -s "$output_file" ]; then
            echo -e "${GREEN}[✓] Base64 decoding successful${NC}"
            return 0
        fi
    fi
    return 1
}

# Hex decoder
decode_hex() {
    local input_file="$1"
    local output_file="$2"
    
    # Clean hex data
    local clean_hex=$(cat "$input_file" | tr -d ' \n\r\t' | grep -E '^[0-9A-Fa-f]*$')
    if [ -n "$clean_hex" ] && [ $(( ${#clean_hex} % 2 )) -eq 0 ]; then
        if echo "$clean_hex" | xxd -r -p > "$output_file" 2>/dev/null; then
            if [ -s "$output_file" ]; then
                echo -e "${GREEN}[✓] Hex decoding successful${NC}"
                return 0
            fi
        fi
    fi
    return 1
}

# URL decoder
decode_url() {
    local input_file="$1"
    local output_file="$2"
    
    # Simple URL decoding
    sed '
        s/%20/ /g; s/%21/!/g; s/%22/"/g; s/%23/#/g; s/%24/$/g;
        s/%26/\&/g; s/%27/'"'"'/g; s/%28/(/g; s/%29/)/g;
        s/%2A/*/g; s/%2B/+/g; s/%2C/,/g; s/%2D/-/g;
        s/%2E/./g; s/%2F/\//g; s/%3A/:/g; s/%3B/;/g;
        s/%3C/</g; s/%3D/=/g; s/%3E/>/g; s/%3F/?/g;
        s/%40/@/g; s/%5B/[/g; s/%5C/\\/g; s/%5D/]/g;
        s/%5E/^/g; s/%5F/_/g; s/%60/`/g; s/%7B/{/g;
        s/%7C/|/g; s/%7D/}/g; s/%7E/~/g
    ' "$input_file" > "$output_file"
    
    if [ -s "$output_file" ]; then
        echo -e "${GREEN}[✓] URL decoding successful${NC}"
        return 0
    fi
    return 1
}

# ROT13 decoder
decode_rot13() {
    local input_file="$1"
    local output_file="$2"
    
    if tr 'A-Za-z' 'N-ZA-Mn-za-m' < "$input_file" > "$output_file" 2>/dev/null; then
        if [ -s "$output_file" ]; then
            echo -e "${GREEN}[✓] ROT13 decoding successful${NC}"
            return 0
        fi
    fi
    return 1
}

# Reverse text decoder
decode_reverse() {
    local input_file="$1"
    local output_file="$2"
    
    if rev "$input_file" > "$output_file" 2>/dev/null; then
        if [ -s "$output_file" ]; then
            echo -e "${GREEN}[✓] Reverse decoding successful${NC}"
            return 0
        fi
    fi
    return 1
}

# Binary to text extraction
extract_text() {
    local input_file="$1"
    local output_file="$2"
    
    if strings "$input_file" > "$output_file" 2>/dev/null; then
        if [ -s "$output_file" ] && [ $(wc -l < "$output_file") -gt 2 ]; then
            echo -e "${GREEN}[✓] Text extraction successful${NC}"
            return 0
        fi
    fi
    return 1
}

# Try all decoders on file
try_all_decoders() {
    local input_file="$1"
    local output_file="$2"
    local decoders=("base64" "hex" "url" "rot13" "reverse" "extract_text")
    
    for decoder in "${decoders[@]}"; do
        echo -e "${BLUE}[>] Trying $decoder...${NC}"
        local temp_output="$TEMP_DIR/try_${decoder}"
        
        case "$decoder" in
            "base64") decode_base64 "$input_file" "$temp_output" ;;
            "hex") decode_hex "$input_file" "$temp_output" ;;
            "url") decode_url "$input_file" "$temp_output" ;;
            "rot13") decode_rot13 "$input_file" "$temp_output" ;;
            "reverse") decode_reverse "$input_file" "$temp_output" ;;
            "extract_text") extract_text "$input_file" "$temp_output" ;;
        esac
        
        if [ $? -eq 0 ] && [ -s "$temp_output" ]; then
            cp "$temp_output" "$output_file"
            rm -f "$temp_output"
            return 0
        fi
        rm -f "$temp_output"
    done
    
    echo -e "${RED}[!] All decoders failed${NC}"
    return 1
}

# Analyze encoding layers
analyze_layers() {
    local file="$1"
    local current_layer=0
    local current_file="$file"
    local layer_info=()
    
    echo -e "${CYAN}[*] Starting deep layer analysis...${NC}"
    
    while [ $current_layer -lt $MAX_LAYERS ]; do
        current_layer=$((current_layer + 1))
        echo -e "${YELLOW}[>] Analyzing layer $current_layer...${NC}"
        
        # Detect encodings at this layer
        local encodings=$(detect_encodings "$current_file")
        local best_encoding=$(echo "$encodings" | head -1 | cut -d':' -f1)
        local best_confidence=$(echo "$encodings" | head -1 | cut -d':' -f2)
        
        layer_info+=("Layer $current_layer: $best_encoding ($best_confidence%)")
        
        # Try to decode to next layer
        local next_file="$TEMP_DIR/layer_${current_layer}"
        
        if try_all_decoders "$current_file" "$next_file"; then
            # Check if we actually got different content
            if [ "$current_file" != "$file" ]; then
                rm -f "$current_file"
            fi
            current_file="$next_file"
        else
            echo -e "${YELLOW}[!] Cannot decode further${NC}"
            break
        fi
        
        # Safety check
        if [ $current_layer -ge $MAX_LAYERS ]; then
            echo -e "${YELLOW}[!] Maximum layers reached${NC}"
            break
        fi
    done
    
    # Display layer analysis results
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║              LAYER ANALYSIS RESULTS           ║"
    echo "╠════════════════════════════════════════════════╣"
    for info in "${layer_info[@]}"; do
        echo "║ $info"
    done
    echo "╠════════════════════════════════════════════════╣"
    echo "║ Total layers found: $((current_layer))"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo $current_layer
}

# Main decoding function
decode_file() {
    local input_file="$1"
    local output_file="$2"
    
    echo -e "${CYAN}[*] Starting comprehensive decoding...${NC}"
    
    # First, analyze layers
    local total_layers=$(analyze_layers "$input_file")
    
    # Now decode through all layers
    echo -e "${CYAN}[*] Decoding through all layers...${NC}"
    
    local current_file="$input_file"
    local decoded_layers=0
    
    for ((layer=1; layer<=total_layers; layer++)); do
        echo -e "${YELLOW}[>] Decoding layer $layer/$total_layers...${NC}"
        
        local temp_output="$TEMP_DIR/decoding_layer_${layer}"
        
        if try_all_decoders "$current_file" "$temp_output"; then
            decoded_layers=$((decoded_layers + 1))
            
            # If this is not the original input, clean up previous temp file
            if [ "$current_file" != "$input_file" ]; then
                rm -f "$current_file"
            fi
            
            current_file="$temp_output"
        else
            echo -e "${RED}[!] Failed to decode layer $layer${NC}"
            break
        fi
    done
    
    # Create final output
    if [ -f "$current_file" ] && [ -s "$current_file" ]; then
        cp "$current_file" "$output_file"
        echo -e "${GREEN}[✓] Successfully decoded $decoded_layers layers${NC}"
        return 0
    else
        echo -e "${RED}[!] Final decoding failed${NC}"
        return 1
    fi
}

# Show help
show_help() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║               SIMPLE DECODER BY ZYUS          ║"
    echo "║     for any error or issue contact at         ║"
    echo "║               IG/TG-@zyus_9                   ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS] <filename>"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -v, --version   Show version information"
    echo "  -a, --analyze   Only analyze file without decoding"
    echo "  -o, --output    Specify output filename"
    echo ""
    echo "Supported encodings:"
    echo "  • Base64        • Hexadecimal    • URL Encoding"
    echo "  • ROT13         • Reverse Text   • Binary Data"
    echo "  • Multi-layer encoding detection"
    echo ""
    echo "Examples:"
    echo "  $0 encoded_file.txt"
    echo "  $0 --analyze secret_message.b64"
    echo "  $0 --output result.txt encoded_data.txt"
    echo ""
    echo -e "${YELLOW}Contact: $CONTACT${NC}"
}

# Show version
show_version() {
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║               SIMPLE DECODER BY ZYUS          ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "Version: $VERSION"
    echo "Author: $AUTHOR"
    echo "Contact: $CONTACT"
}

# Main function
main() {
    display_banner
    
    local input_file=""
    local output_file=""
    local analyze_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                show_version
                exit 0
                ;;
            -a|--analyze)
                analyze_only=true
                shift
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -*)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
            *)
                input_file="$1"
                shift
                ;;
        esac
    done
    
    # Check if input file is provided
    if [ -z "$input_file" ]; then
        echo -e "${RED}[!] Error: No input file specified!${NC}"
        show_help
        exit 1
    fi
    
    # Check if file exists
    if [ ! -f "$input_file" ]; then
        echo -e "${RED}[!] Error: File '$input_file' not found!${NC}"
        exit 1
    fi
    
    # Set default output file if not specified
    if [ -z "$output_file" ]; then
        local base_name=$(basename "$input_file")
        output_file="${base_name%.*}_decoded.txt"
    fi
    
    echo -e "${GREEN}[+] Input file:  $input_file${NC}"
    echo -e "${GREEN}[+] Output file: $output_file${NC}"
    echo ""
    
    # Check dependencies and create temp directory
    check_dependencies
    create_temp_dir
    
    if [ "$analyze_only" = true ]; then
        # Only analyze
        analyze_layers "$input_file" > /dev/null
    else
        # Analyze and decode
        if decode_file "$input_file" "$output_file"; then
            echo -e "${GREEN}"
            echo "╔════════════════════════════════════════════════╗"
            echo "║               DECODING COMPLETE!              ║"
            echo "╠════════════════════════════════════════════════╣"
            echo "║ Input:    $input_file"
            echo "║ Output:   $output_file"
            echo "║ Size:     $(wc -c < "$output_file" 2>/dev/null || echo "unknown") bytes"
            echo "╚════════════════════════════════════════════════╝"
            echo -e "${NC}"
            
            # Show preview
            echo -e "${CYAN}[+] Preview of decoded content:${NC}"
            echo -e "${YELLOW}----------------------------------------${NC}"
            head -10 "$output_file" 2>/dev/null || echo "No readable content found"
            echo -e "${YELLOW}----------------------------------------${NC}"
            
            echo ""
            echo -e "${YELLOW}For any issues contact: $CONTACT${NC}"
        else
            echo -e "${RED}[!] Decoding failed${NC}"
            echo -e "${YELLOW}For help contact: $CONTACT${NC}"
            exit 1
        fi
    fi
}

# Run main function
main "$@"
