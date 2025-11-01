#!/bin/bash

# Super Decoder by ZYUS - Enhanced Version
# Ultimate Multi-Encoding Decoder for Termux & Linux
# Contact: IG/TG-@zyus_9

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
VERSION="4.0.0"
AUTHOR="ZYUS"
CONTACT="IG/TG-@zyus_9"
MAX_LAYERS=50
TIMEOUT=30

# Global variables
TEMP_DIR=""
CURRENT_LAYER=0
SUCCESSFUL_DECODES=0
DETECTED_ENCODINGS=()

# Cleanup function
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        echo -e "${BLUE}[i] Cleaned up temporary files${NC}"
    fi
}

trap cleanup EXIT INT TERM

# Display banner
display_banner() {
    echo -e "${PURPLE}"
    cat << "BANNER"
╔════════════════════════════════════════════════════════════════╗
║                     SUPER DECODER BY ZYUS                     ║
║                  ULTIMATE DECODING FRAMEWORK                  ║
║                      IG/TG: @zyus_9                           ║
╚════════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
    echo -e "${YELLOW}                    Enhanced Version $VERSION${NC}"
    echo -e "${CYAN}           Multi-Format Advanced Decoding System${NC}"
    echo ""
}

# Enhanced logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_debug() { echo -e "${PURPLE}[DEBUG]${NC} $1"; }

# Check and install dependencies
check_dependencies() {
    local deps=("file" "base64" "xxd" "sed" "grep" "awk" "tr" "rev" "strings" "python3" "perl" "jq")
    local missing=()
    
    log_info "Checking dependencies..."
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_warning "Missing dependencies: ${missing[*]}"
        log_info "Attempting to install missing packages..."
        
        # Detect package manager
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
            log_error "Cannot auto-install dependencies. Please install manually: ${missing[*]}"
            return 1
        fi
        
        # Verify installation
        for dep in "${missing[@]}"; do
            if command -v "$dep" &> /dev/null; then
                log_success "Installed: $dep"
            else
                log_error "Failed to install: $dep"
            fi
        done
    else
        log_success "All dependencies satisfied"
    fi
}

# Create temporary directory
create_temp_dir() {
    TEMP_DIR=$(mktemp -d)
    log_info "Temporary workspace: $TEMP_DIR"
}

# Enhanced file type detection
get_file_info() {
    local file="$1"
    local info=""
    
    # Basic file info
    info+="Size: $(wc -c < "$file" 2>/dev/null || echo "unknown") bytes\n"
    info+="Type: $(file -b "$file" 2>/dev/null || echo "unknown")\n"
    info+="Lines: $(wc -l < "$file" 2>/dev/null || echo "0")\n"
    
    # Entropy calculation (simple)
    local entropy=$(head -c 1000 "$file" | ent 2>/dev/null | grep -i "entropy" | head -1 | awk '{print $3}' || echo "unknown")
    info+="Entropy: $entropy\n"
    
    echo -e "$info"
}

# Advanced encoding detection with confidence scoring
detect_encodings() {
    local file="$1"
    local encodings=()
    
    log_info "Advanced encoding analysis started..."
    
    local file_info=$(get_file_info "$file")
    echo -e "${BLUE}[File Analysis]${NC}"
    echo -e "$file_info" | while read -r line; do echo -e "  ${CYAN}$line${NC}"; done
    
    local content=$(head -c 5000 "$file" 2>/dev/null)
    local clean_content=$(echo "$content" | tr -d ' \n\r\t' | head -c 1000)
    
    # Base64 detection (improved)
    if echo "$clean_content" | grep -q -E '^[A-Za-z0-9+/]*={0,2}$'; then
        local len=${#clean_content}
        if [ $((len % 4)) -eq 0 ]; then
            encodings+=("base64:95")
        else
            encodings+=("base64:70")
        fi
    fi
    
    # Hexadecimal detection (improved)
    local hex_check=$(echo "$clean_content" | grep -E '^[0-9A-Fa-f]*$' | head -c 100)
    if [ -n "$hex_check" ] && [ $(( ${#hex_check} % 2 )) -eq 0 ]; then
        encodings+=("hex:90")
    fi
    
    # URL encoding detection
    if echo "$content" | grep -q '%[0-9A-Fa-f][0-9A-Fa-f]'; then
        encodings+=("url:85")
    fi
    
    # HTML entities
    if echo "$content" | grep -q '&[#A-Za-z0-9]*;'; then
        encodings+=("html:80")
    fi
    
    # ROT13 detection
    if echo "$content" | head -c 200 | grep -q -E '^[A-Za-z ]*$' && ! echo "$content" | head -c 200 | grep -q '[N-Zn-z]'; then
        encodings+=("rot13:75")
    fi
    
    # Binary detection
    if echo "$clean_content" | grep -q -E '^[01]{8,}$'; then
        local bin_len=${#clean_content}
        if [ $((bin_len % 8)) -eq 0 ]; then
            encodings+=("binary:88")
        fi
    fi
    
    # Reverse text
    local first_line=$(head -1 "$file" 2>/dev/null)
    if [ -n "$first_line" ] && [ "${#first_line}" -gt 10 ]; then
        encodings+=("reverse:65")
    fi
    
    # Morse code detection
    if echo "$content" | grep -q -E '^[\.\- /]*$'; then
        encodings+=("morse:60")
    fi
    
    # Base32 detection
    if echo "$clean_content" | grep -q -E '^[A-Z2-7]*=*$'; then
        encodings+=("base32:82")
    fi
    
    # Base58 detection (Bitcoin style)
    if echo "$clean_content" | grep -q -E '^[1-9A-HJ-NP-Za-km-z]+$'; then
        encodings+=("base58:78")
    fi
    
    # ASCII art/offset detection
    if echo "$content" | head -c 100 | grep -q -E '[^\x00-\x7F]'; then
        encodings+=("ascii_offset:70")
    fi
    
    # XOR detection (simple)
    local printable_count=$(head -c 100 "$file" | tr -cd '[:print:]' | wc -c)
    if [ "$printable_count" -lt 50 ]; then
        encodings+=("xor_simple:55")
    fi
    
    # Display detected encodings
    if [ ${#encodings[@]} -gt 0 ]; then
        log_success "Detected potential encodings:"
        for encoding in "${encodings[@]}"; do
            local enc_type=$(echo "$encoding" | cut -d':' -f1)
            local confidence=$(echo "$encoding" | cut -d':' -f2)
            echo -e "  ${GREEN}▶${NC} $enc_type (confidence: ${confidence}%)"
        done
    else
        log_warning "No specific encodings detected with high confidence"
        encodings=("unknown:0")
    fi
    
    DETECTED_ENCODINGS=("${encodings[@]}")
    printf '%s\n' "${encodings[@]}"
}

# Enhanced Base64 decoder
decode_base64() {
    local input_file="$1"
    local output_file="$2"
    
    # Try different base64 variants
    if base64 -d "$input_file" > "$output_file" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    # Try with Python for better error handling
    if python3 -c "
import base64
import sys
try:
    with open('$input_file', 'r') as f:
        data = f.read().strip()
    decoded = base64.b64decode(data, validate=True)
    with open('$output_file', 'wb') as f:
        f.write(decoded)
    sys.exit(0)
except:
    sys.exit(1)
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Enhanced Hex decoder
decode_hex() {
    local input_file="$1"
    local output_file="$2"
    
    # Clean hex data (remove spaces, newlines, etc.)
    local clean_hex=$(cat "$input_file" | tr -d ' \n\r\t' | grep -E '^[0-9A-Fa-f]*$')
    
    if [ -n "$clean_hex" ] && [ $(( ${#clean_hex} % 2 )) -eq 0 ]; then
        if echo "$clean_hex" | xxd -r -p > "$output_file" 2>/dev/null; then
            [ -s "$output_file" ] && return 0
        fi
        
        # Try with Python
        if python3 -c "
import binascii
try:
    with open('$input_file', 'r') as f:
        hex_data = ''.join(f.read().split())
    decoded = binascii.unhexlify(hex_data)
    with open('$output_file', 'wb') as f:
        f.write(decoded)
    print('success')
except Exception as e:
    print(f'error: {e}')
" 2>/dev/null; then
            [ -s "$output_file" ] && return 0
        fi
    fi
    
    return 1
}

# Enhanced URL decoder
decode_url() {
    local input_file="$1"
    local output_file="$2"
    
    # Use Python for proper URL decoding
    if python3 -c "
import urllib.parse
try:
    with open('$input_file', 'r', encoding='utf-8', errors='ignore') as f:
        data = f.read()
    decoded = urllib.parse.unquote(data)
    with open('$output_file', 'w', encoding='utf-8') as f:
        f.write(decoded)
    print('success')
except Exception as e:
    print(f'error: {e}')
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Enhanced ROT13 decoder
decode_rot13() {
    local input_file="$1"
    local output_file="$2"
    
    if tr 'A-Za-z' 'N-ZA-Mn-za-m' < "$input_file" > "$output_file" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    # Try with Python
    if python3 -c "
import codecs
try:
    with open('$input_file', 'r') as f:
        data = f.read()
    decoded = codecs.decode(data, 'rot13')
    with open('$output_file', 'w') as f:
        f.write(decoded)
    print('success')
except:
    pass
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Enhanced Reverse text decoder
decode_reverse() {
    local input_file="$1"
    local output_file="$2"
    
    if rev "$input_file" > "$output_file" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    # Perl version as backup
    if perl -ne 'print scalar reverse $_' "$input_file" > "$output_file" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Binary to text decoder
decode_binary() {
    local input_file="$1"
    local output_file="$2"
    
    local binary_data=$(cat "$input_file" | tr -d ' \n\r\t' | grep -E '^[01]{8,}$')
    
    if [ -n "$binary_data" ]; then
        # Convert binary to text (8-bit chunks)
        echo "$binary_data" | sed 's/\([01]\{8\}\)/\\x\1/g' | xargs -0 printf > "$output_file" 2>/dev/null
        
        if [ -s "$output_file" ]; then
            return 0
        fi
        
        # Try Python implementation
        if python3 -c "
try:
    with open('$input_file', 'r') as f:
        binary = ''.join(f.read().split())
    # Convert binary string to bytes
    n = int(binary, 2)
    decoded = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    with open('$output_file', 'wb') as f:
        f.write(decoded)
    print('success')
except:
    pass
" 2>/dev/null; then
            [ -s "$output_file" ] && return 0
        fi
    fi
    
    return 1
}

# HTML entity decoder
decode_html() {
    local input_file="$1"
    local output_file="$2"
    
    if python3 -c "
import html
try:
    with open('$input_file', 'r', encoding='utf-8', errors='ignore') as f:
        data = f.read()
    decoded = html.unescape(data)
    with open('$output_file', 'w', encoding='utf-8') as f:
        f.write(decoded)
    print('success')
except Exception as e:
    print(f'error: {e}')
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Morse code decoder
decode_morse() {
    local input_file="$1"
    local output_file="$2"
    
    if python3 -c "
MORSE_CODE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', 
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', 
    '9': '----.', '0': '-----', ', ': '--..--', '.': '.-.-.-', '?': '..--..', 
    '/': '-..-.', '-': '-....-', '(': '-.--.', ')': '-.--.-', ' ': '/'
}
REVERSE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}

def decode_morse(morse_code):
    words = morse_code.strip().split(' / ')
    decoded = []
    for word in words:
        letters = word.split(' ')
        decoded_word = ''.join(REVERSE_DICT.get(letter, '') for letter in letters)
        decoded.append(decoded_word)
    return ' '.join(decoded)

try:
    with open('$input_file', 'r') as f:
        morse_data = f.read().strip()
    result = decode_morse(morse_data)
    if result and len(result) > 1:
        with open('$output_file', 'w') as f:
            f.write(result)
        print('success')
except:
    pass
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Base32 decoder
decode_base32() {
    local input_file="$1"
    local output_file="$2"
    
    if python3 -c "
import base64
try:
    with open('$input_file', 'r') as f:
        data = f.read().strip()
    # Add padding if needed
    mod = len(data) % 8
    if mod:
        data += '=' * (8 - mod)
    decoded = base64.b32decode(data, casefold=True)
    with open('$output_file', 'wb') as f:
        f.write(decoded)
    print('success')
except:
    pass
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Base58 decoder (Bitcoin style)
decode_base58() {
    local input_file="$1"
    local output_file="$2"
    
    if python3 -c "
# Base58 decoding (Bitcoin style)
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_decode(s):
    num = 0
    for char in s:
        num = num * 58 + BASE58_ALPHABET.index(char)
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')

try:
    with open('$input_file', 'r') as f:
        data = f.read().strip()
    decoded = base58_decode(data)
    with open('$output_file', 'wb') as f:
        f.write(decoded)
    print('success')
except:
    pass
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# ASCII offset decoder (Caesar cipher variations)
decode_ascii_offset() {
    local input_file="$1"
    local output_file="$2"
    
    if python3 -c "
try:
    with open('$input_file', 'r', encoding='utf-8', errors='ignore') as f:
        data = f.read()
    
    # Try different offsets
    for offset in [1, -1, 13, 3, 5, 7, -3, -5]:
        decoded = ''.join(chr(ord(c) + offset) if c.isprintable() and ord(c) < 127 else c for c in data)
        if any(word in decoded.lower() for word in ['the', 'and', 'is', 'in', 'to', 'of']):
            with open('$output_file', 'w', encoding='utf-8') as f:
                f.write(decoded)
            print(f'success with offset {offset}')
            break
except:
    pass
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Simple XOR decoder
decode_xor_simple() {
    local input_file="$1"
    local output_file="$2"
    
    if python3 -c "
try:
    with open('$input_file', 'rb') as f:
        data = f.read()
    
    # Try single byte XOR keys
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode('utf-8', errors='ignore')
            if any(word in text.lower() for word in ['the', 'and', 'is', 'in', 'to']):
                with open('$output_file', 'wb') as f:
                    f.write(decoded)
                print(f'success with key {key}')
                break
        except:
            continue
except:
    pass
" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Text extraction from binary data
extract_text() {
    local input_file="$1"
    local output_file="$2"
    
    # Use strings command with minimum length
    if strings -n 8 "$input_file" > "$output_file" 2>/dev/null; then
        if [ -s "$output_file" ] && [ $(wc -l < "$output_file") -gt 2 ]; then
            return 0
        fi
    fi
    
    # Try with different encodings
    if iconv -f utf-8 -t utf-8 "$input_file" > "$output_file" 2>/dev/null; then
        [ -s "$output_file" ] && return 0
    fi
    
    return 1
}

# Try all decoders on file with priority
try_all_decoders() {
    local input_file="$1"
    local output_file="$2"
    
    # Get detected encodings with confidence scores
    local encodings=("${DETECTED_ENCODINGS[@]}")
    
    # Sort by confidence (highest first)
    IFS=$'\n' sorted_encodings=($(sort -t: -k2 -nr <<<"${encodings[*]}"))
    unset IFS
    
    # Try detected encodings first (highest confidence first)
    for encoding_info in "${sorted_encodings[@]}"; do
        local decoder=$(echo "$encoding_info" | cut -d':' -f1)
        local confidence=$(echo "$encoding_info" | cut -d':' -f2)
        
        # Skip unknown encoding
        [ "$decoder" = "unknown" ] && continue
        
        echo -e "${BLUE}[>] Trying $decoder (confidence: ${confidence}%)...${NC}"
        local temp_output="$TEMP_DIR/try_${decoder}_${CURRENT_LAYER}"
        
        if "decode_${decoder}" "$input_file" "$temp_output"; then
            cp "$temp_output" "$output_file"
            rm -f "$temp_output"
            log_success "$decoder decoding successful"
            SUCCESSFUL_DECODES=$((SUCCESSFUL_DECODES + 1))
            return 0
        fi
        rm -f "$temp_output"
    done
    
    # If no detected encodings worked, try all decoders
    local fallback_decoders=("base64" "hex" "url" "binary" "html" "rot13" "base32" "reverse" "ascii_offset" "morse" "xor_simple" "extract_text")
    
    for decoder in "${fallback_decoders[@]}"; do
        # Skip if already tried
        if printf '%s\n' "${sorted_encodings[@]}" | grep -q "^${decoder}:"; then
            continue
        fi
        
        echo -e "${BLUE}[>] Fallback: trying $decoder...${NC}"
        local temp_output="$TEMP_DIR/fallback_${decoder}_${CURRENT_LAYER}"
        
        if "decode_${decoder}" "$input_file" "$temp_output"; then
            cp "$temp_output" "$output_file"
            rm -f "$temp_output"
            log_success "$decoder decoding successful"
            SUCCESSFUL_DECODES=$((SUCCESSFUL_DECODES + 1))
            return 0
        fi
        rm -f "$temp_output"
    done
    
    log_error "All decoding attempts failed"
    return 1
}

# Deep layer analysis with progress tracking
analyze_layers() {
    local file="$1"
    local current_layer=0
    local current_file="$file"
    local layer_info=()
    
    log_info "Starting deep multi-layer analysis..."
    echo -e "${CYAN}=================================================${NC}"
    
    while [ $current_layer -lt $MAX_LAYERS ]; do
        CURRENT_LAYER=$((current_layer + 1))
        echo -e "${YELLOW}[Layer $CURRENT_LAYER] Analysis in progress...${NC}"
        
        # Detect encodings at this layer
        local encodings=$(detect_encodings "$current_file")
        local best_encoding=$(echo "$encodings" | head -1 | cut -d':' -f1)
        local best_confidence=$(echo "$encodings" | head -1 | cut -d':' -f2)
        
        layer_info+=("Layer $CURRENT_LAYER: $best_encoding ($best_confidence%)")
        
        # Try to decode to next layer
        local next_file="$TEMP_DIR/layer_${CURRENT_LAYER}"
        
        if try_all_decoders "$current_file" "$next_file"; then
            # Check if we actually got different content
            if ! cmp -s "$current_file" "$next_file" 2>/dev/null; then
                # If this is not the original input, clean up previous temp file
                if [ "$current_file" != "$file" ]; then
                    rm -f "$current_file"
                fi
                current_file="$next_file"
                echo -e "${GREEN}[✓] Layer $CURRENT_LAYER decoded successfully${NC}"
            else
                echo -e "${YELLOW}[!] No change after decoding - stopping${NC}"
                rm -f "$next_file"
                break
            fi
        else
            echo -e "${YELLOW}[!] Cannot decode further${NC}"
            break
        fi
        
        # Safety check - don't go too deep if no meaningful progress
        if [ $CURRENT_LAYER -ge $MAX_LAYERS ]; then
            echo -e "${YELLOW}[!] Maximum layer depth reached${NC}"
            break
        fi
        
        # Progress indicator
        echo -e "${BLUE}[Progress]${NC} Completed $CURRENT_LAYER layers"
        echo -e "${CYAN}-------------------------------------------------${NC}"
    done
    
    # Display comprehensive layer analysis results
    echo -e "${GREEN}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                   LAYER ANALYSIS COMPLETE                     ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    for info in "${layer_info[@]}"; do
        printf "║ %-56s ║\n" "$info"
    done
    echo "╠════════════════════════════════════════════════════════════════╣"
    printf "║ Total layers processed: %-35s ║\n" "$CURRENT_LAYER"
    printf "║ Successful decodes: %-39s ║\n" "$SUCCESSFUL_DECODES"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "$current_file"
}

# Main decoding function
decode_file() {
    local input_file="$1"
    local output_file="$2"
    
    log_info "Starting comprehensive multi-layer decoding..."
    echo -e "${CYAN}=================================================${NC}"
    
    # Analyze layers and get final decoded file
    local final_file=$(analyze_layers "$input_file")
    
    # Create final output
    if [ -f "$final_file" ] && [ -s "$final_file" ]; then
        cp "$final_file" "$output_file"
        
        # Final statistics
        local original_size=$(wc -c < "$input_file" 2>/dev/null || echo 0)
        local final_size=$(wc -c < "$output_file" 2>/dev/null || echo 0)
        
        echo -e "${GREEN}"
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║                   DECODING COMPLETED SUCCESSFULLY!           ║"
        echo "╠════════════════════════════════════════════════════════════════╣"
        printf "║ %-58s ║\n" "Input: $input_file"
        printf "║ %-58s ║\n" "Output: $output_file"
        printf "║ %-58s ║\n" "Original size: $original_size bytes"
        printf "║ %-58s ║\n" "Final size: $final_size bytes"
        printf "║ %-58s ║\n" "Layers processed: $CURRENT_LAYER"
        printf "║ %-58s ║\n" "Successful decodes: $SUCCESSFUL_DECODES"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        
        return 0
    else
        log_error "Final decoding failed - no readable content produced"
        return 1
    fi
}

# Show detailed help
show_help() {
    echo -e "${GREEN}"
    cat << "HELP"
╔════════════════════════════════════════════════════════════════╗
║                     SUPER DECODER BY ZYUS                     ║
║                  ULTIMATE DECODING FRAMEWORK                  ║
╚════════════════════════════════════════════════════════════════╝
HELP
    echo -e "${NC}"
    
    echo -e "${YELLOW}Usage:${NC} $0 [OPTIONS] <filename>"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Show version information"
    echo "  -a, --analyze       Only analyze file without decoding"
    echo "  -o, --output FILE   Specify output filename"
    echo "  -l, --layers NUM    Set maximum layers to decode (default: 50)"
    echo "  -d, --debug         Enable debug output"
    echo ""
    echo -e "${YELLOW}Supported Encodings:${NC}"
    echo "  • Base64            • Hexadecimal       • URL Encoding"
    echo "  • ROT13             • Reverse Text      • Binary Data"
    echo "  • HTML Entities     • Morse Code        • Base32"
    echo "  • Base58            • ASCII Offset      • Simple XOR"
    echo "  • Multi-layer nested encoding detection"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 encoded_file.txt"
    echo "  $0 --analyze secret_message.b64"
    echo "  $0 --output result.txt --layers 25 encoded_data.txt"
    echo "  $0 --debug complex_encoded_file"
    echo ""
    echo -e "${CYAN}Contact: $CONTACT${NC}"
    echo -e "${CYAN}Version: $VERSION${NC}"
}

# Show version information
show_version() {
    echo -e "${GREEN}"
    cat << "VERSION"
╔════════════════════════════════════════════════════════════════╗
║                     SUPER DECODER BY ZYUS                     ║
╚════════════════════════════════════════════════════════════════╝
VERSION
    echo -e "${NC}"
    echo -e "${YELLOW}Version:${NC} $VERSION"
    echo -e "${YELLOW}Author:${NC} $AUTHOR"
    echo -e "${YELLOW}Contact:${NC} $CONTACT"
    echo -e "${YELLOW}Features:${NC}"
    echo "  - Multi-format decoding support"
    echo "  - Deep layer analysis (up to 50 layers)"
    echo "  - Automatic encoding detection"
    echo "  - Cross-platform compatibility"
    echo "  - Advanced error recovery"
}

# Main function with enhanced argument parsing
main() {
    local input_file=""
    local output_file=""
    local analyze_only=false
    local debug_mode=false
    
    display_banner
    
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
            -l|--layers)
                MAX_LAYERS="$2"
                shift 2
                ;;
            -d|--debug)
                debug_mode=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
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
        log_error "No input file specified!"
        show_help
        exit 1
    fi
    
    # Check if file exists and is readable
    if [ ! -f "$input_file" ]; then
        log_error "File '$input_file' not found!"
        exit 1
    fi
    
    if [ ! -r "$input_file" ]; then
        log_error "File '$input_file' is not readable!"
        exit 1
    fi
    
    # Set default output file if not specified
    if [ -z "$output_file" ]; then
        local base_name=$(basename "$input_file")
        local extension="${base_name##*.}"
        local name="${base_name%.*}"
        output_file="${name}_decoded.${extension}"
    fi
    
    echo -e "${GREEN}[+] Input file:${NC}  $input_file"
    echo -e "${GREEN}[+] Output file:${NC} $output_file"
    echo -e "${GREEN}[+] Max layers:${NC}  $MAX_LAYERS"
    echo -e "${GREEN}[+] Mode:${NC}        $([ "$analyze_only" = true ] && echo "Analysis Only" || echo "Full Decode")"
    echo ""
    
    # Check dependencies and create temp directory
    if ! check_dependencies; then
        log_error "Dependency check failed"
        exit 1
    fi
    
    create_temp_dir
    
    if [ "$analyze_only" = true ]; then
        # Only analyze
        log_info "Starting analysis mode..."
        analyze_layers "$input_file" > /dev/null
        echo -e "${CYAN}[+] Analysis complete. Use without --analyze to decode.${NC}"
    else
        # Analyze and decode
        if decode_file "$input_file" "$output_file"; then
            # Show final preview
            echo -e "${CYAN}[+] Final decoded content preview:${NC}"
            echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
            head -15 "$output_file" 2>/dev/null | cat -n | head -15
            echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}[✓] Decoding completed successfully!${NC}"
            echo ""
            echo -e "${YELLOW}Next steps:${NC}"
            echo "  View full output: cat '$output_file'"
            echo "  Analyze further: $0 --analyze '$output_file'"
            echo ""
            echo -e "${CYAN}For any issues or advanced decoding needs, contact: $CONTACT${NC}"
        else
            log_error "Decoding process failed"
            echo -e "${YELLOW}Suggestions:${NC}"
            echo "  • Try with --analyze flag first to see detected encodings"
            echo "  • Check if the file is corrupted or uses unsupported encoding"
            echo "  • Increase layer limit with --layers 100"
            echo "  • Contact $CONTACT for support"
            exit 1
        fi
    fi
}

# Run main function with all arguments
main "$@"
