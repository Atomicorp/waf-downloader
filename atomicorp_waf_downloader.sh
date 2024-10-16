#!/bin/bash

# Atomicorp WAF Rule Downloader
# License: The Unlicense (https://unlicense.org/)

VERSION_URL="https://updates.atomicorp.com/channels/rules/VERSION"
APACHE_RULES_BASE_URL="https://updates.atomicorp.com/channels/rules/subscription/modsec"
NGINX_RULES_BASE_URL="https://updates.atomicorp.com/channels/rules/nginx-latest/nginx-waf"
CONFIG_FILE="waf_rule_config"  # Adjusted path handling below
TMP_FILE="/tmp/atomicorp_version"
TMP_DIR=$(mktemp -d -t atomicorp_modsec_XXXXXX)

# Default WAF rule classes
DEFAULT_RULE_CLASSES=(
    "MODSEC_00_ANTIEVASION"
    "MODSEC_03_DOS"
    "MODSEC_10_ANTIMALWARE"
    "MODSEC_10_RULES"
    "MODSEC_11_ADV_RULES"
    "MODSEC_12_ADV_XSS_RULES"
    "MODSEC_12_BRUTE"
    "MODSEC_20_USERAGENTS"
    "MODSEC_30_ANTISPAM"
    "MODSEC_50_ROOTKITS"
    "MODSEC_60_RECONS"
    "MODSEC_61_RECONS_DLP"
    "MODSEC_99_JITP"
    "MODSEC_99_MALWARE_OUTPUT"
)

# Usage function to display help
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -c                 Check the latest MODSEC_VERSION"
    echo "  -d                 Download WAF rules for the selected rule classes"
    echo "  -t RULE_TYPE       Rule type: 'apache' or 'nginx' (default: apache)"
    echo "  -u USERNAME        Username for authentication"
    echo "  -p PASSWORD        Password for authentication"
    echo "  -o OUTPUT_DIR      Directory to store the extracted contents (default: current directory)"
    echo "  -r RULE_CLASSES    Comma-separated list of WAF rule classes to download (default: predefined set)"
    echo "  -l                 List all available rule classes from waf_rule_config"
    echo "  -h                 Show this help message"
    echo
    echo "Example:"
    echo "  $0 -d -t apache -u your_username -p 'your_password' -o /path/to/output"
    exit 1
}

# Function to fetch the latest MODSEC_VERSION
get_modsec_version() {
    echo "Fetching the latest version from $VERSION_URL ..."
    local tmp_version_file="$TMP_DIR/version.txt"

    if curl -s -o "$tmp_version_file" "$VERSION_URL"; then
        MODSEC_VERSION=$(grep -oP 'MODSEC_VERSION=\K[^\n]+' "$tmp_version_file")
        echo "Latest MODSEC_VERSION: $MODSEC_VERSION"
    else
        echo "Error: Unable to fetch version information!" >&2
        exit 1
    fi
}

# Function to determine the extracted directory path (modsec or nginx-waf)
get_extracted_dir() {
    if [ -d "$TMP_DIR/modsec" ]; then
        echo "$TMP_DIR/modsec"
    elif [ -d "$TMP_DIR/nginx-waf" ]; then
        echo "$TMP_DIR/nginx-waf"
    else
        echo "Error: Neither modsec nor nginx-waf directory found in the extracted files." >&2
        exit 1
    fi
}

# Function to download the selected WAF rules
download_and_extract_config() {
    get_modsec_version
    local rule_url
    local bz2_file="$TMP_DIR/waf_rules_${MODSEC_VERSION}.tar.bz2"

    if [ "$RULE_TYPE" == "apache" ]; then
        rule_url="${APACHE_RULES_BASE_URL}-${MODSEC_VERSION}.tar.bz2"
    elif [ "$RULE_TYPE" == "nginx" ]; then
        rule_url="${NGINX_RULES_BASE_URL}-${MODSEC_VERSION}.tar.bz2"
    else
        echo "Error: Invalid rule type. Use 'apache' or 'nginx'." >&2
        exit 1
    fi

    echo "Downloading WAF rules from $rule_url to $bz2_file ..."
    if curl -u "$USERNAME:$PASSWORD" -o "$bz2_file" "$rule_url"; then
        echo "Extracting $bz2_file to $TMP_DIR ..."
        tar -xjf "$bz2_file" -C "$TMP_DIR" || exit 1
    else
        echo "Error: Failed to download WAF rules. Please check your credentials or network connection." >&2
        exit 1
    fi
}

# Function to list all available rule classes from waf_rule_config
list_rule_classes() {
    download_and_extract_config
    local extracted_dir
    extracted_dir=$(get_extracted_dir)

    if [ -f "$extracted_dir/$CONFIG_FILE" ]; then
        echo "Available rule classes from waf_rule_config:"
        awk -F',' 'NR > 1 {print $4}' "$extracted_dir/$CONFIG_FILE" | sort -u | sed '/^$/d'
    else
        echo "Error: Config file not found at $extracted_dir/$CONFIG_FILE" >&2
        exit 1
    fi

    echo "Cleanup temporary files..."
    rm -rf "$TMP_DIR"
}

# Function to download WAF rules based on selected classes
download_waf_rules() {
    download_and_extract_config
    local extracted_dir
    extracted_dir=$(get_extracted_dir)

    if [ -f "$extracted_dir/$CONFIG_FILE" ]; then
        echo "Processing waf_rule_config..."
        while IFS=',' read -r version description filename variable default severity _; do
            if [[ " ${RULE_CLASSES[@]} " =~ " $variable " && "$default" == "yes" ]]; then
                if [ -f "$extracted_dir/$filename" ]; then
                    echo "Copying $filename to $OUTPUT_DIR..."
                    cp "$extracted_dir/$filename" "$OUTPUT_DIR/" || exit 1
                else
                    echo "Warning: $filename not found, skipping..."
                fi
            fi
        done < "$extracted_dir/$CONFIG_FILE"
    else
        echo "Error: Config file not found at $extracted_dir/$CONFIG_FILE" >&2
        exit 1
    fi

    echo "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}

# Parse command-line arguments
CHECK_VERSION=0
DOWNLOAD_RULES=0
LIST_CLASSES=0
USERNAME=""
PASSWORD=""
OUTPUT_DIR="."
RULE_CLASSES=("${DEFAULT_RULE_CLASSES[@]}")
RULE_TYPE="apache"  # Default to apache

# If no arguments are provided, display the usage information
if [ $# -eq 0 ]; then
    usage
fi

while getopts "cdu:p:o:r:t:lh" opt; do
    case "$opt" in
        c) CHECK_VERSION=1 ;;
        d) DOWNLOAD_RULES=1 ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        r) IFS=',' read -r -a RULE_CLASSES <<< "$OPTARG" ;;
        t) RULE_TYPE="$OPTARG" ;;
        l) LIST_CLASSES=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Ensure the output directory exists or create it
if [ "$DOWNLOAD_RULES" -eq 1 ] && [ ! -d "$OUTPUT_DIR" ]; then
    echo "Creating output directory: $OUTPUT_DIR"
    if ! mkdir -p "$OUTPUT_DIR"; then
        echo "Error: Failed to create output directory $OUTPUT_DIR" >&2
        exit 1
    fi
fi

# Main script logic
if [ "$CHECK_VERSION" -eq 1 ]; then
    get_modsec_version
fi

if [ "$LIST_CLASSES" -eq 1 ]; then
    list_rule_classes
fi

if [ "$DOWNLOAD_RULES" -eq 1 ]; then
    if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
        echo "Error: Username and password are required to download the rules." >&2
        usage
    fi

    download_waf_rules
fi

# Cleanup temporary version file
rm -f "$TMP_FILE"
