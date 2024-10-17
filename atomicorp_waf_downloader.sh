#!/bin/bash

# Atomicorp WAF Rule Downloader
# License: The Unlicense (https://unlicense.org/)

VERSION="1.0.0"
VERSION_URL="https://updates.atomicorp.com/channels/rules/VERSION"
APACHE_RULES_BASE_URL="https://updates.atomicorp.com/channels/rules/subscription/modsec"
NGINX_RULES_BASE_URL="https://updates.atomicorp.com/channels/rules/nginx-latest/nginx-waf"
CONFIG_FILE="waf_rule_config"
TMP_DIR=$(mktemp -d -t atomicorp_modsec_XXXXXX)

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

# Cleanup function to remove temporary files
cleanup() {
    echo "Cleaning up temporary files..."
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

usage() {
    echo "Atomicorp WAF Rule Downloader - Version $VERSION"
    echo  
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -c                 Check the latest MODSEC_VERSION"
    echo "  -d                 Download WAF rules for selected rule classes"
    echo "  -t RULE_TYPE       Rule type: 'apache' or 'nginx' (default: apache)"
    echo "  -u USERNAME        Username for authentication"
    echo "  -p PASSWORD        Password for authentication"
    echo "  -o OUTPUT_DIR      Directory to store the extracted contents"
    echo "  -r RULE_CLASSES    Comma-separated list of rule classes (default: predefined set)"
    echo "  -l                 List available rule classes from waf_rule_config"
    echo "  -h                 Show this help message"
    exit 1
}

get_modsec_version() {
    echo "Fetching latest version from $VERSION_URL ..."
    if ! curl -s -o "$TMP_DIR/version.txt" "$VERSION_URL"; then
        echo "Error: Unable to fetch version information!" >&2
        exit 1
    fi
    MODSEC_VERSION=$(grep -oP 'MODSEC_VERSION=\K[^\n]+' "$TMP_DIR/version.txt")
    echo "Latest MODSEC_VERSION: $MODSEC_VERSION"
}

get_extracted_dir() {
    if [ -d "$TMP_DIR/modsec" ]; then
        echo "$TMP_DIR/modsec"
    elif [ -d "$TMP_DIR/nginx-waf" ]; then
        echo "$TMP_DIR/nginx-waf"
    else
        echo "Error: Extracted directory not found." >&2
        exit 1
    fi
}

download_and_extract_config() {
    get_modsec_version
    local rule_url bz2_file
    bz2_file="$TMP_DIR/waf_rules_${MODSEC_VERSION}.tar.bz2"

    case "$RULE_TYPE" in
        apache) rule_url="${APACHE_RULES_BASE_URL}-${MODSEC_VERSION}.tar.bz2" ;;
        nginx) rule_url="${NGINX_RULES_BASE_URL}-${MODSEC_VERSION}.tar.bz2" ;;
        *) echo "Error: Invalid rule type." >&2; exit 1 ;;
    esac

    echo "Downloading WAF rules..."
    if ! curl -u "$USERNAME:$PASSWORD" -o "$bz2_file" "$rule_url"; then
        echo "Error: Download failed. Check credentials or network." >&2
        exit 1
    fi

    echo "Extracting $bz2_file..."
    if ! tar -xjf "$bz2_file" -C "$TMP_DIR"; then
        echo "Error: Extraction failed." >&2
        exit 1
    fi
}

list_rule_classes() {
    download_and_extract_config
    local extracted_dir
    extracted_dir=$(get_extracted_dir)

    if [ -f "$extracted_dir/$CONFIG_FILE" ]; then
        echo "Available rule classes:"
        awk -F',' 'NR > 1 && $2 != "NULL" {printf "%s - %s \n", $4, $2}' \
            "$extracted_dir/$CONFIG_FILE" | sort -u
    else
        echo "Error: Config file not found." >&2
        exit 1
    fi
}

download_waf_rules() {
    download_and_extract_config
    local extracted_dir
    extracted_dir=$(get_extracted_dir)

    if [ -f "$extracted_dir/$CONFIG_FILE" ]; then
        echo "Processing waf_rule_config..."
        while IFS=',' read -r version desc filename var default sev _; do
            if [[ " ${RULE_CLASSES[*]} " =~ " $var " && "$default" == "yes" ]]; then
                if [ -f "$extracted_dir/$filename" ]; then
                    echo "Copying $filename to $OUTPUT_DIR..."
                    cp "$extracted_dir/$filename" "$OUTPUT_DIR/" || exit 1
                else
                    echo "Warning: $filename not found, skipping..."
                fi
            fi
        done < "$extracted_dir/$CONFIG_FILE"
    else
        echo "Error: Config file not found." >&2
        exit 1
    fi
}

# Default values
CHECK_VERSION=0
DOWNLOAD_RULES=0
LIST_CLASSES=0
USERNAME=""
PASSWORD=""
OUTPUT_DIR="."
RULE_TYPE="apache"
RULE_CLASSES=("${DEFAULT_RULE_CLASSES[@]}")

# Parse options
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

# Ensure output directory exists
if [ "$DOWNLOAD_RULES" -eq 1 ] && [ ! -d "$OUTPUT_DIR" ]; then
    echo "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR" || { echo "Error: Unable to create directory." >&2; exit 1; }
fi

# Main logic
if [ "$CHECK_VERSION" -eq 1 ]; then
    get_modsec_version
elif [ "$LIST_CLASSES" -eq 1 ]; then
    list_rule_classes
elif [ "$DOWNLOAD_RULES" -eq 1 ]; then
    if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
        echo "Error: Username and password are required." >&2
        usage
    fi
    download_waf_rules
else
    # If no valid operation was requested, show the usage menu
    usage
fi


if [ "$DOWNLOAD_RULES" -eq 1 ]; then
    if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
        echo "Error: Username and password are required." >&2
        usage
    fi
    download_waf_rules
fi
