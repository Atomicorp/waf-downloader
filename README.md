# Atomicorp WAF Rule Downloader

This project provides a **Bash script** to download, extract, and manage **Apache or NGINX WAF rules** from Atomicorp. The script allows users to **select rule classes**, list available rules, and customize which rules to download based on their needs for both open source and commercial projects. 

---

## Features

- Download **Apache** or **NGINX** WAF rules.
- Select specific WAF **rule classes** to download.
- List available rule classes from the configuration.
- Handle **missing files** gracefully by skipping them.
- Default to **predefined rule classes** if no custom classes are provided.

---

## Prerequisites

- **Bash Shell** (on Linux or macOS)
- **curl** installed
- Atomicorp **username and password** for access

---

## Usage

```bash
./atomicorp_waf_downloader.sh [OPTIONS]

### Options

- `-c`  
  Check the latest MODSEC version.

- `-d`  
  Download WAF rules for the selected rule classes.

- `-t`  
  Select the rule type: `apache` or `nginx` (default: apache).

- `-u`  
  Provide the username for authentication.

- `-p`  
  Provide the password for authentication.

- `-o`  
  Set the output directory to store the extracted contents (default: current directory).

- `-r`  
  Provide a comma-separated list of WAF rule classes to download (default: predefined set).

- `-l`  
  List all available rule classes from the configuration.

- `-h`  
  Show the help message.


## Default Rule Classes

If no rule classes are specified with the `-r` option, the following **default rule classes** will be used:

- `MODSEC_00_ANTIEVASION`
- `MODSEC_03_DOS`
- `MODSEC_10_ANTIMALWARE`
- `MODSEC_10_RULES`
- `MODSEC_11_ADV_RULES`
- `MODSEC_12_ADV_XSS_RULES`
- `MODSEC_12_BRUTE`
- `MODSEC_20_USERAGENTS`
- `MODSEC_30_ANTISPAM`
- `MODSEC_50_ROOTKITS`
- `MODSEC_60_RECONS`
- `MODSEC_61_RECONS_DLP`
- `MODSEC_99_JITP`
- `MODSEC_99_MALWARE_OUTPUT`


## Examples

1. **Check the latest MODSEC version**:
   ```bash
   ./atomicorp_waf_downloader.sh -c

2. **Download Apache WAF rules using predefined classes**:
   ```bash
   ./atomicorp_waf_downloader.sh -d -t apache -u your_username -p 'your_password' -o /path/to/output

3. **Download NGINX WAF rules with custom rule classes**:
   ```bash
   ./atomicorp_waf_downloader.sh -d -t nginx -u your_username -p 'your_password' -o /path/to/output -r MODSEC_10_RULES,MODSEC_12_BRUTE

4. **List all available rule classes**:
   ```bash
   ./atomicorp_waf_downloader.sh -l







