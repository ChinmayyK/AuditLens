#!/bin/bash
set -e

echo "Installing ShieldSentinel scanner tools..."

TOOLS_DIR="/scanner-tools"
WORDLISTS_DIR="$TOOLS_DIR/wordlists"
TEMPLATES_DIR="$TOOLS_DIR/nuclei-templates"

mkdir -p "$WORDLISTS_DIR" "$TEMPLATES_DIR"

# Wordlists: FFUF, Gobuster, and similar tools use WORDLIST_PATH (default
# /scanner-tools/wordlists/common.txt). The API image also downloads
# common.txt at build time; this script is for bare-metal / extra lists.

# Download common wordlist
echo "Downloading wordlists..."
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o "$WORDLISTS_DIR/common.txt"

curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt \
    -o "$WORDLISTS_DIR/directories.txt"

curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt \
    -o "$WORDLISTS_DIR/sqli-payloads.txt"

curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/XSS-Jhaddix.txt \
    -o "$WORDLISTS_DIR/xss-payloads.txt"

# Update nuclei templates
echo "Updating Nuclei templates..."
nuclei -update-templates -templates-directory "$TEMPLATES_DIR" || true

echo "All tools installed successfully."
