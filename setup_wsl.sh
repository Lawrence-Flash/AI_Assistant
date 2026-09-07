#!/usr/bin/env bash
# ==============================================================================
# Enterprise AI-Cybersecurity Assistant: One-Click WSL Setup & Verification
# ==============================================================================

set -e

echo -e "\033[1;36m========================================================\033[0m"
echo -e "\033[1;36m  🛡️  AI-Cybersecurity Assistant v2.5: WSL Setup Script \033[0m"
echo -e "\033[1;36m========================================================\033[0m"

# 1. Check OS
if [ "$(uname -s)" != "Linux" ]; then
    echo -e "\033[1;31m[!] This script is meant to be run inside WSL (Ubuntu/Debian) on Linux.\033[0m"
    exit 1
fi

echo -e "\n\033[1;32m[Step 1/4] Updating package lists & installing system dependencies (nmap, python3)...\033[0m"
sudo apt-get update -y
sudo apt-get install -y nmap python3 python3-pip python3-venv dnsutils

# 2. Virtual Environment Setup
echo -e "\n\033[1;32m[Step 2/4] Setting up Linux Virtual Environment (.venv_wsl)...\033[0m"
if [ ! -d ".venv_wsl" ]; then
    python3 -m venv .venv_wsl
    echo -e "\033[0;32mCreated .venv_wsl directory.\033[0m"
fi

source .venv_wsl/bin/activate
python3 -m pip install --upgrade pip

# 3. Install Python Dependencies
echo -e "\n\033[1;32m[Step 3/4] Installing Python requirements...\033[0m"
pip install -r requirements.txt
pip install -e . --no-deps || true

# 4. Run Verification Test Suite
echo -e "\n\033[1;32m[Step 4/4] Executing Automated Unit Test Suite...\033[0m"
python -m unittest tests/test_suite.py

echo -e "\n\033[1;36m========================================================\033[0m"
echo -e "\033[1;32m  🎉 SETUP & VERIFICATION COMPLETED SUCCESSFULLY!        \033[0m"
echo -e "\033[1;36m========================================================\033[0m"
echo -e "\nTo run the tools in WSL:"
echo -e "  1. Activate virtualenv:  \033[1;33msource .venv_wsl/bin/activate\033[0m"
echo -e "  2. Launch Web Dashboard: \033[1;33mpython app.py\033[0m"
echo -e "     -> Open Windows browser at: \033[1;36mhttp://127.0.0.1:5001\033[0m"
echo -e "  3. Or launch Terminal:   \033[1;33mpython cli.py\033[0m\n"
