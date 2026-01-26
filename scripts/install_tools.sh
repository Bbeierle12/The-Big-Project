#!/usr/bin/env bash
set -euo pipefail

echo "=== NetSec Orchestrator — Tool Installer ==="
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    else
        echo "Unsupported package manager"
        exit 1
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    PKG_MGR="brew"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

install_pkg() {
    local name=$1
    echo "Installing $name..."
    case $PKG_MGR in
        apt)    sudo apt-get install -y "$name" ;;
        dnf)    sudo dnf install -y "$name" ;;
        pacman) sudo pacman -S --noconfirm "$name" ;;
        brew)   brew install "$name" ;;
    esac
}

# Install tools
TOOLS=(nmap suricata zeek tshark clamav fail2ban)

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "✓ $tool already installed"
    else
        install_pkg "$tool" || echo "✗ Failed to install $tool (skipping)"
    fi
done

# ClamAV special handling
if command -v freshclam &>/dev/null; then
    echo "Updating ClamAV signatures..."
    sudo freshclam || echo "ClamAV update failed (may need manual config)"
fi

echo ""
echo "=== Installation complete ==="
echo "Run 'python -m netsec' to start the orchestrator."
