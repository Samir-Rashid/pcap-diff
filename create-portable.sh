#!/usr/bin/env bash
# Create truly portable pcap-diff executable
# Run this script from within nix develop .#impure

set -euo pipefail

echo "🚀 Creating portable pcap-diff executable..."

if ! uv list | grep -q pyinstaller; then
  echo "📦 Installing PyInstaller..."
  uv add --dev pyinstaller
fi

echo "🔨 Building standalone executable..."
uv run pyinstaller --onefile --name pcap-diff src/pcap_diff/main.py

# Get file size
SIZE=$(du -h dist/pcap-diff | cut -f1)

echo "✅ Portable executable created!"
echo "📁 Location: dist/pcap-diff"
echo "📏 Size: $SIZE"
echo ""
echo "📋 To distribute:"
echo "   1. Copy dist/pcap-diff to target system"
echo "   2. Run: chmod +x pcap-diff && ./pcap-diff"
echo ""
echo "💡 This executable includes Python interpreter + all dependencies"
echo "💡 Works on any Linux x86_64 system (no Python required)"
