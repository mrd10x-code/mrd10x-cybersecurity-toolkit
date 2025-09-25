#!/bin/bash
echo "Installing MR.D10X Cybersecurity Toolkit..."
echo "=========================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required!"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install requests

# Make executable
chmod +x mrd10x-toolkit.py

# Create symlink
sudo cp mrd10x-toolkit.py /usr/local/bin/mrd10x-toolkit 2>/dev/null || echo "Skipping symlink creation"

echo "✅ Installation complete!"
echo "🚀 Run with: mrd10x-toolkit"
echo "🔒 Remember: For educational use only!"