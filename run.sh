#!/bin/bash
# OPNsense Security Auditor - Run Script

set -e

echo "=========================================="
echo "OPNsense Security Auditor"
echo "=========================================="
echo ""

# Check if .env exists
if [ ! -f .env ]; then
    echo "❌ Error: .env file not found!"
    echo ""
    echo "Please create .env file from .env.example:"
    echo "  cp .env.example .env"
    echo "  nano .env"
    echo ""
    exit 1
fi

# Source .env
source .env

# Validate required variables
if [ -z "$OPNSENSE_HOST" ] || [ -z "$OPNSENSE_API_KEY" ] || [ -z "$OPNSENSE_API_SECRET" ]; then
    echo "❌ Error: Required environment variables not set!"
    echo ""
    echo "Please configure the following in .env:"
    echo "  - OPNSENSE_HOST"
    echo "  - OPNSENSE_API_KEY"
    echo "  - OPNSENSE_API_SECRET"
    echo ""
    exit 1
fi

echo "Configuration:"
echo "  OPNsense Host: $OPNSENSE_HOST"
echo "  Scan Network: ${SCAN_NETWORK:-192.168.1.0/24}"
echo ""

# Create reports directory if not exists
mkdir -p reports

# Build Docker image if not exists
if [ -z "$(docker images -q opnsensedashboardtester_opnsense-auditor 2> /dev/null)" ]; then
    echo "🔨 Building Docker image..."
    docker-compose build
    echo ""
fi

# Run audit
echo "🚀 Starting security audit..."
echo ""

docker-compose run --rm opnsense-auditor

echo ""
echo "✅ Audit completed!"
echo ""
echo "Reports are available in: ./reports/"
echo ""

# Find latest HTML report
LATEST_HTML=$(ls -t reports/*.html 2>/dev/null | head -n1)

if [ -n "$LATEST_HTML" ]; then
    echo "📊 Latest HTML report: $LATEST_HTML"
    echo ""

    # Ask to open report
    read -p "Open HTML report in browser? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v open &> /dev/null; then
            open "$LATEST_HTML"
        elif command -v xdg-open &> /dev/null; then
            xdg-open "$LATEST_HTML"
        else
            echo "Please open $LATEST_HTML manually"
        fi
    fi
fi

echo ""
echo "=========================================="
