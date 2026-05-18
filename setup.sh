#!/usr/bin/env bash
# SIEM Platform - One-shot setup script
# Run this once on a fresh Ubuntu/Debian machine before docker compose up
set -e

echo "======================================================"
echo "  SIEM Platform Setup"
echo "======================================================"

# 1. Required kernel param for Elasticsearch
echo ">>> Setting vm.max_map_count for Elasticsearch..."
sudo sysctl -w vm.max_map_count=262144
# Make it permanent
grep -q "vm.max_map_count" /etc/sysctl.conf || echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# 2. Create .env if missing
if [ ! -f .env ]; then
    cp .env.example .env
    echo ">>> Created .env from .env.example"
    echo "    Edit .env to add SLACK_WEBHOOK_URL if you want Slack alerts"
fi

# 3. Make sure Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "ERROR: Docker is not running. Start Docker first."
    exit 1
fi

echo ""
echo "======================================================"
echo "  Setup complete! Now run:"
echo "    docker compose up -d --build"
echo ""
echo "  Then open: http://localhost"
echo "  Health:    http://localhost/health"
echo "======================================================"
