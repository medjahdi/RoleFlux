#!/usr/bin/env bash
set -e

echo "🚀 Bootstrapping RoleFlux Local Development Environment..."

# 1. Python Backend Setup
echo "🐍 Setting up Python Virtual Environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created."
else
    echo "⚡ Virtual environment already exists."
fi

source venv/bin/activate
echo "📦 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt
pip install pytest flake8 bandit
echo "✅ Python dependencies installed."

# 2. Next.js Dashboard Setup
echo "⚛️ Setting up Next.js Dashboard..."
if [ -d "dashboard/web" ]; then
    cd dashboard/web
    npm install
    cd ../..
    echo "✅ Next.js dependencies installed."
else
    echo "⚠️ Warning: dashboard/web directory not found."
fi

echo ""
echo "🎉 Setup Complete! You are ready to develop."
echo "To start the attack simulator:"
echo "  source venv/bin/activate && python3 attack-simulator/run_simulation.py"
echo "To start the dashboard:"
echo "  cd dashboard/web && npm run dev"
