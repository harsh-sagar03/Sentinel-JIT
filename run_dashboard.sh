#!/bin/zsh
# Launches the Sentinel-JIT Streamlit dashboard
# Usage: bash run_dashboard.sh

echo "🛡️  Starting Sentinel-JIT Dashboard..."
echo "   Open: http://localhost:8501"
echo ""
python3 -m streamlit run app.py
