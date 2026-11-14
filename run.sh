#!/data/data/com.termux/files/usr/bin/bash
# ULTIMATE AI AGENT - launcher
cd "$(dirname "$0")"
mkdir -p data logs backups reports
exec python main.py
