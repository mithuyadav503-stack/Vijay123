#!/data/data/com.termux/files/usr/bin/bash
# ULTIMATE AI AGENT - Termux setup script
set -e
cd "$(dirname "$0")"

echo "[*] Updating Termux packages..."
pkg update -y >/dev/null 2>&1 || true

echo "[*] Ensuring Python is installed..."
pkg install -y python >/dev/null 2>&1 || pkg install python

echo "[*] Ensuring storage permission (Downloads access)..."
if [ ! -d "$HOME/storage/downloads" ]; then
    echo "    Running termux-setup-storage - please ALLOW the permission dialog."
    termux-setup-storage || true
    sleep 2
fi
if [ ! -d "$HOME/storage/downloads" ]; then
    echo "    [!] Downloads still unavailable. Grant storage permission and re-run setup.sh"
fi

echo "[*] Creating project directories..."
mkdir -p config data logs backups reports
for d in data logs backups reports; do touch "$d/.gitkeep"; done

echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

echo "[*] Verifying Python syntax of all modules..."
python -m py_compile main.py core/*.py tools/*.py tests/*.py
echo "    All modules compile OK."

echo "[*] Running offline self-tests..."
python tests/selftest.py

echo ""
echo "[✓] Setup complete. Launch the agent with:"
echo "    cd ~/storage/downloads/ULTIMATE_AI_AGENT && bash run.sh"
