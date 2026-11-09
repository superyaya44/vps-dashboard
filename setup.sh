#!/bin/bash
set -e
cd "$(dirname "$0")"
python3 -m venv venv
./venv/bin/pip install flask psutil --quiet
cp -n services.example.json services.json 2>/dev/null || true
echo "Setup complete. Edit services.json with your services, then run: ./venv/bin/python api.py"
