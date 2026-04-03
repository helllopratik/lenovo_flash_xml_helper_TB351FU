#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

chmod +x "$SCRIPT_DIR/run_lenovo_decrypt.py"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install pycryptodome

cat <<EOF
Lenovo Flash XML Helper is ready.

Run it with:
  $VENV_DIR/bin/python $SCRIPT_DIR/run_lenovo_decrypt.py --package-dir /path/to/rom --output-dir /path/to/output
EOF
