#!/usr/bin/env bash
# Start pentest-tool (backend + frontend) via WSL.
# Loads nvm explicitly because ~/.bashrc exits early for non-interactive shells.

set -e

export NVM_DIR="/home/farhad/.nvm"
if [ -s "$NVM_DIR/nvm.sh" ]; then
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh"
  nvm use default >/dev/null 2>&1 || true
fi

cd /mnt/c/Users/farha/pentest-tool

if ! command -v npm >/dev/null 2>&1; then
  echo "ERROR: npm tidak ditemukan. Periksa instalasi node/nvm di WSL."
  exit 1
fi

echo "npm: $(npm --version)  node: $(node -v)"
exec npm run dev