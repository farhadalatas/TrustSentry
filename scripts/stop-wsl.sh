#!/usr/bin/env bash
# Stop pentest-tool processes running inside WSL.

pkill -f "pentest-tool" 2>/dev/null || true
echo "Pentest-tool dihentikan."