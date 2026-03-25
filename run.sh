#!/bin/bash
# run.sh — build-free runner; accepts optional custom input dir
# Usage: ./run.sh              (scans input/)
#        ./run.sh /other/dir   (scans that dir instead)
set -e
mkdir -p output
INPUT_DIR="${1:-input}"
go run main.go \
  --input  "$INPUT_DIR" \
  --output output/report.json \
  --workers 4 \
  --config config/rules.json
echo "Done — see output/report.json"
