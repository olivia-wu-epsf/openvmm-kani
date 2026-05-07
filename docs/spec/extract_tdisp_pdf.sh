#!/usr/bin/env bash
# Extract text from the TDISP spec PDF to a sibling .txt file.
set -euo pipefail

SRC="docs/spec/TEE Device Interface Security Protocol - TDISP - v2022-07-27 (3).pdf"
DST="docs/spec/TEE Device Interface Security Protocol - TDISP - v2022-07-27 (3).txt"

if ! command -v pdftotext >/dev/null 2>&1; then
    echo "error: pdftotext not found; install poppler-utils" >&2
    exit 1
fi

pdftotext -layout "$SRC" "$DST"
echo "Wrote: $DST ($(wc -l <"$DST") lines, $(wc -c <"$DST") bytes)"
