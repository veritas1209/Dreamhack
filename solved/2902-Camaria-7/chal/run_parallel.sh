#!/usr/bin/env bash
# Decrypt all blocks in parallel across CPU cores.
#
#   ./run_parallel.sh [JOBS]
#
# JOBS defaults to the number of CPU cores. Each block is an independent task,
# so wall-clock time ~= (num_blocks * per_block_seconds) / JOBS.
# Re-running is safe: already-decrypted blocks (results/NNNNN.bin) are skipped.
set -euo pipefail

export CHAL="${CHAL:-./chal}"
export ENC="${ENC:-./hello_png.enc}"
export OUTDIR="${OUTDIR:-./results}"
export TMPDIR="${TMPDIR:-/tmp}"

JOBS="${1:-$(nproc)}"

# number of 16-byte blocks; we decrypt indices 1..N-1 (index 0 is internal CONST)
NBLK=$(( $(stat -c%s "$ENC") / 16 ))
LAST=$(( NBLK - 1 ))
echo "file has $NBLK cipher blocks; decrypting indices 1..$LAST with $JOBS jobs"

mkdir -p "$OUTDIR"
chmod +x "$CHAL" 2>/dev/null || true

seq 1 "$LAST" | xargs -P "$JOBS" -I{} python3 decrypt_block.py {}

echo "done. assembling..."
python3 assemble.py
