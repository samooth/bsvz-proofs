#!/usr/bin/env bash
# Cross-check bsvz-zkp against the pure-Node AnchorChain reference (ref.js).
# Verifies byte-for-byte compatibility of the generators, challenge, commit,
# and a fixed-nonce Schnorr proof.
set -euo pipefail
cd "$(dirname "$0")/.."

zig build crosscheck 2>&1 | grep -E '^(G|H|BP_U|g0|g1|h0|h1|challenge|commit\(1234,5678\)|schnorr\.a|schnorr\.s):' > /tmp/bsvz-zkp-crosscheck-zig.out
node crosscheck/ref.js > /tmp/bsvz-zkp-crosscheck-js.out

if diff -u /tmp/bsvz-zkp-crosscheck-js.out /tmp/bsvz-zkp-crosscheck-zig.out; then
  echo "crosscheck OK: bsvz-zkp matches the AnchorChain reference"
else
  echo "crosscheck FAILED: output differs" >&2
  exit 1
fi
