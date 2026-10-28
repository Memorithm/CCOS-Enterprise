#!/usr/bin/env bash
# Fetch sentence-transformers/all-MiniLM-L6-v2 at a pinned revision and verify sha256.
# Usage: ./fetch-model.sh <dest-dir>
set -euo pipefail
dest=${1:?dest dir}
rev=c9745ed1d9f207416be6d2e6f8de32d1f16199bf
mkdir -p "$dest"
for f in config.json tokenizer.json model.safetensors; do
  curl -sfL -o "$dest/$f" "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/$rev/$f"
done
cd "$dest" && sha256sum -c - <<'SUMS'
953f9c0d463486b10a6871cc2fd59f223b2c70184f49815e7efbcab5d8908b41  config.json
be50c3628f2bf5bb5e3a7f17b1f74611b2561a3a27eeab05e5aa30f411572037  tokenizer.json
53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db  model.safetensors
SUMS
