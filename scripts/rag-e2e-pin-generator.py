#!/usr/bin/env python3
"""Hash a locally downloaded generator snapshot and fill the manifest's generator pins.

weights_sha256 = sha256 over lines "<sha256(shard)>  <shard name>\\n" for every
*.safetensors shard, sorted by name. tokenizer_sha256 = sha256(tokenizer.json).
prompt_sha256 = sha256(prompt file bytes). Fails closed if the tokenizer or prompt
hash disagrees with the preregistered value already in the manifest. Writes no
results and measures nothing; the readiness gate stays the authority.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def aggregate_weights(snapshot: Path) -> str:
    shards = sorted(snapshot.glob("*.safetensors"), key=lambda p: p.name)
    if not shards:
        raise SystemExit("pin error: no *.safetensors shards in snapshot")
    listing = "".join(f"{file_sha(p)}  {p.name}\n" for p in shards)
    return "sha256:" + hashlib.sha256(listing.encode()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    man = json.loads(a.manifest.read_text(encoding="utf-8"))
    gen = man["protocol"]["generator"]
    tok = "sha256:" + file_sha(a.snapshot / "tokenizer.json")
    prompt = "sha256:" + file_sha(a.manifest.parent / gen["prompt_path"])
    errors = []
    if tok != gen["tokenizer_sha256"]:
        errors.append(f"tokenizer_sha256 mismatch: {tok} != prereg {gen['tokenizer_sha256']}")
    if prompt != gen["prompt_sha256"]:
        errors.append(f"prompt_sha256 mismatch: {prompt} != prereg {gen['prompt_sha256']}")
    if errors:
        for e in errors:
            print("pin error: " + e, file=sys.stderr)
        return 1
    gen["weights_sha256"] = aggregate_weights(a.snapshot)
    a.out.write_text(json.dumps(man, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"weights_sha256": gen["weights_sha256"], "tokenizer_sha256": tok, "prompt_sha256": prompt}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
