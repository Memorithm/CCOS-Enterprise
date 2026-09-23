#!/usr/bin/env python3
"""Build a blinded, randomized answer-review packet plus a private result binding map."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = ROOT / "scripts" / "evaluate-rag-campaign.py"
spec = importlib.util.spec_from_file_location("rag_eval", EVALUATOR)
rag = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(rag)


def opaque_review_id(seed: int, arm_id: str, query_id: str, result_hash: str) -> str:
    material = f"{seed}\0{arm_id}\0{query_id}\0{result_hash}".encode()
    return hashlib.sha256(material).hexdigest()[:32]


def build_packet(manifest_path: Path, seed: int) -> tuple[list[dict], list[dict]]:
    manifest_path = manifest_path.resolve()
    root = manifest_path.parent
    manifest = rag.decode(rag.bounded_read(manifest_path, 2 * 1024 * 1024))
    queries = rag.index(rag.artifact(root, manifest["queries"]), "id")
    docs = rag.index(rag.artifact(root, manifest["corpus"]), "id")

    packet = []
    mapping = []
    seen_review_ids = set()

    for arm in manifest["arms"]:
        arm_id = rag.label(arm["id"])
        rows = rag.index(rag.artifact(root, arm["results"]), "query_id")
        rag.require(set(rows) == set(queries), "missing/extra query output")
        for query_id in sorted(queries):
            row = rows[query_id]
            result_hash = rag.judgment_result_hash(arm_id, row)
            review_id = opaque_review_id(seed, arm_id, query_id, result_hash)
            rag.require(review_id not in seen_review_ids, "review id collision")
            seen_review_ids.add(review_id)

            aliases = {}
            sources = []
            for position, doc_id in enumerate(row["context_doc_ids"], start=1):
                rag.require(doc_id in docs, "context contains unknown source")
                alias = f"source-{position}"
                aliases[doc_id] = alias
                source = docs[doc_id]
                sources.append({
                    "source": alias,
                    "text": source["text"],
                    "content_sha256": source["content_sha256"],
                })

            answer = row["answer"]
            citations = []
            for citation in answer["citations"]:
                citations.append({
                    "source": aliases.get(citation["doc_id"], "unmapped"),
                    "source_sha256": citation["source_sha256"],
                    "start": citation["start"],
                    "end": citation["end"],
                    "quote_sha256": citation["quote_sha256"],
                })

            packet.append({
                "review_id": review_id,
                "query_id": query_id,
                "question": queries[query_id]["text"],
                "answer": {
                    "text": answer["text"],
                    "abstained": answer["abstained"],
                    "citations": citations,
                },
                "sources": sources,
            })
            mapping.append({
                "review_id": review_id,
                "arm_id": arm_id,
                "query_id": query_id,
                "result_sha256": result_hash,
            })

    rng = random.Random(seed)
    rng.shuffle(packet)
    mapping.sort(key=lambda row: row["review_id"])
    return packet, mapping


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("wb") as stream:
        for row in rows:
            stream.write(rag.canonical(row) + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--seed", required=True, type=int)
    parser.add_argument("--packet", required=True, type=Path)
    parser.add_argument("--mapping", required=True, type=Path)
    args = parser.parse_args()
    require_separate = args.packet.resolve() != args.mapping.resolve()
    if not require_separate:
        print("review error: packet and private mapping must be different files", file=sys.stderr)
        return 1
    try:
        packet, mapping = build_packet(args.manifest, args.seed)
        write_jsonl(args.packet, packet)
        write_jsonl(args.mapping, mapping)
    except (OSError, rag.InvalidCampaign, ValueError) as exc:
        print(f"review error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "reviews": len(packet),
        "packet_sha256": rag.sha(args.packet.read_bytes()),
        "mapping_sha256": rag.sha(args.mapping.read_bytes()),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
