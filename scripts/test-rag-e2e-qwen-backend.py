#!/usr/bin/env python3
"""Model-free tests of the frozen v1 parse rule of scripts/rag_e2e_qwen_backend.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rag_e2e_qwen_backend import parse_answer  # noqa: E402

P = "Answer ...\n\n[A#1] alpha text\n[B#2] beta\n\nQuestion: q\nAnswer:"
L = {"A#1": 10, "B#2": 4}.get


def lens(d):
    return L(d, 0)


assert parse_answer("", P, lens) == (True, [])
assert parse_answer("I must abstain.", P, lens) == (True, [])
assert parse_answer("The sources do not contain the answer.", P, lens) == (True, [])
ab, c = parse_answer("Paris [A#1] and [B#2] [A#1] [Z#9]", P, lens)
assert not ab and c == [{"doc_id": "A#1", "start": 0, "end": 10}, {"doc_id": "B#2", "start": 0, "end": 4}], c
assert parse_answer("Paris.", P, lens) == (False, [])
print("rag_e2e_qwen_backend parse tests: ok")
