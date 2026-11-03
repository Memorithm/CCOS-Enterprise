#!/usr/bin/env python3
"""Model-free tests of the frozen v1 judge render/parse rules and the gold sidecar."""

import importlib.util
import sys
from pathlib import Path

S = Path(__file__).resolve().parent
sys.path.insert(0, str(S))
from rag_e2e_mistral_judge import parse_review, render  # noqa: E402

spec = importlib.util.spec_from_file_location("gold", S / "rag-e2e-squad-gold.py")
gold = importlib.util.module_from_spec(spec); spec.loader.exec_module(gold)

D = S.parent / "docs" / "campaigns" / "2026-11-02-rag-e2e"
P = (D / "judge-prompt.v1.txt").read_text()
R = (S.parent / "docs" / "campaigns" / "rag-e2e" / "rubric.md").read_text()
row = {"review_id": "r1", "question": "Q?", "gold_answers": ["Paris"], "abstained": False,
       "answer": "Paris [A#1]", "cited_quotes": ["Paris is the capital."]}
ab = dict(row, abstained=True, answer="", cited_quotes=[], gold_answers="UNANSWERABLE")
t = render(P, R, row)
assert "Q?" in t and '["Paris"]' in t and "- Paris is the capital." in t
assert "UNANSWERABLE" in render(P, R, ab) and "(none)" in render(P, R, ab)
ok = parse_review('x {"answer_correct": true, "total_claims": 2, "supported_claims": 1, "note": "n"} y', row)
assert ok == {"review_id": "r1", "answer_correct": True, "total_claims": 2, "supported_claims": 1, "note": "n"}, ok
assert parse_review('{"answer_correct": true, "total_claims": 3, "supported_claims": 1}', ab)["total_claims"] == 0
assert parse_review("no json", row) is None
assert parse_review('{"answer_correct": "yes", "total_claims": 1, "supported_claims": 1}', row) is None
assert parse_review('{"answer_correct": true, "total_claims": 0, "supported_claims": 0}', row) is None
assert parse_review('{"answer_correct": true, "total_claims": 1, "supported_claims": 2}', row) is None
dev = {"data": [{"paragraphs": [{"qas": [{"id": "a", "answers": [{"text": "x"}, {"text": "x"}, {"text": "y"}]},
                                         {"id": "b", "answers": [], "is_impossible": True}]}]}]}
assert list(gold.gold_rows(dev)) == [{"query_id": "a", "answers": ["x", "y"]}, {"query_id": "b", "answers": []}]
print("rag_e2e_mistral_judge tests: ok")
