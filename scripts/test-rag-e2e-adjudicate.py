#!/usr/bin/env python3
"""Smoke-fixture tests for the RAG E2E adjudication kit."""

import copy
import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures" / "rag-campaign-smoke"
RUBRIC = ROOT / "docs" / "campaigns" / "rag-e2e" / "rubric.md"
spec = importlib.util.spec_from_file_location("kit", ROOT / "scripts" / "rag-e2e-adjudicate.py")
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)
ARMS = ["ccos", "dense", "hybrid", "lexical", "reranked"]


def arms():
    return kit.parse_arms([f"{a}={FIX / (a + '.jsonl')}" for a in ARMS])


def raises(fn):
    try:
        fn()
    except kit.KitError:
        return True
    return False


def reviews_for(key, a):
    return [{"review_id": k["review_id"], "answer_correct": True,
             "total_claims": 0 if a[k["arm_id"]][k["query_id"]]["answer"]["abstained"] else 1,
             "supported_claims": 0 if a[k["arm_id"]][k["query_id"]]["answer"]["abstained"] else 1} for k in key]


def main():
    q, c, a = kit.read_jsonl(FIX / "queries.jsonl"), kit.read_jsonl(FIX / "corpus.jsonl"), arms()
    packet, key = kit.export(q, c, a, 20261102)
    packet2, key2 = kit.export(q, c, a, 20261102)
    assert packet == packet2 and key == key2, "deterministic for a fixed seed"
    assert kit.export(q, c, a, 1)[1] != key, "seed changes order"
    assert all("arm" not in json.dumps(sorted(p)) for p in packet), "packet is blind"
    assert len(packet) == len(ARMS) * len(q)
    for k in key:
        assert k["result_sha256"] == kit.ev.judgment_result_hash(k["arm_id"], a[k["arm_id"]][k["query_id"]])

    rh = kit.rubric_hash(RUBRIC)
    assert rh.startswith("sha256:") and len(rh) == 71
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "r.md"; bad.write_bytes(b"x \n")
        assert raises(lambda: kit.rubric_hash(bad))

    reviews = reviews_for(key, a)
    judged = kit.import_reviews(key, reviews, a, rh, "llm:test")
    assert len(judged) == len(key) and all(j["blinded"] and j["rubric_sha256"] == rh for j in judged)

    stale_key = [k for k in key if k["arm_id"] == "ccos"][:1]
    stale = copy.deepcopy(a); stale["ccos"][stale_key[0]["query_id"]]["latency_ms"] += 1
    assert raises(lambda: kit.import_reviews(stale_key, [r for r in reviews if r["review_id"] == stale_key[0]["review_id"]], stale, rh, "x"))
    assert raises(lambda: kit.import_reviews(key, reviews[1:], a, rh, "x")), "missing review"
    assert raises(lambda: kit.import_reviews(key, reviews + reviews[:1], a, rh, "x")), "duplicate"
    assert raises(lambda: kit.import_reviews(key, reviews + [{"review_id": "zz"}], a, rh, "x")), "unknown"
    broken = copy.deepcopy(reviews); broken[0]["supported_claims"] = 5
    assert raises(lambda: kit.import_reviews(key, broken, a, rh, "x"))

    same = [{"review_id": str(i), "answer_correct": i % 2 == 0} for i in range(10)]
    assert kit.kappa(same, same)["kappa"] == 1.0
    flipped = [dict(r, answer_correct=not r["answer_correct"]) for r in same]
    assert kit.kappa(same, flipped)["kappa"] < 0.6
    with tempfile.TemporaryDirectory() as d:
        p1, p2 = Path(d) / "a.jsonl", Path(d) / "b.jsonl"
        kit.write_jsonl(p1, same); kit.write_jsonl(p2, flipped)
        assert kit.main(["kappa", "--primary", str(p1), "--secondary", str(p2)]) == 3, "kappa<0.6 -> INCONCLUSIVE exit"
        assert kit.main(["kappa", "--primary", str(p1), "--secondary", str(p1)]) == 0
    # End to end: kit judgments are accepted by the schema-3 scorer.
    import hashlib, shutil, subprocess
    with tempfile.TemporaryDirectory() as d:
        t = Path(d) / "c"; shutil.copytree(FIX, t)
        m = json.loads((t / "manifest.json").read_text(encoding="utf-8"))
        kit.write_jsonl(t / "judgments.jsonl", kit.import_reviews(key, reviews, a, m["protocol"]["rubric_sha256"], "llm:test"))
        m["judgments"]["sha256"] = "sha256:" + hashlib.sha256((t / "judgments.jsonl").read_bytes()).hexdigest()
        (t / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
        r = subprocess.run(["python3", str(ROOT / "scripts" / "evaluate-rag-campaign.py"), str(t / "manifest.json")],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert json.loads(r.stdout)["superiority_claim"] is False
    print("rag-e2e adjudication kit tests passed")


if __name__ == "__main__":
    main()
