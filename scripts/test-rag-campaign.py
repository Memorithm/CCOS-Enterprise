#!/usr/bin/env python3
"""Adversarial scorer/contract tests; fixtures are synthetic, not RAG results."""
import importlib.util
import json
import math
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

SPEC = importlib.util.spec_from_file_location("campaign", Path(__file__).with_name("evaluate-rag-campaign.py"))
CAMPAIGN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAMPAIGN)
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures/rag-campaign-smoke"


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "case"
        shutil.copytree(FIXTURE, self.root)
        self.path = self.root / "manifest.json"
        self.manifest = json.loads(self.path.read_text())

    def evaluate(self):
        self.path.write_text(json.dumps(self.manifest))
        return CAMPAIGN.evaluate(self.path)

    def rows(self, spec):
        return [json.loads(line) for line in (self.root / spec["path"]).read_text().splitlines()]

    def replace(self, spec, rows):
        data = b"".join(CAMPAIGN.canonical(row) + b"\n" for row in rows)
        (self.root / spec["path"]).write_bytes(data)
        spec["sha256"] = CAMPAIGN.sha(data)

    def test_frozen_report_is_deterministic_and_makes_no_superiority_claim(self):
        first = self.evaluate()
        self.assertEqual(first, self.evaluate())
        self.assertFalse(first["superiority_claim"])
        self.assertEqual(first["scope"], "synthetic_smoke")
        self.assertEqual(first["arms"]["ccos"]["summary"]["ndcg"], 1)
        self.assertEqual(first["comparisons"][0]["paired_cluster_bootstrap"]["ndcg"]["ci95"], [0, 0])

    def test_modified_bytes_and_duplicate_json_keys_are_rejected(self):
        corpus = self.root / self.manifest["corpus"]["path"]
        corpus.write_bytes(corpus.read_bytes() + b"\n")
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "content hash mismatch"):
            self.evaluate()
        with self.assertRaises(CAMPAIGN.InvalidCampaign):
            CAMPAIGN.decode('{"x":1,"x":2}')
        with self.assertRaises(CAMPAIGN.InvalidCampaign):
            CAMPAIGN.decode('{"x":NaN}')

    def test_missing_query_and_duplicate_rank_are_rejected(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        self.replace(spec, rows[:-1])
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "missing/extra query"):
            self.evaluate()
        rows[0]["ranking"] *= 2
        self.replace(spec, rows)
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "duplicate ranking"):
            self.evaluate()

    def test_leaks_stale_citations_and_budget_failures_remain_in_report(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        rows[0]["ranking"] += ["beta-lyon", "acme-old"]
        rows[0]["context_doc_ids"] += ["beta-lyon", "acme-old"]
        rows[0]["context_tokens"] = 129
        rows[0]["answer"]["citations"][0]["quote_sha256"] = CAMPAIGN.sha(b"invented quote")
        self.replace(spec, rows)
        report = self.evaluate()
        adverse = report["arms"]["ccos"]["rows"]["q-fr"]
        for key in ("rights_violations", "stale_returns", "budget_violations", "citation_violations"):
            self.assertEqual(adverse[key], 1)
        self.assertEqual(adverse["context_violations"], 2)
        self.assertEqual(adverse["task_success"], 0)
        self.assertFalse(report["arms"]["ccos"]["summary"]["protocol_clean"])
        self.assertLess(report["comparisons"][0]["paired_cluster_bootstrap"]["task_success"]["mean_delta"], 0)

    def test_hash_valid_foreign_citation_is_still_ineligible(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        foreign = rows[2]["answer"]["citations"][0]
        rows[0]["answer"]["citations"] = [foreign]
        self.replace(spec, rows)
        row = self.evaluate()["arms"]["ccos"]["rows"]["q-fr"]
        self.assertEqual(row["valid_citations"], 0)
        self.assertEqual(row["citation_rights_violations"], 1)

    def test_known_rank_two_metrics_and_unsupported_answer_are_counted(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        rows[0]["ranking"] = ["acme-api", "acme-paris"]
        rows[3]["answer"] = {"text": "Invented secret", "abstained": False, "citations": []}
        self.replace(spec, rows)
        judgments = self.rows(self.manifest["judgments"])
        judgment = next(j for j in judgments if j["arm_id"] == "ccos" and j["query_id"] == "q-deleted")
        judgment.update(total_claims=1, supported_claims=0, answer_correct=False)
        self.replace(self.manifest["judgments"], judgments)
        result = self.evaluate()["arms"]["ccos"]["rows"]
        self.assertAlmostEqual(result["q-fr"]["ndcg"], 1 / math.log2(3))
        self.assertEqual(result["q-fr"]["recall"], 1)
        self.assertEqual(result["q-fr"]["mrr"], 0.5)
        self.assertEqual(result["q-deleted"]["unsupported_claims"], 1)
        self.assertEqual(result["q-deleted"]["task_success"], 0)

    def test_protocol_and_encoder_mismatches_cannot_win_a_comparison(self):
        self.manifest["arms"][2]["encoder"]["dimension"] = 256
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "encoder substitution"):
            self.evaluate()
        self.manifest["arms"][2]["encoder"]["dimension"] = 128
        self.manifest["protocol"]["context_tokens"] = 256
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "runner protocol differs"):
            self.evaluate()

    def test_malformed_citation_claims_are_scored_as_invalid_not_dropped(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        citation = rows[0]["answer"]["citations"][0]
        citation.update(start=-1, source_sha256="hallucinated hash")
        self.replace(spec, rows)
        adverse = self.evaluate()["arms"]["ccos"]["rows"]["q-fr"]
        self.assertEqual(adverse["citation_violations"], 1)
        self.assertEqual(adverse["task_success"], 0)

    def test_failed_runtime_is_never_rewarded_as_correct_abstention(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        rows[3]["status"] = "error"
        self.replace(spec, rows)
        row = self.evaluate()["arms"]["ccos"]["rows"]["q-deleted"]
        self.assertEqual(row["runtime_failures"], 1)
        self.assertEqual(row["task_success"], 0)
        self.assertEqual(row["abstention_correct"], 0)

    def test_positive_qrels_cannot_reward_an_unauthorized_source(self):
        spec = self.manifest["qrels"]
        rows = self.rows(spec)
        rows[0]["doc_id"] = "beta-lyon"
        self.replace(spec, rows)
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "positive qrel violates"):
            self.evaluate()

    def test_synthetic_judgments_are_not_a_holdout_and_paths_cannot_escape(self):
        self.manifest["scope"] = "held_out"
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "synthetic judgments"):
            self.evaluate()
        self.manifest["scope"] = "synthetic_smoke"
        self.manifest["corpus"]["path"] = "../outside.jsonl"
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "escapes"):
            self.evaluate()

    def test_bootstrap_uses_paired_clusters_and_handles_missing_denominators(self):
        left = {"a": {"group": "x", "m": 1}, "b": {"group": "y", "m": 0}}
        right = {"a": {"group": "x", "m": 0}, "b": {"group": "y", "m": 1}}
        result = CAMPAIGN.paired_interval(left, right, "m", 7, 1000)
        self.assertEqual(result["mean_delta"], 0)
        self.assertEqual(result["ci95"], [-1, 1])
        left["b"]["m"] = None
        self.assertIsNone(CAMPAIGN.paired_interval(left, right, "m", 7, 1000)["ci95"])


if __name__ == "__main__":
    unittest.main()
