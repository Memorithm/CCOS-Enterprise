#!/usr/bin/env python3
"""Adversarial scorer/contract tests; fixtures are synthetic, not RAG results."""
import importlib.util
import json
import math
from pathlib import Path
import shutil
import subprocess
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

    def replace_and_rejudge(self, spec, rows):
        """Only metric tests manufacture new synthetic reviews for changed outputs."""
        self.replace(spec, rows)
        aid = next(a["id"] for a in self.manifest["arms"] if a["results"] is spec)
        judgments = self.rows(self.manifest["judgments"])
        by_query = {r["query_id"]: r for r in rows}
        for judgment in judgments:
            if judgment["arm_id"] == aid:
                judgment["result_sha256"] = CAMPAIGN.judgment_result_hash(aid, by_query[judgment["query_id"]])
        self.replace(self.manifest["judgments"], judgments)

    def test_frozen_report_is_deterministic_and_makes_no_superiority_claim(self):
        first = self.evaluate()
        self.assertEqual(first, self.evaluate())
        self.assertFalse(first["superiority_claim"])
        self.assertEqual(first["scope"], "synthetic_smoke")
        self.assertEqual(first["arms"]["ccos"]["summary"]["ndcg"], 1)
        self.assertEqual(first["arms"]["ccos"]["summary"]["qrel_coverage"], 1)
        self.assertEqual(first["decision_rule"]["primary_baseline"], "reranked")
        self.assertTrue(first["decision_rule_assessment"]["eligible_to_claim"])
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

    def test_changed_answer_cannot_reuse_a_favorable_judgment(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        rows[0]["answer"]["text"] = "An unrelated invented answer."
        self.replace(spec, rows)
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "judgment result hash mismatch"):
            self.evaluate()

    def test_every_part_of_the_reviewed_result_is_bound(self):
        mutations = [
            lambda r: r.update(context_doc_ids=[]),
            lambda r: r.update(ranking=list(reversed(r["ranking"])) + ["acme-api"]),
            lambda r: r["answer"].update(citations=[]),
            lambda r: r["answer"]["citations"][0].update(end=1),
            lambda r: r.update(status="error"),
            lambda r: r.update(latency_ms=r["latency_ms"] + 1),
            lambda r: r.update(protocol_sha256=CAMPAIGN.sha(b"other protocol")),
        ]
        spec = self.manifest["arms"][0]["results"]
        original = self.rows(spec)
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                rows = json.loads(json.dumps(original))
                mutate(rows[0])
                self.replace(spec, rows)
                with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "judgment result hash mismatch"):
                    self.evaluate()

    def test_identical_outputs_from_different_arms_do_not_share_review_receipts(self):
        judgments = self.rows(self.manifest["judgments"])
        a = next(j for j in judgments if j["arm_id"] == "ccos" and j["query_id"] == "q-fr")
        b = next(j for j in judgments if j["arm_id"] == "dense" and j["query_id"] == "q-fr")
        self.assertNotEqual(a["result_sha256"], b["result_sha256"])
        a["result_sha256"] = b["result_sha256"]
        self.replace(self.manifest["judgments"], judgments)
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "judgment result hash mismatch"):
            self.evaluate()

    def test_legacy_and_missing_review_bindings_are_refused(self):
        self.manifest["schema_version"] = 1
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "requires schema 3"):
            self.evaluate()
        self.manifest["schema_version"] = 3
        judgments = self.rows(self.manifest["judgments"])
        del judgments[0]["result_sha256"]
        self.replace(self.manifest["judgments"], judgments)
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "unexpected/missing fields"):
            self.evaluate()

    def test_json_formatting_does_not_change_reviewed_content(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        raw = b"".join(json.dumps(dict(reversed(list(r.items()))), ensure_ascii=True).encode() + b"\n" for r in rows)
        (self.root / spec["path"]).write_bytes(raw)
        spec["sha256"] = CAMPAIGN.sha(raw)
        self.assertEqual(self.evaluate()["arms"]["ccos"]["summary"]["task_success"], 1)

    def test_cli_refuses_stale_review_without_emitting_a_partial_report(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        rows[0]["answer"]["text"] = "Unreviewed replacement."
        self.replace(spec, rows)
        self.path.write_text(json.dumps(self.manifest))
        result = subprocess.run([sys.executable, str(Path(CAMPAIGN.__file__)), str(self.path)],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("judgment result hash mismatch", result.stderr)

    def test_missing_query_and_duplicate_rank_are_rejected(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        self.replace(spec, rows[:-1])
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "missing/extra query"):
            self.evaluate()
        rows[0]["ranking"] *= 2
        self.replace_and_rejudge(spec, rows)
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "duplicate ranking"):
            self.evaluate()

    def test_leaks_stale_citations_and_budget_failures_remain_in_report(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        rows[0]["ranking"] += ["beta-lyon", "acme-old"]
        rows[0]["context_doc_ids"] += ["beta-lyon", "acme-old"]
        rows[0]["context_tokens"] = 129
        rows[0]["answer"]["citations"][0]["quote_sha256"] = CAMPAIGN.sha(b"invented quote")
        self.replace_and_rejudge(spec, rows)
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
        self.replace_and_rejudge(spec, rows)
        row = self.evaluate()["arms"]["ccos"]["rows"]["q-fr"]
        self.assertEqual(row["valid_citations"], 0)
        self.assertEqual(row["citation_rights_violations"], 1)

    def test_known_rank_two_metrics_and_unsupported_answer_are_counted(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        rows[0]["ranking"] = ["acme-api", "acme-paris"]
        rows[3]["answer"] = {"text": "Invented secret", "abstained": False, "citations": []}
        self.replace_and_rejudge(spec, rows)
        judgments = self.rows(self.manifest["judgments"])
        judgment = next(j for j in judgments if j["arm_id"] == "ccos" and j["query_id"] == "q-deleted")
        judgment.update(total_claims=1, supported_claims=0, answer_correct=False)
        self.replace(self.manifest["judgments"], judgments)
        result = self.evaluate()["arms"]["ccos"]["rows"]
        self.assertAlmostEqual(result["q-fr"]["ndcg"], 1 / math.log2(3))
        self.assertEqual(result["q-fr"]["recall"], 1)
        self.assertEqual(result["q-fr"]["mrr"], 0.5)
        self.assertEqual(result["q-deleted"]["unsupported_claims"], 1)
        self.assertEqual(result["q-fr"]["retrieved_judged_documents"], 1)
        self.assertEqual(result["q-fr"]["retrieved_unjudged_documents"], 1)
        self.assertEqual(result["q-fr"]["qrel_coverage"], 0.5)
        self.assertIsNone(result["q-deleted"]["qrel_coverage"])
        self.assertEqual(result["q-deleted"]["task_success"], 0)

    def test_decision_rule_must_name_a_compared_rag_baseline(self):
        self.manifest["decision_rule"]["primary_baseline"] = "ccos"
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "must be a RAG arm"):
            self.evaluate()
        self.manifest["decision_rule"]["primary_baseline"] = "reranked"
        self.manifest["comparisons"] = [c for c in self.manifest["comparisons"] if c["baseline"] != "reranked"]
        with self.assertRaisesRegex(CAMPAIGN.InvalidCampaign, "not compared|missing governed/reference"):
            self.evaluate()

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
        self.replace_and_rejudge(spec, rows)
        adverse = self.evaluate()["arms"]["ccos"]["rows"]["q-fr"]
        self.assertEqual(adverse["citation_violations"], 1)
        self.assertEqual(adverse["task_success"], 0)

    def test_failed_runtime_is_never_rewarded_as_correct_abstention(self):
        spec = self.manifest["arms"][0]["results"]
        rows = self.rows(spec)
        rows[3]["status"] = "error"
        self.replace_and_rejudge(spec, rows)
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
