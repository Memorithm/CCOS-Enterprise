#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-rag-blinded-review.py"
MANIFEST = ROOT / "fixtures" / "rag-campaign-smoke" / "manifest.json"
spec = importlib.util.spec_from_file_location("blind", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def test_packet_is_deterministic_for_fixed_seed_and_has_no_arm_identity():
    packet_a, mapping_a = module.build_packet(MANIFEST, 20260923)
    packet_b, mapping_b = module.build_packet(MANIFEST, 20260923)
    assert packet_a == packet_b
    assert mapping_a == mapping_b
    encoded = "\n".join(json.dumps(row, sort_keys=True) for row in packet_a)
    assert '"arm_id"' not in encoded
    assert "governed_memory" not in encoded
    assert "reranked" not in encoded


def test_private_mapping_binds_every_review_to_exact_result():
    packet, mapping = module.build_packet(MANIFEST, 17)
    assert len(packet) == len(mapping)
    assert {row["review_id"] for row in packet} == {row["review_id"] for row in mapping}
    assert len({row["result_sha256"] for row in mapping}) >= 1
    assert all(row["result_sha256"].startswith("sha256:") for row in mapping)


def test_packet_uses_opaque_source_aliases_not_document_ids():
    packet, _ = module.build_packet(MANIFEST, 19)
    for item in packet:
        assert all(source["source"].startswith("source-") for source in item["sources"])
        for citation in item["answer"]["citations"]:
            assert citation["source"] == "unmapped" or citation["source"].startswith("source-")


def test_review_ids_change_when_blinding_seed_changes():
    packet_a, _ = module.build_packet(MANIFEST, 1)
    packet_b, _ = module.build_packet(MANIFEST, 2)
    assert {row["review_id"] for row in packet_a} != {row["review_id"] for row in packet_b}


if __name__ == "__main__":
    tests = [
        test_packet_is_deterministic_for_fixed_seed_and_has_no_arm_identity,
        test_private_mapping_binds_every_review_to_exact_result,
        test_packet_uses_opaque_source_aliases_not_document_ids,
        test_review_ids_change_when_blinding_seed_changes,
    ]
    for test in tests:
        test()
    print(f"{len(tests)} blinded-review tests passed")
