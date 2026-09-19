#!/usr/bin/env python3
"""Hash-bound, paired evaluation of externally executed CCOS/RAG arms.

This evaluates supplied artifacts; it does not run or train encoders/generators,
authenticate runner measurements, judge truth, or automatically claim superiority.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
import re
import statistics


class InvalidCampaign(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise InvalidCampaign(message)


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), "unexpected/missing fields")


def integer(value, low=0, high=10**12):
    require(type(value) is int and low <= value <= high, "invalid integer")
    return value


def number(value, positive=False):
    require(type(value) in (int, float) and math.isfinite(value)
            and (value > 0 if positive else value >= 0), "invalid measurement")
    return value


def label(value):
    require(isinstance(value, str) and 0 < len(value) <= 256 and value.strip() == value
            and not any(ord(c) < 32 for c in value), "invalid label")
    return value


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def valid_hash(value):
    require(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "invalid SHA-256")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def judgment_result_hash(arm_id, row):
    """Bind review to one arm's complete output, including its frozen protocol."""
    return sha(canonical({"arm_id": arm_id, "result": row}))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    def bad_constant(_):
        raise InvalidCampaign("non-finite JSON number")
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=bad_constant)


def bounded_read(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "artifact exceeds byte ceiling")
    return data


def artifact(root, spec):
    fields(spec, "path sha256")
    valid_hash(spec["sha256"])
    require(isinstance(spec["path"], str), "artifact path must be text")
    path = (root / spec["path"]).resolve()
    require(path.is_relative_to(root) and path.is_file(), "artifact escapes manifest directory or is absent")
    data = bounded_read(path, 256 * 1024 * 1024)
    require(sha(data) == spec["sha256"], "artifact content hash mismatch")
    return [decode(line) for line in data.splitlines() if line.strip()]


def index(rows, key):
    result = {}
    for row in rows:
        value = label(row[key])
        require(value not in result, "duplicate row identity")
        result[value] = row
    require(result, "empty artifact")
    return result


def eligible(doc, query):
    return (doc["tenant"] == query["tenant"] and query["principal"] in doc["principals"]
            and doc["state"] == "active")


def mean(values):
    values = [v for v in values if v is not None]
    return statistics.fmean(values) if values else None


def quantile(values, percent):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percent / 100) - 1)] if ordered else None


def citation_valid(citation, docs):
    fields(citation, "doc_id source_sha256 start end quote_sha256")
    require(isinstance(citation["doc_id"], str), "citation ID must be text")
    start, end = citation["start"], citation["end"]
    require(type(start) is int and type(end) is int, "citation offsets must be integers")
    require(isinstance(citation["source_sha256"], str) and isinstance(citation["quote_sha256"], str), "citation hashes must be text")
    doc = docs.get(citation["doc_id"])
    if doc is None:
        return False
    raw = doc["text"].encode()
    return (citation["source_sha256"] == doc["content_sha256"] and 0 <= start < end <= len(raw)
            and sha(raw[start:end]) == citation["quote_sha256"])


def evaluate_row(row, query, docs, qrels, judgment, protocol, protocol_hash):
    fields(row, "query_id status protocol_sha256 ranking context_doc_ids answer latency_ms context_tokens answer_tokens embedding_tokens")
    require(row["status"] in ("ok", "error"), "invalid runtime outcome")
    require(row["protocol_sha256"] == protocol_hash, "runner protocol differs from frozen comparison")
    require(isinstance(row["ranking"], list) and len(row["ranking"]) <= 1000, "invalid ranking")
    require(all(isinstance(x, str) and x in docs for x in row["ranking"]), "ranking has unknown source")
    require(len(set(row["ranking"])) == len(row["ranking"]), "duplicate ranking source")
    context = row["context_doc_ids"]
    require(isinstance(context, list) and all(isinstance(x, str) and x in row["ranking"] for x in context)
            and len(set(context)) == len(context), "context must trace to unique ranked sources")
    answer = row["answer"]
    fields(answer, "text abstained citations")
    require(isinstance(answer["text"], str) and len(answer["text"].encode()) <= 1024 * 1024
            and type(answer["abstained"]) is bool and isinstance(answer["citations"], list)
            and len(answer["citations"]) <= 1024, "invalid answer")
    require(not answer["abstained"] or (not answer["text"] and not answer["citations"]), "abstention contains answer/citations")
    require(answer["abstained"] or bool(answer["text"].strip()), "non-abstention has no answer")
    require(row["status"] == "ok" or answer["abstained"], "failed runtime cannot claim a completed answer")
    runtime_failures = int(row["status"] != "ok")
    context_tokens, answer_tokens = integer(row["context_tokens"]), integer(row["answer_tokens"])
    integer(row["embedding_tokens"])
    number(row["latency_ms"])
    budget_violations = int(context_tokens > protocol["context_tokens"] or answer_tokens > protocol["answer_tokens"])
    returned = row["ranking"]
    rights_violations = sum(docs[x]["tenant"] != query["tenant"] or query["principal"] not in docs[x]["principals"] for x in returned)
    stale_returns = sum(docs[x]["state"] != "active" for x in returned)
    context_violations = sum(not eligible(docs[x], query) for x in context)
    valid_citations = sum(citation_valid(c, docs) and c["doc_id"] in context and eligible(docs[c["doc_id"]], query)
                          for c in answer["citations"])
    total_citations = len(answer["citations"])
    citation_rights_violations = sum(c["doc_id"] in docs and (
        docs[c["doc_id"]]["tenant"] != query["tenant"] or query["principal"] not in docs[c["doc_id"]]["principals"]
    ) for c in answer["citations"])
    labels = qrels.get(query["id"], {})
    top = returned[:protocol["k"]]
    positives = {doc for doc, grade in labels.items() if grade > 0}
    gain = lambda grade: 2**grade - 1
    dcg = sum(gain(labels.get(doc, 0)) / math.log2(i + 2) for i, doc in enumerate(top))
    ideal = sum(gain(grade) / math.log2(i + 2)
                for i, grade in enumerate(sorted(labels.values(), reverse=True)[:protocol["k"]]))
    claims = judgment["total_claims"]
    supported = judgment["supported_claims"]
    require(not answer["abstained"] or claims == 0, "abstention has judged claims")
    require(answer["abstained"] or claims > 0, "answer has no adjudicated claims")
    success = bool(judgment["answer_correct"] and not (runtime_failures or rights_violations or stale_returns or context_violations or budget_violations or citation_rights_violations))
    if query["answerable"]:
        success &= not answer["abstained"] and supported == claims and total_citations > 0 and valid_citations == total_citations
    else:
        success &= answer["abstained"]
    return {
        "query_id": query["id"], "group": query["group"], "ndcg": dcg / ideal if ideal else None,
        "recall": len(set(top) & positives) / len(positives) if positives else None,
        "mrr": next((1 / (i + 1) for i, doc in enumerate(top) if doc in positives), 0.0) if positives else None,
        "abstention_correct": int(not runtime_failures and answer["abstained"] == (not query["answerable"])),
        "task_success": int(success), "adjudicated_support": supported / claims if claims else None,
        "unsupported_claims": claims - supported, "rights_violations": rights_violations,
        "stale_returns": stale_returns, "context_violations": context_violations, "budget_violations": budget_violations,
        "citation_count": total_citations, "valid_citations": valid_citations,
        "citation_violations": total_citations - valid_citations, "citation_rights_violations": citation_rights_violations,
        "latency_ms": row["latency_ms"], "context_tokens": context_tokens, "answer_tokens": answer_tokens,
        "embedding_tokens": row["embedding_tokens"],
        "runtime_failures": runtime_failures,
    }


def paired_interval(left, right, metric, seed, samples):
    groups = {}
    for qid in sorted(left):
        a, b = left[qid], right[qid]
        if a[metric] is not None and b[metric] is not None:
            groups.setdefault(a["group"], []).append(a[metric] - b[metric])
    differences = [v for values in groups.values() for v in values]
    result = {"mean_delta": mean(differences), "queries": len(differences), "clusters": len(groups), "ci95": None}
    if len(groups) < 2:
        return result
    rng = random.Random(seed)
    ordered = [groups[k] for k in sorted(groups)]
    estimates = [statistics.fmean(v for values in rng.choices(ordered, k=len(ordered)) for v in values)
                 for _ in range(samples)]
    result["ci95"] = [quantile(estimates, 2.5), quantile(estimates, 97.5)]
    return result


def evaluate(path):
    path = Path(path).resolve()
    root = path.parent
    manifest_bytes = bounded_read(path, 2 * 1024 * 1024)
    manifest = decode(manifest_bytes)
    fields(manifest, "schema_version scope protocol corpus queries qrels judgments arms comparisons dataset_provenance")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 2 and manifest["scope"] in ("synthetic_smoke", "held_out"), "unsupported campaign (requires schema 2 with result-bound judgments)")
    provenance = manifest["dataset_provenance"]
    fields(provenance, "origin license split_author training_overlap_audit_sha256")
    for key in ("origin", "license", "split_author"):
        label(provenance[key])
    valid_hash(provenance["training_overlap_audit_sha256"])
    protocol = manifest["protocol"]
    fields(protocol, "generator hardware context_tokens answer_tokens k seed bootstrap_samples rubric_sha256")
    fields(protocol["generator"], "weights_sha256 tokenizer_sha256 prompt_sha256 temperature seed")
    for key in ("weights_sha256", "tokenizer_sha256", "prompt_sha256"):
        valid_hash(protocol["generator"][key])
    number(protocol["generator"]["temperature"])
    integer(protocol["generator"]["seed"])
    fields(protocol["hardware"], "host_id cpu accelerator ram_bytes concurrency")
    for key in ("host_id", "cpu", "accelerator"):
        label(protocol["hardware"][key])
    integer(protocol["hardware"]["ram_bytes"], 1)
    integer(protocol["hardware"]["concurrency"], 1, 1024)
    integer(protocol["context_tokens"], 1)
    integer(protocol["answer_tokens"], 1)
    integer(protocol["k"], 1, 100)
    integer(protocol["seed"])
    integer(protocol["bootstrap_samples"], 100, 10000)
    valid_hash(protocol["rubric_sha256"])
    # Bind the executed protocol and retrieval inputs. Blinded answer judgments arrive later
    # and are bound by the final manifest, not passed to the evaluated runners.
    protocol_hash = sha(canonical({"protocol": protocol, "corpus": manifest["corpus"]["sha256"],
                                   "queries": manifest["queries"]["sha256"], "qrels": manifest["qrels"]["sha256"]}))
    docs = index(artifact(root, manifest["corpus"]), "id")
    for doc in docs.values():
        fields(doc, "id tenant principals state text content_sha256")
        label(doc["tenant"])
        require(isinstance(doc["principals"], list) and bool(doc["principals"]), "missing document rights")
        require(len({label(p) for p in doc["principals"]}) == len(doc["principals"]), "duplicate principal")
        require(doc["state"] in ("active", "deleted", "superseded") and isinstance(doc["text"], str), "invalid source")
        require(sha(doc["text"].encode()) == doc["content_sha256"], "source bytes do not match source hash")
    queries = index(artifact(root, manifest["queries"]), "id")
    for query in queries.values():
        fields(query, "id tenant principal text answerable group split")
        for key in ("tenant", "principal", "group"):
            label(query[key])
        require(query["split"] == "test" and isinstance(query["text"], str) and bool(query["text"])
                and type(query["answerable"]) is bool, "invalid test query")
    qrels = {}
    for rel in artifact(root, manifest["qrels"]):
        fields(rel, "query_id doc_id relevance")
        require(rel["query_id"] in queries and rel["doc_id"] in docs, "unknown qrel identity")
        grade = integer(rel["relevance"], 0, 3)
        labels = qrels.setdefault(rel["query_id"], {})
        require(rel["doc_id"] not in labels, "duplicate judgment")
        require(grade == 0 or eligible(docs[rel["doc_id"]], queries[rel["query_id"]]), "positive qrel violates source eligibility")
        labels[rel["doc_id"]] = grade
    for query in queries.values():
        require(query["answerable"] == any(v > 0 for v in qrels.get(query["id"], {}).values()), "answerability and qrels disagree")
    arms = index(manifest["arms"], "id")
    require(len(arms) <= 64 and len(queries) <= 100000, "campaign population ceiling exceeded")
    require({a["family"] for a in arms.values()} == {"governed_memory", "lexical", "dense", "hybrid", "reranked"}, "all five reference families are required")
    judgments = {}
    for judgment in artifact(root, manifest["judgments"]):
        fields(judgment, "arm_id query_id result_sha256 total_claims supported_claims answer_correct adjudicator blinded rubric_sha256")
        key = (judgment["arm_id"], judgment["query_id"])
        require(key[0] in arms and key[1] in queries and key not in judgments, "invalid/duplicate answer judgment")
        valid_hash(judgment["result_sha256"])
        integer(judgment["supported_claims"], 0, integer(judgment["total_claims"], 0, 10000))
        require(type(judgment["answer_correct"]) is bool and judgment["blinded"] is True
                and judgment["rubric_sha256"] == protocol["rubric_sha256"], "invalid adjudication protocol")
        label(judgment["adjudicator"])
        require(manifest["scope"] != "held_out" or not judgment["adjudicator"].startswith("synthetic"), "synthetic judgments cannot be a held-out claim")
        judgments[key] = judgment
    require(len(judgments) == len(arms) * len(queries), "missing answer judgments")
    results = {}
    metrics = ("ndcg", "recall", "mrr", "abstention_correct", "task_success", "adjudicated_support")
    counts = ("runtime_failures", "unsupported_claims", "rights_violations", "stale_returns", "context_violations", "budget_violations", "citation_count", "valid_citations", "citation_violations", "citation_rights_violations", "context_tokens", "answer_tokens", "embedding_tokens")
    for aid, arm in arms.items():
        fields(arm, "id family encoder runner measurement results")
        if arm["family"] == "lexical":
            require(arm["encoder"] is None, "lexical arm cannot hide an encoder")
        else:
            encoder = arm["encoder"]
            fields(encoder, "weights_sha256 tokenizer_sha256 pooling normalization dimension query_instruction_sha256 document_instruction_sha256")
            for key in ("weights_sha256", "tokenizer_sha256", "query_instruction_sha256", "document_instruction_sha256"):
                valid_hash(encoder[key])
            label(encoder["pooling"])
            label(encoder["normalization"])
            integer(encoder["dimension"], 1, 8192)
        fields(arm["runner"], "code_sha command index_config")
        require(isinstance(arm["runner"]["code_sha"], str) and re.fullmatch(r"[0-9a-f]{40}", arm["runner"]["code_sha"]), "runner code SHA missing")
        require(isinstance(arm["runner"]["command"], list) and all(isinstance(s, str) for s in arm["runner"]["command"])
                and arm["runner"]["command"] and isinstance(arm["runner"]["index_config"], dict), "missing runner recipe")
        measure = arm["measurement"]
        fields(measure, "wall_seconds restart_ms peak_rss_bytes")
        number(measure["wall_seconds"], positive=True)
        number(measure["restart_ms"])
        integer(measure["peak_rss_bytes"], 1)
        rows = index(artifact(root, arm["results"]), "query_id")
        require(set(rows) == set(queries), "missing/extra query output")
        for qid, row in rows.items():
            require(judgments[(aid, qid)]["result_sha256"] == judgment_result_hash(aid, row),
                    "judgment result hash mismatch: " + aid + "/" + qid)
        evaluated = {qid: evaluate_row(rows[qid], queries[qid], docs, qrels, judgments[(aid, qid)], protocol, protocol_hash) for qid in sorted(queries)}
        summary = {key: mean([r[key] for r in evaluated.values()]) for key in metrics}
        summary.update({key: sum(r[key] for r in evaluated.values()) for key in counts})
        summary["citation_integrity"] = (summary["valid_citations"] / summary["citation_count"] if summary["citation_count"] else None)
        summary["latency_ms"] = {f"p{p}": quantile([r["latency_ms"] for r in evaluated.values()], p) for p in (50, 95, 99)}
        summary["throughput_queries_per_second"] = len(queries) / measure["wall_seconds"]
        summary["protocol_clean"] = not any(summary[k] for k in ("runtime_failures", "rights_violations", "stale_returns", "context_violations", "budget_violations", "citation_violations", "citation_rights_violations"))
        results[aid] = {"family": arm["family"], "encoder": arm["encoder"], "runner": arm["runner"], "measurement": measure, "summary": summary, "rows": evaluated}
    comparisons = []
    pairs = set()
    for comparison in manifest["comparisons"]:
        fields(comparison, "candidate baseline")
        pair = (comparison["candidate"], comparison["baseline"])
        require(pair not in pairs and all(x in arms for x in pair), "invalid comparison")
        pairs.add(pair)
        candidate, baseline = (arms[x] for x in pair)
        require(candidate["family"] == "governed_memory" and baseline["family"] != "governed_memory", "invalid baseline pairing")
        require(baseline["family"] == "lexical" or candidate["encoder"] == baseline["encoder"], "encoder substitution confounds paired system comparison")
        comparisons.append({**comparison, "paired_cluster_bootstrap": {metric: paired_interval(results[pair[0]]["rows"], results[pair[1]]["rows"], metric, protocol["seed"], protocol["bootstrap_samples"]) for metric in metrics}})
    for aid, arm in arms.items():
        if arm["family"] == "governed_memory":
            require({arms[b]["family"] for a, b in pairs if a == aid} == {"lexical", "dense", "hybrid", "reranked"}, "missing governed/reference comparison")
    return {"schema_version": 2, "scope": manifest["scope"], "manifest_sha256": sha(manifest_bytes),
            "evaluator_sha256": sha(Path(__file__).read_bytes()), "protocol_sha256": protocol_hash,
            "protocol": protocol, "dataset_provenance": provenance, "query_count": len(queries), "source_count": len(docs),
            "superiority_claim": False, "arms": results, "comparisons": comparisons}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        result = evaluate(args.manifest)
    except (ValueError, OSError, TypeError, KeyError, UnicodeError) as error:
        parser.exit(2, f"campaign refused: {error}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
