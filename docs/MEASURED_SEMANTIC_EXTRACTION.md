# A06: measurable relation observations

The opt-in `ccos_enterprise_extract::semantic::extract_relations` API adds a
versioned English/French rule baseline alongside existing structural/prose
extraction. It recognizes explicit present-tense employment, location and
dependency phrases, including their listed negated forms. It produces named
**mentions**, relation kind, polarity, raw byte spans and an EvidenceRecord.
There is no entity identity resolution, journal write, trust promotion or model
call. `kind()` is fixed to `AssertionKind::Observation` with no setter.

Candidate IDs bind rule version, tenant, source ID, whole-source hash, raw unit
span and relation tuple. Evidence IDs reuse the existing extraction identity
contract. Input hashing is verified by the existing normalizer/parser; BOM,
CRLF and UTF-8 positions retain their original source offsets. Supporting a
sentence pattern does not prove that its assertion is true.

This is intentionally a narrow semantic baseline: title-case/proper-name-like
mentions, one relation per line, exact language phrases and optional final full
stop. Pronouns, questions, uncertainty, attribution, coordination, historical
qualifiers, markup and unrecognized wording abstain. No generalized NER,
coreference, multilingual coverage, open-ended entailment or learned extraction
quality is claimed. Limits are 4 MiB raw input, 8,192 parsed units, 2,048 bytes per
unit, 128 bytes per mention and 4,096 output candidates. Oversized units abstain;
whole-input/output ceilings reject the batch.

## Reproduce the evaluation

```bash
cargo run --locked --release -p ccos-enterprise-extract \
  --example semantic_extract_eval -- fixtures/semantic-relations-v1.jsonl \
  > /tmp/semantic-evaluation.json
```

The 48 authored synthetic regression cases include 28 expected relation tuples
and 20 cases requiring abstention. Eight positive paraphrases deliberately lie
outside the rule grammar and count as missed relations. The scorer matches the
full subject/relation/polarity/object tuple, reports TP/FP/FN, micro precision,
recall, F1, case coverage, abstentions and individual timings, and verifies
mention spans, source hashes and Observation-only output. Missing denominators
produce null, never an invented perfect score. Every adverse case is retained.

The JSON records fixture hash, executable hash, rule version, code SHA and dirty
state. The fixture and implementation were developed together: **this is not an
independent holdout or evidence of production extraction quality**. Latencies
are a short, cold, sequential fixture run, not throughput or an industrial SLO.
CI runs the fixture on Rust 1.89 and stable, archives both reports and rejects
false-positive or recall regression against this limited baseline.

Next qualification requires separately curated, blinded French/English domain
documents, independently reviewed spans/relations, document-level disjoint
splits and measured disagreement. Compare structural-only, these rules and a
fixed learned extractor under the same input, latency and review budgets.
Report entity linking, negation, temporal qualifiers, unsupported claims and
abstention separately. Model candidates must remain observational and cite
their raw sources; canonical promotion remains an explicit governed decision.

## Recorded local regression, 2026-09-19

[Raw report](benchmarks/semantic-relations-20260919-aarch64.json), clean code
`94d68ff9c582852268eda42affb49ca6d33f9617`, Rust 1.89, ARM64 NVIDIA Thor:
20 TP, 0 FP, 8 FN; precision 1.0, recall 0.714286, F1 0.833333, case coverage
0.416667. The 28 abstained units include eight missed paraphrases. These numbers
apply only to the authored fixture, not independent language understanding.
