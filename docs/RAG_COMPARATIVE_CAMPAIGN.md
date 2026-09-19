# Reproducible CCOS / RAG comparison campaign

Status: executable artifact contract and scorer; **no real-model comparison has
been run**. The committed smoke inputs contain invented timings and identical
synthetic outputs for every arm. They test the evaluator, not the systems.

## Question and controlled arms

Test whether governed memory improves supported, correct task completion under
the same evidence, rights, token budget and operating constraints as strong RAG.
RAG baselines must receive the same tenant/ACL/deletion information and may
implement filtering, provenance, reranking and abstention. Deliberately weak or
ungoverned RAG is not an acceptable reference.

| Arm | Required recorded configuration |
| --- | --- |
| Lexical | Existing Core BM25 interface; tokenizer, k1/b, retrieval depth |
| Dense | Frozen encoder/tokenizer/instructions, exact search first |
| Hybrid | Same dense encoder plus lexical retrieval; frozen fusion rule |
| Reranked | Strong hybrid candidates plus frozen reranker, candidate depth |
| Governed memory | Same encoder; admitted tenant, loadout, lineage, projection and source citations |

Use the reviewed Core benchmark/import implementation through its existing
interface; do not copy a second retriever or importer into Enterprise. Its
[lineage](../core/UPSTREAM_CCOS_BEIR.json) and
[strict BEIR contract](../core/docs/BEIR_IMPORT_CONTRACT.md) remain unchanged.
This scorer consumes a common **source-document** ranking and actual served
answer artifacts, not BEIR input files. Adapters must map memory assets back to
their exact evidence/source IDs and record that transformation.

For an encoder experiment, run each encoder in both governed and dense/hybrid/
reranked arms. The scorer refuses paired comparisons with different encoder
weights, tokenizer, dimension, pooling, normalization or instructions. Equal
dimension alone is insufficient. Measure ANN approximation loss separately from
encoder quality. A proprietary encoder must beat qualified alternatives under
this experiment before becoming a product dependency.

## Freeze before execution

The complete schema is demonstrated by
[the smoke manifest](../fixtures/rag-campaign-smoke/manifest.json). Replace every
synthetic input, runner recipe, model hash, timing and adjudication for a real run.
Use one directory per immutable campaign; all paths must resolve inside it.

1. Curate authorized, versioned French/English documents and questions, recording
   origin and license. Split by source document and related document family;
   exclude test data from training, adaptation, distillation and negative mining.
   Preserve the training-overlap audit and its hash. The scorer checks metadata
   shape, not the truth of an overlap declaration.
2. Freeze the corpus, queries, graded qrels and common protocol hashes. Include
   answerable questions and explicit unanswerable, deleted, superseded and
   forbidden-tenant/principal controls. Positively judged sources must be
   eligible. Record cluster IDs for related questions, not one independent ID
   for every paraphrase. A source's current status must be supplied identically
   to all arms at each tested lifecycle checkpoint.
3. Pin generator weights, tokenizer, prompt, temperature/seed, hardware,
   concurrency, context/answer token ceilings and retrieval cutoff `k`. Record
   each arm's exact code SHA, command and index configuration. Tune only on a
   separate development split with comparable budgets, then freeze test runs.
4. Pre-register the primary task metric and minimum meaningful improvement,
   maximum p95 latency/RAM/cost regression and zero tolerated tenant/rights or
   deletion violations. Compare against the strongest preselected RAG arm; do
   not select it after observing which comparison favors CCOS. Secondary arms
   and encoder ablations remain exploratory unless multiplicity is addressed.
5. Execute every query, including failures, under the common protocol. Record
   source rankings, selected context IDs, answers/abstention, raw byte citations,
   latency and actual token counts. Record wall-clock batch duration separately
   from summed latency, peak RSS and restart time. Interleave randomized arm
   order and repeat trials; use separate manifests per repetition/checkpoint.
6. Blind and randomize answer presentation for independent adjudication. Store
   total/supported claims, answer correctness, adjudicator ID, rubric hash and
   `result_sha256` in a separate frozen JSONL file. Capture this result binding
   **when the reviewer receives the output**, preserving it with that review.
   Integrity of a quote does not judge entailment
   or answer correctness. Audit disagreements and retain adverse cases.

The runtime protocol digest binds inputs and common execution settings; answer
judgments arrive later and are bound by the final manifest hash. Hashes identify
bytes, not an authenticated runner. Runner latency/RSS/token counts, blinded
review declarations and training provenance require independent operational
verification. This preparation does not silently launch paid model jobs or
download restricted datasets.

### Schema 2: bind each judgment to the result actually reviewed

An `(arm_id, query_id)` join alone permits a substituted answer to inherit an old
favorable review, even when the result artifact's file hash is updated correctly.
Each judgment now requires `result_sha256`, calculated as SHA-256 of the UTF-8
canonical JSON object `{"arm_id": arm_id, "result": complete_result_row}`. Use
`judgment_result_hash()` in the evaluator: sorted object keys, compact separators,
unescaped Unicode, no non-finite numbers, no trailing newline. Array order and
all row fields are significant, including query ID, protocol hash, answer,
citations, context, ranking, runtime outcome and measured costs.

The review export must retain the hash captured at review time. Do not recompute
old review hashes against replacement results merely to make validation pass.
Changed results require a new review; JSON whitespace/key-order changes alone do
not. The scorer checks every binding before scoring that arm. A missing or stale
binding refuses the entire campaign, with no partial report. It does not repair
bindings or relabel results automatically.

Schema 1 is refused. For existing campaigns, recover the exact reviewed outputs
and their review records, verify their correspondence, then export schema 2;
otherwise repeat adjudication. The synthetic fixture was explicitly re-bound as
test data. These hashes prevent unnoticed mismatch, not coordinated falsification
of both results and reviews; they are not signatures or proof of honest review.

## Run and inspect

```bash
python3 scripts/test-rag-campaign.py
python3 scripts/evaluate-rag-campaign.py \
  fixtures/rag-campaign-smoke/manifest.json > /tmp/rag-smoke-report.json
# Real, pre-executed and independently judged artifacts:
python3 scripts/evaluate-rag-campaign.py /path/to/campaign/manifest.json \
  > /path/to/campaign/report.json
```

Malformed input, missing queries, duplicate IDs/ranks, tampered artifacts,
protocol mismatches, ineligible positive qrels and unmatched encoder comparisons
exit nonzero without a partial report. Policy, stale-result, citation, answer
and budget failures in structurally valid outputs remain in the report; they
are never removed as inconvenient queries. A failed external runner must still
produce a schema-valid `status: error` abstention record with its measured cost
and appropriate negative adjudication. Runtime failures never earn task or
abstention success, including on unanswerable questions. Do not silently omit
failed requests or label them `status: ok`.

Reports include nDCG@k (gain `2^relevance - 1`), Recall@k, MRR@k, abstention,
adjudicated support, task success, citation integrity, unauthorized/stale
returns, budget violations, token totals, p50/p95/p99, batch throughput, peak
RSS and restart time. Unjudged documents have relevance zero; disclose judgment
coverage. Retrieval means exclude questions without positive qrels and report
null where undefined. Those questions still count in abstention/task metrics.
The full per-query rows preserve denominators and misses.

Task success requires a correct adjudication, no observed policy/budget breach,
and, for answerable queries, fully supported claims plus valid eligible citations.
For unanswerable queries it requires abstention. Support is a supplied review
judgment, not inferred from cosine similarity, trust labels or quote hashes.
`protocol_clean` checks observed rights/staleness/budget/citation violations; it
does not certify runner honesty or unobserved infrastructure.

Paired 95% percentile bootstrap intervals resample query clusters with a fixed
seed, preserving each pair of system outputs. Fewer than two populated clusters
produce no interval. Intervals are exploratory, not adjusted for multiple
comparisons; small or correlated datasets need further statistical review.
Conditional support comparisons use only queries with judgments in both arms;
task success and abstention retain every query to expose coverage differences.

The evaluator always emits `superiority_claim: false`. A claim that CCOS exceeds
RAG requires completed real runs, independent judgments, the registered decision
rule, zero authority regressions and reproducible artifacts. A09 scale/recovery,
A06 authored regression, and this synthetic smoke run do not establish that claim.

Input ceilings: 2 MiB manifest, 256 MiB per artifact, 64 arms, 100k queries,
1,000 returned source IDs and 1,024 citations per query. These are input limits,
not constant-memory or latency guarantees. The scorer runs offline and accesses
only explicit local campaign files; it does not fetch source URLs or execute
runner commands from the manifest.
