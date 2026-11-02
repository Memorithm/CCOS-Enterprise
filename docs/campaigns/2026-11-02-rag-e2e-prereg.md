# RAG E2E campaign v1 — preregistration (DRAFT, not ready to run)

Status: **prereg drafted**. No run has happened, no generator/judge weights are downloaded, no
result exists. `superiority_claim` stays `false` (the evaluator always emits it). Nothing here
claims CCOS is a long-context or "1M-token" attention window; CCOS is governed external memory
with bounded per-turn recall ([MODEL_RUNTIME_INTEGRATION.md](../MODEL_RUNTIME_INTEGRATION.md)).

Contract: [RAG_COMPARATIVE_CAMPAIGN.md](../RAG_COMPARATIVE_CAMPAIGN.md), manifest schema 3,
scorer `scripts/evaluate-rag-campaign.py`, readiness gate `scripts/check-rag-campaign-readiness.py`,
inventory gate `scripts/check-rag-dataset-inventory.py`. Unblocks roadmap front 5
([fronts map](../roadmap/2026-10-28-fronts-map.md)) from "bloqué" to "prereg drafted" only.

## Defaults (chosen autonomously, revisable before freeze)

Every value below is a **default** picked by the agent with delegated autonomy. Any change before
the freeze commit is allowed and must be recorded in a dated amendment; after freeze, changes
require a new prereg version.

| # | Choice | Default | Rationale |
| --- | --- | --- | --- |
| 1 | Generator | `Qwen/Qwen2.5-7B-Instruct` (Apache-2.0), bf16 | Open weights, 7B class fits Thor; no generator is named in CCOS docs. CUDA (Thor) is an *optional runner path*, not a product dependency; a CPU/llama.cpp runner of the same pinned weights is admissible for re-runs. |
| 2 | Adjudicator | `mistralai/Mistral-7B-Instruct-v0.3` (Apache-2.0), temperature 0 | Different model family from the generator (avoids self-preference); license-clean; blind + randomized presentation. Human second review on a subsample (below). |
| 3 | Dataset | SQuAD 2.0 dev (EN, CC BY-SA 4.0) as test, document = Wikipedia paragraph; ~50 % unanswerable | Gold answers + explicit unanswerables; license compatible with redistribution of derived artifacts with attribution. BEIR sets (inventoried) have qrels but no gold answers, so they cannot score answer correctness. French secondary (exploratory): PIAF (license to verify before use). |
| 4 | Budget | k = 10 context docs, candidate pool 100, context ≤ 3,072 tokens, answer ≤ 256 tokens, temperature 0, seeds 1/2/3 | k/pool match BEIR v4/v5 (nDCG@10, pool/depth 100); 3 seeds match prior campaigns. |
| 5 | CCOS arm | campaign-example `DocumentMemory` (`docmem_fused_minilm`) — **scoped claim** | Product-path parity (front 3) is not done; results only speak for the campaign example, not the governed recall API. |

## Hypotheses

- **H1 (primary)**: on SQuAD 2.0 test queries, mean adjudicated `task_success` of the `ccos` arm
  minus the primary baseline `reranked` is ≥ **+0.02**, with paired cluster-bootstrap 95 % lower
  bound > 0 for each of seeds 1, 2, 3.
- **H2 (guardrail)**: zero authority regressions (unauthorized/stale/forbidden-tenant returns) for
  `ccos`; p95 latency, peak RSS and cost regressions vs `reranked` each ≤ 25 %.
- Secondary (exploratory, no multiplicity correction): `ccos` vs lexical/dense/hybrid; abstention
  accuracy on unanswerables; citation integrity; retrieval nDCG@10 with qrel coverage.

Outcome labels: **CONFIRMED** iff H1 and H2 hold; **REFUTED** iff mean Δ ≤ 0 on every seed;
otherwise **INCONCLUSIVE**. A CONFIRMED result still only supports the scoped claim (row 5).

## Arms (all five families required by the readiness gate)

| Arm id | Family | Configuration (frozen) |
| --- | --- | --- |
| `lexical` | lexical | Core BM25, k1 = 1.2, b = 0.75, depth 100 |
| `dense` | dense | all-MiniLM-L6-v2 @ `c9745ed1d9f207416be6d2e6f8de32d1f16199bf`, exact search |
| `hybrid` | hybrid | BM25 + same MiniLM, RRF (as `hybrid_bm25_minilm_rrf`, BEIR v5) |
| `reranked` | reranked | `hybrid` top-100 → frozen cross-encoder `cross-encoder/ms-marco-MiniLM-L-6-v2` (SHA pinned at download) → top-10. **Primary baseline**, preselected as strongest RAG reference by construction (not chosen after results). |
| `ccos` | governed_memory | `DocumentMemory` fused (α = 0.5 frozen from SciFact train, v3), same MiniLM; tenant/loadout/lineage recorded; citations mapped back to source paragraph IDs |

Every arm gets the identical generator, prompt, budgets, lifecycle status and tenant/ACL info.

## Generator pin fields (filled at download, before freeze)

```
generator.model_id        = Qwen/Qwen2.5-7B-Instruct
generator.hf_revision     = <commit SHA — PENDING download>
generator.weights_sha256  = <sha256 over sorted safetensors shards — PENDING>
generator.tokenizer_sha256= <sha256 of tokenizer.json — PENDING>
generator.prompt_sha256   = <sha256 of frozen prompt template file — PENDING>
generator.temperature     = 0 ; top_p = 1 ; seed ∈ {1,2,3}
runtime                   = <runner name + version, e.g. transformers/vLLM/llama.cpp — PENDING>
hardware                  = host_id, cpu, accelerator, ram_bytes, concurrency = 1 (measured)
```

The first campaign run must pin the exact SHA and hashes in the manifest **before** launch; a
missing pin fails the readiness gate and the run does not start.

## Adjudication

- Judge sees: question, gold answers (or "unanswerable"), the answer text, cited quotes. Not the arm
  id. Rows from all arms are shuffled with a fixed seed (`20261102`) before review.
- `result_sha256` (schema 3, `judgment_result_hash()`) is captured when the judge receives each
  row and stored with its judgment; never recomputed afterwards.
- Fields per judgment: `answer_correct`, `total_claims`, `supported_claims`, `adjudicator`,
  `rubric_sha256`, `blinded: true`, `result_sha256`.
- **Dual review**: stratified random subsample of 10 % of queries (min 200 rows, both
  answerable/unanswerable strata) independently judged by a human reviewer. Report Cohen's κ on
  `answer_correct` and raw agreement on support. If κ < 0.6 the campaign is reported as
  adjudication-unreliable (INCONCLUSIVE regardless of H1). The second reviewer may be scheduled
  after the LLM pass, but before results are published.
- Disagreements and adverse cases are retained, not dropped.

### Rubric draft (hash procedure)

1. `answer_correct` (answerable): answer is semantically equivalent to at least one gold answer
   (SQuAD normalisation as a reference, judge decides paraphrases). Unanswerable: correct iff the
   model abstains.
2. Claims: split the answer into atomic factual claims; a claim is supported iff a cited quote
   entails it. Uncited claims are unsupported.
3. Runtime `status: error` rows: `answer_correct = false`, zero supported claims.

The final rubric text is stored as `rubric.md` in the campaign directory; `rubric_sha256` =
SHA-256 of its UTF-8 bytes (LF line endings, no trailing whitespace) and is placed in both the
manifest `protocol.rubric_sha256` and every judgment row before any judgment is made.

## Decision rule (manifest `decision_rule`, schema 3)

```json
{
  "primary_baseline": "reranked",
  "primary_metric": "task_success",
  "minimum_mean_improvement": 0.02,
  "max_p95_latency_regression_percent": 25,
  "max_peak_rss_regression_percent": 25,
  "max_cost_regression_percent": 25,
  "require_zero_authority_regressions": true
}
```

## Dataset, splits and contamination audit

- Source: SQuAD 2.0 (Rajpurkar et al., 2018), CC BY-SA 4.0. Dataset file SHA-256 recorded at
  download (PENDING). `dataset_provenance.origin`, `.license`, `.split_author` filled accordingly.
- Splits by Wikipedia **article** (document family): SQuAD train articles → train/dev (tuning only
  on dev, e.g. abstention prompt), SQuAD dev articles → test. Query clusters = article id.
- Controls added identically for all arms: deleted and superseded paragraphs, a forbidden second
  tenant holding duplicated paragraphs; authorized flags recorded in the inventory consumed by
  `check-rag-dataset-inventory.py`.
- **Contamination audit (required)**: SQuAD/Wikipedia are very likely in the pretraining data of
  both generator and judge. This inflates absolute accuracy for *every* arm equally because the
  generator is shared; the paired Δ is the quantity of interest. The audit records: (a) closed-book
  baseline (generator with empty context) accuracy on test; (b) the model cards' declared data;
  (c) the audit file's SHA-256 → `training_overlap_audit_sha256`. A closed-book accuracy close to
  the arms' accuracy is reported as a limitation.

## Failure recording

Every query is executed for every arm and seed. A failed generation/timeout/OOM produces a
schema-valid row with `status: "error"`, `answer.abstained: true`, measured cost and tokens; it
never earns task or abstention success. No retries that change outputs; no silent skips. Invalid
runs are reported, not re-run with changes.

## Readiness checklist

| Item | State |
| --- | --- |
| Protocol, arms, decision rule, budgets, seeds | drafted (this doc) |
| Generator / judge / reranker SHAs | **PENDING download** |
| Dataset file hashes, inventory, controls | **PENDING** |
| Contamination audit file | **PENDING** |
| Rubric file + hash | draft above, file **PENDING** |
| Generator runner (retrieval JSONL → answer JSONL) | scaffold PR (`feat/rag-e2e-generator-runner`) |
| Adjudication kit (blinding/shuffle export, judgment import) | **TODO** |
| Arm adapters emitting common source rankings | **TODO** (reuse BEIR v3/v5 examples) |
| `check-rag-campaign-readiness.py` passes on real manifest | **not yet** — run must not start before |
| Front 3 product-path parity (to upgrade the scoped claim) | parallel prerequisite, open |
