# Preregistration — BEIR retrieval campaign, CCOS governed memory vs RAG baselines

Status: **preregistered, not yet run.** Frozen before any test-split result was produced.
Base: main `6981350`. Results go in a separate commit that cites this file's commit SHA.

## Scope (and what this is NOT)

- Retrieval-only. This is **not** the end-to-end campaign of
  [RAG_COMPARATIVE_CAMPAIGN.md](../RAG_COMPARATIVE_CAMPAIGN.md): no generator, no answers,
  no blinded adjudication. That campaign stays **blocked** (needs pinned generator weights and
  independent adjudicators); `superiority_claim` stays `false` regardless of outcome here.
- SML-GENIUS as a `SemanticMemoryProvider`: **deferred**. SML-GENIUS (`588143af`) exposes no
  document-retrieval API to adapt; building one is out of scope and is not preregistered.

## Data (public, not committed; held outside the repo)

BEIR test splits, strict import (`core/examples/support/beir_import.rs`), all positively
judged queries, no filtering.

| dataset | file | sha256 |
|---|---|---|
| SciFact | corpus.jsonl | dec31c8182f3d744c7d2c09423756fd1d17cbef75808db13ba01cc0aab4d1ac6 |
| SciFact | queries.jsonl | 8ff84a7c903f722981cd8d595c022660140c51867b27608a6d4910db86080313 |
| SciFact | qrels/test.tsv | 0864bb985e0ca2367ba217977e72004d549054b2b06666ed9d4825ac7c21284c |
| NFCorpus | corpus.jsonl | 10cc83ef1826b1425e6a87090b5140b39b27755d5a27e48215a88611c899991f |
| NFCorpus | queries.jsonl | d024e6621b84925d485ae473d316a0c3af31c62c8068a59fb29d22f7613aef2a |
| NFCorpus | qrels/test.tsv | f8fba6ef3d4dd9c3a242a8ba4ae38276fc3622fce7dcbae764766d564542fd2a |

Source: `https://public.ukp.informatik.tu-darmstadt.de/thakur/BEIR/datasets/{scifact,nfcorpus}.zip`.

## Arms (harness `core/examples/beir_campaign.rs`, frozen in this commit)

| arm | configuration |
|---|---|
| bm25 | `Bm25Index` k1=1.2 b=0.75, lowercase-alnum tokenizer |
| tfidf_dense | `CcosEncoder` hashed TF-IDF d=512, exact search |
| lsa_dense | `LsaEncoder` d=512 rank=128, exact search (the shared dense encoder) |
| hybrid_bm25_lsa_rrf | RRF(k=60) over bm25 + lsa_dense |
| ccos_memory_semantic | `CcosMemory::new()`, each doc ingested as `doc/<i>.txt`, `Recall::Semantic`, unbounded token budget, window order → first 100 distinct docs |
| ccos_memory_hybrid | same memory, `Recall::Hybrid` |

Encoder parity: all baseline dense arms share one fitted LSA encoder. The CCOS memory arms use
`CcosMemory`'s **internal** TF-IDF / causally-weighted LSA, which the public API does not allow
replacing, so memory-vs-dense is **not encoder-matched** and is reported that way.
No hyperparameter is tuned: all values are existing committed defaults (no dev split used).
Retrieval depth 100.

## Decision rule (fixed now)

- Primary: SciFact nDCG@10, `ccos_memory_hybrid` vs `bm25`. BM25 is preselected as the strongest
  baseline from the prior committed measurement (`core/docs/MEASUREMENT_beir.md`).
- Meaningful improvement: mean paired delta ≥ +0.01 **and** 95% paired bootstrap lower bound > 0
  for all three seeds (1, 2, 3; 10,000 query resamples). Otherwise: "no improvement shown".
- Secondary/exploratory: every other arm vs bm25, and NFCorpus. No multiplicity correction.
- Determinism: run twice; stdout must be byte-identical (sha256 recorded). Timings on stderr.
- Negatives kept: every judged query counted; empty memory windows score 0 and are counted;
  a crash or a run over 2 h per dataset is reported as a failed arm, not dropped.
