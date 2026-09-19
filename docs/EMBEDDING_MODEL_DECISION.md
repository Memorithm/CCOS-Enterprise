# Compact Memorithm embeddings: decision record, 2026-09-19

## Decision

Evaluate a compact domain-adapted encoder behind an Enterprise-local, governed
interface. Do not claim that Rust, vector compression, a trust label, or a model
owned by Memorithm establishes retrieval or answer superiority. Training a new
foundation encoder is not a prerequisite for this experiment. Production adoption
depends on held-out results against lexical, dense, hybrid and reranked baselines.

The current `memory.evidence.write` accepts externally computed embeddings. It
does not implement a text encoder. Core already contains deterministic TF-IDF/LSA
retrievers; keep those in Core and consume their reviewed interfaces without
copying or enabling Enterprise dependencies in Core.

## Existing ecosystem component inspected

`Memorithm/scirust` at `9b34f52df617b71b233d00017fdc0728504b6342` has
[`scirust-core/src/embed.rs`](https://github.com/Memorithm/scirust/blob/9b34f52df617b71b233d00017fdc0728504b6342/scirust-core/src/embed.rs).
`EmbeddingEngine` constructs MiniLLM with a character tokenizer, mean-pools hidden
states and normalizes the output (128 dimensions by default). Its unit tests
exercise dimensions, finite values, normalization and a sentence-pair similarity.
These are not evidence of retrieval quality on independently judged documents.
Audit training, checkpoint loading, tokenization, batching and numerical parity
before selecting this component. No SciRust dependency revision or Core subtree
is changed by this decision.

Reusable work should live in SciRust for generic tensor/inference/training
operations, and in Enterprise for admission, tenant separation, quotas and model
selection. An upstream change needs that repository's own tests and exact-head
CI; a component's existence is not qualification for adoption.

## Experiments to register before training

1. Freeze corpus/query/qrel hashes, document-level train/dev/test partitions,
   generator revision, tokenizer, context budget, rights and evaluation rubric.
   Include French, technical documents, paraphrases, entity/date confusions,
   negation, contradictory and superseded evidence. No evaluation examples in
   training or hard-negative mining. No cross-tenant training without an explicit
   authorized dataset.
2. Compare existing encoders with a compact adapted encoder. Candidate capacity
   of 40–120 million parameters and 128/256 output dimensions is a research
   proposal, not a validated optimum. Keep generic-domain holdouts to measure
   regressions. Distillation and contrastive hard-negative training are separate
   ablations; record teacher and data provenance.
3. Keep a lexical baseline, a dense baseline, hybrid retrieval and a reranker.
   Evaluate the encoder with exact vector search first, then measure the adapter's
   approximate-index loss separately. Swap encoders inside both the CCOS and RAG
   arms so an encoder improvement cannot be misattributed to governance.
4. Report Recall@10/100, nDCG@10, MRR@10, citation span/hash validity, independently
   assessed answer support, abstention, deletion/revocation behavior, throughput,
   p50/p95/p99 and resident memory. Use paired query-level uncertainty estimates;
   publish unfavorable results and failed cases.
5. Accept only a predeclared quality/cost trade-off that generalizes to the
   holdouts. A Rust port must demonstrate numerical/ranking parity with the
   reference implementation and actual performance on the deployment hardware.
   Pure-Rust training is a separate engineering decision from Rust inference.

## Model-space and governance requirements

Persist model and tokenizer content hashes, pooling, normalization, query/document
instructions, dimension, precision and encoder revision with each index generation.
Equal vector dimensions do not mean equal embedding spaces. A change requires
an explicit re-embedding generation and recovery validation; no silent mixing.
The encoder may propose candidates only. It cannot promote trust, bypass
`Deployment::admit`, widen a tenant/loadout, or create canonical truth.

## Primary external references

- Google DeepMind, *EmbeddingGemma*, 2025, [model card](https://huggingface.co/google/embeddinggemma-300m):
  compact multilingual encoder with configurable output dimensions. This is a
  candidate baseline; its published results are not CCOS measurements.
- Zhang et al., *Qwen3 Embedding*, 2025-06-05, revised 2025-06-11,
  [paper](https://arxiv.org/abs/2506.05176) and
  [0.6B model card](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B):
  multilingual embedding/reranking baselines.
- Hugging Face, [Text Embeddings Inference](https://github.com/huggingface/text-embeddings-inference)
  and [Candle](https://github.com/huggingface/candle), inspected 2026-09-19:
  reference Rust inference implementations. No speed advantage is assumed.

Status: decision and evaluation design only. No newly trained model, measured
quality gain, model artifact or completed comparative campaign is claimed.

The [campaign contract and scorer](RAG_COMPARATIVE_CAMPAIGN.md) are now executable.
They require the same encoder in each governed/dense/hybrid/reranked comparison
and preserve negative results. The next evidence needed is an authorized,
independently judged domain corpus and completed real-model runs. The existing
[A06 rule baseline](MEASURED_SEMANTIC_EXTRACTION.md) has measured authored-fixture
misses; it is not proof that a proprietary embedding model would fix them.
