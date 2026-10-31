# Model ↔ CCOS runtime integration contract

Status: contract document (2026-10-31). Describes tools that already exist on `main`;
introduces no new capability and claims no new measurement.

## Purpose and non-goals

CCOS Enterprise gives an agent runtime **extra-long *useful* context through governed
external memory**: an unbounded-over-time, tenant-scoped store from which each turn
recalls a **bounded** slice that the model then reads inside its own, ordinary context
window.

Non-goals (explicit):

* CCOS does **not** give any model a native 1M+ token attention window. The model's
  attention window is whatever the model has; CCOS only chooses what to put in it.
* No claim that governed recall beats modern RAG end to end (see
  [RAG comparative campaign](RAG_COMPARATIVE_CAMPAIGN.md)).
* No latency, throughput or retrieval-quality SLO is stated here.

## Agent loop

```
admit ─▶ recall / context (bounded budget) ─▶ model generate ─▶ evidence write ─▶ next turn
```

1. **Admit** — every call is a `tools/call` that passes identity verification and
   `Deployment::admit` (RBAC, tenancy, quota, model allow-list) before any memory access.
2. **Recall** — `memory.document_recall` (query text) or `memory.context` (client
   embedding) returns governed items bounded by `context_max_items` /
   `context_max_payload_bytes`.
3. **Generate** — the runtime assembles prompt = system + recalled slice + conversation,
   keeping an output reserve (below). Generation happens outside CCOS.
4. **Evidence write** — useful outputs/observations are appended with
   `memory.evidence.write`; the server fixes them as `Unverified` `Evidence` in the `Tenant`
   space. Writing never promotes trust.
5. **Next turn** — recall again; only items admitted by the trust policy re-enter context.

## Tool surface

| Tool | Transport | Admission | Typical args | Returns | Failure modes |
|---|---|---|---|---|---|
| `memory.document_recall` | stdio MCP; HTTP `POST /v1/memory/document_recall` | `memory.read` + `Deployment::admit`; tenant must equal projection tenant | `query` (≤ 8192 B), `k` (default 8, ≤ 256), `context_max_items` (default 8, ≤ 256), `context_max_payload_bytes` (default 64 KiB, ≤ 4 MiB) | governed items + `structuredContent.ranking` (and `ranking_alpha`/`ranking_pool` when fused) | invalid args, refused admission, tenant mismatch, governance rejection (unknown asset, relabelled space, lineage, trust) — fail closed |
| `memory.context` | stdio MCP; HTTP `POST /v1/memory/context` | `memory.read` + admit | `embedding` (required), `recall_max_items` (≤ 1024), `recall_max_shortlist` (≤ 8192), `recall_max_payload_bytes` (≤ 16 MiB), `context_max_items` (≤ 256), `context_max_payload_bytes` (≤ 4 MiB) | bounded structured context of verified items | as above; the client must produce the embedding |
| `memory.evidence.write` | **stdio MCP only** (not an HTTP route) | `memory.write` + admit | `asset_id`, `evidence_ref`, `embedding`, `payload_bytes` | appended asset (space=`Tenant`, stratum=`Evidence`, trust=`Unverified`) | client-chosen `space`/`stratum`/`trust`/`parents`/`loadout` are refused |
| `memory.purge` | stdio MCP | `memory.purge` (separate from write) | see [physical purge](GOVERNED_PHYSICAL_PURGE.md) | purge receipt, non-resurrection floor | missing permission, invalid target |

HTTP specifics (1 MiB body, no TLS, one principal + one tenant per process, error codes
400/401/403/404/405/413/422/503) are in [HTTP gateway](HTTP_GATEWAY.md). The client never
chooses tenant, actor, model, space, policy or ranking.

## Token budgets

CCOS budgets in **items and bytes**, not tokens. The runtime converts:

* **Input slice budget** = model window − system prompt − conversation − **output reserve**.
  Map it to `context_max_payload_bytes` with a conservative bytes-per-token ratio for the
  model's tokenizer (measure it for your tokenizer; none is asserted here).
* **Output reserve** — kept by the runtime; CCOS has no knowledge of it.
* Hard per-call maxima: 256 items and 4 MiB payload (`MAX_MEMORY_CONTEXT_ITEMS`,
  `MAX_MEMORY_CONTEXT_PAYLOAD_BYTES` in `ccos-enterprise-memory/src/context_budget.rs`).
* Store limits — 64 MiB per governance projection, 256 MiB per provider image (see
  [governed memory vs RAG](GOVERNED_MEMORY_VS_RAG.md),
  [store contract](GOVERNED_MEMORY_STORE_CONTRACT.md)) — are **input ceilings, not SLOs**,
  and bound total governed memory, not what a model can attend to.

## Identity, tenant, space and trust

* One process = one principal + one tenant (stdio and HTTP PR1). Tenant assertion in HTTP
  can only cause a refusal, never a rebind.
* Spaces come from the durable bootstrap loadout, never from the client.
* Recall uses `GovernedRecallTrustPolicy::VerifiedOnly` on the served path; freshly written
  `Evidence` is `Unverified` and therefore does not re-enter served context until promoted
  through governance.
* [Verified citations](VERIFIED_MEMORY_CITATIONS.md) prove **integrity** (content hash +
  byte span), **not truth**.

## Ranking options for `memory.document_recall`

Selected by the operator at boot via `CCOS_ENTERPRISE_DOCUMENT_RANKING`:

* `lexical_bm25` (default, no vectors).
* `dense` / `fused` (default α 0.5, pool 100) when an encoder is injected
  ([document_ranking.rs](../crates/ccos-enterprise-mcp/src/document_ranking.rs)). The dense
  encoder has a packed CUDA path (#275) whose speedup is probe-only; GPU corpus re-measure is
  still open ([GPU execution path](gpu-execution-path.md)).
* SML concurrent arm (`ccos-enterprise-sml-retrieval`, #241): trait + governance wrapper,
  status `NotBeirValidated`, **not wired into the served MCP/HTTP path**. SML sigpage-v0 is
  not exposed (#243).

Ranking scores are ordering data only; every item still passes `admit_governed_recall`.

## Claim language

* Product: "Governed, tenant-isolated external memory with bounded per-turn recall,
  audit and verified-integrity citations."
* Research: any claim of quality vs RAG, long-context equivalence, or speedup requires a
  measured campaign; until then say "not measured".
* Never: "CCOS gives the model a 1M-token context window."

## Open gaps

* RAG E2E remains blocked on the generator and adjudication arms — no end-to-end answer
  quality is claimed.
* IngestGuard / ConformalGuard are **not wired** (FPR-v13 refuted).
* GPU corpus re-measure for the dense encoder is open.
* `memory.evidence.write` requires a client-produced embedding and is not exposed over HTTP.
* SML retrieval arm not served.

## Native long attention (Voie B)

Native long-context attention is a model-side research track living in SML-GENIUS, not in
CCOS Enterprise. If it produces a validated model, it would consume this same contract —
a longer window simply allows a larger input slice budget; governance is unchanged.
