# HTTP gateway for governed reads (PR1)

Status: **PR1 — minimal transport, off by default** (feature `http-gateway`). Dated 2026-10-29.

## Why

Until now `memory.document_recall` (DocumentMemory, lexical BM25 by default; dense/fused only
via operator config, #240) and `memory.context` were served only by the stdio MCP binary
(#236/#237/#240). `ccos-enterprise-gateway` is a pure request/tool-name model with no transport.
This PR adds the smallest HTTP transport that reuses the stdio admission path instead of
building a second front door.

## Cartography (what already existed)

| Piece | Role |
|---|---|
| `ccos-enterprise-gateway` | `GatewayRequest` type + tool-name ordering. No I/O. |
| `ccos-enterprise-runtime::Deployment::admit` | RBAC, tenant, quota, replay, audit. |
| `ccos-enterprise-mcp-server` (`Server::handle`) | Process bound to one signed principal + one tenant; journal, effect witness, settlement. |
| `served_governed_stdio.rs` | `memory.context` / `memory.document_recall` execution seam. |

No HTTP framework (hyper/axum/tokio) is in the workspace; none is added.

## Design

* `CCOS_ENTERPRISE_HTTP_BIND=<addr:port>` makes the same binary serve HTTP instead of stdio.
  Without the feature, setting it is a boot error (never a silent stdio fallback).
* Each request is translated into the exact stdio `tools/call` message and passed to
  `Server::handle`: identity re-check, `Deployment::admit`, `ToolRequested/Started/Finished`
  journal, `effect.json` witness and governance settlement are the stdio code, unchanged.
* `Authorization: Bearer <identity token>` is verified per request with the process
  authenticator and must prove the process-bound org/actor (401 if unverifiable, 403 if
  another principal).
* The client never chooses tenant, actor, host, model, space, policy or ranking: `_meta.ccos`
  is filled by the server. Body keys are an allow-list; anything else is 400. An optional
  `tenant` assertion is allowed only so a mismatch is refused (403), never rebound.
* Ranking is the boot configuration (`CCOS_ENTERPRISE_DOCUMENT_RANKING`, default
  `lexical_bm25`) and is echoed as `structuredContent.ranking`.
* SML sigpage-v0 is **not** exposed (NEGATIVE, #243). Only governed DocumentMemory is served.

### Routes

| Method | Path | Tool |
|---|---|---|
| POST | `/v1/memory/document_recall` | `memory.document_recall` |
| POST | `/v1/memory/context` | `memory.context` |

Request:

```json
{ "request_id": "r-1", "turn_id": "?", "step_id": "?", "execution_attempt_id": "?",
  "tenant": "? (assertion only)", "arguments": { "query": "...", "k": 8 } }
```

Response: `200 {"ok":true,"tool":...,"result":{...MCP tool result...}}` (replay returns
`structuredContent.replayed: true`); errors `{"ok":false,"error":{"code","message"}}` with
400 invalid arguments / 401 unauthenticated / 403 forbidden / 404 / 405 / 413 / 422 tool error /
503 durable state unavailable.

## Limits (explicit)

* Single-threaded, `Connection: close`, no keep-alive, 1 MiB body, 16 KiB head, 10 s I/O timeout.
* **No TLS**: bind to localhost or put a TLS-terminating proxy in front.
* One process = one principal + one tenant, exactly like stdio. Multi-tenant HTTP is PR2+.
* No latency/throughput numbers are claimed; none were measured.

## Tests

`crates/ccos-enterprise-mcp/tests/governed_document_recall_http.rs` (runs under
`--all-features` in CI) spawns the real binary on `127.0.0.1:0` and checks: governed recall
(only the verified active asset, `ranking=lexical_bm25`), effect witness + execution journal,
replay suppression, unknown argument / envelope fields refused, foreign tenant refused,
missing/forged/other-principal tokens refused, 404/405 routing.

## Roadmap

* **PR1 (2026-10-29, this PR)**: std-only transport, two routes, admission reuse, tests.
* **PR2 (target 2026-11)**: TLS (rustls) or documented proxy contract; bounded concurrency
  (the `Server` is `&mut`, so a single admission worker behind a queue); structured access log.
* **PR3 (target 2026-12)**: per-request principal (multi-actor per process) once
  `Deployment::admit` callers can bind identity per request without the process token; then
  evaluate `memory.skills`/write tools over HTTP. Benchmarks only after real measurement.
