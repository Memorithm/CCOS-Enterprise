# FPR-v12 run inputs (SHA-asserted by the harness)
- `deepset-prompt-injections.jsonl` sha256 `2c46bfa4…2ef8` (deepset/prompt-injections, Apache-2.0; converter unchanged since v5).
- `chat_v9.jsonl.gz` → `chat_v9.jsonl` sha256 `aaa6cc3b…d882` (built by `../../2026-10-30-ingest-guard-fpr-v9/build_chat_v9.py`;
  Dolly CC BY-SA 3.0, OASST1 Apache-2.0, HH-RLHF MIT, NQ-open CC BY-SA 3.0).
- BEIR SciFact/NFCorpus/FiQA are downloaded by the workflow from the public BEIR mirror; corpus SHAs asserted by the harness.
Vendored only so the self-hosted Thor job (`.github/workflows/fpr-v12-campaign-thor.yml`) has no private data path.
