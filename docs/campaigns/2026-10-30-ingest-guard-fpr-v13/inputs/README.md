# FPR-v13 run inputs (SHA-asserted by the harness)
- `chat_v13.jsonl.gz` → `chat_v13.jsonl` sha256 `14de7a08656d90ba21320408b356178a746a9478a76234bce88cbc066b03762a`
  (built by `../build_chat_v13.py` from `chat_v9.jsonl` `aaa6cc3b…d882` + the pinned OASST1 dump `286a6e9a…a185c`;
  Dolly CC BY-SA 3.0, OASST1 Apache-2.0 (incl. new `oasst1_de`), HH-RLHF MIT, NQ-open CC BY-SA 3.0).
- deepset: reused from `../../2026-10-30-ingest-guard-fpr-v12/inputs/deepset-prompt-injections.jsonl` (sha256 `2c46bfa4…2ef8`, Apache-2.0).
- BEIR SciFact/NFCorpus/FiQA: downloaded by the workflow from the public BEIR mirror; corpus SHAs asserted by the harness.
