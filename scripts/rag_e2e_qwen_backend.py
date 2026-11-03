"""Pinned Qwen2.5-7B-Instruct backend for `scripts/rag-e2e-generate.py --backend rag_e2e_qwen_backend:make_backend`.

Env (all required except where noted):
  RAG_E2E_SNAPSHOT  local snapshot dir of Qwen/Qwen2.5-7B-Instruct @ a09a3545 (verified by the workflow)
  RAG_E2E_CORPUS    corpus.jsonl (to bind citations to the cited documents' bytes)
  RAG_E2E_DEVICE    optional, default "cuda"

Frozen v1 decoding/parse rules (no tuning, no metrics):
  * the frozen prompt is sent as the single user turn of the model's own chat template;
  * greedy decoding (do_sample=False), max_new_tokens = answer budget, bf16;
  * abstained  <=> the answer matches ABSTAIN_RE (case-insensitive) or is empty;
  * citations  = distinct `[doc_id]` markers in the answer whose doc_id is in the prompt's sources,
    each bound to the whole cited document span (0, len(utf-8 bytes)); the model emits no offsets,
    so no finer span is claimed. Markers are kept in the answer text.
"""

from __future__ import annotations

import json
import os
import re

ABSTAIN_RE = re.compile(r"\babstain|\bdo(?:es)? not contain|\bcannot (?:be )?answer|\bunanswerable", re.I)
CITE_RE = re.compile(r"\[([^\[\]\n]+)\]")
SOURCE_RE = re.compile(r"^\[([^\[\]\n]+)\] ", re.M)


def parse_answer(text: str, prompt: str, doc_bytes_len) -> tuple[bool, list[dict]]:
    """Pure v1 parse rule (tested without a model)."""
    text = text.strip()
    if not text or ABSTAIN_RE.search(text):
        return True, []
    allowed = set(SOURCE_RE.findall(prompt))
    seen, cites = set(), []
    for doc_id in CITE_RE.findall(text):
        doc_id = doc_id.strip()
        if doc_id in allowed and doc_id not in seen:
            seen.add(doc_id)
            n = doc_bytes_len(doc_id)
            if n > 0:
                cites.append({"doc_id": doc_id, "start": 0, "end": n})
    return False, cites


class QwenBackend:
    def __init__(self, snapshot: str, corpus: str, device: str = "cuda"):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(snapshot)
        self.model = AutoModelForCausalLM.from_pretrained(snapshot, torch_dtype=torch.bfloat16).to(device).eval()
        self.device = device
        with open(corpus, encoding="utf-8") as f:
            self.lens = {d["id"]: len(d["text"].encode()) for d in map(json.loads, filter(str.strip, f))}

    def count_tokens(self, text: str) -> int:
        return len(self.tok.encode(text, add_special_tokens=False))

    def generate(self, prompt: str, max_tokens: int) -> dict:
        ids = self.tok.apply_chat_template([{"role": "user", "content": prompt}], add_generation_prompt=True,
                                           return_tensors="pt").to(self.device)
        with self.torch.inference_mode():
            out = self.model.generate(ids, max_new_tokens=max_tokens, do_sample=False, temperature=None,
                                      top_p=None, top_k=None, pad_token_id=self.tok.eos_token_id)
        new = out[0, ids.shape[1]:]
        text = self.tok.decode(new, skip_special_tokens=True).strip()
        abstained, cites = parse_answer(text, prompt, lambda d: self.lens.get(d, 0))
        return {"text": text, "abstained": abstained, "citations": cites, "answer_tokens": int(new.shape[0])}


def make_backend():
    return QwenBackend(os.environ["RAG_E2E_SNAPSHOT"], os.environ["RAG_E2E_CORPUS"],
                       os.environ.get("RAG_E2E_DEVICE", "cuda"))
