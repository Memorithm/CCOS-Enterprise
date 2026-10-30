#!/usr/bin/env bash
# Fetch sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2 (Apache-2.0) at a pinned
# revision and verify sha256. Weights stay on local disk (never committed).
# Usage: ./fetch-model-multilingual.sh <dest-dir>
#   e.g. ./fetch-model-multilingual.sh /workspace/models/paraphrase-multilingual-MiniLM-L12-v2
set -euo pipefail
dest=${1:?dest dir}
repo=sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2
rev=e8f8c211226b894fcb81acc59f3b34ba3efd5f42
mkdir -p "$dest/1_Pooling"
for f in config.json tokenizer.json model.safetensors sentence_bert_config.json modules.json \
  config_sentence_transformers.json 1_Pooling/config.json; do
  curl -sfL -o "$dest/$f" "https://huggingface.co/$repo/resolve/$rev/$f"
done
cd "$dest" && sha256sum -c - <<'SUMS'
6300193cb75e01cf80c96decef7187dfb33094d97cc1490b7ead6ff134476e4e  config.json
2c3387be76557bd40970cec13153b3bbf80407865484b209e655e5e4729076b8  tokenizer.json
eaa086f0ffee582aeb45b36e34cdd1fe2d6de2bef61f8a559a1bbc9bd955917b  model.safetensors
70f4448f31320443fe3557cacea5abf2dcc4915dda8c80646bec9f3bb0aa5a1f  sentence_bert_config.json
8f4b264b80206c830bebbdcae377e137925650a433b689343a63bdc9b3145460  modules.json
b8c64b5cece00d8424b4896ea75b512b6008576088497609dfeb6bd63e6d36b8  config_sentence_transformers.json
4be450dde3b0273bb9787637cfbd28fe04a7ba6ab9d36ac48e92b11e350ffc23  1_Pooling/config.json
SUMS
