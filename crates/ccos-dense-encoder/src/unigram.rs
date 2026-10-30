//! Minimal SentencePiece **Unigram** tokenizer, equivalent to the Hugging Face `tokenizers`
//! pipeline shipped in `tokenizer.json` by XLM-R-vocabulary sentence-transformers such as
//! `paraphrase-multilingual-MiniLM-L12-v2`:
//!
//! 1. special/added tokens (`<s>`, `</s>`, `<pad>`, `<unk>`, `<mask>`, …) are split out of the raw
//!    text first and mapped straight to their ids (as `AddedVocabulary` does);
//! 2. `Precompiled` normalizer: the SentencePiece `precompiled_charsmap` (a Darts double-array trie
//!    plus a NUL-separated replacement blob, i.e. `nmt_nfkc`) applied per extended grapheme
//!    cluster, falling back to per-char, exactly like `spm_precompiled::Precompiled`;
//! 3. `WhitespaceSplit` + `Metaspace { replacement = '▁', add_prefix_space = true }`;
//! 4. Unigram Viterbi (max total log-prob; unknown chars → `unk` scored `min_score − 10`,
//!    consecutive unknowns fused), as `tokenizers::models::unigram::Unigram::encode`;
//! 5. `TemplateProcessing` `<s> $A </s>`, truncated so the total is at most `max_len`.

use std::collections::HashMap;
use unicode_segmentation::UnicodeSegmentation;

const UNK_PENALTY: f64 = 10.0;

/// Darts double-array trie + replacement blob from SentencePiece `precompiled_charsmap`.
#[derive(Debug, Clone)]
struct CharsMap {
    trie: Vec<u32>,
    normalized: Vec<u8>,
}

impl CharsMap {
    fn from_bytes(b: &[u8]) -> Result<Self, String> {
        let n = u32::from_le_bytes(
            b.get(..4)
                .ok_or("charsmap: truncated")?
                .try_into()
                .map_err(|_| "charsmap: truncated")?,
        ) as usize;
        let tb = b.get(4..4 + n).ok_or("charsmap: bad trie size")?;
        let trie = tb
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Ok(Self {
            trie,
            normalized: b[4 + n..].to_vec(),
        })
    }

    /// Values of every key that is a prefix of `key` (shortest first), Darts `commonPrefixSearch`.
    fn prefix_values(&self, key: &[u8]) -> Vec<usize> {
        let offset = |u: u32| ((u >> 10) << ((u & (1 << 9)) >> 6)) as usize;
        let label = |u: u32| u & ((1 << 31) | 0xFF);
        let has_leaf = |u: u32| (u >> 8) & 1 == 1;
        let value = |u: u32| (u & ((1 << 31) - 1)) as usize;
        let mut out = Vec::new();
        let Some(&root) = self.trie.first() else {
            return out;
        };
        let mut pos = offset(root);
        for &c in key {
            if c == 0 {
                break;
            }
            pos ^= c as usize;
            let Some(&u) = self.trie.get(pos) else {
                break;
            };
            if label(u) != c as u32 {
                break;
            }
            pos ^= offset(u);
            if has_leaf(u) {
                if let Some(&v) = self.trie.get(pos) {
                    out.push(value(v));
                }
            }
        }
        out
    }

    fn transform(&self, chunk: &str) -> Option<&str> {
        let i = *self.prefix_values(chunk.as_bytes()).first()?;
        let tail = self.normalized.get(i..)?;
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        std::str::from_utf8(&tail[..end]).ok()
    }

    fn normalize(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for g in s.graphemes(true) {
            if g.len() < 6 {
                if let Some(n) = self.transform(g) {
                    out.push_str(n);
                    continue;
                }
            }
            for (p, c) in g.char_indices() {
                let part = &g[p..p + c.len_utf8()];
                out.push_str(self.transform(part).unwrap_or(part));
            }
        }
        out
    }
}

/// Standard base64 decoder (the charsmap is base64 in `tokenizer.json`).
fn b64(s: &str) -> Result<Vec<u8>, String> {
    let val = |c: u8| -> Result<u32, String> {
        Ok(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(format!("base64: bad byte {c}")),
        } as u32)
    };
    let s: Vec<u8> = s
        .bytes()
        .filter(|&c| c != b'=' && !c.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for ch in s.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in ch.iter().enumerate() {
            acc |= val(c)? << (18 - 6 * i);
        }
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..ch.len()]);
    }
    Ok(out)
}

/// Unigram (SentencePiece) tokenizer state.
#[derive(Debug, Clone)]
pub struct Unigram {
    pieces: HashMap<String, (u32, f64)>,
    max_piece_chars: usize,
    unk: u32,
    unk_score: f64,
    bos: u32,
    eos: u32,
    /// Added/special tokens matched verbatim in the raw text, longest first.
    specials: Vec<(String, u32)>,
    charsmap: Option<CharsMap>,
    max_len: usize,
}

impl Unigram {
    /// Build from a parsed `tokenizer.json` (`model.type = "Unigram"`).
    pub fn from_json(t: &serde_json::Value, max_len: usize) -> Result<Self, String> {
        let m = &t["model"];
        if m["type"] != "Unigram" {
            return Err("tokenizer.json: model.type must be Unigram".into());
        }
        let vocab = m["vocab"]
            .as_array()
            .ok_or("tokenizer.json: model.vocab missing")?;
        let mut pieces = HashMap::with_capacity(vocab.len());
        let (mut min_score, mut max_piece_chars) = (f64::INFINITY, 1usize);
        for (i, e) in vocab.iter().enumerate() {
            let p = e[0].as_str().ok_or("vocab entry: piece")?;
            let s = e[1].as_f64().ok_or("vocab entry: score")?;
            min_score = min_score.min(s);
            max_piece_chars = max_piece_chars.max(p.chars().count());
            pieces.entry(p.to_string()).or_insert((i as u32, s));
        }
        let unk = m["unk_id"]
            .as_u64()
            .ok_or("tokenizer.json: unk_id missing")? as u32;
        let id = |s: &str| pieces.get(s).map(|v| v.0).ok_or(format!("vocab lacks {s}"));
        let (bos, eos) = (id("<s>")?, id("</s>")?);
        let n = &t["normalizer"];
        let charsmap = match n["type"].as_str() {
            None => None,
            Some("Precompiled") => Some(CharsMap::from_bytes(&b64(n["precompiled_charsmap"]
                .as_str()
                .ok_or("precompiled_charsmap missing")?)?)?),
            Some(o) => return Err(format!("tokenizer.json: unsupported normalizer {o}")),
        };
        let pre = &t["pre_tokenizer"];
        let ok_pre = pre["type"] == "Metaspace"
            || (pre["type"] == "Sequence"
                && pre["pretokenizers"].as_array().is_some_and(|a| {
                    a.iter()
                        .all(|p| p["type"] == "WhitespaceSplit" || p["type"] == "Metaspace")
                }));
        if !ok_pre {
            return Err("tokenizer.json: WhitespaceSplit/Metaspace pre-tokenizer required".into());
        }
        let mut specials: Vec<(String, u32)> = t["added_tokens"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some((e["content"].as_str()?.to_string(), e["id"].as_u64()? as u32))
                    })
                    .collect()
            })
            .unwrap_or_default();
        specials.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Ok(Self {
            pieces,
            max_piece_chars,
            unk,
            unk_score: min_score - UNK_PENALTY,
            bos,
            eos,
            specials,
            charsmap,
            max_len: max_len.max(2),
        })
    }

    /// Viterbi segmentation of one pre-token (already `▁`-prefixed).
    fn viterbi(&self, word: &str, out: &mut Vec<u32>) {
        let idx: Vec<usize> = word
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(word.len()))
            .collect();
        let n = idx.len() - 1;
        // best[e] = (score, start char, id) of the best path ending at char e.
        let mut best: Vec<Option<(f64, usize, u32)>> = vec![None; n + 1];
        best[0] = Some((0.0, 0, 0));
        for s in 0..n {
            let Some((base, _, _)) = best[s] else {
                continue;
            };
            let mut single = false;
            for e in s + 1..=n.min(s + self.max_piece_chars) {
                if let Some(&(id, sc)) = self.pieces.get(&word[idx[s]..idx[e]]) {
                    single |= e == s + 1;
                    let c = base + sc;
                    if best[e].is_none_or(|b| c > b.0) {
                        best[e] = Some((c, s, id));
                    }
                }
            }
            if !single {
                let c = base + self.unk_score;
                if best[s + 1].is_none_or(|b| c > b.0) {
                    best[s + 1] = Some((c, s, self.unk));
                }
            }
        }
        let mut rev = Vec::new();
        let mut e = n;
        while e > 0 {
            let Some((_, s, id)) = best[e] else { break };
            // fuse consecutive unknowns (`fuse_unk = true`)
            if !(id == self.unk && rev.last() == Some(&self.unk)) {
                rev.push(id);
            }
            e = s;
        }
        out.extend(rev.into_iter().rev());
    }

    fn segment(&self, text: &str, out: &mut Vec<u32>) {
        let norm = match &self.charsmap {
            Some(c) => c.normalize(text),
            None => text.to_string(),
        };
        for w in norm.split_whitespace() {
            let w = format!("\u{2581}{}", w.replace(' ', "\u{2581}"));
            self.viterbi(&w, out);
        }
    }

    /// Content token ids (no `<s>`/`</s>`, no truncation).
    pub fn tokenize(&self, text: &str) -> Vec<u32> {
        let mut out = Vec::new();
        let mut rest = text;
        'outer: while !rest.is_empty() {
            let mut first: Option<(usize, &str, u32)> = None;
            for (s, id) in &self.specials {
                if let Some(p) = rest.find(s.as_str()) {
                    if first.is_none_or(|f| p < f.0) {
                        first = Some((p, s, *id));
                    }
                }
            }
            match first {
                Some((p, s, id)) => {
                    self.segment(&rest[..p], &mut out);
                    out.push(id);
                    rest = &rest[p + s.len()..];
                }
                None => {
                    self.segment(rest, &mut out);
                    break 'outer;
                }
            }
        }
        out
    }

    /// Token ids `<s> … </s>`, truncated so the total length is at most `max_len`.
    pub fn encode(&self, text: &str) -> Vec<u32> {
        let mut ids = vec![self.bos];
        let mut body = self.tokenize(text);
        body.truncate(self.max_len - 2);
        ids.extend(body);
        ids.push(self.eos);
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny(max_len: usize) -> Unigram {
        let v = serde_json::json!({
            "added_tokens": [{"id": 0, "content": "<s>"}, {"id": 2, "content": "</s>"}],
            "normalizer": null,
            "pre_tokenizer": {"type": "Sequence", "pretokenizers": [
                {"type": "WhitespaceSplit"}, {"type": "Metaspace", "replacement": "▁"}]},
            "model": {"type": "Unigram", "unk_id": 3, "vocab": [
                ["<s>", 0.0], ["<pad>", 0.0], ["</s>", 0.0], ["<unk>", 0.0],
                ["▁", -2.0], ["▁hal", -3.0], ["lo", -3.0], ["▁hallo", -4.0],
                ["h", -5.0], ["a", -5.0], ["l", -5.0], ["o", -5.0], ["▁w", -4.0], ["elt", -4.0]]}
        });
        Unigram::from_json(&v, max_len).unwrap()
    }

    #[test]
    fn viterbi_picks_best_path_and_fuses_unk() {
        let t = tiny(16);
        // "▁hallo" (-4) beats "▁hal"+"lo" (-6); "ÿÿ" → one fused <unk>.
        assert_eq!(t.encode("hallo welt ÿÿ"), vec![0, 7, 12, 13, 4, 3, 2]);
    }

    #[test]
    fn specials_are_split_verbatim_and_truncation_keeps_eos() {
        let t = tiny(5);
        assert_eq!(t.encode("hallo</s>hallo hallo hallo"), vec![0, 7, 2, 7, 2]);
    }

    #[test]
    fn base64_roundtrip() {
        assert_eq!(b64("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(b64("SGk").unwrap(), b"Hi");
    }
}
