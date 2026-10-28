//! Minimal BERT WordPiece tokenizer (uncased), equivalent to the Hugging Face `tokenizers`
//! pipeline used by all-MiniLM-L6-v2: `BertNormalizer {clean_text, handle_chinese_chars,
//! strip_accents = lowercase, lowercase}` → `BertPreTokenizer` → `WordPiece {unk = [UNK],
//! prefix = ##, max_input_chars_per_word = 100}` → `[CLS] A [SEP]`, truncated to `max_len`.
//! Vocabulary and settings are read from `tokenizer.json`.

use std::collections::HashMap;
use unicode_categories::UnicodeCategories;
use unicode_normalization::UnicodeNormalization;

/// WordPiece tokenizer state.
#[derive(Debug, Clone)]
pub struct WordPiece {
    vocab: HashMap<String, u32>,
    unk: u32,
    cls: u32,
    sep: u32,
    prefix: String,
    max_chars: usize,
    lowercase: bool,
    strip_accents: bool,
    max_len: usize,
}

fn is_control(c: char) -> bool {
    !matches!(c, '\t' | '\n' | '\r') && c.is_other()
}

fn is_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || c.is_whitespace()
}

fn is_chinese(c: char) -> bool {
    matches!(c as u32,
        0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0x20000..=0x2A6DF | 0x2A700..=0x2B73F
        | 0x2B740..=0x2B81F | 0x2B920..=0x2CEAF | 0xF900..=0xFAFF | 0x2F800..=0x2FA1F)
}

fn is_punc(c: char) -> bool {
    c.is_ascii_punctuation() || c.is_punctuation()
}

impl WordPiece {
    /// Build from a parsed `tokenizer.json`.
    pub fn from_json(t: &serde_json::Value, max_len: usize) -> Result<Self, String> {
        let m = &t["model"];
        if m["type"] != "WordPiece" {
            return Err("tokenizer.json: model.type must be WordPiece".into());
        }
        let n = &t["normalizer"];
        if n["type"] != "BertNormalizer" || t["pre_tokenizer"]["type"] != "BertPreTokenizer" {
            return Err("tokenizer.json: BertNormalizer + BertPreTokenizer required".into());
        }
        let vocab: HashMap<String, u32> = m["vocab"]
            .as_object()
            .ok_or("tokenizer.json: model.vocab missing")?
            .iter()
            .filter_map(|(k, v)| v.as_u64().map(|v| (k.clone(), v as u32)))
            .collect();
        let id = |s: &str| vocab.get(s).copied().ok_or(format!("vocab lacks {s}"));
        let lowercase = n["lowercase"].as_bool().unwrap_or(true);
        Ok(Self {
            unk: id(m["unk_token"].as_str().unwrap_or("[UNK]"))?,
            cls: id("[CLS]")?,
            sep: id("[SEP]")?,
            prefix: m["continuing_subword_prefix"]
                .as_str()
                .unwrap_or("##")
                .to_string(),
            max_chars: m["max_input_chars_per_word"].as_u64().unwrap_or(100) as usize,
            strip_accents: n["strip_accents"].as_bool().unwrap_or(lowercase),
            lowercase,
            vocab,
            max_len: max_len.max(2),
        })
    }

    fn normalize(&self, text: &str) -> String {
        let mut s = String::with_capacity(text.len());
        for c in text.chars() {
            if c == '\0' || c == '\u{fffd}' || is_control(c) {
                continue;
            }
            if is_ws(c) {
                s.push(' ');
            } else if is_chinese(c) {
                s.push(' ');
                s.push(c);
                s.push(' ');
            } else {
                s.push(c);
            }
        }
        if self.strip_accents {
            s = s.nfd().filter(|c| !c.is_mark_nonspacing()).collect();
        }
        if self.lowercase {
            s = s.to_lowercase();
        }
        s
    }

    fn words(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        for w in s.split(char::is_whitespace).filter(|w| !w.is_empty()) {
            let mut cur = String::new();
            for c in w.chars() {
                if is_punc(c) {
                    if !cur.is_empty() {
                        out.push(std::mem::take(&mut cur));
                    }
                    out.push(c.to_string());
                } else {
                    cur.push(c);
                }
            }
            if !cur.is_empty() {
                out.push(cur);
            }
        }
        out
    }

    fn wordpiece(&self, w: &str, out: &mut Vec<u32>) {
        let chars: Vec<char> = w.chars().collect();
        if chars.len() > self.max_chars {
            out.push(self.unk);
            return;
        }
        let mut pieces = Vec::new();
        let mut start = 0;
        while start < chars.len() {
            let mut end = chars.len();
            let mut found = None;
            while start < end {
                let mut sub: String = chars[start..end].iter().collect();
                if start > 0 {
                    sub.insert_str(0, &self.prefix);
                }
                if let Some(&id) = self.vocab.get(&sub) {
                    found = Some(id);
                    break;
                }
                end -= 1;
            }
            match found {
                Some(id) => {
                    pieces.push(id);
                    start = end;
                }
                None => {
                    out.push(self.unk);
                    return;
                }
            }
        }
        out.extend(pieces);
    }

    /// Token ids `[CLS] … [SEP]`, truncated so the total length is at most `max_len`.
    pub fn encode(&self, text: &str) -> Vec<u32> {
        let mut ids = vec![self.cls];
        let budget = self.max_len - 1;
        for w in Self::words(&self.normalize(text)) {
            self.wordpiece(&w, &mut ids);
            if ids.len() >= budget {
                break;
            }
        }
        ids.truncate(budget);
        ids.push(self.sep);
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny(max_len: usize) -> WordPiece {
        let v = serde_json::json!({
            "normalizer": {"type": "BertNormalizer", "lowercase": true, "strip_accents": null},
            "pre_tokenizer": {"type": "BertPreTokenizer"},
            "model": {"type": "WordPiece", "unk_token": "[UNK]", "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100,
                "vocab": {"[UNK]": 0, "[CLS]": 1, "[SEP]": 2, "cafe": 3, "un": 4, "##aff": 5,
                    "##able": 6, ",": 7, "–": 8}}
        });
        WordPiece::from_json(&v, max_len).unwrap()
    }

    #[test]
    fn normalises_splits_and_wordpieces() {
        let t = tiny(16);
        assert_eq!(
            t.encode("Café, UNAFFABLE–x"),
            vec![1, 3, 7, 4, 5, 6, 8, 0, 2]
        );
    }

    #[test]
    fn truncates_to_max_len_with_sep() {
        let t = tiny(8);
        let ids = t.encode("cafe cafe cafe cafe cafe cafe cafe cafe cafe");
        assert_eq!(ids.len(), 8);
        assert_eq!((ids[0], ids[7]), (1, 2));
    }
}
