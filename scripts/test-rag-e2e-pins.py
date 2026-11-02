#!/usr/bin/env python3
"""The frozen prompt file must equal the generator's PROMPT; the skeleton must fail readiness."""
import hashlib, importlib.util, json, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
D = ROOT / "docs/campaigns/2026-11-02-rag-e2e"


def load(name, path):
    s = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(s); s.loader.exec_module(m); return m


class Pins(unittest.TestCase):
    def test_prompt_frozen(self):
        gen = load("g", ROOT / "scripts/rag-e2e-generate.py")
        data = (D / "generator-prompt.v1.txt").read_bytes()
        self.assertEqual(data.decode(), gen.PROMPT)
        man = json.loads((D / "manifest.skeleton.json").read_text())
        self.assertEqual(man["protocol"]["generator"]["prompt_sha256"], "sha256:" + hashlib.sha256(data).hexdigest())
        self.assertIs(man["superiority_claim"], False)

    def test_skeleton_fails_closed(self):
        r = subprocess.run([sys.executable, str(ROOT / "scripts/check-rag-campaign-readiness.py"), str(D / "manifest.skeleton.json")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn('"ready": true', r.stdout)

    def test_pin_tool(self):
        pin = ROOT / "scripts/rag-e2e-pin-generator.py"
        with tempfile.TemporaryDirectory() as t:
            t = Path(t); snap = t / "snap"; snap.mkdir()
            (snap / "b.safetensors").write_bytes(b"B"); (snap / "a.safetensors").write_bytes(b"A")
            (snap / "tokenizer.json").write_bytes(b"{}")
            man = json.loads((D / "manifest.skeleton.json").read_text())
            man["protocol"]["generator"]["tokenizer_sha256"] = "sha256:" + hashlib.sha256(b"{}").hexdigest()
            (t / "generator-prompt.v1.txt").write_bytes((D / "generator-prompt.v1.txt").read_bytes())
            (t / "m.json").write_text(json.dumps(man))
            r = subprocess.run([sys.executable, str(pin), "--snapshot", str(snap), "--manifest", str(t / "m.json"), "--out", str(t / "o.json")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            listing = f"{hashlib.sha256(b'A').hexdigest()}  a.safetensors\n{hashlib.sha256(b'B').hexdigest()}  b.safetensors\n"
            out = json.loads((t / "o.json").read_text())
            self.assertEqual(out["protocol"]["generator"]["weights_sha256"], "sha256:" + hashlib.sha256(listing.encode()).hexdigest())
            (snap / "tokenizer.json").write_bytes(b"tampered")
            r = subprocess.run([sys.executable, str(pin), "--snapshot", str(snap), "--manifest", str(t / "m.json"), "--out", str(t / "o2.json")], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)


if __name__ == "__main__":
    unittest.main()
