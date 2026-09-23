#!/usr/bin/env python3
"""Adversarial regressions for full-history and newly introduced author policy."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "scripts/check-author-policy.sh"

def run(*args, cwd=ROOT, **kw):
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, **kw)

# Exercise the real immutable legacy objects; never manufacture accepted hashes.
actual = run(str(POLICY), "HEAD")
assert actual.returncode == 0, actual.stdout + actual.stderr
with tempfile.TemporaryDirectory(prefix="author-policy-") as tmp:
    repo = Path(tmp)
    (repo / "scripts").mkdir()
    shutil.copy2(POLICY, repo / "scripts/check-author-policy.sh")
    run("git", "init", "-q", cwd=repo, check=True)
    run("git", "config", "core.hooksPath", "/dev/null", cwd=repo, check=True)
    env = dict(os.environ, GIT_AUTHOR_NAME="MEMOPERF",
               GIT_AUTHOR_EMAIL="contact@checkupauto.fr",
               GIT_COMMITTER_NAME="MEMOPERF",
               GIT_COMMITTER_EMAIL="contact@checkupauto.fr")

    def commit(message, **identity):
        run("git", "-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", message,
            cwd=repo, env=dict(env, **identity), check=True)
        return run("git", "rev-parse", "HEAD", cwd=repo, check=True).stdout.strip()

    def check(rev, expected):
        result = run("bash", "scripts/check-author-policy.sh", rev, cwd=repo)
        assert (result.returncode == 0) == expected, (rev, result.stdout, result.stderr)

    base = commit("policy: authorized baseline")
    check("HEAD", True)
    checkup = commit("policy: CHECKUPAUTO alias",
                     GIT_AUTHOR_NAME="CHECKUPAUTO",
                     GIT_COMMITTER_NAME="CHECKUPAUTO")
    check(f"{checkup}^..{checkup}", True)
    legacy_new = commit("policy: legacy display name is no longer active",
                        GIT_AUTHOR_NAME="ZEKRITI Tarek",
                        GIT_COMMITTER_NAME="ZEKRITI Tarek")
    check(f"{legacy_new}^..{legacy_new}", False)
    check("does-not-exist", False)
    check("HEAD..HEAD", False)
    for msg, identity in [
        ("ordinary", {"GIT_AUTHOR_NAME": "Other Human"}),
        ("ordinary", {"GIT_COMMITTER_NAME": "Other Human"}),
        ("ordinary", {"GIT_AUTHOR_EMAIL": "codex@example.test"}),
        ("ordinary\n\nCo-authored-by: MEMOPERF <memoperf@users.noreply.github.com>", {}),
        ("ordinary\n\nCo-authored-by: Other Human <other@example.test>", {}),
        ("ordinary\n\nGenerated-by: assistant", {}),
        ("ordinary\n\nAI-generated", {}),
    ]:
        head = commit(msg, **identity)
        check(f"{head}^..{head}", False)
    head = commit("policy: ordinary GitHub squash",
                  GIT_COMMITTER_NAME="GitHub", GIT_COMMITTER_EMAIL="noreply@github.com")
    check(f"{head}^..{head}", True)
    check(f"{base}..{head}", False)  # a clean tip cannot hide a bad ancestor
    (repo / ".git/shallow").write_text(head + "\n")
    check("HEAD", False)
print("author policy: historic normalization and adversarial regressions passed")
