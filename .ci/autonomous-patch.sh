#!/usr/bin/env bash
set -euo pipefail
PRODUCT_BASE=12c1ea604c39006821e3273b631ab6b8aedc4c96
PRODUCT_BRANCH=feat/backup-restore-workflow

python3 - <<'PY'
from pathlib import Path

p = Path('crates/ccos-enterprise-backup/src/lib.rs')
s = p.read_text()

def one(old, new, label):
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f'{label}: expected one anchor, found {n}')
    s = s.replace(old, new, 1)

one(
'''/// Recovery owns the ordering and freeze state. The replay callback performs\n/// the actual deterministic journal-tail replay and returns the number of\n/// records applied; the verification callback runs against the atomically\n/// switched live path. Any error leaves `policy.writes_frozen == true`.\n''',
'''/// Recovery owns the ordering and freeze state. The replay callback performs\n/// the actual deterministic journal-tail replay and returns the number of\n/// records applied; the verification callback validates the fully replayed,\n/// resealed private staging candidate before any public live-pointer switch.\n/// Any error leaves `policy.writes_frozen == true`.\n''',
'recovery ordering docs')

one(
'''    verify_live: &dyn Fn(&Path) -> Result<(), String>,\n''',
'''    verify_recovered: &dyn Fn(&Path) -> Result<(), String>,\n''',
'verifier parameter')

one(
'''    if let Err(error) = promote_staged(staging, live) {\n        stages.push(RecoveryStage::FailClosed {\n            detail: format!("promotion failed: {error}"),\n        });\n        return failed(stages);\n    }\n\n    match verify_live(live) {\n        Ok(()) => stages.push(RecoveryStage::VerifyEndToEnd { ok: true }),\n        Err(error) => {\n            stages.push(RecoveryStage::VerifyEndToEnd { ok: false });\n            stages.push(RecoveryStage::FailClosed {\n                detail: format!("end-to-end verification failed: {error}"),\n            });\n            return failed(stages);\n        }\n    }\n\n    policy.writes_frozen = false;\n''',
'''    // The recovered state is not public until end-to-end verification has\n    // accepted the exact replayed/resealed candidate. A failed verifier must\n    // therefore leave the existing `live` pointer untouched (or absent on a\n    // first recovery), rather than publishing state the transaction reports\n    // as failed.\n    match verify_recovered(staging) {\n        Ok(()) => stages.push(RecoveryStage::VerifyEndToEnd { ok: true }),\n        Err(error) => {\n            stages.push(RecoveryStage::VerifyEndToEnd { ok: false });\n            stages.push(RecoveryStage::FailClosed {\n                detail: format!("end-to-end verification failed: {error}"),\n            });\n            return failed(stages);\n        }\n    }\n\n    if let Err(error) = promote_staged(staging, live) {\n        stages.push(RecoveryStage::FailClosed {\n            detail: format!("promotion failed: {error}"),\n        });\n        return failed(stages);\n    }\n\n    policy.writes_frozen = false;\n''',
'verify before promotion')

anchor = '''    #[test]\n    #[cfg(unix)]\n    fn recovery_failure_remains_frozen() {\n'''
extra = '''    #[test]\n    #[cfg(unix)]\n    fn failed_end_to_end_verification_does_not_publish_live() {\n        let root = scratch("dr-verify-fail");\n        let target = FsBackupTarget::new(&root);\n        create_backup(&target, "acme", &segments(1), 1).unwrap();\n        let parent = scratch("dr-verify-fail-parent");\n        std::fs::create_dir_all(&parent).unwrap();\n        let staging = parent.join("stage");\n        let live = parent.join("live");\n        let mut policy = BackupPolicy {\n            tenant: "acme".into(),\n            rpo_seconds: 300,\n            rto_seconds: 600,\n            writes_frozen: false,\n        };\n        let outcome = run_disaster_recovery(\n            "acme",\n            &mut policy,\n            &target,\n            &staging,\n            &live,\n            100,\n            &|path| {\n                std::fs::write(path.join(SEGMENTS_DIR).join("ledger"), b"ledger-replayed")\n                    .map_err(|error| error.to_string())?;\n                Ok(1)\n            },\n            &|path| {\n                assert_eq!(path, staging.as_path(), "verification must inspect private staging");\n                Err("candidate rejected".into())\n            },\n        );\n        assert!(!outcome.recovered);\n        assert!(policy.writes_frozen);\n        assert!(!live.exists(), "failed verification must not publish live");\n        assert!(outcome\n            .stages\n            .iter()\n            .any(|stage| matches!(stage, RecoveryStage::VerifyEndToEnd { ok: false })));\n        let _ = std::fs::remove_dir_all(root);\n        let _ = std::fs::remove_dir_all(parent);\n    }\n\n'''
if s.count(anchor) != 1:
    raise SystemExit(f'test anchor count={s.count(anchor)}')
s = s.replace(anchor, extra + anchor, 1)
p.write_text(s)
PY

cargo fmt --all
cargo check -p ccos-enterprise-backup
cargo clippy -p ccos-enterprise-backup --all-targets -- -D warnings
cargo test -p ccos-enterprise-backup --release
cargo test -p ccos-enterprise-conformance --test backup_workflow --release
cargo test -p ccos-enterprise-conformance --test stress_backup_fuzz --release

rm -f .ci/autonomous-patch.sh .ci/prepatch.py
rmdir .ci 2>/dev/null || true

git config user.name MEMOPERF
git config user.email contact@checkupauto.fr
git reset --soft "$PRODUCT_BASE"
git add -A
if git diff --cached --quiet; then
  echo "no product changes" >&2
  exit 1
fi
git commit -m "fix(backup): verify recovery before live promotion"
git push --force-with-lease=refs/heads/${PRODUCT_BRANCH}:${PRODUCT_BASE} origin HEAD:refs/heads/${PRODUCT_BRANCH}
