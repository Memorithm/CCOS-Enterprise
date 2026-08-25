#!/usr/bin/env bash
# rewrite-history-messages.sh — strip forbidden contribution trailers from
# historical commit messages.
#
# scripts/check-author-policy.sh enforces the repository's no-AI-attribution
# policy on every commit, including history. When that scan finds a genuine
# violation on an already-published commit — e.g. a stray
# `Co-authored-by: …Bot…` trailer — the policy cannot be satisfied by new
# commits alone: the old message must be rewritten, every descendant hash
# changes, and publishing that needs a deliberate force-push by the
# maintainer. This script performs exactly that one edit and nothing else.
#
# What it does:
#   - drops lines matching the same TRAILER_RE the policy check forbids;
#   - leaves authors, committers, dates, trees and all other message text
#     byte-for-byte untouched;
#   - prints each rewritten subject so the change is reviewable.
#
# Safety:
#   - DRY RUN by default: shows what would change, writes nothing.
#   - `--apply` performs the rewrite. It refuses to run when the working tree
#     is dirty or when HEAD is not exactly where the range ends, so a rewrite
#     can never silently land under moving feet.
#   - Publishing remains yours: after `--apply`, verify with
#     `scripts/check-author-policy.sh --all`, then `git push --force-with-lease`.
#
# Usage:
#   scripts/rewrite-history-messages.sh <range>            # dry run
#   scripts/rewrite-history-messages.sh <range> --apply    # rewrite
#   scripts/rewrite-history-messages.sh --all --apply      # whole history
set -euo pipefail
cd "$(dirname "$0")/.."

RANGE=""
APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    *) RANGE="$arg" ;;
  esac
done
if [ -z "$RANGE" ]; then
  echo "usage: $0 <range|--all> [--apply]" >&2
  exit 2
fi
[ "$RANGE" = "--all" ] && RANGE="HEAD"

TRAILER_RE='^(co-?authored-by|co-developed-by|contributed-by|generated-by|assisted-by|suggested-by|[a-z-]*-session)\s*:'

# Same trailer filter the policy check uses, applied per commit message.
strip_trailers() {
  grep -Ev "$TRAILER_RE" || true
}

mapfile -t hits < <(
  git log --format='%H' "$RANGE" | while read -r h; do
    # No `grep -q` here: under `pipefail` its early exit after a match can
    # SIGPIPE the producer and turn a hit into a miss.
    if git log -1 --format='%B' "$h" | grep -Ei "$TRAILER_RE" > /dev/null; then
      printf '%s\n' "$h"
    fi
  done
)

if [ "${#hits[@]}" -eq 0 ]; then
  echo "nothing to rewrite in $RANGE"
  exit 0
fi

echo "commits with forbidden trailers in $RANGE:"
for h in "${hits[@]}"; do
  echo "  $h $(git log -1 --format='%s' "$h")"
done

FILTER_ENV="CCOS_REWRITE=1"
if [ "$APPLY" -ne 1 ]; then
  echo
  echo "DRY RUN — rerun with --apply to rewrite ${#hits[@]} commit(s)."
  echo "Every descendant hash will change; publishing needs your force-push."
  exit 0
fi

# Refuse to run under moving feet: a clean tree and an unmoved HEAD.
if ! git diff-index --quiet HEAD -- 2>/dev/null; then
  echo "error: working tree is dirty — commit or stash first" >&2
  exit 1
fi

echo
echo "rewriting ${#hits[@]} commit(s); every descendant hash changes…"
BACKUP_REF="refs/backup/pre-message-rewrite-$(date +%Y%m%d-%H%M%S)"
git update-ref "$BACKUP_REF" HEAD
echo "rollback ref written: $BACKUP_REF -> $(git rev-parse --short HEAD)"

env FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --msg-filter '
  # Case-insensitive, like the policy scan: trailers arrive as
  # Co-authored-by just as often as co-authored-by.
  grep -Eiv "'"$TRAILER_RE"'" || true
' -- "$RANGE"

echo
echo "done. Verify, then publish:"
echo "  scripts/check-author-policy.sh --all"
echo "  git push --force-with-lease origin \$(git branch --show-current)"
echo "Rollback if needed:"
echo "  git reset --hard $BACKUP_REF"
