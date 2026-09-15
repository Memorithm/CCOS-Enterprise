#!/usr/bin/env bash
# Shared fail-closed CI primitives. Source this file; no implicit tool execution.
# A negative grep result is success only for status 1, never for a scanner error.
require_no_matches() {
  if [ "$#" -eq 0 ]; then
    echo 'CI guard: missing scanner command' >&2
    return 2
  fi
  local status
  if "$@"; then
    echo 'CI guard: forbidden match detected' >&2
    return 1
  else
    status=$?
  fi
  if [ "$status" -ne 1 ]; then
    echo "CI guard: scanner failed (exit $status)" >&2
    return "$status"
  fi
  return 0
}

# First require a successful, nonempty producer; only then inspect its output.
# This avoids negated pipelines and grep -q/SIGPIPE ambiguity. No eval is used.
require_clean_output() (
  if [ "$#" -lt 2 ]; then
    echo 'CI guard: expected PATTERN COMMAND [ARG...]' >&2
    exit 2
  fi
  local pattern="$1" output status
  shift
  output=$(mktemp) || exit "$?"
  trap 'rm -f -- "$output"' EXIT
  if "$@" > "$output"; then
    :
  else
    status=$?
    echo "CI guard: producer failed (exit $status)" >&2
    exit "$status"
  fi
  if [ ! -s "$output" ]; then
    echo 'CI guard: producer returned empty output' >&2
    exit 2
  fi
  require_no_matches grep -iE -- "$pattern" "$output"
)
