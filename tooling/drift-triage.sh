#!/usr/bin/env bash
# drift-triage.sh — AI triage of an upstream nftables parser diff.
#
# Layer 3 of the upstream-sync pipeline (docs/upstream-sync.md). When the
# scheduled watcher detects that upstream nftables has moved past the pinned
# revision, it produces a diff of the parser source files and hands it to this
# script, which asks Claude to classify each change and map it onto the schema.
#
# Why AI here and nowhere else in the pipeline: the mapping from a C `strcmp`
# ladder or `json_unpack` call to a Nix `attrTag` branch or `types.enum` entry
# is *semantic*, not syntactic — a plain text diff is too noisy (line shifts,
# refactors), and the deterministic checks (Layers 2 and 4) only cover the
# structured cases. This step is TRIAGE AND DRAFTING ONLY: its output is a
# report for a human to review, and every change it proposes is gated by the
# real-parser checks (corpus, enum extraction, pinned-nft integration). An
# AI-hallucinated enum value dies at the conformance test against real `nft`.
#
# Usage:
#   drift-triage.sh --diff <diff-file> --schema-dir <lib/schema> \
#       --spec-coverage <docs/spec-coverage.md> \
#       --old-rev <sha> --new-rev <sha> --out <report.md>
#
# Requires: curl, jq, and ANTHROPIC_API_KEY in the environment.
# Model: claude-opus-4-8 (the most capable model — this is a low-frequency,
# correctness-sensitive task, so cost is not the constraint).

set -euo pipefail

MODEL="claude-opus-4-8"
DIFF= SCHEMA_DIR= SPEC= OLD_REV= NEW_REV= OUT=

while [ $# -gt 0 ]; do
  case "$1" in
    --diff) DIFF=$2; shift 2 ;;
    --schema-dir) SCHEMA_DIR=$2; shift 2 ;;
    --spec-coverage) SPEC=$2; shift 2 ;;
    --old-rev) OLD_REV=$2; shift 2 ;;
    --new-rev) NEW_REV=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

: "${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY must be set}"
for f in "$DIFF" "$SPEC"; do
  [ -f "$f" ] || { echo "missing file: $f" >&2; exit 2; }
done
[ -d "$SCHEMA_DIR" ] || { echo "missing schema dir: $SCHEMA_DIR" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Assemble the schema files into one grounding blob. primitives.nix carries the
# enums (the highest-churn surface); the union files carry the tags.
schema_blob=$work/schema.txt
: >"$schema_blob"
for f in primitives.nix statements.nix expressions.nix objects.nix commands.nix; do
  if [ -f "$SCHEMA_DIR/$f" ]; then
    printf '\n===== lib/schema/%s =====\n' "$f" >>"$schema_blob"
    cat "$SCHEMA_DIR/$f" >>"$schema_blob"
  fi
done

SYSTEM='You are a maintainer of nix-nft-types, a Nix library whose type schema
in lib/schema/ is hand-derived to be 1:1 with the nftables JSON parser
(src/parser_json.c) plus its lookup tables in src/meta.c and src/rt.c. Each
schema file cites the exact parser lines it mirrors. Your job is to triage a
diff of the upstream parser between two revisions and report what the schema
must change to stay in sync.

This is triage for a human reviewer, gated by an automated test suite that runs
the real nft parser. Therefore:
- Be precise and conservative. Do not invent enum values, fields, or tags that
  are not in the diff. If a hunk is ambiguous, say so rather than guessing.
- Classify, do not just summarize. Distinguish real schema-relevant changes
  from refactor noise (renames of internal C symbols, whitespace, comment
  edits, changes to code paths the JSON parser does not reach).
- Ground every claim in the diff and, where possible, the cited schema lines.'

PROMPT_FILE=$work/prompt.txt
{
  printf 'nftables moved from %s to %s.\n\n' "$OLD_REV" "$NEW_REV"
  printf 'Produce a Markdown drift report with these sections:\n\n'
  printf '1. **Verdict** — one of: NO SCHEMA-RELEVANT CHANGES / REVIEW NEEDED / SCHEMA CHANGES REQUIRED.\n'
  printf '2. **Findings** — for each schema-relevant hunk, a numbered entry in the style of docs/spec-coverage.md'\''s G-N gaps:\n'
  printf '   - Parser: the file + (new) line range and the accepted token/field/tag.\n'
  printf '   - Classification: new-enum-value | new-field | new-statement-tag | new-expression-tag | new-object-kind | removed | renamed | semantics-change | refactor-noise.\n'
  printf '   - Schema impact: the exact lib/schema/<file> option/enum to change, or "none".\n'
  printf '   - Proposed edit: a minimal Nix snippet, or "n/a".\n'
  printf '   - Confidence: high | medium | low, with a one-line reason.\n'
  printf '3. **Draft spec-coverage.md entry** — for any confirmed gap, an entry in the existing G-N format.\n'
  printf '4. **Excluded** — hunks you classified as refactor-noise, one line each, so coverage is auditable.\n\n'
  printf 'Remember: do not propose a change you cannot ground in the diff. The test suite will reject anything the real parser does not accept.\n\n'
  printf '========== UPSTREAM PARSER DIFF (%s..%s) ==========\n' "$OLD_REV" "$NEW_REV"
  cat "$DIFF"
  printf '\n\n========== CURRENT SCHEMA (lib/schema/) ==========\n'
  cat "$schema_blob"
  printf '\n\n========== docs/spec-coverage.md (methodology + G-N format) ==========\n'
  cat "$SPEC"
} >"$PROMPT_FILE"

# Build the request body with jq so the (large) prompt is escaped correctly.
# effort=high for a correctness-sensitive task; non-streaming with a generous
# curl timeout (a report fits well under max_tokens, so no SSE handling needed).
body=$work/body.json
jq -n \
  --arg model "$MODEL" \
  --arg system "$SYSTEM" \
  --rawfile prompt "$PROMPT_FILE" \
  '{
     model: $model,
     max_tokens: 16000,
     output_config: { effort: "high" },
     system: $system,
     messages: [ { role: "user", content: $prompt } ]
   }' >"$body"

resp=$work/resp.json
curl -sS --max-time 900 https://api.anthropic.com/v1/messages \
  -H "content-type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  --data-binary @"$body" >"$resp"

if [ "$(jq -r '.type // empty' "$resp")" = "error" ]; then
  echo "Anthropic API error:" >&2
  jq -r '.error.message // "unknown"' "$resp" >&2
  exit 1
fi

# Concatenate every text block (skips thinking blocks if ever enabled).
report=$(jq -r '[.content[] | select(.type == "text") | .text] | join("\n")' "$resp")
if [ -z "$report" ]; then
  echo "empty response from model; raw payload:" >&2
  cat "$resp" >&2
  exit 1
fi

{
  printf '# nftables upstream drift report\n\n'
  printf '_Pinned `%s` → upstream `%s`. Generated by `tooling/drift-triage.sh` (%s).\n' \
    "$OLD_REV" "$NEW_REV" "$MODEL"
  printf 'AI triage — review before acting; the test suite is the gate, not this report._\n\n'
  printf -- '---\n\n'
  printf '%s\n' "$report"
} >"$OUT"

echo "wrote $OUT"
