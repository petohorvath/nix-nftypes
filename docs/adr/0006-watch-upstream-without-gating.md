# Watch upstream nftables weekly without gating merges

Merges are gated only by deterministic checks, run with the locked `nixpkgs` and with the project policy's stable and unstable pins. Newer nftables reaches the project through a scheduled workflow that never gates and never edits `flake.lock`: a source watch compares each branch tip's patched source with the locked one and keeps one drift issue per branch, and a canary runs the nftables-facing tests against each branch tip with `continue-on-error`. Moving the lock is a separate, reviewed change, so corpus baseline changes and other drift failures land in that change rather than in unrelated work.

## Consequences

- Optional AI triage only drafts prose for the drift issue; a missing or failed triage never changes the deterministic result.
- The unstable branch usually carries a newer nftables than the stable lock, so its drift issue normally stays open until a lock update catches up.

## Evidence

- `9e239ae` introduces the weekly canary and the issue-filing source diff, "drafting only, gated by the deterministic checks"; `b787032` moves both onto nixpkgs branch tips.
- `.github/workflows/upstream-sync.yml` (the `continue-on-error: true # non-gating` canary job) and `docs/upstream-sync.md` "Weekly branch-tip workflow" and "Updating inputs".
- `bd0a4ea` closes superseded drift issues so each branch keeps at most one; `888bfb8` makes stale corpus baselines fail, noting the corpus only changes when `flake.lock` moves.
