# Watch upstream nftables without gating merges

Merges are gated only by deterministic checks, run with the locked `nixpkgs` and with the project policy's stable and unstable pins. Newer nftables reaches the project through a scheduled workflow that never gates and never edits `flake.lock`: a source watch compares each pin's patched source with the locked one and keeps one drift issue per pin. Moving the lock is a separate, reviewed change, so corpus baseline changes and other drift failures land in that change rather than in unrelated work. The workflow reads the pins from the policy instead of resolving nixpkgs branches itself, and the policy's Pin-bump tests run the checks with proposed pins before their release, so the project needs no canary of its own.

## Considered options

- A source watch and a non-gating canary that ran nine nftables-facing tests against each nixpkgs branch tip, resolved by the workflow: added in `9e239ae` and `b787032`. The canary warned up to a week before a pin bump, but only on `x86_64-linux`, against revisions the policy had not approved, and it repeated the policy's stable and unstable test runs. The policy's Pin-bump tests cover both Linux systems with the revisions about to be released and hold the release on failure.
- AI triage of the source diff, which drafted a prose report for the Drift issue when an `ANTHROPIC_API_KEY` secret was configured: added in `9e239ae` as drafting only, gated by the deterministic checks. No key was ever configured, so every Drift issue carried the deterministic report alone, and the step was removed.

## Consequences

- The unstable pin usually carries a newer nftables than the stable lock, so its drift issue normally stays open until a lock update catches up.
- Drift appears after the policy releases a pin bump, not when a branch moves.

## Evidence

- `9e239ae` introduces the weekly canary and the issue-filing source diff; `b787032` moves both onto nixpkgs branch tips.
- `bd0a4ea` closes superseded drift issues so each branch keeps at most one; `888bfb8` makes stale corpus baselines fail, noting the corpus only changes when `flake.lock` moves.
- `.github/workflows/upstream-sync.yml` reads the pins with the policy checker's `validate` command and has no canary job; `tests/suites/nixpkgs-source-policy.nix` fails if it resolves a nixpkgs branch itself or reads a different policy series than `check.yml`.
- The policy's `data/repos.json` lists `petohorvath/nix-nftypes`; `docs/upstream-sync.md` "Daily policy-pin workflow" and "Updating inputs".
