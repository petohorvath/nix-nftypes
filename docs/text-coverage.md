# Text renderer — coverage gaps

The text renderer (`lib/text/`, exposed as `nftlib.toText` /
`nftlib.toTextPretty`) emits the multi-line `.nft` form that
`nft -f rules.nft` consumes. The JSON renderer is the
authoritative path; the text renderer mirrors it position-for-position
in the pipeline.

Common-path coverage is enforced by:

- `tests/text-parity.nix` — ~30 schema-level expected-string assertions
  for `toText`.
- `tests/text-integration.nix` — pipes each integration case's text
  rendering through `unshare -rn nft -c -f -`.
- `tests/render-equivalence.nix` — for ~9 cases (including the full
  basic-firewall-dsl example), loads JSON and text into separate netns
  and diffs `nft list ruleset` byte-for-byte. This is the 1:1 contract.

The items below are written from the nft docs without live-parser
coverage. Real usage may surface issues. For anything on this list,
the JSON path is the supported target.

## Items not covered by live-parser tests

### Tunnel objects (vxlan / erspan v1 / erspan v2 / geneve)

`add tunnel` with the various nested bodies has parity tests
(`text-parity.nix`) but no live-parser integration. The sandboxed
netns typically lacks the required kernel modules (vxlan, erspan,
geneve), so `nft -c -f` either skips validation or rejects depending
on the environment. The byte-level output follows the nft man page
but isn't validated end-to-end.

### Rare statements

The following statements have schema-level parity tests but no
live-parser integration:

- `xt` (deprecated xtables escape hatch — also rejected by JSON
  parser; see `docs/spec-coverage.md` E2)
- `last` (matching-time tracking)
- `mangle` (header-field rewrite)
- `meter` (rate-limited statement)
- `tproxy` (transparent proxy)
- the inline `synproxy` statement form
- the `reset tcp option` form

### Reserved-word name collisions

`offload` as a flowtable name is known-broken in text — the text
parser treats `offload` as a reserved word in flowtable position
even though the JSON parser accepts it. Documented in
`tests/text-integration.nix::knownTextLimitations`.

Other nftables keywords (`route`, `filter`, `nat`, …) likely hit the
same class of issue if used as object names. Not exhaustively tested.

### `in` operator with named-set refs

Exercised with anonymous sets (`meta iif in { eth0, eth1 }`).
Behaviour with named-set references (`meta iif in @named`) is
untested in the text renderer.

### Comment emission position

`comment "..."` is emitted at the canonical position for each kind
per the nft man page, but not cross-checked byte-for-byte against
`nft list ruleset` output. A subtle position-mismatch would round-trip
through schema validation but might confuse byte-diffing tools.

## When a text-grammar issue surfaces

1. Add a parity test to `tests/text-parity.nix` covering the case.
2. Add a live-parser test to `tests/text-integration.nix`.
3. If JSON↔text equivalence is expected, add to
   `tests/render-equivalence.nix`.
4. Patch the renderer in `lib/text/`.

The "test before patch" order is deliberate — the renderer is small
enough that getting expected output right matters more than the patch
itself.
