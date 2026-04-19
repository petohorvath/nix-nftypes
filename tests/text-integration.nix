{ lib, nftlib }:

# Live-parser integration test for the text renderer.
#
# Reuses the cases from tests/dsl-integration.nix; for each one renders
# via toTextPretty (the multi-line form) and pipes to
# `unshare -rn nft -c -f -` (no `-j` — exercises the text grammar).
#
# Some cases use names or constructs that the JSON parser accepts but
# the text grammar doesn't (e.g. `offload` is a reserved keyword in the
# flowtable position even though it's a valid JSON name). Those cases
# appear in `knownTextLimitations` and are skipped — the JSON path
# remains the supported path for them.

let
  inherit (import ./dsl-integration.nix { inherit lib nftlib; }) cases;

  # Cases the nft text grammar can't represent. The JSON renderer
  # accepts them; this is a hard text-grammar limitation in nftables.
  knownTextLimitations = [
    # `offload` is a reserved keyword in flowtable name and `flow add`
    # reference positions. The home-router example's flowtable is named
    # "offload" and is referenced from `flow add @offload`; nft -c -f
    # rejects both. Verified against the upstream parser_bison.y
    # grammar.
    "example-home-router-dsl"

    # `add rule … handle 42 …` resolves the handle against existing
    # kernel state. Inside the unprivileged sandbox there's no rule
    # with handle 42, so nft fails with "Could not process rule: No
    # such file or directory". Same caveat as the JSON-side
    # dsl-integration suite — but the JSON path works because nft -c -j
    # tolerates the dangling handle in check-only mode while nft -c
    # (text) doesn't.
    "add-rule-via-tree-and-standalone"
  ];

  textCases = builtins.filter (c: !(builtins.elem c.name knownTextLimitations)) cases;

  runIntegrationTests =
    pkgs: cases':
    pkgs.runCommandLocal "text-integration-tests"
      {
        nativeBuildInputs = [
          pkgs.nftables
          pkgs.util-linux
        ];
      }
      ''
        set +e
        failed=0
        ${lib.concatMapStringsSep "\n" (c: ''
          printf '=== %s ===\n' ${lib.escapeShellArg c.name}
          ruleset=$(cat <<'RULESET_EOF'
          ${nftlib.toTextPretty c.ruleset}
          RULESET_EOF
          )
          if nft_err=$(unshare -rn nft -c -f - <<<"$ruleset" 2>&1); then
            echo "PASS"
          else
            echo "FAIL:"
            echo "$nft_err" | sed 's/^/    /'
            echo "$ruleset" | sed 's/^/    | /'
            failed=$((failed + 1))
          fi
        '') cases'}
        if [ "$failed" -gt 0 ]; then
          echo "$failed text-integration test(s) failed"
          exit 1
        fi
        echo "All ${toString (builtins.length cases')} text-integration tests passed (${toString (builtins.length knownTextLimitations)} skipped due to known text-grammar limitations)"
        touch $out
      '';
in
{
  inherit
    cases
    textCases
    knownTextLimitations
    runIntegrationTests
    ;
}
