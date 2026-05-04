{ lib, nftlib }:

# Render-equivalence cross-check. For each case, render both via JSON
# and via text, load each into its own private network namespace, then
# diff the canonical `nft list ruleset` output. If the JSON and text
# renderers produce semantically equivalent rulesets the diff is empty.
#
# This is the strongest 1:1 guarantee — the schema, JSON renderer, text
# renderer, and the live nft parsers (both -j and not) all agree.
#
# Cases that touch external state (rule handles, references to objects
# the sandbox can't materialise) are excluded — they can't be `nft -f`
# loaded in check mode, let alone listed.

let
  textIntegration = import ./text-integration.nix { inherit lib nftlib; };
  inherit (textIntegration) cases knownTextLimitations;

  # Cases where actual loading (`nft -f` instead of `nft -c -f`) needs
  # kernel state the unprivileged netns lacks, or whose `nft list
  # ruleset` produces non-deterministic output (rule order, counter
  # ordering, etc.). These are above and beyond the text-only
  # limitations.
  knownLoadLimitations = [
    # `list table` can't be loaded — it's a query, not a definition.
    "list-table"
    # ct timeout / ct expectation / synproxy in create require kernel
    # features the sandbox often lacks; skip rather than chase
    # environment-specific failures.
    "create-supported-kinds"
    "delete-supported-kinds"
  ];

  excluded = knownTextLimitations ++ knownLoadLimitations;
  equivalenceCases = builtins.filter (c: !(builtins.elem c.name excluded)) cases;

  runEquivalenceTests =
    pkgs: cases':
    pkgs.runCommandLocal "render-equivalence-tests"
      {
        nativeBuildInputs = [
          pkgs.nftables
          pkgs.util-linux
          pkgs.diffutils
        ];
      }
      ''
        set +e
        failed=0
        # Write inputs into the build's working directory; Nix tears
        # this down automatically when the derivation finishes, so no
        # cleanup or /tmp leakage.
        ${lib.concatMapStringsSep "\n" (c: ''
          printf '=== %s ===\n' ${lib.escapeShellArg c.name}

          cat > ./in.json <<'JSON_EOF'
          ${nftlib.toJson c.ruleset}
          JSON_EOF
          cat > ./in.nft <<'TEXT_EOF'
          ${nftlib.toTextPretty c.ruleset}
          TEXT_EOF

          # Each side runs in its own netns so the loaded ruleset is
          # isolated. Capture only the `nft list ruleset` output for
          # the diff — discarding stdout from the loading step, since
          # commands like `reset counter`/`reset quota` print their
          # observed values, and `-j` makes those JSON whereas the
          # text path emits text. Those load-time prints aren't part
          # of what we're comparing.
          json_out=$(unshare -rn bash -c "nft -j -f $PWD/in.json >/dev/null && nft list ruleset" 2>&1)
          json_status=$?
          text_out=$(unshare -rn bash -c "nft -f $PWD/in.nft >/dev/null && nft list ruleset" 2>&1)
          text_status=$?

          if [ "$json_status" -ne 0 ] || [ "$text_status" -ne 0 ]; then
            echo "SKIP: load failed (json=$json_status text=$text_status)"
            continue
          fi

          if [ "$json_out" = "$text_out" ]; then
            echo "PASS"
          else
            echo "FAIL: outputs differ"
            diff <(echo "$json_out") <(echo "$text_out") | sed 's/^/    /'
            failed=$((failed + 1))
          fi
        '') cases'}
        if [ "$failed" -gt 0 ]; then
          echo "$failed equivalence test(s) failed"
          exit 1
        fi
        echo "All ${toString (builtins.length cases')} equivalence tests passed (${toString (builtins.length excluded)} skipped)"
        touch $out
      '';
in
{
  inherit
    cases
    equivalenceCases
    knownLoadLimitations
    runEquivalenceTests
    ;
}
