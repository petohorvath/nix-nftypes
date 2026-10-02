/*
  Render a SAFE ifname set through both renderers, load each via the
  real `nft` parser inside a private netns, dump the resulting set,
  and assert the element count matches what we declared. The element-
  count check is the regression-specific assertion: pre-fix, a
  `[ "eth0,eth1" ]` element widened to two; this integration test
  confirms the count is exactly preserved on the safe path so we
  would notice if a future refactor reintroduced bare-comma rendering.
*/
{
  fixtures,
  nftlib,
  pkgs,
}:
let
  safeRuleset = fixtures.ifnameRulesets.setElem "eth0";
  twoElemRuleset = nftlib.dsl.ruleset [
    (nftlib.dsl.table "inet" "fw" {
      sets.iifs = {
        type = "ifname";
        elements = [
          "eth0"
          "wlp3s0"
        ];
      };
    })
  ];
  textOut1 = nftlib.toTextPretty safeRuleset;
  jsonOut1 = nftlib.toJson safeRuleset;
  textOut2 = nftlib.toTextPretty twoElemRuleset;
  jsonOut2 = nftlib.toJson twoElemRuleset;
in
pkgs.runCommandLocal "ifname-safety-integration"
  {
    nativeBuildInputs = [
      pkgs.nftables
      pkgs.util-linux
      pkgs.jq
    ];
  }
  ''
    set -e

    run_case() {
      local label="$1" expected_count="$2" loader_flag="$3" file="$4"
      unshare -rn -- sh -c "
        set -e
        nft $loader_flag -f $file
        got=\$(nft -j list set inet fw iifs |
          jq '[.nftables[] | select(.set) | .set.elem[]] | length')
        want=$expected_count
        if [ \"\$got\" != \"\$want\" ]; then
          printf '%s: element-count mismatch\n  want: %s\n  got:  %s\n' \
            \"$label\" \"\$want\" \"\$got\" >&2
          nft list set inet fw iifs >&2
          exit 1
        fi
      "
    }

    cat <<'TEXT1' > one_text.nft
    ${textOut1}
    TEXT1
    cat <<'JSON1' > one_json.json
    ${jsonOut1}
    JSON1
    cat <<'TEXT2' > two_text.nft
    ${textOut2}
    TEXT2
    cat <<'JSON2' > two_json.json
    ${jsonOut2}
    JSON2

    run_case "text single-elem" 1 "" one_text.nft
    run_case "json single-elem" 1 "-j" one_json.json
    run_case "text two-elem"    2 "" two_text.nft
    run_case "json two-elem"    2 "-j" two_json.json

    echo "All ifname-safety integration tests passed"
    touch $out
  ''
