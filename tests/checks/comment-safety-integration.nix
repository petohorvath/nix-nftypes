/*
  Integration: render a *safe* comment through text and JSON paths,
  round-trip through `nft -f` inside a private netns, dump the
  ruleset, assert the comment value survives unchanged.
*/
{
  fixtures,
  nftlib,
  pkgs,
}:
let
  safeComment = "round-trip me (with spaces & punct!)";
  safeRuleset = fixtures.commentRulesets.tableComment safeComment;
  textOut = nftlib.toTextPretty safeRuleset;
  jsonOut = nftlib.toJson safeRuleset;
in
pkgs.runCommandLocal "comment-safety-integration"
  {
    nativeBuildInputs = [
      pkgs.nftables
      pkgs.util-linux
      pkgs.jq
    ];
  }
  ''
    set -e
    cat <<'TEXT_EOF' > rules.nft
    ${textOut}
    TEXT_EOF
    cat <<'JSON_EOF' > rules.json
    ${jsonOut}
    JSON_EOF

    # Text path: load via nft -f, dump via nft list ruleset -j, extract
    # the comment with jq (avoids text-renderer quirks in the dump
    # format).
    unshare -rn -- sh -c '
      set -e
      nft -f rules.nft
      got=$(nft -j list ruleset |
        jq -r ".nftables[] | select(.table) | .table.comment")
      want="${safeComment}"
      if [ "$got" != "$want" ]; then
        printf "text round-trip mismatch\n  want: %s\n  got:  %s\n" \
          "$want" "$got" >&2
        exit 1
      fi
    '

    # JSON path: same comparison via the -j ingestion path.
    unshare -rn -- sh -c '
      set -e
      nft -j -f rules.json
      got=$(nft -j list ruleset |
        jq -r ".nftables[] | select(.table) | .table.comment")
      want="${safeComment}"
      if [ "$got" != "$want" ]; then
        printf "json round-trip mismatch\n  want: %s\n  got:  %s\n" \
          "$want" "$got" >&2
        exit 1
      fi
    '

    echo "All comment-safety integration tests passed"
    touch $out
  ''
