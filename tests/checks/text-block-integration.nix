/*
  Block-form live-parser check: each table is rendered with
  toTextBlockPretty and toTextBlock, wrapped in
  `table <family> <name> { ... }`, and piped through
  `unshare -rn nft -c -f -` to verify the upstream parser accepts it.
*/
{
  fixtures,
  nftlib,
  pkgs,
}:
let
  inherit (pkgs) lib;
  inherit (fixtures) blockTables;
  inherit (nftlib) dsl;

  cases = [
    {
      name = "inline-and-named-limits";
      table = blockTables.limitTable;
    }
    {
      name = "chain-object-references";
      table = blockTables.referencedTable;
    }
    {
      name = "minimal-base-chain";
      table = dsl.table "inet" "fw" { chains.input = blockTables.baseChain; };
    }
    {
      name = "chain-with-rules";
      table = dsl.table "inet" "fw" {
        chains.input = blockTables.baseChain // {
          policy = "drop";
          rules = [
            [ dsl.accept ]
            [ dsl.drop ]
          ];
        };
      };
    }
    {
      name = "mixed-chain-set-counter";
      table = dsl.table "inet" "fw" {
        chains.input = blockTables.baseChain // {
          rules = [ [ dsl.accept ] ];
        };
        sets.lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
        };
        counters.hits = { };
      };
    }
    {
      name = "set-with-inline-elements";
      table = dsl.table "inet" "fw" {
        sets.blocked = {
          type = "ipv4_addr";
          elements = [ "192.0.2.1" ];
        };
      };
    }
  ];

  caseForms = lib.concatMap (c: [
    {
      inherit (c) name table;
      form = "pretty";
      rendered = nftlib.toTextBlockPretty c.table;
    }
    {
      inherit (c) name table;
      form = "compact";
      rendered = nftlib.toTextBlock c.table;
    }
  ]) cases;
in
pkgs.runCommandLocal "text-block-integration-tests"
  {
    nativeBuildInputs = [
      pkgs.nftables
      pkgs.util-linux
    ];
  }
  ''
    set +e
    failed=0
    ${lib.concatMapStringsSep "\n" (cf: ''
        printf '=== %s (%s) ===\n' ${lib.escapeShellArg cf.name} ${cf.form}
        inner=$(cat <<'INNER_EOF'
      ${cf.rendered}
      INNER_EOF
        )
        ruleset="table ${cf.table.family} ${cf.table.name} {
      $inner
      }"
        if nft_err=$(unshare -rn nft -c -f - <<<"$ruleset" 2>&1); then
          echo "PASS"
        else
          echo "FAIL:"
          echo "$nft_err" | sed 's/^/    /'
          echo "$ruleset" | sed 's/^/    | /'
          failed=$((failed + 1))
        fi
    '') caseForms}
    if [ "$failed" -gt 0 ]; then
      echo "$failed text-block-integration test(s) failed"
      exit 1
    fi
    echo "All ${toString (builtins.length caseForms)}" \
      "text-block-integration tests passed"
    touch $out
  ''
