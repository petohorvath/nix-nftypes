{ pkgs, lib }:

# End-to-end check on validation error-message format. Each case is a Nix
# expression that should fail to evaluate, paired with a regex the stderr
# from `nix-instantiate --eval` must match. Confirms the "names the
# offending path" property: when the DSL catches a bad value, the error
# says *where* the bad value lives, not just *that* it's bad.
#
# Companion suite: tests/dsl-validation.nix asserts each constructor
# throws; this suite asserts the thrown message has the expected shape.

let
  # Boilerplate prepended to every case expression: imports the in-tree
  # `lib` against `nixpkgs.lib`. We import `${pkgs.path}/lib` directly
  # rather than the whole nixpkgs to avoid instantiating the package set
  # (which would trip the sandbox over derivation unpacks).
  preamble = ''
    let
      lib = import ${pkgs.path}/lib;
      nftlib = import ${../lib} { inherit lib; };
    in
  '';

  cases = [
    {
      name = "table-unknown-key";
      body = ''
        nftlib.toJson (nftlib.dsl.ruleset [
          (nftlib.dsl.table "ip" "t" {
            chians.c = { };
          })
        ])
      '';
      pathRegex = "dsl\\.table ip\\.t has unsupported key.*chians";
    }
    {
      name = "chains-c-prio";
      body = ''
        nftlib.toJson (nftlib.dsl.ruleset [
          (nftlib.dsl.table "ip" "t" {
            chains.c = { prio = "filter"; };
          })
        ])
      '';
      pathRegex = "chains\\.c\\.prio";
    }
    {
      name = "create-chain-prio";
      body = ''
        nftlib.toJson (nftlib.dsl.create.chain {
          family = "ip"; table = "t"; name = "c";
          prio = "filter";
        })
      '';
      pathRegex = "create\\.chain\\.prio";
    }
    {
      name = "tree-counters-bad-packets";
      body = ''
        nftlib.toJson (nftlib.dsl.ruleset [
          (nftlib.dsl.table "ip" "t" {
            counters.c = { packets = "lots"; };
          })
        ])
      '';
      pathRegex = "counters\\.c\\.packets";
    }
    {
      name = "rule-bad-handle";
      body = ''
        nftlib.toJson (nftlib.dsl.rule {
          family = "ip"; table = "t"; chain = "c";
          expr = [ ]; handle = "abc";
        })
      '';
      pathRegex = "rule\\.handle";
    }
    {
      name = "flushTable-bad-family";
      body = ''
        nftlib.toJson (nftlib.dsl.flushTable {
          family = "wireguard"; name = "t";
        })
      '';
      pathRegex = "flushTable\\.family";
    }
  ];

  # `nix-instantiate --eval` against each expression file inside the
  # sandbox. Sandboxed Nix needs a writable HOME / state dir for its
  # in-process eval cache; we point it at fresh tempdirs so it doesn't
  # try to use /homeless-shelter.
  runMessageTests =
    pkgs.runCommandLocal "dsl-validation-messages"
      {
        nativeBuildInputs = [ pkgs.nix ];
      }
      ''
        set +e
        export HOME=$(mktemp -d)
        export NIX_STATE_DIR=$(mktemp -d)
        export NIX_LOG_DIR=$(mktemp -d)

        failed=0
        ${lib.concatMapStringsSep "\n" (c: ''
          printf '=== %s ===\n' ${lib.escapeShellArg c.name}
          exprFile=$(mktemp --suffix=.nix)
          cat > "$exprFile" <<'EXPR_EOF'
          ${preamble}
          ${c.body}
          EXPR_EOF
          err=$(nix-instantiate --eval --strict --read-write-mode "$exprFile" 2>&1 || true)
          if printf '%s\n' "$err" | grep -qE ${lib.escapeShellArg c.pathRegex}; then
            echo "PASS"
          else
            echo "FAIL: expected stderr to match ${lib.escapeShellArg c.pathRegex}"
            printf '%s\n' "$err" | sed 's/^/    /'
            failed=$((failed + 1))
          fi
          rm -f "$exprFile"
        '') cases}
        if [ "$failed" -gt 0 ]; then
          echo "$failed message-format test(s) failed"
          exit 1
        fi
        echo "All ${toString (builtins.length cases)} message-format tests passed"
        touch $out
      '';
in
{
  inherit cases runMessageTests;
}
