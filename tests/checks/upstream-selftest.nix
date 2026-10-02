{
  helpers,
  nftablesSource,
  pkgs,
}:

# Red-path self-tests for the nixpkgs-source tooling (docs/upstream-sync.md).
#
# The drift checks exist to turn silent schema rot into red CI — which
# means the worst failure mode is the checks themselves rotting silently
# GREEN: an extraction regex that stops matching, a baseline that swallows
# everything, a validator that accepts anything. Every test here injects a
# defect and asserts the machinery actually fails:
#
#   - enum drift injected into the schema  → checker exits non-zero, names
#     the missing token;
#   - a renamed C table                    → loud EXTRACTION FAILURE, not a
#     vacuous "no drift";
#   - a table the regex can no longer read → plausibility-floor failure;
#   - an unbaselined corpus statement      → upstream-corpus's `newDrift`
#     is non-empty.
#
# The read-back validator's red paths (unknown top tags, fields, and
# statements) are unit tests in tests/suites/schema.nix.

let
  inherit (pkgs) lib;
  inherit (helpers) nftlib;

  # A fake nftables tree whose corpus contains one statement shape that is
  # deliberately not in the schema and matches no baselined pattern —
  # upstream-corpus.nix pointed at it must classify it as new drift.
  fakeCorpusSource = pkgs.runCommandLocal "fake-nftables-corpus" { } ''
    mkdir -p $out/tests/py/any
    cat > $out/tests/py/any/fake.t.json <<'EOF'
    # frobnicate the wug
    [
        {
            "frobnicate": { "wug": 1 }
        }
    ]
    EOF
  '';
  fakeCorpus = import ./upstream-corpus.nix {
    inherit helpers pkgs;
    nftablesSource = fakeCorpusSource;
  };

  # Same combined document upstream-enums.nix feeds the checker.
  schemaDocument = {
    enums = nftlib.enums;
    statementTags = builtins.attrNames nftlib.types.statement.functor.payload.tags;
    expressionTags = builtins.attrNames nftlib.types.taggedExpression.functor.payload.tags;
  };
  schemaJson = pkgs.writeText "schema-tokens.json" (builtins.toJSON schemaDocument);
  # The real schema minus rtKey "ipsec" — reintroducing the exact historical
  # gap G1 so the checker must rediscover it.
  doctoredSchemaJson = pkgs.writeText "schema-tokens-doctored.json" (
    builtins.toJSON (
      schemaDocument
      // {
        enums = nftlib.enums // {
          rtKey = lib.remove "ipsec" nftlib.enums.rtKey;
        };
      }
    )
  );
  # The real schema minus the `tproxy` statement tag — a dispatch-table
  # token the checker must flag as a missing statement kind.
  doctoredTagsJson = pkgs.writeText "schema-tokens-doctored-tags.json" (
    builtins.toJSON (
      schemaDocument // { statementTags = lib.remove "tproxy" schemaDocument.statementTags; }
    )
  );

  runTests =
    _pkgs:
    pkgs.runCommandLocal "nftables-tooling-selftests"
      {
        nativeBuildInputs = [ pkgs.python3 ];
      }
      ''
        fail() { echo "SELFTEST FAIL: $*"; exit 1; }
        echo "=== unbaselined corpus statement must be flagged as new drift ==="
        ${lib.optionalString (fakeCorpus.newDrift == [ ]) ''
          fail "corpus check did not flag an unbaselined statement"
        ''}
        check=${../../tooling/check-upstream-enums.py}

        echo "=== injected enum drift (schema without rtKey 'ipsec')" \
          "must go red ==="
        if python3 "$check" ${nftablesSource} ${doctoredSchemaJson} \
          > out-drift.txt 2>&1; then
          cat out-drift.txt
          fail "checker passed on a schema known to be missing a parser token"
        fi
        grep -q "DRIFT DETECTED" out-drift.txt || {
          cat out-drift.txt
          fail "no DRIFT DETECTED banner"
        }
        grep -q "ipsec" out-drift.txt || {
          cat out-drift.txt
          fail "report does not name the missing token"
        }

        echo "=== injected tag drift (schema without statement 'tproxy')" \
          "must go red ==="
        if python3 "$check" ${nftablesSource} ${doctoredTagsJson} \
          > out-tags.txt 2>&1; then
          cat out-tags.txt
          fail "checker passed on a schema known to be missing a" \
            "dispatch-table tag"
        fi
        grep -q "DRIFT DETECTED" out-tags.txt || {
          cat out-tags.txt
          fail "no DRIFT DETECTED banner for tag drift"
        }
        grep -q "tproxy" out-tags.txt || {
          cat out-tags.txt
          fail "report does not name the missing tag"
        }

        echo "=== renamed C table must fail loudly, not pass vacuously ==="
        mkdir -p doctored-rename/src
        cp ${nftablesSource}/src/parser_json.c ${nftablesSource}/src/meta.c \
          doctored-rename/src/
        chmod +w doctored-rename/src/*
        sed -i 's/rt_key_tbl/rt_key_renamed/g' doctored-rename/src/parser_json.c
        if python3 "$check" doctored-rename ${schemaJson} \
          > out-rename.txt 2>&1; then
          cat out-rename.txt
          fail "checker passed with a registry table missing from the source"
        fi
        grep -q "EXTRACTION FAILURE" out-rename.txt || {
          cat out-rename.txt
          fail "no EXTRACTION FAILURE on renamed table"
        }

        echo "=== unreadable table body must trip the plausibility floor ==="
        mkdir -p doctored-floor/src
        cp ${nftablesSource}/src/parser_json.c ${nftablesSource}/src/meta.c \
          doctored-floor/src/
        chmod +w doctored-floor/src/*
        sed -i 's/META_TEMPLATE(/META_TEMPLAT_(/g' doctored-floor/src/meta.c
        if python3 "$check" doctored-floor ${schemaJson} \
          > out-floor.txt 2>&1; then
          cat out-floor.txt
          fail "checker passed after token extraction collapsed to zero"
        fi
        grep -q "plausibility floor" out-floor.txt || {
          cat out-floor.txt
          fail "no floor failure on emptied extraction"
        }

        echo "=== control: undoctored inputs must still pass ==="
        python3 "$check" ${nftablesSource} ${schemaJson} \
          > out-control.txt 2>&1 \
          || { cat out-control.txt; fail "checker red on undoctored inputs"; }

        echo "All tooling red-path self-tests passed"
        touch $out
      '';
in
{
  inherit runTests;
}
