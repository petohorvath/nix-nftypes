/*
  Source-side probes over the package set's patched nftables source
  (docs/upstream-sync.md). They run the Python tooling and record what it
  reports; the nix-unit suites decide what counts as drift.
*/
{
  nftablesSource,
  nftlib,
  pkgs,
  recordRuns,
}:
let
  inherit (pkgs) lib;

  checkEnums = ../../tooling/check-upstream-enums.py;

  # Normalizes `tests/py/**/*.t.json` under `source` to
  # `[ { file, title, expr }, … ]`.
  normalizeCorpus =
    name: source:
    pkgs.runCommandLocal name { nativeBuildInputs = [ pkgs.python3 ]; } ''
      python3 ${../../tooling/normalize-corpus.py} ${source}/tests/py > $out
    '';

  # A fake nftables tree whose corpus contains one statement shape that is
  # deliberately not in the schema and matches no baselined pattern.
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

  # The schema's accepted tokens, in the document the checker reads.
  schemaDocument = {
    enums = nftlib.enums;
    statementTags = builtins.attrNames nftlib.types.statement.functor.payload.tags;
    expressionTags = builtins.attrNames nftlib.types.taggedExpression.functor.payload.tags;
  };
  schemaJson = name: document: pkgs.writeText "${name}.json" (builtins.toJSON document);
  schemaTokens = schemaJson "schema-tokens" schemaDocument;

  renameTable = "s/rt_key_tbl/rt_key_renamed/g";
  breakTemplates = "s/META_TEMPLATE(/META_TEMPLAT_(/g";

  # Copies the two C files the checker reads and applies `sedScript` to
  # `file`, producing a doctored source tree in `dir`.
  doctorSource = dir: file: sedScript: ''
    mkdir -p ${dir}/src
    cp ${nftablesSource}/src/parser_json.c ${nftablesSource}/src/meta.c \
      ${dir}/src/
    chmod +w ${dir}/src/*
    sed -i ${lib.escapeShellArg sedScript} ${dir}/src/${file}
  '';
in
{
  # `[ { file, title, expr }, … ]` from the packaged corpus.
  nftablesCorpus = normalizeCorpus "nft-corpus.json" nftablesSource;

  nftablesEnumExtraction = recordRuns {
    name = "nftables-enum-extraction-probe";
    nativeBuildInputs = [ pkgs.python3 ];
    runs.check = "python3 ${checkEnums} ${nftablesSource} ${schemaTokens}";
  };

  # Each run feeds the checker one injected defect, plus an undoctored
  # control run.
  nftablesToolingSelftest = recordRuns {
    name = "nftables-tooling-selftest-probe";
    nativeBuildInputs = [ pkgs.python3 ];
    runs = {
      # The real schema minus rtKey "ipsec", reintroducing the historical
      # gap G1 so the checker must rediscover it.
      enumDrift = "python3 ${checkEnums} ${nftablesSource} ${
        schemaJson "schema-tokens-doctored" (
          schemaDocument
          // {
            enums = nftlib.enums // {
              rtKey = lib.remove "ipsec" nftlib.enums.rtKey;
            };
          }
        )
      }";
      # The real schema minus the `tproxy` statement tag.
      tagDrift = "python3 ${checkEnums} ${nftablesSource} ${
        schemaJson "schema-tokens-doctored-tags" (
          schemaDocument // { statementTags = lib.remove "tproxy" schemaDocument.statementTags; }
        )
      }";
      renamedTable = ''
        ${doctorSource "doctored-rename" "parser_json.c" renameTable}
        python3 ${checkEnums} doctored-rename ${schemaTokens}
      '';
      unreadableTable = ''
        ${doctorSource "doctored-floor" "meta.c" breakTemplates}
        python3 ${checkEnums} doctored-floor ${schemaTokens}
      '';
      control = "python3 ${checkEnums} ${nftablesSource} ${schemaTokens}";
    };
  };

  # The fake corpus, normalized the same way as the real one.
  nftablesToolingSelftestCorpus = normalizeCorpus "fake-nft-corpus.json" fakeCorpusSource;

  # The provenance of the source tree, compared against the package set's
  # nftables derivation, and the files the source checks read.
  nftablesSourceProvenance = pkgs.writeText "nftables-source-provenance.json" (
    builtins.toJSON {
      source = {
        src = if nftablesSource ? src then toString nftablesSource.src else null;
        patches = if nftablesSource ? patches then map toString nftablesSource.patches else null;
      };
      package = {
        src = toString pkgs.nftables.src;
        patches = map toString (pkgs.nftables.patches or [ ]);
      };
    }
  );

  nftablesSourceTree = recordRuns {
    name = "nftables-source-tree-probe";
    runs = {
      parser = "test -f ${nftablesSource}/src/parser_json.c";
      serializer = "test -f ${nftablesSource}/src/json.c";
      corpus = "test -d ${nftablesSource}/tests/py";
    };
  };
}
