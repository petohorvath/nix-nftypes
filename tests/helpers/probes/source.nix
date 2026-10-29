/*
  Source-side probes over the package set's patched nftables source
  (docs/upstream-sync.md). They run the Python tooling and record what it
  reports; the nix-unit suites decide what counts as drift.
*/
{
  nftablesSource,
  pkgs,
  recordRuns,
}:
let
  inherit (pkgs) lib;

  extractTokens = ../../../tooling/extract-upstream-tokens.py;

  normalizeCorpusScript = ../../../tooling/normalize-corpus.py;

  # Normalizes `tests/py/**/*.t.json` under `source` to
  # `[ { file, title, expr }, … ]`.
  normalizeCorpus =
    name: source:
    pkgs.runCommandLocal name { nativeBuildInputs = [ pkgs.python3 ]; } ''
      python3 ${normalizeCorpusScript} ${source}/tests/py > $out
    '';

  # A fake nftables tree holding one corpus file, `fake.t.json`.
  writeFakeCorpus =
    name: records:
    pkgs.runCommandLocal name { } ''
      mkdir -p $out/tests/py/any
      cp ${pkgs.writeText "fake.t.json" records} $out/tests/py/any/fake.t.json
    '';

  # A fake corpus with one statement shape not in the schema nor in the
  # baseline, and two records whose titles hold brackets, as nftables' IPv6
  # NAT and `srh sid[N]` records do.
  fakeCorpusSource = writeFakeCorpus "fake-nftables-corpus" ''
    # frobnicate the wug
    [
        {
            "frobnicate": { "wug": 1 }
        }
    ]

    # dnat to [2001:db8::1]:80
    [
        {
            "dnat": { "addr": "2001:db8::1", "port": 80 }
        }
    ]

    # srh sid[1] dead::beef
    [
        {
            "match": {
                "left": { "exthdr": { "field": "sid[1]", "name": "srh" } },
                "op": "==",
                "right": "dead::beef"
            }
        }
    ]
  '';

  # A fake corpus whose second record's array is cut short.
  unparsableCorpusSource = writeFakeCorpus "unparsable-nftables-corpus" ''
    # accept
    [
        {
            "accept": null
        }
    ]

    # half an array
    [
        {
            "accept": null
        }
  '';

  # A patch hook, normalized the way the source package passes it: the
  # source tree has `""` where the package has `null` or nothing.
  patchHookOrEmpty = drv: name: if drv ? ${name} && drv.${name} != null then drv.${name} else "";

  # Unpack- and patch-phase attributes the source package does not pass.
  unpassedAttributes = [
    "sourceRoot"
    "setSourceRoot"
    "preUnpack"
    "postUnpack"
    "unpackPhase"
    "patchPhase"
  ];

  # What decides the source tree, on the source side and on `package`'s
  # side, and `package`'s unpassed attributes. `package` is the package
  # set's nftables, or a doctored copy in the self-tests.
  provenanceRecord = package: {
    source = {
      src = if nftablesSource ? src then toString nftablesSource.src else null;
      patches = if nftablesSource ? patches then map toString nftablesSource.patches else null;
      patchFlags = nftablesSource.patchFlags or null;
      prePatch = patchHookOrEmpty nftablesSource "prePatch";
      postPatch = patchHookOrEmpty nftablesSource "postPatch";
    };
    package = {
      src = toString package.src;
      patches = map toString (package.patches or [ ]);
      patchFlags = package.patchFlags or null;
      prePatch = patchHookOrEmpty package "prePatch";
      postPatch = patchHookOrEmpty package "postPatch";
      unpassed = lib.genAttrs unpassedAttributes (attribute: package.${attribute} or null);
    };
  };

  # A sed script per C file the extractor reads, deleting one entry of
  # each table.
  missingEntryEdits = {
    byteUnit."statement.c" = "/^\t\"kbytes\",$/d";
    ctDirKey."parser_json.c" = "/^\t\tNFT_CT_ZONE,$/d";
    ctKey."ct.c" = "/CT_TEMPLATE(\"secmark\",/d";
    expressionTag."parser_json.c" = "/{ \"osf\", json_parse_osf_expr,/d";
    family."parser_json.c" = "/{ \"netdev\", NFPROTO_NETDEV }/d";
    fibResult."parser_json.c" = "/= \"check\",/d";
    metaKey."meta.c" = "/META_TEMPLATE(\"secmark\",/d";
    payloadField."proto.c" = "/\\[IGMPHDR_MRT\\]/d";
    rtKey."parser_json.c" = "/{ \"ipsec\", NFT_RT_XFRM },/d";
    statementTag."parser_json.c" = "/{ \"tproxy\", json_parse_tproxy_stmt },/d";
  };

  # Rewrites entries as designated initializers with the token last:
  # family_tbl's and stmt_parser_tbl's, and two meta and two ct templates,
  # whose macro call spans two lines.
  designatedEntryEdits = {
    "ct.c" =
      "/CT_TEMPLATE(\"\\(bytes\\|zone\\)\",/{N;s/CT_TEMPLATE(\\(\"[a-z]*\"\\),\\([^)]*\\))/{ .dtype = \\2, .token = \\1 }/}";
    "parser_json.c" = lib.concatStringsSep "\n" [
      "s/{ \\(\"[a-z0-9]*\"\\), \\(NFPROTO_[A-Z0-9]*\\) }/{ .val = \\2, .name = \\1 }/"
      "s/{ \\(\"[a-z ]*\"\\), \\(json_parse_[a-z_]*_stmt\\) }/{ .cb = \\2, .key = \\1 }/"
    ];
    "meta.c" =
      "/META_TEMPLATE(\"\\(length\\|mark\\)\",/{N;s/META_TEMPLATE(\\(\"[a-z]*\"\\),\\([^)]*\\))/{ .dtype = \\2, .token = \\1 }/}";
  };

  # Copies the C files the extractor reads to `dir`/src and applies each
  # file's sed script in `edits`, `{ <file> = <script>; }`.
  doctorSource =
    dir: edits:
    ''
      mkdir -p ${dir}/src
      cp ${nftablesSource}/src/{ct,meta,parser_json,proto,statement}.c \
        ${dir}/src/
      chmod +w ${dir}/src/*
    ''
    + lib.concatStrings (
      lib.mapAttrsToList (file: script: ''
        sed -i ${lib.escapeShellArg script} ${dir}/src/${file}
      '') edits
    );

  # Runs the extractor on a source tree doctored with `edits`.
  extractDoctored = name: edits: ''
    ${doctorSource "doctored-${name}" edits}
    python3 ${extractTokens} doctored-${name}
  '';
in
{
  # `[ { file, title, expr }, … ]` from the packaged corpus.
  nftablesCorpus = normalizeCorpus "nft-corpus.json" nftablesSource;

  # `{ <table> = [ <token> … ]; }` as the `extract` run's output.
  nftablesEnumExtraction = recordRuns {
    name = "nftables-enum-extraction-probe";
    nativeBuildInputs = [ pkgs.python3 ];
    runs.extract = "python3 ${extractTokens} ${nftablesSource}";
  };

  # Each run feeds the tooling one injected defect, plus an undoctored
  # control extraction.
  nftablesToolingSelftest = recordRuns {
    name = "nftables-tooling-selftest-probe";
    nativeBuildInputs = [ pkgs.python3 ];
    runs =
      lib.mapAttrs' (
        name: edits: lib.nameValuePair "missingEntry_${name}" (extractDoctored name edits)
      ) missingEntryEdits
      // {
        renamedTable = extractDoctored "rename" { "parser_json.c" = "s/rt_key_tbl/rt_key_renamed/g"; };
        unreadableTable = extractDoctored "floor" { "meta.c" = "s/META_TEMPLATE(/META_TEMPLAT_(/g"; };
        designatedEntries = extractDoctored "designated" designatedEntryEdits;
        control = "python3 ${extractTokens} ${nftablesSource}";
        unparsableCorpusRecord = "python3 ${normalizeCorpusScript} ${unparsableCorpusSource}/tests/py";
      };
  };

  # The fake corpus, normalized the same way as the real one.
  nftablesToolingSelftestCorpus = normalizeCorpus "fake-nft-corpus.json" fakeCorpusSource;

  # Provenance records of doctored nftables packages against the real
  # source tree. Only their attributes are read; neither is built.
  nftablesToolingSelftestProvenance = pkgs.writeText "nftables-tooling-selftest-provenance.json" (
    builtins.toJSON {
      droppedPostPatch = provenanceRecord (pkgs.nftables.overrideAttrs { postPatch = "touch doctored"; });
      unpassedPostUnpack = provenanceRecord (
        pkgs.nftables.overrideAttrs { postUnpack = "touch doctored"; }
      );
    }
  );

  # The provenance of the source tree, compared against the package set's
  # nftables derivation, and the files the source checks read.
  nftablesSourceProvenance = pkgs.writeText "nftables-source-provenance.json" (
    builtins.toJSON (provenanceRecord pkgs.nftables)
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
