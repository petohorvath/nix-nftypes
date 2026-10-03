{
  lib,
  nftlib,
  ...
}:

# Regression coverage for the set/map datatype injection class.
# Sets and maps carry a `type` field naming the element datatype
# (`ipv4_addr`, `ether_addr`, `inet_service`, `ifname`, …). The text
# renderer emitted that name bare into `type <X>`; a value like
# `"ipv4_addr\n}\nadd chain inet fw pwned { … }\nadd set …"` closed the
# set body early and dropped a fresh `add chain` into the rendered file,
# accepted by `nft -f` as a real chain at attacker-chosen priority.
#
# Concatenated keys render the list joined by ` . `
# (`ipv4_addr . inet_service`); every list element flows through the same
# bare path and is now checked individually.
#
# Renderer-level fix: `renderDatatype` in lib/text/objects.nix
# asserts each name string against the shared `nft-safe-scalar`
# predicate. The JSON path is unaffected; libnftables receives the
# literal bytes and rejects unknown datatypes at the syscall layer.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toTextPretty;

  rulesetWithSetType =
    type:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        sets.evil = {
          inherit type;
        };
      })
    ];

  # Map carries two datatype slots — the key type and the value type.
  rulesetWithMapType =
    type:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        maps.evil = {
          inherit type;
          map = "mark";
        };
      })
    ];

  rulesetWithMapValueType =
    valueType:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        maps.evil = {
          type = "ipv4_addr";
          map = valueType;
        };
      })
    ];

  # Concatenated key: list-of-strings shape, each element a separate
  # datatype name. Render path joins them with ` . `, so any unsafe
  # element pollutes the clause.
  rulesetWithConcatKey =
    parts:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        sets.evil = {
          type = parts;
        };
      })
    ];

  surfaces = {
    setType = rulesetWithSetType;
    mapKeyType = rulesetWithMapType;
    mapValueType = rulesetWithMapValueType;
  };

  badInputs = {
    newline = "ipv4_addr\n}\nadd chain inet fw pwned { type filter hook input priority -10; policy accept; }";
    semicolon = "ipv4_addr; }\n";
    brace = "ipv4_addr}";
    quote = ''ipv4_addr"'';
    backslash = ''ipv4_addr\'';
    space = "ipv4 addr";
    hash = "ipv4_addr#";
    comma = "ipv4_addr,extra";
    empty = "";
  };

  goodInputs = {
    ipv4 = "ipv4_addr";
    ipv6 = "ipv6_addr";
    ether = "ether_addr";
    service = "inet_service";
    ifname = "ifname";
    proto = "inet_proto";
  };

  rejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testRendererRejects_${surface}_${badName}";
        value = {
          expr = nftlib.toText (surfaces.${surface} badValue);
          expectedError.msg = "refusing to render a set/map datatype";
        };
      }) badInputs
    ) (builtins.attrNames surfaces)
  );

  concatRejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testRendererRejects_concatKey_${badName}";
      value = {
        # Inject the unsafe byte through the SECOND element to prove
        # the per-element walk is wired up (not just the head).
        expr = nftlib.toText (rulesetWithConcatKey [
          "ipv4_addr"
          badValue
        ]);
        expectedError.msg = "refusing to render a set/map datatype";
      };
    }) badInputs
  );

  acceptanceTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (goodName: goodValue: {
        name = "testRendererAccepts_${surface}_${goodName}";
        value = {
          expr = builtins.isString (nftlib.toText (surfaces.${surface} goodValue));
          expected = true;
        };
      }) goodInputs
    ) (builtins.attrNames surfaces)
  );

  concatAcceptanceTests = {
    testRendererAccepts_concatKey_pair = {
      expr = builtins.isString (
        nftlib.toText (rulesetWithConcatKey [
          "ipv4_addr"
          "inet_service"
        ])
      );
      expected = true;
    };
  };

  prettyTests = {
    testPrettyRejectsInjection = {
      expr = toTextPretty (rulesetWithSetType badInputs.newline);
      expectedError.msg = "refusing to render a set/map datatype";
    };
    testPrettyAcceptsCleanDatatype = {
      expr = builtins.isString (toTextPretty (rulesetWithSetType "ipv4_addr"));
      expected = true;
    };
  };
in
rejectionTests // concatRejectionTests // acceptanceTests // concatAcceptanceTests // prettyTests
