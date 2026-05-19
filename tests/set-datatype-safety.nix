{ lib, nftlib }:

# Regression coverage for the set/map datatype injection class.
# Sets and maps carry a `type` field naming the element datatype
# (`ipv4_addr`, `ether_addr`, `inet_service`, `ifname`, …). The text
# renderer emitted that name bare into `type <X>`; a value like
# `"ipv4_addr\n}\nadd chain inet fw pwned { … }\nadd set inet fw dummy { type ipv4_addr"`
# closed the set body early and dropped a fresh `add chain` into the
# rendered file, accepted by `nft -f` as a real chain at attacker-
# chosen priority.
#
# Concatenated keys render the list joined by ` . ` (`ipv4_addr . inet_service`);
# every list element flows through the same bare path and is now
# checked individually.
#
# Renderer-level fix: `renderDatatype` in lib/text/objects.nix
# asserts each name string against the shared `nft-safe-scalar`
# predicate. The JSON path is unaffected; libnftables receives the
# literal bytes and rejects unknown datatypes at the syscall layer.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toText toTextPretty;

  evalSucceeds = expr: (builtins.tryEval expr).success;

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

  rendererRejects = body: !(evalSucceeds (toText body));

  rejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testRendererRejects_${surface}_${badName}";
        value = {
          expr = rendererRejects (surfaces.${surface} badValue);
          expected = true;
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
        expr = rendererRejects (rulesetWithConcatKey [
          "ipv4_addr"
          badValue
        ]);
        expected = true;
      };
    }) badInputs
  );

  acceptanceTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (goodName: goodValue: {
        name = "testRendererAccepts_${surface}_${goodName}";
        value = {
          expr = rendererRejects (surfaces.${surface} goodValue);
          expected = false;
        };
      }) goodInputs
    ) (builtins.attrNames surfaces)
  );

  concatAcceptanceTests = {
    testRendererAccepts_concatKey_pair = {
      expr = rendererRejects (rulesetWithConcatKey [
        "ipv4_addr"
        "inet_service"
      ]);
      expected = false;
    };
  };

  prettyTests = {
    testPrettyRejectsInjection = {
      expr = evalSucceeds (toTextPretty (rulesetWithSetType badInputs.newline));
      expected = false;
    };
    testPrettyAcceptsCleanDatatype = {
      expr = evalSucceeds (toTextPretty (rulesetWithSetType "ipv4_addr"));
      expected = true;
    };
  };

  tests =
    rejectionTests // concatRejectionTests // acceptanceTests // concatAcceptanceTests // prettyTests;

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "set-datatype-safety-tests";
    inherit tests;
  };
in
{
  inherit tests runTests;
}
