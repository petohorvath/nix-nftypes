{ lib, nftlib }:

# Regression coverage for the expression-scalar injection class.
# `expression` accepts plain strings as atoms — IP addresses, set
# references (`@trusted`), enum-like names (`established`), ICMP types
# (`host-unreachable`). The text renderer's `renderScalar` emitted
# these byte-for-byte into the surrounding statement, so a value like
# `"established\nadd chain inet fw pwned { … policy accept; }"`
# rendered as two text lines that `nft -f` parsed as two top-level
# statements — the second arbitrary attacker input.
#
# The fix is renderer-only: `renderScalar` now asserts the scalar
# matches `nft-safe-scalar.nix`'s predicate (no whitespace, no nft-
# grammar metacharacters, no control chars, non-empty). The schema
# branch in `expression` stays `types.str` because nixpkgs' `oneOf`
# description path triggers infinite recursion when a constrained
# string type sits alongside the recursive `listOf expression`
# branch; the renderer assert covers the same ground for the text
# path, and the JSON path is structurally safe (libnftables stores
# the literal bytes; the kernel rejects unsafe identifiers at the
# syscall boundary).

let
  dsl = nftlib.dsl;
  inherit (nftlib) toText toTextPretty toJson;

  nftSafeScalar = import ../lib/nft-safe-scalar.nix { };

  injectionPayload = ''
    established
    add chain inet fw pwned { type filter hook input priority -200; policy accept; }'';

  evalSucceeds = expr: (builtins.tryEval expr).success;

  # Surface 1: match RHS as a bare scalar string against a non-ifname
  # LHS. ifname LHSs route through `isIfnameLhs` and quote the value;
  # non-ifname LHSs (ct.state, mark, etc.) fall through to renderScalar.
  rulesetWithMatchRhs =
    rhs:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [
            [
              (dsl.eq dsl.fields.ct.state rhs)
              dsl.accept
            ]
          ];
        };
      })
    ];

  # Surface 2: scalar string element inside an anonymous set. The set
  # body type accepts arbitrary expressions; a plain string flows
  # through renderScalar at element-render time.
  rulesetWithSetElement =
    elem:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [
            [
              (dsl.inSet dsl.fields.ct.state [ elem ])
              dsl.accept
            ]
          ];
        };
      })
    ];

  # Surface 3: NAT addr expression — the schema lets `addr` be an
  # `expr`, so a bare string lands on the same renderScalar path.
  rulesetWithNatAddr =
    addr:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.post = {
          type = "nat";
          hook = "postrouting";
          prio = 100;
          rules = [ [ (dsl.snat { inherit addr; }) ] ];
        };
      })
    ];

  surfaces = {
    matchRhs = rulesetWithMatchRhs;
    setElement = rulesetWithSetElement;
    natAddr = rulesetWithNatAddr;
  };

  badInputs = {
    newline = "x\nadd chain inet fw bypass { type filter hook input priority -10; policy accept; }";
    semicolon = "x; chain bypass { policy accept; }; #";
    brace = "x{policy accept;}";
    quote = ''has " quote'';
    backslash = ''has \ backslash'';
    space = "x y";
    tab = "x\ttab";
    hash = "x#bar";
    comma = "x,y";
    empty = "";
  };

  goodInputs = {
    ipv4 = "1.2.3.4";
    ipv4_prefix = "192.168.0.0/16";
    ipv6 = "2001:db8::1";
    setRef = "@trusted_v4";
    icmpType = "host-unreachable";
    enumName = "established";
  };

  rendererRejects = body: !(evalSucceeds (toText body));
  prettyRejects = body: !(evalSucceeds (toTextPretty body));
  jsonAccepts = body: evalSucceeds (toJson body);

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

  prettyRejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testPrettyRendererRejects_matchRhs_${badName}";
      value = {
        expr = prettyRejects (rulesetWithMatchRhs badValue);
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

  # JSON path: libnftables stores the literal string. The kernel
  # rejects unsafe identifiers at the syscall boundary, but
  # `builtins.toJSON` itself succeeds for any string. Pin that the
  # text-path tightening didn't accidentally couple to the JSON path.
  jsonPassthroughTests = {
    testJsonAcceptsCommaScalar = {
      expr = jsonAccepts (rulesetWithMatchRhs "x,y");
      expected = true;
    };
    testJsonAcceptsNewlineScalar = {
      expr = jsonAccepts (rulesetWithMatchRhs "x\ny");
      expected = true;
    };
  };

  # Predicate-level coverage — pin the byte set directly so a future
  # refactor that loosens it breaks here.
  predicateTests = lib.listToAttrs (
    (lib.mapAttrsToList (n: v: {
      name = "testPredicateRejects_${n}";
      value = {
        expr = nftSafeScalar.isSafe v;
        expected = false;
      };
    }) badInputs)
    ++ (lib.mapAttrsToList (n: v: {
      name = "testPredicateAccepts_${n}";
      value = {
        expr = nftSafeScalar.isSafe v;
        expected = true;
      };
    }) goodInputs)
  );

  tests =
    rejectionTests // prettyRejectionTests // acceptanceTests // jsonPassthroughTests // predicateTests;

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "expr-scalar-safety-tests";
    inherit tests;
  };
in
{
  inherit tests runTests;
}
