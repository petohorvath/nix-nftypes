{
  helpers,
  internal,
  lib,
  nftlib,
  ...
}:

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
  inherit (nftlib) dsl toJson;

  inherit (internal) nftSafeScalar;

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

  # The UTF-8 encoding of a code point.
  utf8 = codePoint: builtins.fromJSON ''"\u${codePoint}"'';

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
    # nft's lexer reads a byte above 0x7F in a bare token as junk.
    noBreakSpace = "x${utf8 "00a0"}y";
    nonAscii = "x${utf8 "00e9"}";
  };

  goodInputs = {
    ipv4 = "1.2.3.4";
    ipv6 = "2001:db8::1";
    setRef = "@trusted_v4";
    icmpType = "host-unreachable";
    enumName = "established";
  };

  rejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testRendererRejects_${surface}_${badName}";
        value = {
          expr = nftlib.toText (surfaces.${surface} badValue);
          expectedError.msg = helpers.refusals.scalar;
        };
      }) badInputs
    ) (builtins.attrNames surfaces)
  );

  prettyRejectionTests = lib.listToAttrs (
    lib.mapAttrsToList (badName: badValue: {
      name = "testPrettyRendererRejects_matchRhs_${badName}";
      value = {
        expr = nftlib.toTextPretty (rulesetWithMatchRhs badValue);
        expectedError.msg = helpers.refusals.scalar;
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

  # JSON path: libnftables stores the literal string. The kernel
  # rejects unsafe identifiers at the syscall boundary, but
  # `builtins.toJSON` itself succeeds for any string. Pin that the
  # text-path tightening didn't accidentally couple to the JSON path.
  jsonPassthroughTests = {
    testJsonAcceptsCommaScalar = {
      expr = builtins.isString (toJson (rulesetWithMatchRhs "x,y"));
      expected = true;
    };
    testJsonAcceptsNewlineScalar = {
      expr = builtins.isString (toJson (rulesetWithMatchRhs "x\ny"));
      expected = true;
    };
  };

  /*
    A bare string containing `/`: nft's JSON parser reads `10.0.0.0/8` as
    a hostname and rejects it, while text loads it as a prefix, so a typo
    such as `198.51.100.7/0` would match every address. Text refuses it
    and points to `dsl.expr.prefix`.
  */
  rawRule = expr: {
    nftables = [
      {
        add.rule = {
          family = "inet";
          table = "t";
          chain = "c";
          inherit expr;
        };
      }
    ];
  };

  saddr.payload = {
    protocol = "ip";
    field = "saddr";
  };

  matchSaddr =
    right:
    rawRule [
      {
        match = {
          left = saddr;
          op = "==";
          inherit right;
        };
      }
    ];

  rawObject = kind: body: {
    nftables = [
      {
        add.${kind} = {
          family = "inet";
          table = "t";
          name = "s";
        }
        // body;
      }
    ];
  };

  typo = "198.51.100.7/0";

  # Field label → a raw ruleset with the string `bad` in that position.
  casesWith = bad: {
    "match right" = matchSaddr bad;
    "set element" = rawObject "set" {
      type = "ipv4_addr";
      flags = [ "interval" ];
      elem = [ bad ];
    };
    "map element" = rawObject "map" {
      type = "ipv4_addr";
      map = "mark";
      flags = [ "interval" ];
      elem = [
        [
          bad
          1
        ]
      ];
    };
    "map element value" = rawObject "map" {
      type = "mark";
      map = "ipv4_addr";
      elem = [
        [
          1
          bad
        ]
      ];
    };
    "match right set element" = matchSaddr { set = [ bad ]; };
    "map lookup key" = rawRule [
      {
        mangle = {
          key.meta.key = "mark";
          value.map = {
            key = saddr;
            data.set = [
              [
                bad
                1
              ]
            ];
          };
        };
      }
    ];
    # Where the renderer knows no slot, the Refusal names the expression.
    expression = rawRule [
      {
        snat.addr = bad;
      }
    ];
  };

  barePrefixCases = casesWith typo;

  # A range written as a string, which text loads as a range and JSON
  # rejects as a hostname.
  bareRangeCases = casesWith "198.51.100.1-198.51.100.9";

  # The elements of a set on the right of a match share its field.
  fieldOf = name: if name == "match right set element" then "match right" else name;

  barePrefixTests =
    lib.mapAttrs' (name: ruleset: {
      name = "testRefusesBarePrefix_${lib.replaceStrings [ " " ] [ "_" ] name}";
      value = {
        expr = nftlib.toText ruleset;
        expectedError.msg = helpers.refusals.barePrefix (fieldOf name);
      };
    }) barePrefixCases
    // {
      testPrefixExpressionRenders = {
        expr = nftlib.toText (matchSaddr {
          prefix = {
            addr = "198.51.100.0";
            len = 24;
          };
        });
        expected = "add rule inet t c ip saddr == 198.51.100.0/24\n";
      };
    };

  bareRangeTests =
    lib.mapAttrs' (name: ruleset: {
      name = "testRefusesBareRange_${lib.replaceStrings [ " " ] [ "_" ] name}";
      value = {
        expr = nftlib.toText ruleset;
        expectedError.msg = helpers.refusals.bareRange (fieldOf name);
      };
    }) bareRangeCases
    // {
      testRangeExpressionRenders = {
        expr = nftlib.toText (matchSaddr {
          range = [
            "198.51.100.1"
            "198.51.100.9"
          ];
        });
        expected = "add rule inet t c ip saddr == 198.51.100.1-198.51.100.9\n";
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
in
barePrefixTests
// bareRangeTests
// rejectionTests
// prettyRejectionTests
// acceptanceTests
// jsonPassthroughTests
// predicateTests
