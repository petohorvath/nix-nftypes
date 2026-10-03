{
  fixtures,
  helpers,
  lib,
  nftlib,
  ...
}:

# Regression coverage for the ifname widening / unsafe-byte class
# across every surface where an interface name reaches the text
# renderer. Pre-fix the audit-flagged path was a `type = "ifname"` set
# whose element contained `,`: rendered as `elements = { eth0,eth1 }`,
# nft's text parser lexed the comma as the element separator, silently
# broadening the set to two interfaces the user never declared. The
# kernel's 15-byte IFNAMSIZ cap rules out fitting a `; chain bypass`
# injection like the C1 comment case, but silent widening is still a
# real correctness gap.
#
# Common predicate (lib/nft-safe-ifname.nix): rejects `,` `;` `{` `}`
# `"` `\` `#` and control chars on top of the kernel's `dev_valid_name`
# rules (no `/` `:` whitespace, not `.` / `..`, ≤15 bytes). Both schema
# and renderer consult `isSafe` / `findUnsafeOrNull` /
# `findUnsafeIfnameElementOrNull` so the two layers can't drift.
#
# Surfaces fixed:
#   - set/map elements (the audit-flagged path). DSL emit
#     (lib/table.nix) cross-field-checks set/map `type`
#     vs `elem` siblings at evalModules time and throws naming the
#     user's tree path; the text renderer
#     (lib/text/objects.nix `renderSetOrMapBody`) repeats the assert
#     as defence-in-depth for raw-attrset callers.
#   - chain.dev (netdev-family base chains) and flowtable.dev.
#     Multi-dev lists render bare comma-joined as `devices = { … }`;
#     the schema (lib/schema/objects.nix) types both fields as
#     `listOrSingleton ifname` and the renderer
#     (lib/text/objects.nix `assertSafeDev`) asserts each dev again.
#   - `meta iifname` / `oifname` / `sdifname` / `ibrname` / `obrname`
#     and `fib … oifname` match RHS. Pre-fix bare `meta iifname
#     eth0,eth1` lexed `,` as a bitmask operator and rejected ifname
#     as a non-bitmask type — parse error at activation, not silent
#     widening, but unhelpful UX. `match.right` is the open
#     `expression` union so the schema can't statically constrain it;
#     the renderer (lib/text/statements.nix `renderMatch` /
#     `isIfnameLhs`) is the sole gate, asserting ifname-safety and
#     emitting the value quoted.
#
# Also exposed: `nftlib.types.ifname` — public primitive so downstream
# consumers can tighten their own interface-name surfaces against the
# same rule.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toJson toText toTextPretty;

  inherit (helpers.internals) nftSafeIfname;

  # The audit's PoC payload — silently widens to two interfaces pre-fix.
  wideningPayload = "eth0,eth1";

  surfaces = {
    inherit (fixtures.ifnameRulesets)
      chainDevString
      flowtableDevString
      mapKey
      setElem
      setElemWithOptions
      ;
    chainDevList = v: fixtures.ifnameRulesets.chainDevList [ v ];
    flowtableDevList = v: fixtures.ifnameRulesets.flowtableDevList [ v ];
  };

  # ----- Bad / good ifname samples ----------------------------------------

  badIfnames = {
    # The audit's comma-widening PoC.
    comma = "eth0,eth1";
    # Other nft-text-grammar splitters / corrupters.
    semicolon = "eth0;chain";
    openBrace = "eth0{x";
    closeBrace = "eth0}";
    quote = ''eth0"'';
    backslash = ''eth0\x'';
    hash = "eth0#c";
    # Kernel-rejected (`dev_valid_name`) bytes.
    slash = "eth/0";
    colon = "eth:0";
    space = "eth 0";
    tab = "eth\t0";
    newline = "eth\n0";
    # Kernel-rejected reserved names + length boundary.
    dot = ".";
    dotdot = "..";
    empty = "";
    oversize = "abcdefghijklmnop"; # 16 bytes, IFNAMSIZ-1 is 15
  };

  goodIfnames = {
    short = "eth0";
    wifi = "wlp3s0";
    vlan = "vlan100";
    vlanDot = "eth0.100";
    veth = "veth-pod1";
    tun = "tun0";
    bridge = "br0";
    single = "a";
    maxLen = "abcdefghijklmno"; # 15 bytes, IFNAMSIZ-1
  };

  # ----- Per-surface × bad-input rejection tests --------------------------

  schemaRejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testDslRejects_${surface}_${badName}";
        value = {
          expr = nftlib.toJson (surfaces.${surface} badValue);
          expectedError.msg = "safe interface name";
        };
      }) badIfnames
    ) (builtins.attrNames surfaces)
  );

  # Per-surface × good-input acceptance tests.
  schemaAcceptanceTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (goodName: goodValue: {
        name = "testDslAccepts_${surface}_${goodName}";
        value = {
          expr = builtins.isString (nftlib.toJson (surfaces.${surface} goodValue));
          expected = true;
        };
      }) goodIfnames
    ) (builtins.attrNames surfaces)
  );

  # ----- No-false-positive: a non-ifname set tolerates commas etc. -------
  #
  # The check must NOT fire when `type` is anything other than `"ifname"`.
  # `type = "string"` accepts any string element; the dev / commit-author
  # name surfaces use it. A comma in such an element should pass through.

  nonIfnameTolerates = {
    testDslAcceptsCommaInStringSet = {
      expr = builtins.isString (
        nftlib.toJson (
          dsl.ruleset [
            (dsl.table "inet" "fw" {
              sets.tags = {
                type = "string";
                elements = [ "a,b" ];
              };
            })
          ]
        )
      );
      expected = true;
    };
  };

  # ----- Predicate-level tests --------------------------------------------
  # The byte-level predicate is shared between the DSL emit check and the
  # renderer's defence-in-depth assert. Pin its outcome directly so a
  # future refactor that loosens it breaks here.

  predicateTests = lib.listToAttrs (
    (lib.mapAttrsToList (n: v: {
      name = "testPredicateRejects_${n}";
      value = {
        expr = nftSafeIfname.isSafe v;
        expected = false;
      };
    }) badIfnames)
    ++ (lib.mapAttrsToList (n: v: {
      name = "testPredicateAccepts_${n}";
      value = {
        expr = nftSafeIfname.isSafe v;
        expected = true;
      };
    }) goodIfnames)
  );

  # ----- Renderer-level: raw attrset bypassing the DSL ---------------------
  # The text renderer's defence-in-depth assert must catch malicious
  # input that wasn't routed through the DSL emit check. The JSON path
  # is structurally safe (JSON quotes the literal bytes), so toJson
  # passes through without throwing.

  rawWideningRuleset =
    payload: elem:
    {
      nftables = [
        {
          add.set = {
            family = "inet";
            table = "fw";
            name = "iifs";
            type = "ifname";
            elem = [ elem ];
          };
        }
      ];
    }
    // payload;

  maliciousRawRuleset = rawWideningRuleset { } wideningPayload;
  safeRawRuleset = rawWideningRuleset { } "eth0";

  # Raw chain (netdev family) with a malicious dev list. Bypasses the
  # DSL — the renderer's `assertSafeDev` must catch it.
  rawChainDevRuleset = {
    nftables = [
      {
        add.chain = {
          family = "netdev";
          table = "t";
          name = "ingress";
          type = "filter";
          hook = "ingress";
          prio = 0;
          dev = [
            wideningPayload
            "eth2"
          ];
        };
      }
    ];
  };

  rawFlowtableDevRuleset = {
    nftables = [
      {
        add.flowtable = {
          family = "inet";
          table = "t";
          name = "ft";
          hook = "ingress";
          prio = 0;
          dev = [
            wideningPayload
            "eth2"
          ];
        };
      }
    ];
  };

  # Match RHS goes through the text renderer only — match.right is the
  # open `expression` union, so the schema can't statically constrain
  # it. Build raw rule envelopes (skipping the DSL for clarity about
  # the test shape) and exercise the renderer's `isIfnameLhs` /
  # ifname-safe assertion.
  rawMatchRule = metaKey: rightVal: {
    nftables = [
      {
        add.rule = {
          family = "inet";
          table = "t";
          chain = "c";
          expr = [
            {
              match = {
                left = {
                  meta = {
                    key = metaKey;
                  };
                };
                op = "==";
                right = rightVal;
              };
            }
          ];
        };
      }
    ];
  };

  matchRhsTests = {
    # Each ifname-typed meta key throws on the widening payload.
    testMatchThrowsOn_iifname = {
      expr = (toText (rawMatchRule "iifname" wideningPayload));
      expectedError.msg = "ifname-typed match RHS";
    };
    testMatchThrowsOn_oifname = {
      expr = (toText (rawMatchRule "oifname" wideningPayload));
      expectedError.msg = "ifname-typed match RHS";
    };
    testMatchThrowsOn_sdifname = {
      expr = (toText (rawMatchRule "sdifname" wideningPayload));
      expectedError.msg = "ifname-typed match RHS";
    };
    testMatchThrowsOn_ibrname = {
      expr = (toText (rawMatchRule "ibrname" wideningPayload));
      expectedError.msg = "ifname-typed match RHS";
    };
    testMatchThrowsOn_obrname = {
      expr = (toText (rawMatchRule "obrname" wideningPayload));
      expectedError.msg = "ifname-typed match RHS";
    };

    # Non-ifname meta keys are unaffected — `mark` accepts integer
    # comparison and shouldn't see a stricter ifname check applied.
    testMatchAcceptsNonIfnameKey = {
      expr = builtins.isString ((toText (rawMatchRule "mark" 100)));
      expected = true;
    };

    # Safe ifname renders QUOTED post-fix (the new behaviour). Pin the
    # exact output so a future refactor that drops the quoting breaks
    # here.
    testMatchQuotesSafeIfname = {
      expr = toText (rawMatchRule "iifname" "eth0");
      expected = "add rule inet t c meta iifname \"eth0\"";
    };

    # `@`-prefixed string is the named-set reference form; must stay
    # bare so nft reads it as a setRef and not as a quoted ifname
    # literal.
    testMatchPreservesSetRefBare = {
      expr = toText (rawMatchRule "iifname" "@trusted");
      expected = "add rule inet t c meta iifname @trusted";
    };

    # Anonymous set RHS goes through renderSet, not the new
    # single-string path; pin that it's untouched. (The set-element-
    # widening question for anonymous sets is the same class as the
    # named-set fix but a separate path — out of scope here.)
    testMatchAnonymousSetRhsUnchanged = {
      expr = toText (
        rawMatchRule "iifname" {
          set = [
            "lo"
            "eth0"
          ];
        }
      );
      expected = "add rule inet t c meta iifname { lo, eth0 }";
    };
  };

  rendererTests = {
    testTextThrowsOnMaliciousRaw = {
      expr = (toText maliciousRawRuleset);
      expectedError.msg = "ifname-typed set/map element";
    };
    testTextPrettyThrowsOnMaliciousRaw = {
      expr = (toTextPretty maliciousRawRuleset);
      expectedError.msg = "ifname-typed set/map element";
    };
    testTextAcceptsSafeRaw = {
      expr = builtins.isString ((toText safeRawRuleset));
      expected = true;
    };
    testTextThrowsOnMaliciousChainDev = {
      expr = (toTextPretty rawChainDevRuleset);
      expectedError.msg = "chain/flowtable device";
    };
    testTextThrowsOnMaliciousFlowtableDev = {
      expr = (toTextPretty rawFlowtableDevRuleset);
      expectedError.msg = "chain/flowtable device";
    };
    # JSON path is intrinsically safe — `builtins.toJSON` quotes the
    # element bytes so the comma stays inside one JSON string. The
    # kernel's `dev_valid_name` rejects the resulting ifname at
    # activation time, which is acceptable: an activation-time error is
    # not the silent widening that motivated this PR. Pin the encoding
    # so a future refactor that re-injects bytes breaks here.
    testJsonRoundTripsLiteralBytes = {
      expr = toJson maliciousRawRuleset;
      expected = "{\"nftables\":[{\"add\":{\"set\":{\"elem\":[\"eth0,eth1\"],\"family\":\"inet\",\"name\":\"iifs\",\"table\":\"fw\",\"type\":\"ifname\"}}}]}";
    };
  };
in
schemaRejectionTests
// schemaAcceptanceTests
// nonIfnameTolerates
// predicateTests
// matchRhsTests
// rendererTests
