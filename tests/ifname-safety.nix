{ lib, nftlib }:

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
# and renderer consult `isSafe` / `firstUnsafe` / `badIfnameElement`
# so the two layers can't drift.
#
# Surfaces fixed:
#   - set/map elements (the audit-flagged path). DSL emit
#     (lib/dsl/structure/render.nix) cross-field-checks set/map `type`
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

  # Internal handle to the renderer/predicate — exercised directly so
  # the defence-in-depth assert is pinned independently of the DSL emit
  # check. Production callers should not import these paths.
  nftSafeIfname = import ../lib/nft-safe-ifname.nix { };

  # The audit's PoC payload — silently widens to two interfaces pre-fix.
  wideningPayload = "eth0,eth1";

  evalSucceeds = expr: (builtins.tryEval expr).success;

  # ----- Ruleset builders per surface -------------------------------------
  #
  # Each surface produces a ruleset whose only interesting field is the
  # ifname element bytes. The set/map name and chain plumbing are
  # constant; only the element changes.

  rulesetSetElem =
    elem:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        sets.iifs = {
          type = "ifname";
          elements = [ elem ];
        };
      })
    ];

  # Same set but the element carries options (`{ elem = { val; … }; }`):
  # the cross-field walker has to dig through the wrapper.
  rulesetSetElemWithOptions =
    elem:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        sets.iifs = {
          type = "ifname";
          elements = [
            {
              elem = {
                val = elem;
                comment = "ok";
              };
            }
          ];
        };
      })
    ];

  # Map keyed on ifname. The key is the typed slot (the map's `type`
  # describes its key datatype), so `[k, v]` element pairs need their
  # KEY validated.
  rulesetMapKey =
    key:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        maps.iif_marks = {
          type = "ifname";
          map = "mark";
          elements = [
            [
              key
              1
            ]
          ];
        };
      })
    ];

  # netdev-family base chain bound to an ifname. Single-dev string
  # form — the schema types `chain.dev` as `listOrSingleton ifname`.
  rulesetChainDevString =
    dev:
    dsl.ruleset [
      (dsl.table "netdev" "t" {
        chains.ingress = {
          type = "filter";
          hook = "ingress";
          prio = 0;
          inherit dev;
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  # netdev-family base chain bound to a list of ifnames — the path
  # the audit's widening PoC exercises.
  rulesetChainDevList =
    devs:
    dsl.ruleset [
      (dsl.table "netdev" "t" {
        chains.ingress = {
          type = "filter";
          hook = "ingress";
          prio = 0;
          dev = devs;
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  # Flowtable dev field — same `listOrSingleton ifname` shape as
  # chain.dev; rendered as `devices = { … }` inside the flowtable
  # body.
  rulesetFlowtableDevString =
    dev:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        flowtables.ft = {
          hook = "ingress";
          prio = 0;
          inherit dev;
        };
      })
    ];

  rulesetFlowtableDevList =
    devs:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        flowtables.ft = {
          hook = "ingress";
          prio = 0;
          dev = devs;
        };
      })
    ];

  surfaces = {
    setElem = rulesetSetElem;
    setElemWithOptions = rulesetSetElemWithOptions;
    mapKey = rulesetMapKey;
    chainDevString = rulesetChainDevString;
    chainDevList = v: rulesetChainDevList [ v ];
    flowtableDevString = rulesetFlowtableDevString;
    flowtableDevList = v: rulesetFlowtableDevList [ v ];
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

  schemaRejects = body: !(evalSucceeds (toJson body));

  # ----- Per-surface × bad-input rejection tests --------------------------

  schemaRejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testDslRejects_${surface}_${badName}";
        value = {
          expr = schemaRejects (surfaces.${surface} badValue);
          expected = true;
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
          expr = schemaRejects (surfaces.${surface} goodValue);
          expected = false;
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
      expr = schemaRejects (
        dsl.ruleset [
          (dsl.table "inet" "fw" {
            sets.tags = {
              type = "string";
              elements = [ "a,b" ];
            };
          })
        ]
      );
      expected = false;
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

  malRaw = rawWideningRuleset { } wideningPayload;
  safeRaw = rawWideningRuleset { } "eth0";

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
      expr = evalSucceeds (toText (rawMatchRule "iifname" wideningPayload));
      expected = false;
    };
    testMatchThrowsOn_oifname = {
      expr = evalSucceeds (toText (rawMatchRule "oifname" wideningPayload));
      expected = false;
    };
    testMatchThrowsOn_sdifname = {
      expr = evalSucceeds (toText (rawMatchRule "sdifname" wideningPayload));
      expected = false;
    };
    testMatchThrowsOn_ibrname = {
      expr = evalSucceeds (toText (rawMatchRule "ibrname" wideningPayload));
      expected = false;
    };
    testMatchThrowsOn_obrname = {
      expr = evalSucceeds (toText (rawMatchRule "obrname" wideningPayload));
      expected = false;
    };

    # Non-ifname meta keys are unaffected — `mark` accepts integer
    # comparison and shouldn't see a stricter ifname check applied.
    testMatchAcceptsNonIfnameKey = {
      expr = evalSucceeds (toText (rawMatchRule "mark" 100));
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
      expr = evalSucceeds (toText malRaw);
      expected = false;
    };
    testTextPrettyThrowsOnMaliciousRaw = {
      expr = evalSucceeds (toTextPretty malRaw);
      expected = false;
    };
    testTextAcceptsSafeRaw = {
      expr = evalSucceeds (toText safeRaw);
      expected = true;
    };
    testTextThrowsOnMaliciousChainDev = {
      expr = evalSucceeds (toTextPretty rawChainDevRuleset);
      expected = false;
    };
    testTextThrowsOnMaliciousFlowtableDev = {
      expr = evalSucceeds (toTextPretty rawFlowtableDevRuleset);
      expected = false;
    };
    # JSON path is intrinsically safe — `builtins.toJSON` quotes the
    # element bytes so the comma stays inside one JSON string. The
    # kernel's `dev_valid_name` rejects the resulting ifname at
    # activation time, which is acceptable: an activation-time error is
    # not the silent widening that motivated this PR. Pin the encoding
    # so a future refactor that re-injects bytes breaks here.
    testJsonRoundTripsLiteralBytes = {
      expr = toJson malRaw;
      expected = ''{"nftables":[{"add":{"set":{"elem":["eth0,eth1"],"family":"inet","name":"iifs","table":"fw","type":"ifname"}}}]}'';
    };
  };

  tests =
    schemaRejectionTests
    // schemaAcceptanceTests
    // nonIfnameTolerates
    // predicateTests
    // matchRhsTests
    // rendererTests;

  # ----- Integration ------------------------------------------------------
  #
  # Render a SAFE ifname set through both renderers, load each via the
  # real `nft` parser inside a private netns, dump the resulting set,
  # and assert the element count matches what we declared. The element-
  # count check is the regression-specific assertion: pre-fix, a
  # `[ "eth0,eth1" ]` element widened to two; this integration test
  # confirms the count is exactly preserved on the safe path so we
  # would notice if a future refactor reintroduced bare-comma rendering.

  runIntegrationTests =
    pkgs:
    let
      safeRuleset = rulesetSetElem "eth0";
      twoElemRuleset = dsl.ruleset [
        (dsl.table "inet" "fw" {
          sets.iifs = {
            type = "ifname";
            elements = [
              "eth0"
              "wlp3s0"
            ];
          };
        })
      ];
      textOut1 = toTextPretty safeRuleset;
      jsonOut1 = toJson safeRuleset;
      textOut2 = toTextPretty twoElemRuleset;
      jsonOut2 = toJson twoElemRuleset;
    in
    pkgs.runCommandLocal "ifname-safety-integration"
      {
        nativeBuildInputs = [
          pkgs.nftables
          pkgs.util-linux
          pkgs.jq
        ];
      }
      ''
        set -e

        run_case() {
          local label="$1" expected_count="$2" loader_flag="$3" file="$4"
          unshare -rn -- sh -c "
            set -e
            nft $loader_flag -f $file
            got=\$(nft -j list set inet fw iifs | jq '[.nftables[] | select(.set) | .set.elem[]] | length')
            want=$expected_count
            if [ \"\$got\" != \"\$want\" ]; then
              printf '%s: element-count mismatch\n  want: %s\n  got:  %s\n' \"$label\" \"\$want\" \"\$got\" >&2
              nft list set inet fw iifs >&2
              exit 1
            fi
          "
        }

        cat <<'TEXT1' > one_text.nft
        ${textOut1}
        TEXT1
        cat <<'JSON1' > one_json.json
        ${jsonOut1}
        JSON1
        cat <<'TEXT2' > two_text.nft
        ${textOut2}
        TEXT2
        cat <<'JSON2' > two_json.json
        ${jsonOut2}
        JSON2

        run_case "text single-elem" 1 "" one_text.nft
        run_case "json single-elem" 1 "-j" one_json.json
        run_case "text two-elem"    2 "" two_text.nft
        run_case "json two-elem"    2 "-j" two_json.json

        echo "All ifname-safety integration tests passed"
        touch $out
      '';

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "ifname-safety-tests";
    inherit tests;
  };
in
{
  inherit tests runTests runIntegrationTests;
}
