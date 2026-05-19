{ lib, nftlib }:

# Regression coverage for the ifname set/map element widening class. Pre-
# fix: a `type = "ifname"` set whose element contained `,` rendered as
# `elements = { eth0,eth1 }` and nft's text parser lexed the comma as
# the element separator, silently broadening the set to two interfaces
# the user never declared. The kernel's 15-byte IFNAMSIZ cap rules out
# fitting a whole `; chain bypass { ... }; #` injection into one element,
# so the practical worst case is silent widening (not the full firewall
# bypass C1 enabled), but it's still a real correctness gap.
#
# The fix is layered (mirrors C1):
#   - DSL emit (lib/dsl/structure/render.nix): cross-field check at
#     evalModules time. The set/map body's `type` and `elem` siblings
#     can't be related at the primitive-type level, so the validation
#     runs after `validate` returns and throws naming the user's tree
#     path (`sets.<n>: …`).
#   - Schema primitive (lib/schema/primitives.nix `ifname`): exposed as
#     a public type so downstream consumers can tighten their own
#     interfaces against the same rule.
#   - Renderer (lib/text/objects.nix `renderSetOrMapBody`): throws on
#     the same predicate as defence-in-depth for raw-attrset callers
#     that bypass the DSL.
#
#   - chain `dev` field (netdev-family base chains) and flowtable
#     `dev` field — both render multi-device lists as bare comma-joined
#     `devices = { … }`, and a `,` in an element widens identically to
#     the set/map case. Tightened to `listOrSingleton ifname` so the
#     schema check fires at the option boundary; the text renderer
#     applies the same defence-in-depth assert via `assertSafeDev`.
#
# Audit follow-up (NOT covered here — different mechanism, separate
# PR): the `meta iifname` match RHS is a parse error rather than
# silent widening (nft reads the unquoted comma as a bitmask operator
# and rejects ifname as a non-bitmask type), so it's less dangerous
# but still poor UX.

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
