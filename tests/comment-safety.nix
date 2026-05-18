{ lib, nftlib }:

# Regression coverage for the nft quoted-string injection class (table-
# comment / log-prefix). Pre-fix: any '"' or control character in user
# input rendered into text that nft's lexer split into multiple
# statements — at table scope a malicious comment injected a real
# `chain bypass { policy accept; }`, a full firewall bypass.
#
# The fix is layered:
#   - Schema: commentOption, elemBody.comment, logBody.prefix are now
#     `nftQuotedString` — '"' / '\' / control / >128B rejected at
#     `evalModules` time.
#   - Renderer: `primitives.escape` / `quoteString` assert on the same
#     character set, so any caller bypassing the schema (raw attrsets,
#     third-party DSLs) fails loudly instead of producing broken text.
#
# Tests below pin both layers and exercise the regression PoC directly
# (a "naive" attrset whose comment WOULD render to injectable text
# pre-fix, fed through `toTextPretty` post-fix → throws).

let
  dsl = nftlib.dsl;
  inherit (nftlib) toJson toText toTextPretty;

  # Internal handle to the renderer primitives — exercised directly so the
  # renderer-level defence-in-depth assert is pinned independently of the
  # schema. Production callers should not import this path.
  textPrimitives = import ../lib/text/primitives.nix { inherit lib; };

  # The audit's malicious comment payload — verified end-to-end to inject
  # a chain at priority -10 with `policy accept` pre-fix.
  injectionPayload = ''X"; chain bypass { type filter hook input priority -10; policy accept; }; #'';

  evalSucceeds = expr: (builtins.tryEval expr).success;

  # Build a minimal ruleset whose only interesting field is `comment` on a
  # table — the directly-exploitable surface.
  rulesetWithTableComment =
    comment:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        inherit comment;
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  rulesetWithChainComment =
    comment:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        chains.c = {
          inherit comment;
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  rulesetWithRuleComment =
    comment:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [
            {
              expr = [ dsl.accept ];
              inherit comment;
            }
          ];
        };
      })
    ];

  rulesetWithElementComment =
    comment:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        sets.s = {
          type = "ipv4_addr";
          elem = [
            {
              elem = {
                val = "1.2.3.4";
                inherit comment;
              };
            }
          ];
        };
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ dsl.accept ] ];
        };
      })
    ];

  rulesetWithLogPrefix =
    prefix:
    dsl.ruleset [
      (dsl.table "inet" "t" {
        chains.c = {
          type = "filter";
          hook = "input";
          prio = 0;
          policy = "accept";
          rules = [ [ (dsl.log { inherit prefix; }) ] ];
        };
      })
    ];

  # Sample bad inputs — each individually unsafe for nft text rendering.
  # NUL bytes are absent because Nix string literals cannot represent
  # them (the parser rejects them). The renderer would still throw on a
  # NUL byte on principle, but constructing the test case would fail
  # before the assert fires.
  badInputs = {
    quote = ''has " quote'';
    backslash = ''has \ backslash'';
    newline = "has\nnewline";
    tab = "has\ttab";
    oversize = lib.concatStrings (lib.replicate 129 "a");
  };

  # 128 bytes — the exact NFTNL_UDATA_COMMENT_MAXLEN. Boundary case must
  # be accepted; oversize (129) above must be rejected.
  maxLength = lib.concatStrings (lib.replicate 128 "a");

  schemaRejects = body: !(evalSucceeds (toJson body));

  # Per-surface × per-bad-input rejection tests. Each emits one test of
  # the form testSchemaRejects_<surface>_<input>.
  # Note: setObjectBody / mapObjectBody intentionally do not declare a
  # `comment` field (pre-existing schema/renderer mismatch — the renderer
  # reads `body.comment or null` but no validator exposes it). The
  # commentOption is on tableBody / chainBody / ruleBody and every
  # `commonObjectOptions` named object (counter, quota, limit, ct helper,
  # ct timeout, ct expectation, secmark, synproxy, tunnel).
  surfaces = {
    tableComment = rulesetWithTableComment;
    chainComment = rulesetWithChainComment;
    ruleComment = rulesetWithRuleComment;
    elementComment = rulesetWithElementComment;
    logPrefix = rulesetWithLogPrefix;
  };

  schemaRejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testSchemaRejects_${surface}_${badName}";
        value = {
          expr = schemaRejects (surfaces.${surface} badValue);
          expected = true;
        };
      }) badInputs
    ) (builtins.attrNames surfaces)
  );

  # Schema-acceptance: every surface accepts a benign value and the
  # 128-byte boundary.
  schemaAcceptanceTests = lib.listToAttrs (
    lib.concatMap (surface: [
      {
        name = "testSchemaAccepts_${surface}_simple";
        value = {
          expr = schemaRejects (surfaces.${surface} "ok comment 123");
          expected = false;
        };
      }
      {
        name = "testSchemaAccepts_${surface}_maxLength";
        value = {
          expr = schemaRejects (surfaces.${surface} maxLength);
          expected = false;
        };
      }
    ]) (builtins.attrNames surfaces)
  );

  # Renderer-level: feed bad input directly to primitives.quoteString,
  # bypassing every schema check. The function must throw.
  rendererTests = {
    testRendererThrowsOnQuote = {
      expr = evalSucceeds (textPrimitives.quoteString badInputs.quote);
      expected = false;
    };
    testRendererThrowsOnBackslash = {
      expr = evalSucceeds (textPrimitives.quoteString badInputs.backslash);
      expected = false;
    };
    testRendererThrowsOnNewline = {
      expr = evalSucceeds (textPrimitives.quoteString badInputs.newline);
      expected = false;
    };
    testRendererThrowsOnTab = {
      expr = evalSucceeds (textPrimitives.quoteString badInputs.tab);
      expected = false;
    };
    testRendererAcceptsClean = {
      expr = evalSucceeds (textPrimitives.quoteString "clean text 123");
      expected = true;
    };
    testEscapeIsIdentityForSafe = {
      expr = textPrimitives.escape "abc";
      expected = "abc";
    };
  };

  # Regression PoC: a raw attrset (NOT routed through dsl.ruleset, so no
  # schema validation) whose comment WOULD have rendered to injectable
  # text pre-fix. Post-fix the renderer's escape-assert catches it.
  #
  # Documents *why* the renderer assert exists: even if a future
  # refactor weakens the schema, the renderer still refuses to emit
  # injectable text.
  rawInjectionRuleset = {
    nftables = [
      {
        add = {
          table = {
            family = "inet";
            name = "t";
            comment = injectionPayload;
          };
        };
      }
    ];
  };

  regressionTests = {
    testRendererBlocksInjectionInToText = {
      expr = evalSucceeds (toText rawInjectionRuleset);
      expected = false;
    };
    testRendererBlocksInjectionInToTextPretty = {
      expr = evalSucceeds (toTextPretty rawInjectionRuleset);
      expected = false;
    };
    # JSON path is structurally safe (builtins.toJSON encodes correctly,
    # libnftables stores the literal bytes as UDATA). Pin the encoding so
    # any future refactor that re-injects via JSON breaks here.
    testJsonRoundTripsLiteralBytes = {
      expr = toJson rawInjectionRuleset;
      expected = ''{"nftables":[{"add":{"table":{"comment":"X\"; chain bypass { type filter hook input priority -10; policy accept; }; #","family":"inet","name":"t"}}}]}'';
    };
  };

  tests = schemaRejectionTests // schemaAcceptanceTests // rendererTests // regressionTests;

  # Integration: render a *safe* comment through text and JSON paths,
  # round-trip through `nft -c -f` inside a private netns, dump the
  # ruleset, assert the comment value survives unchanged.
  runIntegrationTests =
    pkgs:
    let
      safeComment = "round-trip me (with spaces & punct!)";
      safeRuleset = rulesetWithTableComment safeComment;
      textOut = toTextPretty safeRuleset;
      jsonOut = toJson safeRuleset;
    in
    pkgs.runCommandLocal "comment-safety-integration"
      {
        nativeBuildInputs = [
          pkgs.nftables
          pkgs.util-linux
          pkgs.jq
        ];
      }
      ''
        set -e
        cat <<'TEXT_EOF' > rules.nft
        ${textOut}
        TEXT_EOF
        cat <<'JSON_EOF' > rules.json
        ${jsonOut}
        JSON_EOF

        # Text path: load via nft -f, dump via nft list ruleset -j, extract
        # the comment with jq (avoids text-renderer quirks in the dump
        # format).
        unshare -rn -- sh -c '
          set -e
          nft -f rules.nft
          got=$(nft -j list ruleset | jq -r ".nftables[] | select(.table) | .table.comment")
          want="${safeComment}"
          if [ "$got" != "$want" ]; then
            printf "text round-trip mismatch\n  want: %s\n  got:  %s\n" "$want" "$got" >&2
            exit 1
          fi
        '

        # JSON path: same comparison via the -j ingestion path.
        unshare -rn -- sh -c '
          set -e
          nft -j -f rules.json
          got=$(nft -j list ruleset | jq -r ".nftables[] | select(.table) | .table.comment")
          want="${safeComment}"
          if [ "$got" != "$want" ]; then
            printf "json round-trip mismatch\n  want: %s\n  got:  %s\n" "$want" "$got" >&2
            exit 1
          fi
        '

        echo "All comment-safety integration tests passed"
        touch $out
      '';

  runTests =
    pkgs:
    let
      results = lib.runTests tests;
      fmt = res: lib.generators.toPretty { } res;
    in
    if results == [ ] then
      pkgs.runCommandLocal "comment-safety-tests-pass" { } ''
        echo "All ${toString (builtins.length (builtins.attrNames tests))} comment-safety unit tests passed"
        touch $out
      ''
    else
      pkgs.runCommandLocal "comment-safety-tests-fail" { } ''
        cat <<'EOF'
        Comment-safety tests failed:
        ${fmt results}
        EOF
        exit 1
      '';
in
{
  inherit tests runTests runIntegrationTests;
}
