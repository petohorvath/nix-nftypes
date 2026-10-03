{
  fixtures,
  helpers,
  lib,
  nftlib,
  ...
}:

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
#   - Renderer: `primitives.assertSafeString` / `quoteString` assert on the same
#     character set, so any caller bypassing the schema (raw attrsets,
#     third-party DSLs) fails loudly instead of producing broken text.
#
# Tests below pin both layers and exercise the regression PoC directly
# (a "naive" attrset whose comment WOULD render to injectable text
# pre-fix, fed through `toTextPretty` post-fix → throws).

let
  inherit (nftlib) toJson toText toTextPretty;

  inherit (helpers.internals) textPrimitives;

  # The audit's malicious comment payload — verified end-to-end to inject
  # a chain at priority -10 with `policy accept` pre-fix.
  injectionPayload = "X\"; chain bypass { type filter hook input priority -10; policy accept; }; #";

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

  # Per-surface × per-bad-input rejection tests. Each emits one test of
  # the form testSchemaRejects_<surface>_<input>.
  # Note: setObjectBody / mapObjectBody intentionally do not declare a
  # `comment` field (pre-existing schema/renderer mismatch — the renderer
  # reads `body.comment or null` but no validator exposes it). The
  # commentOption is on tableBody / chainBody / ruleBody and every
  # `commonObjectOptions` named object (counter, quota, limit, ct helper,
  # ct timeout, ct expectation, secmark, synproxy, tunnel).
  surfaces = fixtures.commentRulesets;

  schemaRejectionTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testSchemaRejects_${surface}_${badName}";
        value = {
          expr = nftlib.toJson (surfaces.${surface} badValue);
          expectedError.msg = "nft-safe quoted string";
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
          expr = builtins.isString (nftlib.toJson (surfaces.${surface} "ok comment 123"));
          expected = true;
        };
      }
      {
        name = "testSchemaAccepts_${surface}_maxLength";
        value = {
          expr = builtins.isString (nftlib.toJson (surfaces.${surface} maxLength));
          expected = true;
        };
      }
    ]) (builtins.attrNames surfaces)
  );

  # Renderer-level: feed bad input directly to primitives.quoteString,
  # bypassing every schema check. The function must throw.
  rendererTests = {
    testRendererThrowsOnQuote = {
      expr = textPrimitives.quoteString badInputs.quote;
      expectedError.msg = "refusing to render a string containing a character unsafe";
    };
    testRendererThrowsOnBackslash = {
      expr = textPrimitives.quoteString badInputs.backslash;
      expectedError.msg = "refusing to render a string containing a character unsafe";
    };
    testRendererThrowsOnNewline = {
      expr = textPrimitives.quoteString badInputs.newline;
      expectedError.msg = "refusing to render a string containing a character unsafe";
    };
    testRendererThrowsOnTab = {
      expr = textPrimitives.quoteString badInputs.tab;
      expectedError.msg = "refusing to render a string containing a character unsafe";
    };
    testRendererAcceptsClean = {
      expr = builtins.isString (textPrimitives.quoteString "clean text 123");
      expected = true;
    };
    testEscapeIsIdentityForSafe = {
      expr = textPrimitives.assertSafeString "abc";
      expected = "abc";
    };
  };

  # Regression PoC: a raw attrset (NOT routed through dsl.ruleset, so no
  # schema validation) whose comment WOULD have rendered to injectable
  # text pre-fix. Post-fix the renderer's `assertSafeString` catches it.
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
      expr = toText rawInjectionRuleset;
      expectedError.msg = "refusing to render a string containing a character unsafe";
    };
    testRendererBlocksInjectionInToTextPretty = {
      expr = toTextPretty rawInjectionRuleset;
      expectedError.msg = "refusing to render a string containing a character unsafe";
    };
    # JSON path is structurally safe (builtins.toJSON encodes correctly,
    # libnftables stores the literal bytes as UDATA). Pin the encoding so
    # any future refactor that re-injects via JSON breaks here.
    testJsonRoundTripsLiteralBytes = {
      expr = toJson rawInjectionRuleset;
      expected = "{\"nftables\":[{\"add\":{\"table\":{\"comment\":\"X\\\"; chain bypass { type filter hook input priority -10; policy accept; }; #\",\"family\":\"inet\",\"name\":\"t\"}}}]}";
    };
  };
in
schemaRejectionTests // schemaAcceptanceTests // rendererTests // regressionTests
