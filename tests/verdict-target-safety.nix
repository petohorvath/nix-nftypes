{ lib, nftlib }:

# Regression coverage for the verdict-target injection class.
# `jump`/`goto` carry a chain name; the text renderer used to emit it
# bare ("jump ${target}"), so a target string carrying a newline plus a
# top-level command rendered as two lines that `nft -f` then parsed as
# two statements — the second being arbitrary attacker input.
#
# Chain names elsewhere in the renderer go through `primitives.identQuote`
# which either renders bare (matching the unquoted-identifier rule) or
# quoted-and-escape-asserted (where the assert rejects '"', '\', or any
# control character — the parser-meta set). Verdict targets now follow
# the same path, so newline / quote / control-char injection throws at
# render time, and the other invalid bytes that nft rejects in
# identifier position (a quoted name where bare is required) surface as
# the documented load-bearing parse error.
#
# Surface: `jump` and `goto` as rule-body statements. The same render
# entries also dispatch when a verdict appears in vmap data position
# (`{ key : jump foo }`), so the fix covers both code paths even
# though the cases below only exercise the statement form.

let
  dsl = nftlib.dsl;
  inherit (nftlib) toText toTextPretty;

  # Payload from the chain-injection audit — `nft -c -f` accepted this
  # pre-fix as a real `add chain` at priority -200 with `policy accept`,
  # ahead of every user rule.
  injectionPayload = ''
    evil
    add chain inet filter pwned { type filter hook input priority -200; policy accept; }'';

  evalSucceeds = expr: (builtins.tryEval expr).success;

  # Build a minimal ruleset whose only interesting field is the verdict
  # target. The `evil` chain exists so a clean target ("evil") would
  # otherwise render successfully — isolating the injection-byte check.
  rulesetWithJumpTarget =
    target:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.evil = { };
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [ [ (dsl.jump target) ] ];
        };
      })
    ];

  rulesetWithGotoTarget =
    target:
    dsl.ruleset [
      (dsl.table "inet" "fw" {
        chains.evil = { };
        chains.input = {
          type = "filter";
          hook = "input";
          prio = 0;
          rules = [ [ (dsl.goto target) ] ];
        };
      })
    ];

  surfaces = {
    jumpStmt = rulesetWithJumpTarget;
    gotoStmt = rulesetWithGotoTarget;
  };

  # The renderer's first-line defence: identQuote routes any input
  # that isn't a bare identifier through `escape`, which rejects '"',
  # '\', and control characters. The audit's newline-based injection
  # PoC sits inside that set, so it now throws at render time.
  throwingInputs = {
    quote = ''has " quote'';
    backslash = ''has \ backslash'';
    newline = "x\nadd chain inet fw bypass { type filter hook input priority -10; policy accept; }";
    tab = "x\ttab";
  };

  # Parser-meta bytes that aren't in `escape`'s blocklist but also
  # don't match the bare-identifier rule — these fall through to the
  # quoted-string fallback `"…"`, which nft itself rejects in verdict-
  # target position. Pin that the rendered output contains the leading
  # quote so a future renderer change can't silently turn this into a
  # bare emission again.
  quotingInputs = {
    semicolon = "x; chain bypass { policy accept; }; #";
    brace = "x{policy accept;}";
    space = "x y";
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
      }) throwingInputs
    ) (builtins.attrNames surfaces)
  );

  quotingTests = lib.listToAttrs (
    lib.concatMap (
      surface:
      lib.mapAttrsToList (badName: badValue: {
        name = "testRendererQuotes_${surface}_${badName}";
        value = {
          expr = lib.hasInfix ''"${badValue}"'' (toText (surfaces.${surface} badValue));
          expected = true;
        };
      }) quotingInputs
    ) (builtins.attrNames surfaces)
  );

  acceptanceTests = lib.listToAttrs (
    map (surface: {
      name = "testRendererAccepts_${surface}_bareName";
      value = {
        expr = rendererRejects (surfaces.${surface} "evil");
        expected = false;
      };
    }) (builtins.attrNames surfaces)
  );

  # Pretty mode shares the same render path; pin both compact and
  # pretty to catch any future divergence.
  prettyTests = {
    testPrettyRejectsInjection = {
      expr = evalSucceeds (toTextPretty (rulesetWithJumpTarget injectionPayload));
      expected = false;
    };
    testPrettyAcceptsBareName = {
      expr = evalSucceeds (toTextPretty (rulesetWithJumpTarget "evil"));
      expected = true;
    };
  };

  tests = rejectionTests // quotingTests // acceptanceTests // prettyTests;

  runTests = (import ./lib.nix { inherit lib; }).mkRunTests {
    name = "verdict-target-safety-tests";
    inherit tests;
  };
in
{
  inherit tests runTests;
}
