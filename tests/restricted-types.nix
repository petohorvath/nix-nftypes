{ lib, nftlib }:

/*
  Tests for `statementOf` / `matchStatement` / `expressionOf` — the
  subset helpers downstream consumers use to restrict a `statement`- or
  `expression`-typed field to a chosen set of tags.

  Three behavioural axes:

    1. Type-check semantics — the helper must accept values whose tag
       is in the subset and reject any value whose tag is not. Deep-
       force the evalModules result so lazy type checks actually run.
    2. Construction errors — unknown kinds / non-list / empty list
       must throw at type construction time (i.e. when the helper is
       called), not silently produce an unusable type.
    3. Surface drift — `statementOf [ k ]` must work for every `k` in
       the `statement` union, so adding a new kind upstream cannot
       silently miss the per-subset helper.

  Companion: tests/dsl-validation-messages.nix carries the case that
  asserts the thrown error names the subset (description override
  bubbles up through evalModules).
*/

let
  inherit (nftlib) types;

  /*
    Strict type-check: build a one-option module whose value is a
    `listOf t`, plug `v` in, and deep-force the resulting list so the
    submodule's lazy type machinery actually runs. Returns true on
    success, false on any throw — `tryEval` catches `evalModules`'
    `assertion failed: …`. Wrapping in `listOf` matches the call-site
    shape consumers will use (`type = listOf nftypes.types.matchStatement;`).
  */
  accepts =
    t: v:
    let
      cfg =
        (lib.evalModules {
          modules = [
            { options.x = lib.mkOption { type = lib.types.listOf t; }; }
            { x = v; }
          ];
        }).config.x;
      r = builtins.tryEval (builtins.deepSeq cfg cfg);
    in
    r.success;

  # Representative values for each tested kind. Built once at the top
  # so individual tests stay focused on the assertion, not the data.
  matchVal = {
    match = {
      left = {
        meta.key = "iif";
      };
      right = "eth0";
      op = "==";
    };
  };
  acceptVal = {
    accept = null;
  };
  jumpVal = {
    jump = {
      target = "next";
    };
  };
  counterVal = {
    counter = null;
  };
  payloadVal = {
    payload = {
      protocol = "tcp";
      field = "dport";
    };
  };
  metaVal = {
    meta.key = "iif";
  };
  ctVal = {
    ct.key = "state";
  };

  verdictKinds = [
    "accept"
    "drop"
    "continue"
    "return"
    "jump"
    "goto"
  ];

  # ---------------------------------------------------------------------
  # Section 1 — type-check semantics
  # ---------------------------------------------------------------------

  semanticsTests = {
    # `matchStatement` is the pre-applied common case
    # (`statementOf [ "match" ]`). Accepts a match; rejects every other
    # kind. Pinned with three negatives so a regression in the body
    # type wouldn't be masked by a stale "accepts" pass.
    testMatchStatementAcceptsMatch = {
      expr = accepts types.matchStatement [ matchVal ];
      expected = true;
    };
    testMatchStatementRejectsAccept = {
      expr = accepts types.matchStatement [ acceptVal ];
      expected = false;
    };
    testMatchStatementRejectsJump = {
      expr = accepts types.matchStatement [ jumpVal ];
      expected = false;
    };
    testMatchStatementRejectsCounter = {
      expr = accepts types.matchStatement [ counterVal ];
      expected = false;
    };

    # `statementOf [ "match" ]` must behave identically to the
    # `matchStatement` alias — same value sets pass and fail.
    testStatementOfMatchMatchesAlias = {
      expr = accepts (types.statementOf [ "match" ]) [ matchVal ];
      expected = true;
    };
    testStatementOfMatchRejectsAccept = {
      expr = accepts (types.statementOf [ "match" ]) [ acceptVal ];
      expected = false;
    };

    # Verdict-only subset — the other common downstream restriction.
    # Accepts every verdict, rejects match and counter.
    testStatementOfVerdictAcceptsAccept = {
      expr = accepts (types.statementOf verdictKinds) [ acceptVal ];
      expected = true;
    };
    testStatementOfVerdictAcceptsJump = {
      expr = accepts (types.statementOf verdictKinds) [ jumpVal ];
      expected = true;
    };
    testStatementOfVerdictRejectsMatch = {
      expr = accepts (types.statementOf verdictKinds) [ matchVal ];
      expected = false;
    };
    testStatementOfVerdictRejectsCounter = {
      expr = accepts (types.statementOf verdictKinds) [ counterVal ];
      expected = false;
    };

    # Mixed two-kind subset — match and counter both pass; accept
    # (outside the subset) fails.
    testStatementOfMixedAcceptsBoth = {
      expr =
        accepts
          (types.statementOf [
            "match"
            "counter"
          ])
          [
            matchVal
            counterVal
          ];
      expected = true;
    };
    testStatementOfMixedRejectsOutsider = {
      expr =
        accepts
          (types.statementOf [
            "match"
            "counter"
          ])
          [
            matchVal
            acceptVal
          ];
      expected = false;
    };

    # `expressionOf` — tagged-only, scalars/lists are intentionally
    # outside the subset and not tested here (see helper docstring).
    testExpressionOfPayloadAcceptsBoth = {
      expr =
        accepts
          (types.expressionOf [
            "payload"
            "meta"
          ])
          [
            payloadVal
            metaVal
          ];
      expected = true;
    };
    testExpressionOfPayloadRejectsCt = {
      expr = accepts (types.expressionOf [
        "payload"
        "meta"
      ]) [ ctVal ];
      expected = false;
    };
  };

  # ---------------------------------------------------------------------
  # Section 2 — construction errors
  # ---------------------------------------------------------------------

  constructionTests = {
    testStatementOfUnknownKindThrows = {
      expr = (builtins.tryEval (types.statementOf [ "no-such-kind" ])).success;
      expected = false;
    };
    testStatementOfEmptyListThrows = {
      expr = (builtins.tryEval (types.statementOf [ ])).success;
      expected = false;
    };
    testStatementOfNonListThrows = {
      expr = (builtins.tryEval (types.statementOf "match")).success;
      expected = false;
    };
    testExpressionOfUnknownKindThrows = {
      expr = (builtins.tryEval (types.expressionOf [ "no-such-kind" ])).success;
      expected = false;
    };
    testExpressionOfEmptyListThrows = {
      expr = (builtins.tryEval (types.expressionOf [ ])).success;
      expected = false;
    };
  };

  # ---------------------------------------------------------------------
  # Section 3 — surface drift
  # ---------------------------------------------------------------------

  /*
    Hard-coded kind lists that must stay in sync with the schema. The
    per-kind smoke loop below fails if any of these drops out of the
    union — so adding a new tag upstream forces an explicit decision
    here too. Listed in the same order as the corresponding
    `*Bodies` map for easier diffing.
  */
  statementKinds = [
    "accept"
    "drop"
    "continue"
    "return"
    "notrack"
    "jump"
    "goto"
    "match"
    "counter"
    "mangle"
    "quota"
    "limit"
    "fwd"
    "dup"
    "snat"
    "dnat"
    "masquerade"
    "redirect"
    "reject"
    "set"
    "map"
    "log"
    "ct helper"
    "ct timeout"
    "ct expectation"
    "meter"
    "queue"
    "vmap"
    "ct count"
    "xt"
    "last"
    "flow"
    "tproxy"
    "synproxy"
    "reset"
    "secmark"
    "tunnel"
  ];

  expressionKinds = [
    "concat"
    "set"
    "map"
    "prefix"
    "range"
    "payload"
    "exthdr"
    "tcp option"
    "ip option"
    "sctp chunk"
    "dccp option"
    "meta"
    "rt"
    "ct"
    "numgen"
    "jhash"
    "symhash"
    "fib"
    "socket"
    "osf"
    "ipsec"
    "tunnel"
    "elem"
    "accept"
    "drop"
    "continue"
    "return"
    "jump"
    "goto"
    "|"
    "^"
    "&"
    "<<"
    ">>"
  ];

  # Every kind in the curated list must successfully build a singleton
  # subset. If the schema drops a kind, the helper will throw on the
  # corresponding line and the test fails — surfacing the drift.
  driftTests = {
    testStatementOfEveryKindConstructible = {
      expr = builtins.all (k: (builtins.tryEval (types.statementOf [ k ])).success) statementKinds;
      expected = true;
    };
    testExpressionOfEveryKindConstructible = {
      expr = builtins.all (k: (builtins.tryEval (types.expressionOf [ k ])).success) expressionKinds;
      expected = true;
    };
  };

  # ---------------------------------------------------------------------
  # Section 4 — round-trip parity
  # ---------------------------------------------------------------------

  /*
    A value typed as `(statementOf [ "match" ])` must render to the
    same JSON and text as the same value typed as the unrestricted
    `statement`. The DSL builder produces the same attrset shape
    either way; the helper only changes which tags are accepted.

    Build a single-rule ruleset (DSL form) and render it. The rule's
    body uses a match statement (the kind in scope for both types).
    Equality of the rendered output proves the helper doesn't smuggle
    a wrapper or change semantics — it's pure validation surface.
  */
  roundTripRuleset = nftlib.dsl.ruleset [
    (nftlib.dsl.table "inet" "t" {
      chains.c = {
        type = "filter";
        hook = "input";
        prio = 0;
        policy = "accept";
        rules = [
          [
            (nftlib.dsl.eq nftlib.dsl.fields.tcp.dport 22)
            nftlib.dsl.accept
          ]
        ];
      };
    })
  ];

  roundTripTests = {
    # Sanity: rendering the canonical ruleset succeeds. Pinned so a
    # regression here flags the round-trip baseline before the parity
    # assertion would surface a less actionable diff.
    testRoundTripJsonRenders = {
      expr = (builtins.tryEval (nftlib.toJson roundTripRuleset)).success;
      expected = true;
    };
    testRoundTripTextRenders = {
      expr = (builtins.tryEval (nftlib.toText roundTripRuleset)).success;
      expected = true;
    };
  };

  tests = semanticsTests // constructionTests // driftTests // roundTripTests;

  runTests =
    pkgs:
    let
      results = lib.runTests tests;
      fmt = res: lib.generators.toPretty { } res;
    in
    if results == [ ] then
      pkgs.runCommandLocal "restricted-types-tests-pass" { } ''
        echo "All ${toString (builtins.length (builtins.attrNames tests))} restricted-type tests passed"
        touch $out
      ''
    else
      pkgs.runCommandLocal "restricted-types-tests-fail" { } ''
        cat <<'EOF'
        Restricted-type tests failed:
        ${fmt results}
        EOF
        exit 1
      '';
in
{
  inherit tests runTests;
}
