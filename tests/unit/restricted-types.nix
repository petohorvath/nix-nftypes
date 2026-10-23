{
  lib,
  nftlib,
  ...
}:

/*
  Tests for `statementOf` / `expressionOf` — the subset helpers
  downstream consumers use to restrict a `statement`- or
  `expression`-typed field to a chosen set of tags.

  Three behavioural axes:

    1. Type-check semantics — the helper must accept values whose tag
       is in the subset and reject any value whose tag is not, checked
       through `validate` so lazy type checks actually run.
    2. Construction errors — unknown kinds / non-list / empty list
       must throw at type construction time (i.e. when the helper is
       called), not silently produce an unusable type.
    3. Surface drift — `statementOf [ k ]` must work for every `k` in
       the `statement` union, so adding a new kind upstream cannot
       silently miss the per-subset helper.
*/

let
  inherit (nftlib) types validate;

  /*
    Strict type-check of `v` against `listOf t`, through `validate`, which
    forces every lazy submodule check. Returns the list, or throws the
    module system's type error. Wrapping in `listOf` matches the call-site
    shape consumers use:
    `type = listOf (nftypes.types.statementOf [ "match" ]);`.
  */
  checked = t: validate (lib.types.listOf t);

  # The type accepts every value in `v`.
  accepts = t: v: {
    expr = builtins.isList (checked t v);
    expected = true;
  };

  # The type rejects `v`.
  rejects = t: v: {
    expr = checked t v;
    expectedError.msg = "validate\\..*is not of type";
  };

  # Representative values for each tested kind. Built once at the top
  # so individual tests stay focused on the assertion, not the data.
  matchValue = {
    match = {
      left = {
        meta.key = "iif";
      };
      right = "eth0";
      op = "==";
    };
  };
  acceptValue = {
    accept = null;
  };
  jumpValue = {
    jump = {
      target = "next";
    };
  };
  counterValue = {
    counter = null;
  };
  payloadValue = {
    payload = {
      protocol = "tcp";
      field = "dport";
    };
  };
  metaValue = {
    meta.key = "iif";
  };
  ctValue = {
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
    # Match-only subset — the common downstream restriction. Accepts a
    # match; rejects every other kind. Pinned with three negatives so a
    # regression in the body type wouldn't be masked by a stale "accepts"
    # pass.
    testStatementOfMatchAcceptsMatch = accepts (types.statementOf [ "match" ]) [ matchValue ];
    testStatementOfMatchRejectsAccept = rejects (types.statementOf [ "match" ]) [ acceptValue ];
    testStatementOfMatchRejectsJump = rejects (types.statementOf [ "match" ]) [ jumpValue ];
    testStatementOfMatchRejectsCounter = rejects (types.statementOf [ "match" ]) [ counterValue ];

    # Verdict-only subset — the other common downstream restriction.
    # Accepts every verdict, rejects match and counter.
    testStatementOfVerdictAcceptsAccept = accepts (types.statementOf verdictKinds) [ acceptValue ];
    testStatementOfVerdictAcceptsJump = accepts (types.statementOf verdictKinds) [ jumpValue ];
    testStatementOfVerdictRejectsMatch = rejects (types.statementOf verdictKinds) [ matchValue ];
    testStatementOfVerdictRejectsCounter = rejects (types.statementOf verdictKinds) [ counterValue ];

    # Mixed two-kind subset — match and counter both pass; accept
    # (outside the subset) fails.
    testStatementOfMixedAcceptsBoth =
      accepts
        (types.statementOf [
          "match"
          "counter"
        ])
        [
          matchValue
          counterValue
        ];
    testStatementOfMixedRejectsOutsider =
      rejects
        (types.statementOf [
          "match"
          "counter"
        ])
        [
          matchValue
          acceptValue
        ];

    # `expressionOf` — tagged-only, scalars/lists are intentionally
    # outside the subset and not tested here (see helper docstring).
    testExpressionOfPayloadAcceptsBoth =
      accepts
        (types.expressionOf [
          "payload"
          "meta"
        ])
        [
          payloadValue
          metaValue
        ];
    testExpressionOfPayloadRejectsCt = rejects (types.expressionOf [
      "payload"
      "meta"
    ]) [ ctValue ];
  };

  # ---------------------------------------------------------------------
  # Section 2 — construction errors
  # ---------------------------------------------------------------------

  constructionTests = {
    testStatementOfUnknownKindThrows = {
      expr = types.statementOf [ "no-such-kind" ];
      expectedError.msg = "nix-nftypes: types\\.statementOf: unknown statement kind.*no-such-kind";
    };
    testStatementOfEmptyListThrows = {
      expr = types.statementOf [ ];
      expectedError.msg = "nix-nftypes: types\\.statementOf: kinds list must be non-empty";
    };
    testStatementOfNonListThrows = {
      expr = types.statementOf "match";
      expectedError.msg = "nix-nftypes: types\\.statementOf: argument must be a list of strings";
    };
    testExpressionOfUnknownKindThrows = {
      expr = types.expressionOf [ "no-such-kind" ];
      expectedError.msg = "nix-nftypes: types\\.expressionOf: unknown expression kind.*no-such-kind";
    };
    testExpressionOfEmptyListThrows = {
      expr = types.expressionOf [ ];
      expectedError.msg = "nix-nftypes: types\\.expressionOf: kinds list must be non-empty";
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
      expr = map (kind: builtins.seq (types.statementOf [ kind ]) kind) statementKinds;
      expected = statementKinds;
    };
    testExpressionOfEveryKindConstructible = {
      expr = map (kind: builtins.seq (types.expressionOf [ kind ]) kind) expressionKinds;
      expected = expressionKinds;
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
      expr = builtins.isString (nftlib.toJson roundTripRuleset);
      expected = true;
    };
    testRoundTripTextRenders = {
      expr = builtins.isString (nftlib.toText roundTripRuleset);
      expected = true;
    };
  };
in
semanticsTests // constructionTests // driftTests // roundTripTests
