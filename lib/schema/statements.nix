{
  lib,
  internal,
  primitives,
  expressions,
}:

let
  inherit (lib) mkOption types;
  inherit (internal) submodule taggedUnion;
  inherit (primitives) listOrSingleton;
  inherit (primitives.types)
    flowOp
    ipFamily
    logFlag
    logLevel
    logPrefix
    namedReference
    natFlag
    natTypeFlag
    nullLiteral
    operator
    queueFlag
    rejectType
    setOp
    synproxyFlag
    timeUnit
    xtType
    ;
  expr = expressions.expression;

  # A reference to a named stateful object: its name, or a map expression
  # that selects the name (`quota name tcp dport map { … }`).
  objectRef = types.either types.str (expressions.expressionOf [ "map" ]);
  refOrInline = internal.refOrInline objectRef;

  # nft lists a log, masquerade, redirect, queue or reject statement with
  # no options as a null body (src/json.c), and its JSON parser loads that
  # body back, so the body of each takes null.
  orNull = types.either nullLiteral;

  # A translation body that names an address or a port: nft refuses an
  # empty tproxy, and the kernel an snat or dnat with neither.
  addressOrPort =
    name: options:
    internal.discriminatedSubmodule {
      inherit options;
      extraCheck = body: (body.addr or null) != null || (body.port or null) != null;
      description = "${name} body with addr or port";
    };

  # The inline forms of the ct count and synproxy statements; their
  # bodies below add the reference forms.
  ctCountInline = submodule {
    options = {
      val = mkOption {
        type = types.ints.unsigned;
        description = "connection count threshold";
      };
      inv = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = "invert match semantics";
      };
    };
  };

  synproxyInline = submodule {
    options = {
      mss = mkOption {
        type = types.ints.unsigned;
        description = "maximum segment size";
      };
      wscale = mkOption {
        type = types.ints.unsigned;
        description = "window scale";
      };
      flags = mkOption {
        type = types.nullOr (listOrSingleton synproxyFlag);
        default = null;
        description = "synproxy option flags";
      };
    };
  };

  bodies = rec {
    # jump and goto take the same body as the verdict expressions.
    inherit (expressions) verdictTargetBody;

    matchBody = submodule {
      options = {
        left = mkOption {
          type = expr;
          description = "left-hand expression";
        };
        right = mkOption {
          type = expr;
          description = "right-hand expression";
        };
        op = mkOption {
          type = operator;
          description = "comparison operator";
        };
      };
    };

    /*
      Counter: parser_json.c:1894-1920 accepts null (emitted by stateless
      output), an inline `{ packets; bytes; }`, or a reference to a named
      counter. The inline form needs both fields: any other object is
      parsed as a reference and fails.
    */
    counterBody = types.oneOf [
      nullLiteral
      (refOrInline (
        internal.discriminatedSubmodule {
          requireKeys = [
            "packets"
            "bytes"
          ];
          description = "inline counter with packets and bytes";
          options = {
            packets = mkOption {
              type = types.ints.unsigned;
              description = "initial packet counter";
            };
            bytes = mkOption {
              type = types.ints.unsigned;
              description = "initial byte counter";
            };
          };
        }
      ))
    ];

    mangleBody = submodule {
      options = {
        key = mkOption {
          type = expr;
          description = "payload/meta/ct field to change";
        };
        value = mkOption {
          type = expr;
          description = "new value";
        };
      };
    };

    quotaBody = refOrInline (submodule {
      options = {
        val = mkOption {
          type = types.ints.unsigned;
          description = "quota value";
        };
        val_unit = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "unit of val (bytes/kbytes/mbytes/…)";
        };
        used = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "initial used value";
        };
        used_unit = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "unit of used";
        };
        inv = mkOption {
          type = types.nullOr types.bool;
          default = null;
          description = "invert match semantics";
        };
      };
    });

    # Inline limit: `rate` and `per` are required together (parser_json.c:2084).
    limitBody = refOrInline (submodule {
      options = {
        rate = mkOption {
          type = types.ints.positive;
          description = "rate value";
        };
        per = mkOption {
          type = timeUnit;
          description = "time unit (required for inline form)";
        };
        rate_unit = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "unit of rate; defaults to \"packets\"";
        };
        burst = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "burst value; defaults to 0";
        };
        burst_unit = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "unit of burst";
        };
        inv = mkOption {
          type = types.nullOr types.bool;
          default = null;
          description = "invert match semantics";
        };
      };
    });

    fwdBody = submodule {
      options = {
        dev = mkOption {
          type = expr;
          description = "interface to forward on";
        };
        family = mkOption {
          type = types.nullOr ipFamily;
          default = null;
          description = "address family of addr";
        };
        addr = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "destination address";
        };
      };
    };

    dupBody = submodule {
      options = {
        addr = mkOption {
          type = expr;
          description = "duplicate to address";
        };
        dev = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "duplicate on interface";
        };
      };
    };

    natBody = addressOrPort "snat/dnat" {
      addr = mkOption {
        type = types.nullOr expr;
        default = null;
        description = "address to translate to";
      };
      family = mkOption {
        type = types.nullOr ipFamily;
        default = null;
        description = "family of addr (required in inet)";
      };
      port = mkOption {
        type = types.nullOr expr;
        default = null;
        description = "port to translate to";
      };
      flags = mkOption {
        type = types.nullOr (listOrSingleton natFlag);
        default = null;
        description = ''
          NAT mapping flags (random/fully-random/persistent/netmap)
        '';
      };
      type_flags = mkOption {
        type = types.nullOr (listOrSingleton natTypeFlag);
        default = null;
        description = "NAT range semantics (interval/prefix/concat)";
      };
    };

    masqueradeBody = orNull (submodule {
      options = {
        port = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "masquerade/redirect to port";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton natFlag);
          default = null;
          description = "masquerade/redirect flags";
        };
      };
    });

    rejectBody = orNull (submodule {
      options = {
        type = mkOption {
          type = types.nullOr rejectType;
          default = null;
          description = "reject mechanism";
        };
        expr = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "ICMP code (when type is icmp/icmpx/icmpv6)";
        };
      };
    });

    setBody = submodule {
      options = {
        op = mkOption {
          type = setOp;
          description = "operation on the set (add/update/delete)";
        };
        elem = mkOption {
          type = expr;
          description = "element to add/update/delete";
        };
        set = mkOption {
          type = namedReference;
          description = "set reference (\"@name\")";
        };
        stmt = mkOption {
          type = types.nullOr (types.listOf statement);
          default = null;
          description = "stateful statements to attach on add/update";
        };
      };
    };

    # `map` statement: dynamic map modification (distinct from vmap).
    mapBody = submodule {
      options = {
        op = mkOption {
          type = setOp;
          description = "operation (add/update/delete)";
        };
        elem = mkOption {
          type = expr;
          description = "key expression";
        };
        data = mkOption {
          type = expr;
          description = "value expression";
        };
        map = mkOption {
          type = namedReference;
          description = "map reference (\"@name\")";
        };
        stmt = mkOption {
          type = types.nullOr (types.listOf statement);
          default = null;
          description = "stateful statements attached to the element";
        };
      };
    };

    logBody = orNull (submodule {
      options = {
        prefix = mkOption {
          type = types.nullOr logPrefix;
          default = null;
          description = "log prefix";
        };
        group = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "log group";
        };
        snaplen = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "snaplen";
        };
        "queue-threshold" = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "queue threshold";
        };
        level = mkOption {
          type = types.nullOr logLevel;
          default = null;
          description = "log level; defaults to warn";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton logFlag);
          default = null;
          description = "log flags";
        };
      };
    });

    meterBody = submodule {
      options = {
        name = mkOption {
          type = types.str;
          description = "meter name";
        };
        key = mkOption {
          type = expr;
          description = "meter key";
        };
        stmt = mkOption {
          type = statement;
          description = "statement executed when meter passes";
        };
        size = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "maximum number of keys tracked";
        };
      };
    };

    queueBody = orNull (submodule {
      options = {
        num = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "queue number or range (optional — parser_json.c:2831)";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton queueFlag);
          default = null;
          description = "queue flags";
        };
      };
    });

    vmapBody = submodule {
      options = {
        key = mkOption {
          type = expr;
          description = "map key";
        };
        data = mkOption {
          type = expr;
          description = "key → verdict mapping expression";
        };
      };
    };

    # Inline `{ val; inv? }`, or (nftables 1.1.7+) a reference to a named
    # `ct count` object (parser_json.c json_parse_connlimit_stmt).
    ctCountBody = refOrInline ctCountInline;

    xtBody = submodule {
      options = {
        type = mkOption {
          type = xtType;
          description = "xtables kind";
        };
        name = mkOption {
          type = types.str;
          description = "xtables extension name";
        };
      };
    };

    lastBody = types.either nullLiteral (submodule {
      options.used = mkOption {
        type = types.int;
        description = "time in ms since last match (-1 = never matched)";
      };
    });

    flowBody = submodule {
      options = {
        op = mkOption {
          type = flowOp;
          description = "flow offload operation (only \"add\" accepted)";
        };
        flowtable = mkOption {
          type = namedReference;
          description = "flowtable reference (\"@name\")";
        };
      };
    };

    tproxyBody = addressOrPort "tproxy" {
      family = mkOption {
        type = types.nullOr ipFamily;
        default = null;
        description = "address family";
      };
      addr = mkOption {
        type = types.nullOr expr;
        default = null;
        description = "address to redirect to";
      };
      port = mkOption {
        type = types.nullOr expr;
        default = null;
        description = "port to redirect to";
      };
    };

    # synproxy statement: null (empty), inline config, or named reference
    # string/expr. The map reference comes before the permissive anonymous
    # submodule, which would otherwise claim it.
    synproxyBody = types.oneOf [
      nullLiteral
      (expressions.expressionOf [ "map" ])
      synproxyInline
      expr
    ];

    # reset statement (TCP option strip): takes a tcp option expression.
    resetBody = expr;

    # The statements that attach a named object to the packet take the
    # object's name, or a map expression that selects it.
    ctHelperBody = expr;
    ctTimeoutBody = expr;
    ctExpectationBody = expr;
    secmarkBody = expr;
    tunnelBody = expr;

    /*
      Map of tag → body type. Single source of truth for the full
      `statement` attrTag union and the `statementOf` subset helper —
      adding a new statement kind here participates in both without
      drift. Kept inside `bodies` (rather than alongside it) so the
      body submodules above are in scope without qualification.
    */
    bodiesByTag = {
      # Verdicts
      accept = nullLiteral;
      drop = nullLiteral;
      continue = nullLiteral;
      return = nullLiteral;
      notrack = nullLiteral;
      jump = verdictTargetBody;
      goto = verdictTargetBody;
      # Core statements
      match = matchBody;
      counter = counterBody;
      mangle = mangleBody;
      quota = quotaBody;
      limit = limitBody;
      fwd = fwdBody;
      dup = dupBody;
      snat = natBody;
      dnat = natBody;
      masquerade = masqueradeBody;
      redirect = masqueradeBody;
      reject = rejectBody;
      set = setBody;
      map = mapBody;
      log = logBody;
      "ct helper" = ctHelperBody;
      "ct timeout" = ctTimeoutBody;
      "ct expectation" = ctExpectationBody;
      meter = meterBody;
      queue = queueBody;
      vmap = vmapBody;
      "ct count" = ctCountBody;
      xt = xtBody;
      # Statements found in parser_json.c but absent from the in-repo adoc:
      last = lastBody;
      flow = flowBody;
      tproxy = tproxyBody;
      synproxy = synproxyBody;
      reset = resetBody;
      secmark = secmarkBody;
      tunnel = tunnelBody;
    };

    statement = taggedUnion bodiesByTag;

    /*
      `statementOf : [ String ] -> Type` — restrict a `statement`-typed
      field to a subset of statement kinds, validated at `evalModules`
      time. Each element of `kinds` names a tag in the `statement`
      union (see `attrNames` of the statement attrTag).

      Use cases: a downstream "match-only" slot
      (`statementOf [ "match" ]`) or a verdict-only slot
      (`statementOf [ "accept" "drop" "jump" "goto" "return" "continue" ]`).
      Throws at *type construction* time on unknown kinds so typos
      surface immediately rather than at module evaluation.

      The result is `types.attrTag` of the requested subset, with
      `description` overridden to name the allowed kinds so error
      messages read "value is not of type 'statement (one of: match)'"
      instead of the generic "attribute-tagged union".
    */
    statementOf =
      kinds:
      let
        valid = lib.attrNames bodiesByTag;
        invalid = lib.subtractLists valid kinds;
        renderList = xs: lib.concatMapStringsSep ", " (k: ''"${k}"'') xs;
      in
      if !(builtins.isList kinds) then
        throw "nix-nftypes: types.statementOf: argument must be a list of strings"
      else if kinds == [ ] then
        throw "nix-nftypes: types.statementOf: kinds list must be non-empty"
      else if invalid != [ ] then
        throw (
          "nix-nftypes: types.statementOf: unknown statement kind(s): "
          + "${renderList invalid}. Valid kinds: ${renderList valid}."
        )
      else
        taggedUnion (lib.getAttrs kinds bodiesByTag)
        // {
          description = "statement (one of: ${renderList kinds})";
        };
  };
in
{
  inherit (bodies) bodiesByTag statement statementOf;
  all = removeAttrs bodies [
    "bodiesByTag"
    "statement"
    "statementOf"
  ];
}
