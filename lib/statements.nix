{
  lib,
  primitives,
  expressions,
}:

let
  inherit (lib) types mkOption;
  inherit (primitives) listOrSingleton;
  inherit (primitives.types)
    operatorType
    logLevelType
    logFlagType
    natFlagType
    natTypeFlagType
    natFamilyType
    synproxyFlagType
    flowOpType
    queueFlagType
    rejectTypeType
    setOpType
    xtTypeType
    perUnitType
    nullType
    ;
  expr = expressions.expression;

  verdictTargetBody = types.submodule {
    options.target = mkOption {
      type = types.str;
      description = "target chain name";
    };
  };

  bodies = rec {
    matchBody = types.submodule {
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
          type = operatorType;
          description = "comparison operator";
        };
      };
    };

    # Counter: parser_json.c:1914 accepts null (emitted by stateless output),
    # inline {packets, bytes}, or a named-reference string.
    counterRefOrBody = types.oneOf [
      nullType
      types.str
      (types.submodule {
        options = {
          packets = mkOption {
            type = types.nullOr types.ints.unsigned;
            default = null;
            description = "initial packet counter";
          };
          bytes = mkOption {
            type = types.nullOr types.ints.unsigned;
            default = null;
            description = "initial byte counter";
          };
        };
      })
    ];

    mangleBody = types.submodule {
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

    quotaRefOrBody = types.either types.str (
      types.submodule {
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
      }
    );

    # Inline limit: `rate` and `per` are required together (parser_json.c:2084).
    limitRefOrBody = types.either types.str (
      types.submodule {
        options = {
          rate = mkOption {
            type = types.ints.positive;
            description = "rate value";
          };
          per = mkOption {
            type = perUnitType;
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
      }
    );

    fwdBody = types.submodule {
      options = {
        dev = mkOption {
          type = expr;
          description = "interface to forward on";
        };
        family = mkOption {
          type = types.nullOr natFamilyType;
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

    dupBody = types.submodule {
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

    natBody = types.submodule {
      options = {
        addr = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "address to translate to";
        };
        family = mkOption {
          type = types.nullOr natFamilyType;
          default = null;
          description = "family of addr (required in inet)";
        };
        port = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "port to translate to";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton natFlagType);
          default = null;
          description = "NAT mapping flags (random/fully-random/persistent/netmap)";
        };
        type_flags = mkOption {
          type = types.nullOr (listOrSingleton natTypeFlagType);
          default = null;
          description = "NAT range semantics (interval/prefix/concat)";
        };
      };
    };

    masqueradeBody = types.submodule {
      options = {
        port = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "masquerade/redirect to port";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton natFlagType);
          default = null;
          description = "masquerade/redirect flags";
        };
      };
    };

    rejectBody = types.submodule {
      options = {
        type = mkOption {
          type = types.nullOr rejectTypeType;
          default = null;
          description = "reject mechanism";
        };
        expr = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "ICMP code (when type is icmp/icmpx/icmpv6)";
        };
      };
    };

    setStatementBody = types.submodule {
      options = {
        op = mkOption {
          type = setOpType;
          description = "operation on the set (add/update/delete)";
        };
        elem = mkOption {
          type = expr;
          description = "element to add/update/delete";
        };
        set = mkOption {
          type = types.str;
          description = "set reference";
        };
        stmt = mkOption {
          type = types.nullOr (types.listOf statement);
          default = null;
          description = "stateful statements to attach on add/update";
        };
      };
    };

    # `map` statement: dynamic map modification (distinct from vmap).
    mapStatementBody = types.submodule {
      options = {
        op = mkOption {
          type = setOpType;
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
          type = types.str;
          description = "map reference (\"@name\")";
        };
        stmt = mkOption {
          type = types.nullOr (types.listOf statement);
          default = null;
          description = "stateful statements attached to the element";
        };
      };
    };

    logBody = types.submodule {
      options = {
        prefix = mkOption {
          type = types.nullOr types.str;
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
          type = types.nullOr logLevelType;
          default = null;
          description = "log level; defaults to warn";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton logFlagType);
          default = null;
          description = "log flags";
        };
      };
    };

    meterBody = types.submodule {
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

    queueBody = types.submodule {
      options = {
        num = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "queue number or range (optional — parser_json.c:2831)";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton queueFlagType);
          default = null;
          description = "queue flags";
        };
      };
    };

    vmapBody = types.submodule {
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

    ctCountBody = types.submodule {
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

    xtBody = types.submodule {
      options = {
        type = mkOption {
          type = xtTypeType;
          description = "xtables kind";
        };
        name = mkOption {
          type = types.str;
          description = "xtables extension name";
        };
      };
    };

    lastBody = types.either nullType (
      types.submodule {
        options.used = mkOption {
          type = types.int;
          description = "time in ms since last match (-1 = never matched)";
        };
      }
    );

    flowBody = types.submodule {
      options = {
        op = mkOption {
          type = flowOpType;
          description = "flow offload operation (only \"add\" accepted)";
        };
        flowtable = mkOption {
          type = types.str;
          description = "flowtable reference starting with \"@\"";
        };
      };
    };

    tproxyBody = types.submodule {
      options = {
        family = mkOption {
          type = types.nullOr natFamilyType;
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
    };

    synproxyAnonBody = types.submodule {
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
          type = types.nullOr (listOrSingleton synproxyFlagType);
          default = null;
          description = "synproxy option flags";
        };
      };
    };
    # synproxy statement: null (empty), anonymous config, or named reference string/expr.
    synproxyStatementBody = types.oneOf [
      nullType
      synproxyAnonBody
      expr
    ];

    # reset statement (TCP option strip): takes a tcp option expression.
    resetBody = expr;

    statement = types.attrTag (
      lib.mapAttrs (_: type: mkOption { inherit type; }) {
        # Verdicts
        accept = nullType;
        drop = nullType;
        continue = nullType;
        return = nullType;
        notrack = nullType;
        jump = verdictTargetBody;
        goto = verdictTargetBody;
        # Core statements
        match = matchBody;
        counter = counterRefOrBody;
        mangle = mangleBody;
        quota = quotaRefOrBody;
        limit = limitRefOrBody;
        fwd = fwdBody;
        dup = dupBody;
        snat = natBody;
        dnat = natBody;
        masquerade = masqueradeBody;
        redirect = masqueradeBody;
        reject = rejectBody;
        set = setStatementBody;
        map = mapStatementBody;
        log = logBody;
        "ct helper" = expr;
        "ct timeout" = expr;
        "ct expectation" = expr;
        meter = meterBody;
        queue = queueBody;
        vmap = vmapBody;
        "ct count" = ctCountBody;
        xt = xtBody;
        # Statements found in parser_json.c but absent from the in-repo adoc:
        last = lastBody;
        flow = flowBody;
        tproxy = tproxyBody;
        synproxy = synproxyStatementBody;
        reset = resetBody;
        secmark = expr;
        tunnel = expr;
      }
    );
  };
in
{
  inherit (bodies) statement;
  all = removeAttrs bodies [ "statement" ];
}
