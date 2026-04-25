{
  lib,
  internal,
  primitives,
  expressions,
  statements,
}:

let
  inherit (lib) types mkOption;
  inherit (internal) discriminatedSubmodule tagOpt wrap;
  inherit (primitives) listOrSingleton;
  inherit (primitives.types)
    familyType
    hookType
    policyType
    chainTypeType
    tableFlagType
    setFlagType
    setPolicyType
    ctHelperProtoType
    ctTimeoutProtoType
    perUnitType
    rtFamilyType
    synproxyFlagType
    portNumber
    nullType
    ;
  expr = expressions.expression;
  stmt = statements.statement;

  # Set/map datatype: string, list of strings, or { typeof = EXPRESSION; }.
  typeofBody = types.submodule {
    options.typeof = mkOption {
      type = expr;
      description = "extract datatype from expression";
    };
  };
  setDatatype = types.oneOf [
    types.str
    (types.listOf types.str)
    typeofBody
  ];

  # A set element is either a bare expression or a list of expressions.
  setElem = types.either expr (types.listOf expr);

  # ----- Identity-options fragments -----
  # Composable building blocks for the family/table/name/handle/comment fields
  # that appear (in slightly different combinations) on every object kind.
  # Composition: identityCore ⊂ inTableOptions ⊂ namedInTableOptions ⊂
  # commonObjectOptions. Specialised shapes (tableContainerOptions for tables,
  # ruleContainerOptions for rules, elementContainerOptions for elements) are
  # built from the same core.

  identityCore = {
    family = mkOption {
      type = familyType;
      description = "table family";
    };
    handle = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "kernel-assigned handle (delete-by-handle only on input)";
    };
  };

  # Tables have no `table` field of their own.
  tableContainerOptions = identityCore // {
    name = mkOption {
      type = types.str;
      description = "table name";
    };
  };

  # Objects nested inside a table; no `name` of their own (rules use `chain`).
  inTableOptions = identityCore // {
    table = mkOption {
      type = types.str;
      description = "containing table";
    };
  };

  # The common case: in a table, has a name.
  namedInTableOptions = inTableOptions // {
    name = mkOption {
      type = types.str;
      description = "object name";
    };
  };

  # Rules have `chain` instead of `name`.
  ruleContainerOptions = inTableOptions // {
    chain = mkOption {
      type = types.str;
      description = "containing chain";
    };
  };

  # Elements have no `handle` field on the JSON path.
  elementContainerOptions = removeAttrs namedInTableOptions [ "handle" ];

  commentOption = {
    comment = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "free-form object comment";
    };
  };

  # Used by every named object (counter/quota/limit/ct helper/ct timeout/ct
  # expectation/secmark/synproxy/tunnel) — the original `commonObjectOptions`.
  commonObjectOptions = namedInTableOptions // commentOption;

  # Shared by sets and maps (parser_json.c:3307-3436 — both routed to
  # json_parse_cmd_add_set, the only difference is the `map` field).
  setMapCommonOptions = namedInTableOptions // {
    type = mkOption {
      type = setDatatype;
      description = "set datatype";
    };
    policy = mkOption {
      type = types.nullOr setPolicyType;
      default = null;
      description = "set policy";
    };
    flags = mkOption {
      type = types.nullOr (listOrSingleton setFlagType);
      default = null;
      description = "set flags";
    };
    elem = mkOption {
      type = types.nullOr setElem;
      default = null;
      description = "initial elements";
    };
    timeout = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "element timeout in seconds";
    };
    "gc-interval" = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "GC interval in seconds";
    };
    size = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "maximum number of elements";
    };
    "auto-merge" = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "auto-merge adjacent intervals";
    };
    stmt = mkOption {
      type = types.nullOr (types.listOf stmt);
      default = null;
      description = "stateful statements (counter/limit/quota/…) attached to elements";
    };
  };

  bodies = rec {
    tableBody = types.submodule {
      options = tableContainerOptions // {
        flags = mkOption {
          type = types.nullOr (listOrSingleton tableFlagType);
          default = null;
          description = "table flags";
        };
      } // commentOption;
    };

    chainBody = types.submodule {
      options = namedInTableOptions // {
        newname = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "new name (rename command only)";
        };
        type = mkOption {
          type = types.nullOr chainTypeType;
          default = null;
          description = "base chain type (required for base chains)";
        };
        hook = mkOption {
          type = types.nullOr hookType;
          default = null;
          description = "hook point (required for base chains)";
        };
        prio = mkOption {
          type = types.nullOr types.int;
          default = null;
          description = "priority (required for base chains)";
        };
        dev = mkOption {
          # parser_json.c:3143 → json_parse_devs accepts string | [string].
          type = types.nullOr (listOrSingleton types.str);
          default = null;
          description = "bound interface(s) for netdev-family base chains";
        };
        policy = mkOption {
          type = types.nullOr policyType;
          default = null;
          description = "default policy for base chains";
        };
      } // commentOption;
    };

    ruleBody = types.submodule {
      options = ruleContainerOptions // {
        expr = mkOption {
          type = types.listOf stmt;
          description = "rule body — list of statements";
        };
        index = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "rule index";
        };
      } // commentOption;
    };

    setObjectBody = types.submodule {
      options = setMapCommonOptions;
    };

    mapObjectBody = types.submodule {
      options = setMapCommonOptions // {
        # Override `type`'s description: same shape, slightly different intent.
        type = mkOption {
          type = setDatatype;
          description = "map key datatype";
        };
        map = mkOption {
          # parser_json.c:3365 accepts a string (either object-type name like
          # "counter" or datatype) OR a dtype expression (list/typeof).
          type = setDatatype;
          description = "map value datatype or object-type name";
        };
      };
    };

    elementBody = types.submodule {
      options = elementContainerOptions // {
        elem = mkOption {
          type = setElem;
          description = "element(s)";
        };
      };
    };

    flowtableBody = types.submodule {
      options = namedInTableOptions // {
        hook = mkOption {
          type = types.nullOr hookType;
          default = null;
          description = "hook point";
        };
        prio = mkOption {
          type = types.nullOr types.int;
          default = null;
          description = "priority";
        };
        dev = mkOption {
          type = types.nullOr (listOrSingleton types.str);
          default = null;
          description = "bound interface(s)";
        };
      };
    };

    counterObjectBody = types.submodule {
      options = commonObjectOptions // {
        packets = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "packet counter value";
        };
        bytes = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "byte counter value";
        };
      };
    };

    quotaObjectBody = types.submodule {
      options = commonObjectOptions // {
        # parser_json.c:3761: bytes is `json_unpack` (optional, defaults to 0).
        bytes = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "quota threshold in bytes";
        };
        used = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "bytes used so far";
        };
        inv = mkOption {
          type = types.nullOr types.bool;
          default = null;
          description = "invert match semantics";
        };
      };
    };

    ctHelperObjectBody = types.submodule {
      # All fields optional per parser_json.c:3782-3809 (all json_unpack, no _err).
      options = commonObjectOptions // {
        type = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "helper type (e.g. ftp, tftp)";
        };
        protocol = mkOption {
          type = types.nullOr ctHelperProtoType;
          default = null;
          description = "layer-4 protocol (tcp/udp)";
        };
        l3proto = mkOption {
          type = types.nullOr rtFamilyType;
          default = null;
          description = "layer-3 protocol";
        };
      };
    };

    limitObjectBody = types.submodule {
      options = commonObjectOptions // {
        # parser_json.c:3863: rate AND per are required together.
        rate = mkOption {
          type = types.ints.positive;
          description = "rate value";
        };
        per = mkOption {
          type = perUnitType;
          description = "time unit";
        };
        rate_unit = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "unit of rate (packets/kbytes/mbytes/…); defaults to packets";
        };
        burst = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "burst value; defaults to 0";
        };
        burst_unit = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "unit of burst; defaults to bytes";
        };
        inv = mkOption {
          type = types.nullOr types.bool;
          default = null;
          description = "invert match semantics";
        };
      };
    };

    # ct timeout object: parser_json.c:3811-3833 — all fields optional on JSON path.
    ctTimeoutObjectBody = types.submodule {
      options = commonObjectOptions // {
        protocol = mkOption {
          type = types.nullOr ctTimeoutProtoType;
          default = null;
          description = "layer-4 protocol (tcp/udp)";
        };
        l3proto = mkOption {
          type = types.nullOr rtFamilyType;
          default = null;
          description = "layer-3 protocol";
        };
        policy = mkOption {
          type = types.nullOr (types.attrsOf types.ints.unsigned);
          default = null;
          description = "connection-state → timeout-seconds (e.g. { established = 300; })";
        };
      };
    };

    # ct expectation object: parser_json.c:3835-3860 — all fields optional on JSON path.
    ctExpectationObjectBody = types.submodule {
      options = commonObjectOptions // {
        l3proto = mkOption {
          type = types.nullOr rtFamilyType;
          default = null;
          description = "layer-3 protocol";
        };
        protocol = mkOption {
          type = types.nullOr ctTimeoutProtoType;
          default = null;
          description = "layer-4 protocol (tcp/udp)";
        };
        dport = mkOption {
          type = types.nullOr portNumber;
          default = null;
          description = "destination port of expected connection";
        };
        timeout = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "expectation lifetime in milliseconds";
        };
        size = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "maximum concurrent expectations";
        };
      };
    };

    metainfoBody = types.submodule {
      options = {
        version = mkOption {
          type = types.str;
          description = "library version";
        };
        release_name = mkOption {
          type = types.str;
          description = "release name";
        };
        json_schema_version = mkOption {
          type = types.ints.unsigned;
          description = "schema version integer";
        };
      };
    };

    secmarkObjectBody = types.submodule {
      options = commonObjectOptions // {
        # parser_json.c:3769: context is json_unpack (optional).
        context = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "SELinux security context (max 256 chars)";
        };
      };
    };

    synproxyObjectBody = types.submodule {
      options = commonObjectOptions // {
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

    # --- Tunnel nested encapsulation variants ---
    # VXLAN: { gbp: <uint> }
    tunnelVxlanNested = discriminatedSubmodule {
      requireKeys = [ "gbp" ];
      forbidKeys = [ "version" ];
      options.gbp = mkOption {
        type = types.ints.unsigned;
        description = "VXLAN group-based policy ID";
      };
    };

    # ERSPAN v1: { version: 1, index: <uint> }
    tunnelErspanV1Nested = discriminatedSubmodule {
      extraCheck = v: (v.version or null) == 1;
      options = {
        version = mkOption {
          type = types.enum [ 1 ];
          description = "ERSPAN version (1)";
        };
        index = mkOption {
          type = types.ints.unsigned;
          description = "ERSPAN index";
        };
      };
    };

    # ERSPAN v2: { version: 2, dir: "ingress"|"egress", hwid: <uint> }
    tunnelErspanV2Nested = discriminatedSubmodule {
      extraCheck = v: (v.version or null) == 2;
      options = {
        version = mkOption {
          type = types.enum [ 2 ];
          description = "ERSPAN version (2)";
        };
        dir = mkOption {
          type = types.enum [
            "ingress"
            "egress"
          ];
          description = "capture direction";
        };
        hwid = mkOption {
          type = types.ints.unsigned;
          description = "hardware ID";
        };
      };
    };

    # GENEVE: [ { class, opt-type, data }, … ]
    tunnelGeneveOpt = types.submodule {
      options = {
        class = mkOption {
          type = types.ints.unsigned;
          description = "Geneve option class";
        };
        "opt-type" = mkOption {
          type = types.ints.unsigned;
          description = "Geneve option type";
        };
        data = mkOption {
          type = types.str;
          description = "Geneve option data (hex string)";
        };
      };
    };

    tunnelNestedBody = types.oneOf [
      tunnelVxlanNested
      tunnelErspanV1Nested
      tunnelErspanV2Nested
      (types.listOf tunnelGeneveOpt)
    ];

    tunnelTypeType = types.enum [
      "vxlan"
      "erspan"
      "geneve"
    ];

    # Tunnel named object.
    tunnelObjectBody = types.submodule {
      options = commonObjectOptions // {
        id = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "tunnel id";
        };
        "src-ipv4" = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "IPv4 source address";
        };
        "src-ipv6" = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "IPv6 source address";
        };
        "dst-ipv4" = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "IPv4 destination address";
        };
        "dst-ipv6" = mkOption {
          type = types.nullOr expr;
          default = null;
          description = "IPv6 destination address";
        };
        sport = mkOption {
          type = types.nullOr portNumber;
          default = null;
          description = "source port";
        };
        dport = mkOption {
          type = types.nullOr portNumber;
          default = null;
          description = "destination port";
        };
        ttl = mkOption {
          type = types.nullOr (types.ints.between 0 255);
          default = null;
          description = "IP TTL";
        };
        tos = mkOption {
          type = types.nullOr (types.ints.between 0 255);
          default = null;
          description = "IP TOS";
        };
        type = mkOption {
          type = types.nullOr tunnelTypeType;
          default = null;
          description = "tunnel encapsulation (vxlan/erspan/geneve)";
        };
        tunnel = mkOption {
          type = types.nullOr tunnelNestedBody;
          default = null;
          description = "encapsulation-specific nested parameters (shape depends on `type`)";
        };
      };
    };

    # `ruleset` body is `null` (operate on all) OR `{ family = "ip"; }`.
    rulesetBody = types.oneOf [
      nullType
      (types.submodule {
        options.family = mkOption {
          type = familyType;
          description = "limit scope to this family";
        };
      })
    ];

    # Meter object body: meters are anonymous sets internally
    # (parser_json.c routes meter to json_parse_cmd_add_set), so the
    # only fields meaningful for a `flush meter` / `list meter` command
    # are family + table + name (+ handle on listed output).
    meterObjectBody = types.submodule {
      options = namedInTableOptions;
    };
  };

  # Single-tag wrappers for each object kind (convenience).
  wrappers = {
    table = wrap "table" bodies.tableBody;
    chain = wrap "chain" bodies.chainBody;
    rule = wrap "rule" bodies.ruleBody;
    set = wrap "set" bodies.setObjectBody;
    map = wrap "map" bodies.mapObjectBody;
    element = wrap "element" bodies.elementBody;
    flowtable = wrap "flowtable" bodies.flowtableBody;
    counter = wrap "counter" bodies.counterObjectBody;
    quota = wrap "quota" bodies.quotaObjectBody;
    ctHelper = wrap "ct helper" bodies.ctHelperObjectBody;
    limit = wrap "limit" bodies.limitObjectBody;
    ctTimeout = wrap "ct timeout" bodies.ctTimeoutObjectBody;
    ctExpectation = wrap "ct expectation" bodies.ctExpectationObjectBody;
    secmark = wrap "secmark" bodies.secmarkObjectBody;
    synproxy = wrap "synproxy" bodies.synproxyObjectBody;
    tunnel = wrap "tunnel" bodies.tunnelObjectBody;
    metainfo = wrap "metainfo" bodies.metainfoBody;
    ruleset = wrap "ruleset" bodies.rulesetBody;
  };

  addObjectBodies = {
    table = bodies.tableBody;
    chain = bodies.chainBody;
    rule = bodies.ruleBody;
    set = bodies.setObjectBody;
    map = bodies.mapObjectBody;
    element = bodies.elementBody;
    flowtable = bodies.flowtableBody;
    counter = bodies.counterObjectBody;
    quota = bodies.quotaObjectBody;
    "ct helper" = bodies.ctHelperObjectBody;
    limit = bodies.limitObjectBody;
    "ct timeout" = bodies.ctTimeoutObjectBody;
    "ct expectation" = bodies.ctExpectationObjectBody;
    secmark = bodies.secmarkObjectBody;
    synproxy = bodies.synproxyObjectBody;
    tunnel = bodies.tunnelObjectBody;
  };

  addObject = types.attrTag (lib.mapAttrs (_: tagOpt) addObjectBodies);

  listObject = types.attrTag (
    lib.mapAttrs (_: tagOpt) (addObjectBodies // { metainfo = bodies.metainfoBody; })
  );

  # parser_json.c:4297-4304 (json_parse_cmd_flush dispatch table):
  # table, chain, set, map, meter, ruleset. `flowtable` is intentionally
  # absent — the parser rejects `flush flowtable` ("Unknown object passed
  # to flush command.").
  flushObject = types.attrTag (
    lib.mapAttrs (_: tagOpt) {
      table = bodies.tableBody;
      chain = bodies.chainBody;
      set = bodies.setObjectBody;
      map = bodies.mapObjectBody;
      meter = bodies.meterObjectBody;
      ruleset = bodies.rulesetBody;
    }
  );

  resetObject = types.attrTag (
    lib.mapAttrs (_: tagOpt) {
      counter = bodies.counterObjectBody;
      quota = bodies.quotaObjectBody;
      rule = bodies.ruleBody;
      set = bodies.setObjectBody;
      map = bodies.mapObjectBody;
      element = bodies.elementBody;
    }
  );
in
{
  all = bodies // wrappers;
  inherit
    addObject
    listObject
    flushObject
    resetObject
    ;
}
