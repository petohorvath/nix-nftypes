{
  lib,
  primitives,
  expressions,
  statements,
}:

let
  inherit (lib) types mkOption;
  inherit (primitives) listOrSingleton nullType;
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
    limitUnitType
    perUnitType
    rtFamilyType
    synproxyFlagType
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

  commonObjectOptions = {
    family = mkOption {
      type = familyType;
      description = "table family";
    };
    table = mkOption {
      type = types.str;
      description = "containing table name";
    };
    name = mkOption {
      type = types.str;
      description = "object name";
    };
    handle = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "kernel-assigned handle (delete-by-handle only on input)";
    };
    comment = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "free-form object comment";
    };
  };

  bodies = rec {
    tableBody = types.submodule {
      options = {
        family = mkOption {
          type = familyType;
          description = "table family";
        };
        name = mkOption {
          type = types.str;
          description = "table name";
        };
        handle = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "kernel-assigned handle";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton tableFlagType);
          default = null;
          description = "table flags";
        };
        comment = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "table comment";
        };
      };
    };

    chainBody = types.submodule {
      options = {
        family = mkOption {
          type = familyType;
          description = "table family";
        };
        table = mkOption {
          type = types.str;
          description = "containing table";
        };
        name = mkOption {
          type = types.str;
          description = "chain name";
        };
        newname = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "new name (rename command only)";
        };
        handle = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "kernel-assigned handle";
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
        comment = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "chain comment";
        };
      };
    };

    ruleBody = types.submodule {
      options = {
        family = mkOption {
          type = familyType;
          description = "table family";
        };
        table = mkOption {
          type = types.str;
          description = "containing table";
        };
        chain = mkOption {
          type = types.str;
          description = "containing chain";
        };
        expr = mkOption {
          type = types.listOf stmt;
          description = "rule body — list of statements";
        };
        handle = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "rule handle (for replace/delete, or positioning)";
        };
        index = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "rule index";
        };
        comment = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "rule comment";
        };
      };
    };

    setObjectBody = types.submodule {
      options = {
        family = mkOption {
          type = familyType;
          description = "table family";
        };
        table = mkOption {
          type = types.str;
          description = "containing table";
        };
        name = mkOption {
          type = types.str;
          description = "set name";
        };
        handle = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "kernel-assigned handle";
        };
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
    };

    mapObjectBody = types.submodule {
      options = {
        family = mkOption {
          type = familyType;
          description = "table family";
        };
        table = mkOption {
          type = types.str;
          description = "containing table";
        };
        name = mkOption {
          type = types.str;
          description = "map name";
        };
        handle = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "kernel-assigned handle";
        };
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
        policy = mkOption {
          type = types.nullOr setPolicyType;
          default = null;
          description = "map policy";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton setFlagType);
          default = null;
          description = "map flags";
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
          description = "stateful statements attached to elements";
        };
      };
    };

    elementBody = types.submodule {
      options = {
        family = mkOption {
          type = familyType;
          description = "table family";
        };
        table = mkOption {
          type = types.str;
          description = "containing table";
        };
        name = mkOption {
          type = types.str;
          description = "set/map name";
        };
        elem = mkOption {
          type = setElem;
          description = "element(s)";
        };
      };
    };

    flowtableBody = types.submodule {
      options = {
        family = mkOption {
          type = familyType;
          description = "table family";
        };
        table = mkOption {
          type = types.str;
          description = "containing table";
        };
        name = mkOption {
          type = types.str;
          description = "flowtable name";
        };
        handle = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "kernel-assigned handle";
        };
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
        unit = mkOption {
          type = types.nullOr limitUnitType;
          default = null;
          description = "(derived from rate_unit; kept for symmetry)";
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
          type = types.nullOr primitives.portNumber;
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
    tunnelVxlanNested = types.addCheck (types.submodule {
      options.gbp = mkOption {
        type = types.ints.unsigned;
        description = "VXLAN group-based policy ID";
      };
    }) (v: builtins.isAttrs v && v ? gbp && !(v ? version));

    # ERSPAN v1: { version: 1, index: <uint> }
    tunnelErspanV1Nested = types.addCheck (types.submodule {
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
    }) (v: builtins.isAttrs v && (v.version or null) == 1);

    # ERSPAN v2: { version: 2, dir: "ingress"|"egress", hwid: <uint> }
    tunnelErspanV2Nested = types.addCheck (types.submodule {
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
    }) (v: builtins.isAttrs v && (v.version or null) == 2);

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
          type = types.nullOr primitives.portNumber;
          default = null;
          description = "source port";
        };
        dport = mkOption {
          type = types.nullOr primitives.portNumber;
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
  };

  tagOpt = type: mkOption { inherit type; };

  # Single-tag wrappers for each object kind (convenience).
  wrap = key: body: types.attrTag { ${key} = tagOpt body; };

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

  addObject = types.attrTag (
    lib.mapAttrs (_: tagOpt) {
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
    }
  );

  listObject = types.attrTag (
    lib.mapAttrs (_: tagOpt) {
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
      metainfo = bodies.metainfoBody;
    }
  );

  flushObject = types.attrTag (
    lib.mapAttrs (_: tagOpt) {
      table = bodies.tableBody;
      chain = bodies.chainBody;
      set = bodies.setObjectBody;
      map = bodies.mapObjectBody;
      flowtable = bodies.flowtableBody;
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
