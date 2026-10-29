{
  lib,
  internal,
  primitives,
  expressions,
  statements,
}:

let
  inherit (lib) mkOption types;
  inherit (internal)
    discriminatedSubmodule
    submodule
    taggedUnion
    wrap
    ;
  inherit (primitives) listOrSingleton;
  inherit (primitives.types)
    byteUnit
    chainPolicy
    chainType
    comment
    ctL3Protocol
    family
    hook
    ifname
    limitRateUnit
    nullLiteral
    portNumber
    setFlag
    setPolicy
    synproxyFlag
    tableFlag
    tcpUdpProtocol
    timeUnit
    tunnelErspanDirection
    tunnelType
    ;
  expr = expressions.expression;
  stmt = statements.statement;

  # Set/map datatype: string, list of strings, or { typeof = EXPRESSION; }.
  typeofBody = submodule {
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

  # `options` with each option in `names` made optional (null by default).
  # A selection body uses it for the fields its add body requires but nft's
  # JSON parser ignores for the selecting verbs.
  withOptional =
    names: options:
    options
    // lib.genAttrs names (
      name:
      options.${name}
      // {
        type = types.nullOr options.${name}.type;
        default = null;
      }
    );

  # ----- Identity-options fragments -----
  # Composable building blocks for the family/table/name/handle/comment fields
  # that appear (in slightly different combinations) on every object kind.
  # Composition: identityCore ⊂ inTableOptions ⊂ namedInTableOptions ⊂
  # commonObjectOptions. Specialised shapes (tableContainerOptions for tables,
  # ruleContainerOptions for rules, elementContainerOptions for elements) are
  # built from the same core.

  identityCore = {
    family = mkOption {
      type = family;
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
      # See `comment` in lib/schema/primitives.nix for the
      # character-set / length constraints (security-critical: nft has no
      # string-escape syntax, so '"' / '\' / control chars in the rendered
      # text inject statements or corrupt the output).
      type = types.nullOr comment;
      default = null;
      description = "free-form object comment";
    };
  };

  # Used by every named object (counter/quota/limit/ct helper/ct timeout/ct
  # expectation/ct count/secmark/synproxy/tunnel).
  commonObjectOptions = namedInTableOptions // commentOption;

  # Shared by sets and maps (parser_json.c:3307-3436 — both routed to
  # json_parse_cmd_add_set, the only difference is the `map` field).
  # A comment is a Read-back shape: nft's JSON parser ignores it.
  setMapCommonOptions = namedInTableOptions // {
    inherit (commentOption) comment;
    type = mkOption {
      type = setDatatype;
      description = "set datatype";
    };
    policy = mkOption {
      type = types.nullOr setPolicy;
      default = null;
      description = "set policy";
    };
    flags = mkOption {
      type = types.nullOr (listOrSingleton setFlag);
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
      description = ''
        stateful statements (counter/limit/quota/…) attached to elements
      '';
    };
  };

  mapOptions = setMapCommonOptions // {
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

  limitOptions = commonObjectOptions // {
    # parser_json.c:3863: rate AND per are required together.
    rate = mkOption {
      type = types.ints.positive;
      description = "rate value";
    };
    per = mkOption {
      type = timeUnit;
      description = "time unit";
    };
    rate_unit = mkOption {
      type = types.nullOr limitRateUnit;
      default = null;
      description = "unit of rate; defaults to packets";
    };
    burst = mkOption {
      type = types.nullOr types.ints.unsigned;
      default = null;
      description = "burst value; defaults to 0";
    };
    burst_unit = mkOption {
      type = types.nullOr byteUnit;
      default = null;
      description = ''
        unit of a byte rate's burst; defaults to bytes. nft ignores it on
        a packet-rate limit
      '';
    };
    inv = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "invert match semantics";
    };
  };

  synproxyOptions = commonObjectOptions // {
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

  flowtableOptions = namedInTableOptions // {
    hook = mkOption {
      type = hook;
      description = "hook point";
    };
    prio = mkOption {
      type = types.int;
      description = "priority";
    };
    dev = mkOption {
      # Each device is an interface name, as in chainBody.dev.
      type = types.nullOr (listOrSingleton ifname);
      default = null;
      description = "bound interface(s)";
    };
  };

  ruleOptions =
    ruleContainerOptions
    // {
      expr = mkOption {
        type = types.listOf stmt;
        description = "rule body — list of statements";
      };
      index = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = "rule index";
      };
    }
    // commentOption;

  /*
    nft reads a `handle` only in Read-back, in a Selector, and in `insert`
    and `replace` rule; it ignores one on `add`, `create`, and `rename`
    (ADR 0009). `inputBody kind args` is the body of such a command, as
    `discriminatedSubmodule args` without the `handle` that `args.options`
    declares. A value with a handle fails, and the error's description
    points to Read-back.
  */
  inputBody =
    kind: args:
    discriminatedSubmodule (
      args
      // {
        options = removeAttrs args.options [ "handle" ];
        forbidKeys = [ "handle" ];
        description =
          if args ? description then
            "${args.description}, and without a handle, ${handleRejection}"
          else
            "${kind} body without a handle, ${handleRejection}";
      }
    );
  handleRejection = "which nft ignores on add, create, and rename; a handle appears in Read-back, where nft lists it";

  /*
    `listedBody description body`: the input body `body` as Read-back
    lists it, with the handle nft assigned. A value fails as `body` fails
    without its handle, and `description`, if not null, names the check.
    The selecting verbs take it too, for the kinds without a Selector body.
  */
  listedBody =
    description: body:
    let
      check = v: builtins.isAttrs v && body.check (removeAttrs v [ "handle" ]);
      withCheck =
        submodule:
        types.addCheck submodule check
        // {
          substSubModules = modules: withCheck (submodule.substSubModules modules);
        }
        // lib.optionalAttrs (description != null) { inherit description; };
    in
    withCheck (
      types.submoduleWith {
        shorthandOnlyDefinesConfig = true;
        modules = body.getSubModules ++ [ { options = { inherit (identityCore) handle; }; } ];
      }
    );

  chainPlacementDescription = "chain body with type, hook and prio all set (a base chain) or all unset";

  bodies = rec {
    tableBody = inputBody "table" {
      options =
        tableContainerOptions
        // {
          flags = mkOption {
            type = types.nullOr (listOrSingleton tableFlag);
            default = null;
            description = "table flags";
          };
        }
        // commentOption;
    };

    /*
      nft's chain parser reads `type`, `hook` and `prio` as one optional
      group: a chain missing any of them loads as a regular chain whose
      rules never see packets. So a chain sets all three (a base chain) or
      none, which is stricter than the parser: a Known difference (ADR
      0010).
    */
    chainBody = inputBody "chain" {
      extraCheck =
        body:
        let
          setPlacementFields = builtins.filter (field: (body.${field} or null) != null) [
            "type"
            "hook"
            "prio"
          ];
        in
        setPlacementFields == [ ] || builtins.length setPlacementFields == 3;
      description = chainPlacementDescription;
      options =
        namedInTableOptions
        // {
          type = mkOption {
            type = types.nullOr chainType;
            default = null;
            description = "base chain type (with hook and prio)";
          };
          hook = mkOption {
            type = types.nullOr hook;
            default = null;
            description = "hook point (with type and prio)";
          };
          prio = mkOption {
            type = types.nullOr types.int;
            default = null;
            description = "priority (with type and hook)";
          };
          dev = mkOption {
            # parser_json.c:3143 → json_parse_devs accepts string | [string].
            # Each device is an interface name (lib/nft-safe-ifname.nix).
            type = types.nullOr (listOrSingleton ifname);
            default = null;
            description = "bound interface(s) for netdev-family base chains";
          };
          policy = mkOption {
            type = types.nullOr chainPolicy;
            default = null;
            description = "default policy for base chains";
          };
        }
        // commentOption;
    };

    # `rename chain` (parser_json.c, json_parse_cmd_rename) reads only
    # these four fields, and requires each.
    renameChainBody = inputBody "rename chain" {
      options = namedInTableOptions // {
        newname = mkOption {
          type = types.str;
          description = "new chain name";
        };
      };
    };

    # A listed rule, as Read-back emits it, with the `handle` nft assigned.
    ruleBody = submodule {
      options = ruleOptions;
    };

    # `insert rule` puts the rule before the rule with `handle`, at `index`,
    # or, with neither, first in the chain.
    insertRuleBody = submodule {
      options = ruleOptions;
    };

    # `add rule` takes no handle: nft 1.1.6's JSON parser ignores one and
    # appends the rule, while 1.1.7 and text read it as a position (a Known
    # difference, ADR 0010). `index` places the rule.
    addRuleBody = inputBody "rule" {
      options = ruleOptions;
    };

    # `replace rule` (parser_json.c, json_parse_cmd_replace) needs the
    # handle of the rule it replaces, and takes handle 0 as missing ("Handle
    # is required when replacing a rule.").
    replaceRuleBody = submodule {
      options = ruleOptions // {
        handle = mkOption {
          type = types.ints.positive;
          description = "handle of the rule to replace";
        };
      };
    };

    setBody = inputBody "set" {
      options = setMapCommonOptions;
    };

    mapBody = inputBody "map" {
      options = mapOptions;
    };

    elementBody = submodule {
      options = elementContainerOptions // {
        elem = mkOption {
          type = setElem;
          description = "element(s)";
        };
      };
    };

    # `add` and `create` require `hook` and `prio` (parser_json.c,
    # json_parse_cmd_add_flowtable).
    flowtableBody = inputBody "flowtable" {
      options = flowtableOptions;
    };

    /*
      Selection bodies, for the verbs that select an existing object:
      delete, destroy, list, flush, and reset. nft's JSON parser reads
      only the family, table, and name (or handle) for these verbs
      (parser_json.c, json_parse_cmd_add_set, json_parse_cmd_add_object,
      json_parse_cmd_add_flowtable), so the fields adding one requires
      are optional here.
    */
    selectFlowtableBody = submodule {
      options = withOptional [ "hook" "prio" ] flowtableOptions;
    };
    selectSetBody = submodule {
      options = withOptional [ "type" ] setMapCommonOptions;
    };
    selectMapBody = submodule {
      options = withOptional [ "type" "map" ] mapOptions;
    };
    selectLimitBody = submodule {
      options = withOptional [ "rate" "per" ] limitOptions;
    };
    selectSynproxyBody = submodule {
      options = withOptional [ "mss" "wscale" ] synproxyOptions;
    };

    /*
      A rule is selected by its chain and handle (json_parse_cmd_add_rule,
      json_parse_cmd_reset_rule). nft takes handle 0 as no handle, and the
      kernel then deletes every rule in the chain, so the handle is
      positive. nft ignores `expr` here, but `destroy` requires the key.
    */
    selectRuleBody = submodule {
      options = ruleOptions // {
        handle = mkOption {
          type = types.ints.positive;
          description = "handle of the selected rule";
        };
      };
    };

    counterBody = inputBody "counter" {
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

    quotaBody = inputBody "quota" {
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

    # Named connection-count limit (nftables 1.1.7+, NFT_OBJECT_CONNLIMIT).
    # parser_json.c json_parse_cmd_add_object: `val` is required, `inv`
    # optional.
    ctCountBody = inputBody "ct count" {
      options = commonObjectOptions // {
        val = mkOption {
          type = types.ints.unsigned;
          description = "connection count threshold";
        };
        inv = mkOption {
          type = types.nullOr types.bool;
          default = null;
          description = "match above the threshold instead of up to it";
        };
      };
    };

    ctHelperBody = inputBody "ct helper" {
      # All fields optional per parser_json.c:3782-3809 (all json_unpack,
      # no _err).
      options = commonObjectOptions // {
        type = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "helper type (e.g. ftp, tftp)";
        };
        protocol = mkOption {
          type = types.nullOr tcpUdpProtocol;
          default = null;
          description = "layer-4 protocol (tcp/udp)";
        };
        l3proto = mkOption {
          type = types.nullOr ctL3Protocol;
          default = null;
          description = "layer-3 protocol";
        };
      };
    };

    limitBody = inputBody "limit" {
      options = limitOptions;
    };

    # ct timeout object: parser_json.c:3811-3833 — all fields optional on
    # the JSON path.
    ctTimeoutBody = inputBody "ct timeout" {
      options = commonObjectOptions // {
        protocol = mkOption {
          type = types.nullOr tcpUdpProtocol;
          default = null;
          description = "layer-4 protocol (tcp/udp)";
        };
        l3proto = mkOption {
          type = types.nullOr ctL3Protocol;
          default = null;
          description = "layer-3 protocol";
        };
        policy = mkOption {
          type = types.nullOr (types.attrsOf types.ints.unsigned);
          default = null;
          description = ''
            connection-state → timeout-seconds (e.g. { established = 300; })
          '';
        };
      };
    };

    # ct expectation object: parser_json.c:3835-3860 — all fields optional
    # on the JSON path.
    ctExpectationBody = inputBody "ct expectation" {
      options = commonObjectOptions // {
        l3proto = mkOption {
          type = types.nullOr ctL3Protocol;
          default = null;
          # Recent kernels refuse `inet`, and an omitted l3proto in an inet
          # table, with "Address family not supported by protocol".
          description = "layer-3 protocol";
        };
        protocol = mkOption {
          type = types.nullOr tcpUdpProtocol;
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

    metainfoBody = submodule {
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

    secmarkBody = inputBody "secmark" {
      options = commonObjectOptions // {
        # parser_json.c:3769: context is json_unpack (optional).
        context = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "SELinux security context (max 256 chars)";
        };
      };
    };

    synproxyBody = inputBody "synproxy" {
      options = synproxyOptions;
    };

    # --- Tunnel encapsulation variants, the shapes of a tunnel's `tunnel` ---
    # VXLAN: { gbp: <uint> }
    tunnelVxlanBody = discriminatedSubmodule {
      requireKeys = [ "gbp" ];
      forbidKeys = [ "version" ];
      options.gbp = mkOption {
        type = types.ints.unsigned;
        description = "VXLAN group-based policy ID";
      };
    };

    # ERSPAN v1: { version: 1, index: <uint> }
    tunnelErspanV1Body = discriminatedSubmodule {
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
    tunnelErspanV2Body = discriminatedSubmodule {
      extraCheck = v: (v.version or null) == 2;
      options = {
        version = mkOption {
          type = types.enum [ 2 ];
          description = "ERSPAN version (2)";
        };
        dir = mkOption {
          type = tunnelErspanDirection;
          description = "capture direction";
        };
        hwid = mkOption {
          type = types.ints.unsigned;
          description = "hardware ID";
        };
      };
    };

    # GENEVE: [ { class, opt-type, data }, … ]
    tunnelGeneveOptionBody = submodule {
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

    tunnelEncapsulationBody = types.oneOf [
      tunnelVxlanBody
      tunnelErspanV1Body
      tunnelErspanV2Body
      (types.listOf tunnelGeneveOptionBody)
    ];

    tunnelBody = submodule {
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
          type = types.nullOr tunnelType;
          default = null;
          description = "tunnel encapsulation (vxlan/erspan/geneve)";
        };
        tunnel = mkOption {
          type = types.nullOr tunnelEncapsulationBody;
          default = null;
          description = ''
            encapsulation-specific nested parameters (shape depends on `type`)
          '';
        };
      };
    };

    # `ruleset` body is `null` (operate on all) OR `{ family = "ip"; }`.
    flushRulesetBody = types.oneOf [
      nullLiteral
      (submodule {
        options.family = mkOption {
          type = family;
          description = "limit scope to this family";
        };
      })
    ];

    # Meter object body: meters are anonymous sets internally
    # (parser_json.c routes meter to json_parse_cmd_add_set), so the
    # only fields meaningful for a `flush meter` / `list meter` command
    # are family + table + name (+ handle on listed output).
    meterBody = submodule {
      options = namedInTableOptions;
    };
  };

  addObjectBodies = {
    table = bodies.tableBody;
    chain = bodies.chainBody;
    rule = bodies.addRuleBody;
    set = bodies.setBody;
    map = bodies.mapBody;
    element = bodies.elementBody;
    flowtable = bodies.flowtableBody;
    counter = bodies.counterBody;
    quota = bodies.quotaBody;
    "ct helper" = bodies.ctHelperBody;
    limit = bodies.limitBody;
    "ct timeout" = bodies.ctTimeoutBody;
    "ct expectation" = bodies.ctExpectationBody;
    "ct count" = bodies.ctCountBody;
    secmark = bodies.secmarkBody;
    synproxy = bodies.synproxyBody;
  };

  addObject = taggedUnion addObjectBodies;

  # Each add-object kind as Read-back lists it, with the handle nft
  # assigned. A listed rule is `ruleBody`, and an element has no handle.
  listedObjectBodies =
    lib.mapAttrs (kind: listedBody (if kind == "chain" then chainPlacementDescription else null)) (
      removeAttrs addObjectBodies [
        "element"
        "rule"
      ]
    )
    // {
      inherit (addObjectBodies) element;
      rule = bodies.ruleBody;
    };

  # The selection body of each kind whose add body requires fields that
  # the selecting verbs ignore; a union takes the ones it has kinds for,
  # and the listed body, which keeps the handle, for its other add kinds.
  selectBodies = {
    flowtable = bodies.selectFlowtableBody;
    limit = bodies.selectLimitBody;
    map = bodies.selectMapBody;
    rule = bodies.selectRuleBody;
    set = bodies.selectSetBody;
    synproxy = bodies.selectSynproxyBody;
  };
  selecting = lib.mapAttrs (kind: body: selectBodies.${kind} or listedObjectBodies.${kind} or body);

  # `create` accepts every add-object kind except `rule`. nftables rejects
  # `create rule` explicitly; keeping a separate union prevents raw typed
  # commands from accepting a shape that the DSL already omits.
  createObject = taggedUnion (removeAttrs addObjectBodies [ "rule" ]);

  /*
    Kinds whose delete, destroy, or list nft mishandles, so these command
    unions reject them as Known differences (ADR 0010). For delete, list,
    and destroy, the JSON object-command path passes the kernel object
    number as nft's command object type: a ct expectation (9) becomes a
    table, so delete and destroy delete the table and list lists it, and a
    ct timeout (7) becomes a chain, so delete fails and list aborts. nft
    1.1.7 aborts on delete and destroy of a ct count (1.1.6 has no ct count
    object).
  */
  deleteObject = taggedUnion (
    selecting (
      removeAttrs addObjectBodies [
        "ct count"
        "ct expectation"
        "ct timeout"
      ]
    )
  );

  /*
    A bare listed object, the shape `nft -j list` emits: every add-object
    kind plus `metainfo`, `meter`, and `tunnel`. A listed rule keeps its
    `handle`, which nft's JSON parser ignores. A tunnel is Read-back only:
    nft's JSON parser writes its `dport` into `sport` and leaves a missing
    port, `ttl`, or `tos` uninitialised, and nft crashes on delete, destroy,
    and list of one, so no command union accepts it (Known differences,
    ADR 0010).
  */
  readBackObjectBodies = listedObjectBodies // {
    metainfo = bodies.metainfoBody;
    meter = bodies.meterBody;
    tunnel = bodies.tunnelBody;
  };

  readBackObject = taggedUnion readBackObjectBodies;

  /*
    The `list` command (parser_json.c, json_parse_cmd_list): the listed
    kinds (`meter` is singular; the plural list forms are not modelled, see
    docs/spec-coverage.md) minus the mishandled ct timeout, ct
    expectation (see `deleteObject`), and tunnel (see `readBackObjectBodies`).
    nft has no singular `list` of a ct count, element, flowtable, metainfo,
    rule, or synproxy ("Unknown object passed to list command"), so the
    union omits them too (ADR 0009).
  */
  listObject = taggedUnion (
    selecting (
      removeAttrs readBackObjectBodies [
        "ct count"
        "ct expectation"
        "ct timeout"
        "element"
        "flowtable"
        "metainfo"
        "rule"
        "synproxy"
        "tunnel"
      ]
    )
  );

  # parser_json.c:4297-4304 (json_parse_cmd_flush dispatch table):
  # table, chain, set, map, meter, ruleset. `flowtable` is intentionally
  # absent — the parser rejects `flush flowtable` ("Unknown object passed
  # to flush command.").
  flushObject = taggedUnion (selecting {
    table = bodies.tableBody;
    chain = bodies.chainBody;
    set = bodies.setBody;
    map = bodies.mapBody;
    meter = bodies.meterBody;
    ruleset = bodies.flushRulesetBody;
  });

  # `insert` takes only a rule.
  insertObject = wrap "rule" bodies.insertRuleBody;

  # `replace` takes only a rule, and requires its `handle`.
  replaceObject = wrap "rule" bodies.replaceRuleBody;

  # `rename` takes only a chain, and requires its `newname`.
  renameObject = wrap "chain" bodies.renameChainBody;

  resetObject = taggedUnion (selecting {
    counter = bodies.counterBody;
    quota = bodies.quotaBody;
    rule = bodies.ruleBody;
    set = bodies.setBody;
    map = bodies.mapBody;
    element = bodies.elementBody;
  });
in
{
  all = bodies;
  # Internal: each add-object kind's listed body, by JSON tag, for the
  # DSL's selecting builders.
  listed = listedObjectBodies;
  inherit
    addObject
    createObject
    deleteObject
    flushObject
    insertObject
    listObject
    readBackObject
    renameObject
    replaceObject
    resetObject
    ;
}
