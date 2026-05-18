{
  lib,
  internal,
  primitives,
  # Lazy reference to the sibling `statements` module. Only `.statement` is
  # consumed (by `elemBody.stmt`), and the access is deferred until value
  # validation, breaking what would otherwise be a load-order cycle:
  # `statements.nix` already imports from this file (statements consume
  # `expr`), so a direct import in the other direction would deadlock.
  # `lib/default.nix` ties the knot via mutually-recursive let bindings.
  statements,
}:

let
  inherit (lib) types mkOption;
  inherit (internal) discriminatedSubmodule listOfLen listOfMinLen;
  inherit (primitives) listOrSingleton;
  inherit (primitives.types)
    metaKey
    rtKey
    ipFamily
    ctDirection
    ngMode
    fibResult
    fibFlag
    payloadBase
    osfKey
    osfTtl
    socketKey
    xfrmDir
    xfrmKey
    tunnelKey
    nullLiteral
    prefixLength
    nftQuotedString
    ;

  # Fixed-point recursion so bodies and the top-level `expression` type can
  # reference each other. Submodule/oneOf/listOf store their children lazily,
  # so this does not force-evaluate during construction.
  exprs = rec {
    concatBody = types.listOf expression;

    # Anonymous set: expression or list of expressions (mappings are 2-tuples).
    setBody = types.either expression (types.listOf expression);

    mapBody = types.submodule {
      options = {
        key = mkOption {
          type = expression;
          description = "map key expression";
        };
        data = mkOption {
          type = expression;
          description = "map data expression";
        };
      };
    };

    prefixBody = types.submodule {
      options = {
        addr = mkOption {
          type = expression;
          description = "prefix address";
        };
        len = mkOption {
          type = prefixLength;
          description = "prefix length";
        };
      };
    };

    rangeBody = listOfLen 2 expression;

    # Three disjoint payload forms from parser_json.c:660-733:
    #   1. raw:           { base, offset, len }
    #   2. inner-tunnel:  { tunnel, protocol, field }
    #   3. named:         { protocol, field }
    # Discriminated by key presence so `types.oneOf` routes correctly.
    rawPayloadBody = discriminatedSubmodule {
      requireKeys = [
        "base"
        "offset"
        "len"
      ];
      options = {
        base = mkOption {
          type = payloadBase;
          description = "payload base reference";
        };
        offset = mkOption {
          type = types.ints.unsigned;
          description = "bit offset from base";
        };
        len = mkOption {
          type = types.ints.unsigned;
          description = "bit length";
        };
      };
    };

    tunnelPayloadBody = discriminatedSubmodule {
      requireKeys = [
        "tunnel"
        "protocol"
        "field"
      ];
      options = {
        tunnel = mkOption {
          type = types.str;
          description = "inner tunnel protocol (e.g. \"vxlan\", \"geneve\")";
        };
        protocol = mkOption {
          type = types.str;
          description = "inner-header named protocol";
        };
        field = mkOption {
          type = types.str;
          description = "inner-header field name";
        };
      };
    };

    namedPayloadBody = discriminatedSubmodule {
      requireKeys = [
        "protocol"
        "field"
      ];
      forbidKeys = [ "tunnel" ];
      options = {
        protocol = mkOption {
          type = types.str;
          description = "named protocol (e.g. \"tcp\", \"ip\")";
        };
        field = mkOption {
          type = types.str;
          description = "field name (e.g. \"dport\", \"saddr\")";
        };
      };
    };

    payloadBody = types.oneOf [
      rawPayloadBody
      tunnelPayloadBody
      namedPayloadBody
    ];

    exthdrBody = types.submodule {
      options = {
        name = mkOption {
          type = types.str;
          description = "extension header name";
        };
        field = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "field inside header; omit for existence check";
        };
        offset = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "offset (only for rt0)";
        };
      };
    };

    # TCP option has two forms (parser_json.c:745-785):
    #   raw:   { base, offset, len }  — base is tcp option kind (0-255)
    #   named: { name, field? }
    rawTcpOptionBody = discriminatedSubmodule {
      requireKeys = [
        "base"
        "offset"
        "len"
      ];
      options = {
        base = mkOption {
          type = types.ints.between 0 255;
          description = "TCP option kind (0-255)";
        };
        offset = mkOption {
          type = types.ints.unsigned;
          description = "bit offset within the option";
        };
        len = mkOption {
          type = types.ints.unsigned;
          description = "bit length";
        };
      };
    };

    namedTcpOptionBody = discriminatedSubmodule {
      requireKeys = [ "name" ];
      forbidKeys = [ "base" ];
      options = {
        name = mkOption {
          type = types.str;
          description = "TCP option name";
        };
        field = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "TCP option field; omit for existence check";
        };
      };
    };

    tcpOptionBody = types.either rawTcpOptionBody namedTcpOptionBody;

    # IP option (parser_json.c:822): { name, field? }
    ipOptionBody = types.submodule {
      options = {
        name = mkOption {
          type = types.str;
          description = "IP option name";
        };
        field = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "IP option field; omit for existence check";
        };
      };
    };

    sctpChunkBody = types.submodule {
      options = {
        name = mkOption {
          type = types.str;
          description = "SCTP chunk name";
        };
        field = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "SCTP chunk field; omit for existence check";
        };
      };
    };

    dccpOptionBody = types.submodule {
      options.type = mkOption {
        type = types.ints.unsigned;
        description = "DCCP option type number";
      };
    };

    metaBody = types.submodule {
      options.key = mkOption {
        type = metaKey;
        description = "meta key";
      };
    };

    rtBody = types.submodule {
      options = {
        key = mkOption {
          type = rtKey;
          description = "routing data key";
        };
        family = mkOption {
          type = types.nullOr ipFamily;
          default = null;
          description = "address family; defaults to unspecified";
        };
      };
    };

    ctBody = types.submodule {
      options = {
        key = mkOption {
          type = types.str;
          description = "conntrack key (e.g. \"state\", \"saddr\")";
        };
        family = mkOption {
          type = types.nullOr ipFamily;
          default = null;
          description = "address family; required for l3-specific keys";
        };
        dir = mkOption {
          type = types.nullOr ctDirection;
          default = null;
          description = "direction; omit for direction-less keys";
        };
      };
    };

    numgenBody = types.submodule {
      options = {
        mode = mkOption {
          type = ngMode;
          description = "number generator mode";
        };
        mod = mkOption {
          type = types.ints.positive;
          description = "modulus";
        };
        offset = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "offset added to result; defaults to 0";
        };
      };
    };

    jhashBody = types.submodule {
      options = {
        mod = mkOption {
          type = types.ints.positive;
          description = "modulus";
        };
        offset = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "offset; defaults to 0";
        };
        expr = mkOption {
          type = expression;
          description = "expression to hash";
        };
        seed = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "hash seed; defaults to 0";
        };
      };
    };

    symhashBody = types.submodule {
      options = {
        mod = mkOption {
          type = types.ints.positive;
          description = "modulus";
        };
        offset = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "offset; defaults to 0";
        };
      };
    };

    fibBody = types.submodule {
      options = {
        result = mkOption {
          type = fibResult;
          description = "FIB lookup result kind";
        };
        flags = mkOption {
          type = types.nullOr (listOrSingleton fibFlag);
          default = null;
          description = "FIB lookup flags";
        };
      };
    };

    socketBody = types.submodule {
      options.key = mkOption {
        type = socketKey;
        description = "socket key";
      };
    };

    osfBody = types.submodule {
      options = {
        key = mkOption {
          type = osfKey;
          description = "OS fingerprint key";
        };
        ttl = mkOption {
          type = types.nullOr osfTtl;
          default = null;
          description = "TTL matching strategy";
        };
      };
    };

    ipsecBody = types.submodule {
      options = {
        key = mkOption {
          type = xfrmKey;
          description = "xfrm key (saddr/daddr/reqid/spi)";
        };
        family = mkOption {
          type = types.nullOr ipFamily;
          default = null;
          description = "address family (required for saddr/daddr)";
        };
        dir = mkOption {
          type = types.nullOr xfrmDir;
          default = null;
          description = "policy direction (in/out)";
        };
        spnum = mkOption {
          type = types.nullOr (types.ints.between 0 255);
          default = null;
          description = "SA index (0-255)";
        };
      };
    };

    tunnelExprBody = types.submodule {
      options.key = mkOption {
        type = tunnelKey;
        description = "tunnel metadata key (path/id)";
      };
    };

    elemBody = types.submodule {
      options = {
        val = mkOption {
          type = expression;
          description = "element value";
        };
        timeout = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "element timeout in seconds";
        };
        expires = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "remaining time in seconds";
        };
        comment = mkOption {
          type = types.nullOr nftQuotedString;
          default = null;
          description = "element comment";
        };
        # parser_json.c json_parse_set_elem emits a `stmt` array alongside
        # `val`/`timeout`/`expires` for stateful statements (counter/quota/
        # limit/…) attached to the element.
        stmt = mkOption {
          type = types.nullOr (types.listOf statements.statement);
          default = null;
          description = "stateful statements attached to the element";
        };
      };
    };

    verdictTargetBody = types.submodule {
      options.target = mkOption {
        type = types.str;
        description = "target chain name";
      };
    };

    binaryOpBody = listOfMinLen 2 expression;

    /*
      Map of tag → body type. Single source of truth for the private
      `taggedExpression` union (the discriminated `{ <key>: <body> }`
      shape embedded in `expression`) and the public `expressionOf`
      subset helper. Adding a new tag here participates in both.
    */
    expressionBodies = {
      # Compound/structural
      concat = concatBody;
      set = setBody;
      map = mapBody;
      prefix = prefixBody;
      range = rangeBody;
      # Header fields and packet metadata
      payload = payloadBody;
      exthdr = exthdrBody;
      "tcp option" = tcpOptionBody;
      "ip option" = ipOptionBody;
      "sctp chunk" = sctpChunkBody;
      "dccp option" = dccpOptionBody;
      meta = metaBody;
      rt = rtBody;
      ct = ctBody;
      # Generators / derived
      numgen = numgenBody;
      jhash = jhashBody;
      symhash = symhashBody;
      fib = fibBody;
      socket = socketBody;
      osf = osfBody;
      ipsec = ipsecBody;
      tunnel = tunnelExprBody;
      elem = elemBody;
      # Verdicts (valid in vmap data)
      accept = nullLiteral;
      drop = nullLiteral;
      continue = nullLiteral;
      return = nullLiteral;
      jump = verdictTargetBody;
      goto = verdictTargetBody;
      # Binary operators
      "|" = binaryOpBody;
      "^" = binaryOpBody;
      "&" = binaryOpBody;
      "<<" = binaryOpBody;
      ">>" = binaryOpBody;
    };

    # Tagged union of everything represented as `{ <key>: <body> }`.
    taggedExpression = types.attrTag (
      lib.mapAttrs (_: type: mkOption { inherit type; }) expressionBodies
    );

    expression = types.oneOf [
      types.str
      types.int
      types.bool
      (types.listOf expression)
      taggedExpression
    ];

    /*
      `expressionOf : [ String ] -> Type` — restrict an
      `expression`-typed field to a subset of the *tagged* expression
      kinds. Scalars (`str` / `int` / `bool`) and bare expression
      lists, which `expression` accepts as their own oneOf branches,
      are **not** part of the result; consumers that want them on top
      of a tag subset can compose:

        types.oneOf [
          types.str
          (nftypes.types.expressionOf [ "payload" "meta" ])
        ]

      Throws at *type construction* time on unknown kinds so typos
      surface immediately rather than at module evaluation.
    */
    expressionOf =
      kinds:
      let
        valid = lib.attrNames expressionBodies;
        invalid = lib.subtractLists valid kinds;
        renderList = xs: lib.concatMapStringsSep ", " (k: ''"${k}"'') xs;
        base = types.attrTag (
          lib.mapAttrs (_: type: mkOption { inherit type; }) (lib.getAttrs kinds expressionBodies)
        );
      in
      if !(builtins.isList kinds) then
        throw "nftypes.types.expressionOf: argument must be a list of strings"
      else if kinds == [ ] then
        throw "nftypes.types.expressionOf: kinds list must be non-empty"
      else if invalid != [ ] then
        throw (
          "nftypes.types.expressionOf: unknown expression kind(s): "
          + "${renderList invalid}. Valid kinds: ${renderList valid}."
        )
      else
        base
        // {
          description = "tagged expression (one of: ${renderList kinds})";
        };
  };
in
{
  inherit (exprs)
    expression
    taggedExpression
    verdictTargetBody
    expressionOf
    ;
  all = removeAttrs exprs [
    "expression"
    "taggedExpression"
    "expressionBodies"
    "expressionOf"
  ];
}
