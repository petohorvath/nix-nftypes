{
  lib,
  internal,
  primitives,
  # Lazy reference to the sibling `statements` module. Only
  # `.bodiesByTag` is consumed (by the statement keys of `elemReadBackBody`),
  # and the access is deferred until value validation, breaking what would
  # otherwise be a load-order cycle: `statements.nix` already imports from
  # this file (statements consume `expr`), so a direct import in the other
  # direction would deadlock. `lib/default.nix` ties the knot via
  # mutually-recursive let bindings.
  statements,
}:

let
  inherit (lib) mkOption types;
  inherit (internal)
    discriminatedSubmodule
    listOfLen
    listOfMinLen
    restrictedUnion
    submodule
    taggedUnion
    ;
  inherit (import ../word-list.nix { inherit lib; }) conjoin;
  inherit (primitives) listOrSingleton;
  inherit (primitives.types)
    comment
    ctDirection
    ctKey
    fibFlag
    fibResult
    ipFamily
    ipsecDirection
    ipsecKey
    metaKey
    nullLiteral
    numgenMode
    osfKey
    osfTtl
    payloadBase
    prefixLength
    rtKey
    socketKey
    tunnelKey
    ;

  # The ct keys nft's JSON parser takes a direction for (ct_dir_keys in
  # json_parse_ct_expr); it fails any other with a direction ("Direction
  # not supported by CT key").
  ctDirKeys = [
    "l3proto"
    "saddr"
    "daddr"
    "protocol"
    "proto-src"
    "proto-dst"
    "packets"
    "bytes"
    "avgpkt"
    "zone"
    "ip saddr"
    "ip daddr"
    "ip6 saddr"
    "ip6 daddr"
  ];

  # The ct keys nft loads only with a direction: `nft -c -j` (1.1.7) fails
  # each without one ("Invalid argument").
  ctKeysNeedingDir = [
    "saddr"
    "daddr"
    "proto-src"
    "proto-dst"
    "ip saddr"
    "ip daddr"
    "ip6 saddr"
    "ip6 daddr"
  ];

  # The statements nft lists beside an element's value (json.c
  # set_elem_expr_json).
  elemStatementKeys = [
    "counter"
    "quota"
    "limit"
    "last"
  ];

  /*
    Fixed-point recursion so bodies and the top-level `expression` type can
    reference each other. Submodule/oneOf/listOf store their children
    lazily, so this does not force-evaluate during construction.

    `readBack` picks the body of the `elem` tag. nft lists an element's
    statements wherever the element sits, in a set's or map's elements and
    in a rule's anonymous set alike, and its JSON parser ignores them
    there. So input takes the expressions whose elements use `elemBody`,
    and Read-back the ones whose elements use `elemReadBackBody`.
  */
  exprsWith =
    { readBack }:
    rec {
      concatBody = types.listOf expression;

      # Anonymous set: an expression or a list of them (mappings are
      # 2-tuples).
      setBody = types.either expression (types.listOf expression);

      mapBody = submodule {
        options = {
          key = mkOption {
            type = expression;
            description = "map key expression";
          };
          data = mkOption {
            type = mapDataExpression;
            description = "map data expression";
          };
        };
      };

      prefixBody = submodule {
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
      payloadRawBody = discriminatedSubmodule {
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

      payloadTunnelBody = discriminatedSubmodule {
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

      payloadNamedBody = discriminatedSubmodule {
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
        payloadRawBody
        payloadTunnelBody
        payloadNamedBody
      ];

      exthdrBody = submodule {
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
      tcpOptionRawBody = discriminatedSubmodule {
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

      tcpOptionNamedBody = discriminatedSubmodule {
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

      tcpOptionBody = types.either tcpOptionRawBody tcpOptionNamedBody;

      # IP option (parser_json.c:822): { name, field? }
      ipOptionBody = submodule {
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

      sctpChunkBody = submodule {
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

      dccpOptionBody = submodule {
        options.type = mkOption {
          type = types.ints.unsigned;
          description = "DCCP option type number";
        };
      };

      metaBody = submodule {
        options.key = mkOption {
          type = metaKey;
          description = "meta key";
        };
      };

      rtBody = submodule {
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

      # nft's JSON parser reads no `family` here, and its printer writes
      # none (json_parse_ct_expr, ct_expr_json), so the body has none.
      ctBody = discriminatedSubmodule {
        options = {
          key = mkOption {
            type = ctKey;
            description = "conntrack key";
          };
          dir = mkOption {
            type = types.nullOr ctDirection;
            default = null;
            description = "direction; required for the keys nft loads only with one";
          };
        };
        extraCheck =
          body:
          let
            key = body.key or null;
          in
          if (body.dir or null) != null then
            builtins.elem key ctDirKeys
          else
            !(builtins.elem key ctKeysNeedingDir);
        description = "ct body with dir for ${conjoin "and" ctKeysNeedingDir}, and without dir for a key other than ${conjoin "and" ctDirKeys}";
      };

      numgenBody = submodule {
        options = {
          mode = mkOption {
            type = numgenMode;
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

      jhashBody = submodule {
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

      symhashBody = submodule {
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

      # nft fails a FIB lookup without `saddr` or `daddr` among its flags
      # ("fib: need either saddr or daddr").
      fibBody = discriminatedSubmodule {
        options = {
          result = mkOption {
            type = fibResult;
            description = "FIB lookup result kind";
          };
          flags = mkOption {
            type = types.nullOr (listOrSingleton fibFlag);
            default = null;
            description = "FIB lookup flags; saddr or daddr among them";
          };
        };
        extraCheck =
          body: builtins.any (flag: flag == "saddr" || flag == "daddr") (lib.toList (body.flags or [ ]));
        description = "fib body with saddr or daddr among its flags";
      };

      socketBody = submodule {
        options.key = mkOption {
          type = socketKey;
          description = "socket key";
        };
      };

      osfBody = submodule {
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

      # nft fails every IPsec key without a direction ("Invalid argument").
      ipsecBody = discriminatedSubmodule {
        options = {
          key = mkOption {
            type = ipsecKey;
            description = "IPsec key (saddr/daddr/reqid/spi)";
          };
          family = mkOption {
            type = types.nullOr ipFamily;
            default = null;
            description = "address family (required for saddr/daddr)";
          };
          dir = mkOption {
            type = types.nullOr ipsecDirection;
            default = null;
            description = "policy direction (in/out); required";
          };
          spnum = mkOption {
            type = types.nullOr (types.ints.between 0 255);
            default = null;
            description = "SA index (0-255)";
          };
        };
        extraCheck = body: (body.dir or null) != null;
        description = "ipsec body with dir";
      };

      tunnelBody = submodule {
        options.key = mkOption {
          type = tunnelKey;
          description = "tunnel metadata key (path/id)";
        };
      };

      # The element options nft's JSON parser reads
      # (json_parse_set_elem_expr).
      elemOptions = {
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
          type = types.nullOr comment;
          default = null;
          description = "element comment";
        };
      };

      # An element as input: nft's JSON parser ignores the statements nft
      # lists beside its value, so it takes none.
      elemBody = discriminatedSubmodule {
        options = elemOptions;
        forbidKeys = elemStatementKeys;
        description = "element body without ${conjoin "or" elemStatementKeys}, which nft ignores on JSON input and lists in Read-back";
      };

      # An element as Read-back lists it, with the statements nft lists as
      # keys beside `val`. The text renderer refuses them, as text would
      # load them.
      elemReadBackBody = submodule {
        options =
          elemOptions
          // lib.genAttrs elemStatementKeys (
            tag:
            mkOption {
              type = types.nullOr statements.bodiesByTag.${tag};
              default = null;
              description = "element ${tag} statement, as nft lists it";
            }
          );
      };

      verdictTargetBody = submodule {
        options.target = mkOption {
          type = types.str;
          description = "target chain name";
        };
      };

      binaryOperationBody = listOfMinLen 2 expression;

      /*
        Map of tag → body type. Single source of truth for the private
        `taggedExpression` union (the discriminated `{ <key>: <body> }`
        shape embedded in `expression`) and the public `expressionOf`
        Restricted type helper. Adding a new tag here participates in both.
      */
      bodiesByTag = {
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
        tunnel = tunnelBody;
        elem = if readBack then elemReadBackBody else elemBody;
        # Verdicts (valid in vmap data)
        accept = nullLiteral;
        drop = nullLiteral;
        continue = nullLiteral;
        return = nullLiteral;
        jump = verdictTargetBody;
        goto = verdictTargetBody;
        # Binary operators
        "|" = binaryOperationBody;
        "^" = binaryOperationBody;
        "&" = binaryOperationBody;
        "<<" = binaryOperationBody;
        ">>" = binaryOperationBody;
      };

      # Tagged union of everything represented as `{ <key>: <body> }`.
      taggedExpression = taggedUnion bodiesByTag;

      /*
        A string expression. nft's JSON parser reads `10.0.0.0/8` as a
        hostname and rejects it, while text loads it as a prefix, so a
        string takes no `/` unless it is a `@name` reference, whose name
        may contain one. A prefix is a prefix expression.
      */
      expressionString = types.addCheck types.str (s: lib.hasPrefix "@" s || !lib.hasInfix "/" s) // {
        description = "string without `/`";
      };

      # The generated description names each branch's description, and
      # the list branch's names `expression` again, so a type error on a
      # wrong value recursed without end; this one stops there.
      expression =
        types.oneOf [
          expressionString
          types.int
          types.bool
          (types.listOf expression)
          taggedExpression
        ]
        // {
          description = "nft expression (string without `/`, integer, boolean, list of expressions, or tagged expression; write a prefix as { prefix = { addr; len; }; }, which dsl.expr.prefix builds)";
        };

      # The data of a map lookup or a vmap: an expression, but not a bare
      # list, which nft rejects there ("invalid mapping expression list").
      mapDataExpression =
        types.oneOf [
          expressionString
          types.int
          types.bool
          taggedExpression
        ]
        // {
          description = "map data expression (a named map's \"@name\" or an anonymous map { set = [ … ]; }, not a bare list)";
        };

      /*
        `expressionOf : [ String ] -> Type` — restrict an
        `expression`-typed field to chosen *tagged* expression tags, a
        Restricted type. Scalars (`str` / `int` / `bool`) and bare
        expression lists, which `expression` accepts as their own oneOf
        branches, are **not** part of the result; consumers that want them
        on top of the chosen tags can compose:

          types.oneOf [
            types.str
            (nftlib.types.expressionOf [ "payload" "meta" ])
          ]

        `tags` is a non-empty list of tag names from the `expression`
        union. Returns a `types.attrTag` of those tags whose description
        names them. Throws at *type construction* time on unknown tags so
        typos surface immediately rather than at module evaluation.
      */
      expressionOf = restrictedUnion {
        api = "types.expressionOf";
        noun = "expression";
        label = "tagged expression";
        inherit bodiesByTag;
      };
    };

  exprs = exprsWith { readBack = false; };
  readBackExprs = exprsWith { readBack = true; };
in
{
  inherit (exprs)
    bodiesByTag
    expression
    expressionOf
    mapDataExpression
    verdictTargetBody
    ;
  # Internal: the expressions Read-back lists, whose elements take
  # `elemReadBackBody`, for the Read-back statements and objects.
  readBack = {
    inherit (readBackExprs)
      bodiesByTag
      expression
      expressionOf
      mapDataExpression
      verdictTargetBody
      ;
  };
  all = removeAttrs exprs [
    "bodiesByTag"
    "elemOptions"
    "expression"
    "expressionOf"
    "expressionString"
    "mapDataExpression"
    "taggedExpression"
  ];
}
