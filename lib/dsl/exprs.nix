/*
  Expression helpers not covered by the pre-built field tree in ./fields/:
  structural and generator expressions (concat, set, map, prefix, range,
  numgen, …), header-option expressions (tcpOption, ipOption, …), and
  constructors for key-string expressions (ct, rt, fib, …) that carry the
  refinements a Field leaf can't. A key-string expression that takes no
  refinement, such as meta or socket, has its leaves only.

  Every constructor but `setRef`, which builds a reference string,
  validates its body when called (./internal/builder.nix), so a wrong
  value, an unknown argument, or a missing one throws naming the
  constructor and the field, as in `dsl.expr.ct.key`. A constructor that
  takes one attrset takes the fields of its body in
  `types.expressionBodies`, and omits a null one.
*/
{
  expression,
  expressionBodies,
  lib,
}:

let
  inherit (import ./internal/location.nix { inherit lib; }) fail;
  reference = import ./internal/reference.nix { inherit lib; };

  # The location of the `expr` constructor `name`.
  exprBuilder = name: expression.locationOf [ name ];

  # The constructor `name` of the binary operator expression `tag`.
  binaryOperator =
    name: tag: a: b:
    expression.tagged { inherit name tag; } [
      a
      b
    ];
in
{
  # -- Structural -----------------------------------------------------------

  /*
    Concatenate expressions into one compound key, such as an
    address-and-port set lookup. `xs` is the list of expressions. Returns a
    concat expression.
  */
  concat = expression.tagged { name = "concat"; };

  /*
    Build an anonymous set literal. `xs` is the list of elements. A bare
    string would render as a one-element set containing that literal, never
    the caller's intent, so it throws and points to `setRef`. Returns a set
    expression.
  */
  set =
    xs:
    if builtins.isString xs then
      fail (exprBuilder "set") "a bare string (${builtins.toJSON xs}) is not an anonymous-set body, which is a list; reference a named set with `expr.setRef ${builtins.toJSON xs}`, or pass \"@${xs}\" to inSet or notInSet"
    else
      expression.tagged { name = "set"; } xs;

  /*
    Reference a named set, as the right side of a match. `name` is the set
    name, with or without the leading `@` that libnftables JSON uses for
    named references. Returns the reference string `"@<name>"`, the shape
    nft lists, and throws when `name` is not a string.
  */
  setRef = reference.atReference (exprBuilder "setRef");

  /*
    Build a map lookup. `key` is the lookup expression and `data` the
    anonymous map body, or a named map's name with or without its leading
    `@`. Returns a map expression whose named map is `"@<name>"`.
  */
  map =
    key: data:
    expression.tagged { name = "map"; } {
      inherit key;
      data = if builtins.isString data then reference.atReference (exprBuilder "map") data else data;
    };

  /*
    Build an address prefix. `addr` is the network address and `len` the
    prefix length. Returns a prefix expression.
  */
  prefix = addr: len: expression.tagged { name = "prefix"; } { inherit addr len; };

  /*
    Build an inclusive range. `lo` and `hi` are the lower and upper bounds.
    Returns a range expression.
  */
  range =
    lo: hi:
    expression.tagged { name = "range"; } [
      lo
      hi
    ];

  /*
    Build a set element with per-element options. Takes `val`, the element
    value, and the optional `timeout`, `expires`, and `comment`. The
    statements nft lists beside an element's value are Read-back only: its
    JSON parser ignores them, so `elem` takes none, and there is no element
    statement either. Returns an elem expression.
  */
  elem = expression.fromFields { name = "elem"; };

  # -- Generators -----------------------------------------------------------

  /*
    Generate a number per packet. Takes `mode`, `"inc"` or `"random"`,
    `mod`, the modulus, and an optional start value, `offset`. Returns a
    numgen expression.
  */
  numgen = expression.fromFields { name = "numgen"; };

  /*
    Hash an expression with jhash. Takes `mod`, the modulus, `expr`, the
    hashed expression, and the optional `offset` and `seed`. Returns a
    jhash expression.
  */
  jhash = expression.fromFields { name = "jhash"; };

  /*
    Hash the packet's symmetric flow tuple. Takes `mod`, the modulus, and
    an optional start value, `offset`. Returns a symhash expression.
  */
  symhash = expression.fromFields { name = "symhash"; };

  # -- Header option / extension escape hatches -----------------------------

  /*
    Reference a TCP option by name. Takes `name`, the option (for example
    `"maxseg"`), and an optional option field, `field`. Returns a
    `tcp option` expression.
  */
  tcpOption = expression.fromFields {
    name = "tcpOption";
    tag = "tcp option";
    type = expressionBodies.tcpOptionNamedBody;
  };

  /*
    Reference raw TCP option bits. Takes `base`, the option kind, and
    `offset` and `len`, which locate the bits. Returns a `tcp option`
    expression.
  */
  tcpOptionRaw = expression.fromFields {
    name = "tcpOptionRaw";
    tag = "tcp option";
    type = expressionBodies.tcpOptionRawBody;
  };

  /*
    Reference an IPv4 option by name. Takes `name`, the option, and an
    optional option field, `field`. Returns an `ip option` expression.
  */
  ipOption = expression.fromFields {
    name = "ipOption";
    tag = "ip option";
  };

  /*
    Reference an SCTP chunk by name. Takes `name`, the chunk type, and an
    optional chunk field, `field`. Returns an `sctp chunk` expression.
  */
  sctpChunk = expression.fromFields {
    name = "sctpChunk";
    tag = "sctp chunk";
  };

  /*
    Test for a DCCP option. `type` is the option type number. Returns a
    `dccp option` expression.
  */
  dccpOption =
    type:
    expression.tagged {
      name = "dccpOption";
      tag = "dccp option";
    } { inherit type; };

  /*
    Reference an IPv6 extension header. Takes `name`, the header, and the
    optional refinements `field` and `offset`. Returns an exthdr
    expression.
  */
  exthdr = expression.fromFields { name = "exthdr"; };

  # -- Refined key-string expressions ---------------------------------------
  # The pre-built field tree covers the keys nft loads bare; these take a
  # key with its refinements (`family`, `dir`, …), and require the ones nft
  # needs.

  /*
    Reference a conntrack key with a direction. Takes `key`, the conntrack
    key, and `dir`, the direction, which nft needs for `saddr`, `daddr`,
    `proto-src`, `proto-dst`, and the `ip` and `ip6` addresses, and takes
    only for these and `l3proto`, `protocol`, `packets`, `bytes`,
    `avgpkt`, and `zone`; the constructor throws otherwise. Returns a ct
    expression.
  */
  ct = expression.fromFields { name = "ct"; };

  /*
    Reference routing data. Takes `key`, the routing key, and an optional
    address family, `family`. Returns an rt expression.
  */
  rt = expression.fromFields { name = "rt"; };

  /*
    Look up the forwarding information base. Takes `result`, the requested
    result (`"oif"`, `"type"`, …), and `flags`, the lookup flags, one or a
    list. nft needs `saddr` or `daddr` among them, so the constructor
    throws without either. Returns a fib expression.
  */
  fib = expression.fromFields { name = "fib"; };

  /*
    Reference passive OS fingerprinting data. Takes `key`, `"name"` or
    `"version"`, and an optional TTL mode, `ttl`. Returns an osf
    expression.
  */
  osf = expression.fromFields { name = "osf"; };

  /*
    Reference IPsec (xfrm) state. Takes `key`, the ipsec key, and `dir`,
    the policy direction, `"in"` or `"out"`, which nft needs for every
    key, so the constructor throws without it; `family` and `spnum` are
    optional refinements. Returns an ipsec expression.
  */
  ipsec = expression.fromFields { name = "ipsec"; };

  # -- Binary operators -----------------------------------------------------

  /*
    Combine two expressions with bitwise OR. `a` and `b` are the operands.
    Returns a `|` expression.
  */
  bitOr = binaryOperator "bitOr" "|";

  /*
    Combine two expressions with bitwise XOR. `a` and `b` are the operands.
    Returns a `^` expression.
  */
  bitXor = binaryOperator "bitXor" "^";

  /*
    Combine two expressions with bitwise AND, typically to mask a value.
    `a` and `b` are the operands. Returns a `&` expression.
  */
  bitAnd = binaryOperator "bitAnd" "&";

  /*
    Shift an expression left. `a` is the value and `b` the shift count.
    Returns a `<<` expression.
  */
  shiftLeft = binaryOperator "shiftLeft" "<<";

  /*
    Shift an expression right. `a` is the value and `b` the shift count.
    Returns a `>>` expression.
  */
  shiftRight = binaryOperator "shiftRight" ">>";
}
