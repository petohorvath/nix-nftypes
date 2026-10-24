/*
  Expression helpers not covered by the pre-built field tree in ./fields/:
  structural and generator expressions (concat, set, map, prefix, range,
  numgen, …), header-option expressions (tcpOption, ipOption, …), and
  constructors for key-string expressions (ct, rt, fib, …) that carry the
  refinements a Field leaf can't. A key-string expression that takes no
  refinement, such as meta or socket, has its leaves only.
*/
{ lib }:

let
  compact = import ./internal/compact.nix { inherit lib; };
  location = import ./internal/location.nix { inherit lib; };
  reference = import ./internal/reference.nix { inherit lib; };

  # Throw `message` from the `expr` constructor `name`.
  fail =
    name:
    location.fail (
      location.builder [
        "expr"
        name
      ]
    );
in
{
  # -- Structural -----------------------------------------------------------

  /*
    Concatenate expressions into one compound key, such as an
    address-and-port set lookup. `xs` is the list of expressions. Returns a
    concat expression.
  */
  concat = xs: { concat = xs; };

  /*
    Build an anonymous set literal. `xs` is the list of elements. A bare
    string would render as a one-element set containing that literal, never
    the caller's intent, so it throws and points to `setRef`. Returns a set
    expression.
  */
  set =
    xs:
    if builtins.isString xs then
      throw ''
        nix-nftypes: dsl.expr.set: a bare string ("${xs}") is not a valid anonymous-set body —
        anonymous sets are lists. For a named-set reference, use
        `expr.setRef "${xs}"` (or pass `"@${xs}"` directly to inSet/notInSet).
      ''
    else
      { set = xs; };

  /*
    Reference a named set, as the right side of a match. `name` is the set
    name, with or without the leading `@` that libnftables JSON uses for
    named references. Returns the reference string `"@<name>"`, the shape
    nft lists, and throws when `name` is not a string.
  */
  setRef = reference.atReference "expr.setRef";

  /*
    Build a map lookup. `key` is the lookup expression and `data` the
    anonymous map body, or a named map's name with or without its leading
    `@`. Returns a map expression whose named map is `"@<name>"`.
  */
  map = key: data: {
    map = {
      inherit key;
      data = if builtins.isString data then reference.atReference "expr.map" data else data;
    };
  };

  /*
    Reference a named map, for the data of a map lookup (`map`) or a
    verdict map (`vmap`). `name` is the map name, with or without the
    leading `@`. Returns the reference string `"@<name>"`, as `setRef`
    does, and throws when `name` is not a string.
  */
  mapRef = reference.atReference "expr.mapRef";

  /*
    Build an address prefix. `addr` is the network address and `len` the
    prefix length. Returns a prefix expression.
  */
  prefix = addr: len: { prefix = { inherit addr len; }; };

  /*
    Build an inclusive range. `lo` and `hi` are the lower and upper bounds.
    Returns a range expression.
  */
  range = lo: hi: {
    range = [
      lo
      hi
    ];
  };

  /*
    Build a set element with per-element options. `val` is the element
    value; `timeout`, `expires`, and `comment` are optional and omitted
    when null. There is no element statement: nft's JSON parser ignores
    one. Returns an elem expression.
  */
  elem =
    {
      val,
      timeout ? null,
      expires ? null,
      comment ? null,
    }:
    {
      elem = compact {
        inherit
          val
          timeout
          expires
          comment
          ;
      };
    };

  # -- Generators -----------------------------------------------------------

  /*
    Generate a number per packet. `mode` is `"inc"` or `"random"`, `mod`
    the modulus, and `offset` an optional start value. Returns a numgen
    expression.
  */
  numgen =
    {
      mode,
      mod,
      offset ? null,
    }:
    {
      numgen = compact { inherit mode mod offset; };
    };

  /*
    Hash an expression with jhash. `mod` is the modulus, `expr` the hashed
    expression, and `offset` and `seed` are optional. Returns a jhash
    expression.
  */
  jhash =
    {
      mod,
      expr,
      offset ? null,
      seed ? null,
    }:
    {
      jhash = compact {
        inherit
          mod
          expr
          offset
          seed
          ;
      };
    };

  /*
    Hash the packet's symmetric flow tuple. `mod` is the modulus and
    `offset` an optional start value. Returns a symhash expression.
  */
  symhash =
    {
      mod,
      offset ? null,
    }:
    {
      symhash = compact { inherit mod offset; };
    };

  # -- Header option / extension escape hatches -----------------------------

  /*
    Reference a TCP option by name. `name` is the option (for example
    `"maxseg"`) and `field` an optional option field. Returns a
    `tcp option` expression.
  */
  tcpOption =
    {
      name,
      field ? null,
    }:
    {
      "tcp option" = compact { inherit name field; };
    };

  /*
    Reference raw TCP option bits. `base` is the option kind, and `offset`
    and `len` locate the bits. Returns a `tcp option` expression.
  */
  tcpOptionRaw =
    {
      base,
      offset,
      len,
    }:
    {
      "tcp option" = { inherit base offset len; };
    };

  /*
    Reference an IPv4 option by name. `name` is the option and `field` an
    optional option field. Returns an `ip option` expression.
  */
  ipOption =
    {
      name,
      field ? null,
    }:
    {
      "ip option" = compact { inherit name field; };
    };

  /*
    Reference an SCTP chunk by name. `name` is the chunk type and `field`
    an optional chunk field. Returns an `sctp chunk` expression.
  */
  sctpChunk =
    {
      name,
      field ? null,
    }:
    {
      "sctp chunk" = compact { inherit name field; };
    };

  /*
    Test for a DCCP option. `type` is the option type number. Returns a
    `dccp option` expression.
  */
  dccpOption = type: {
    "dccp option" = {
      inherit type;
    };
  };

  /*
    Reference an IPv6 extension header. `name` is the header, and `field`
    and `offset` are optional refinements. Returns an exthdr expression.
  */
  exthdr =
    {
      name,
      field ? null,
      offset ? null,
    }:
    {
      exthdr = compact { inherit name field offset; };
    };

  # -- Refined key-string expressions ---------------------------------------
  # The pre-built field tree covers the keys nft loads bare; these take a
  # key with its refinements (`family`, `dir`, …), and require the ones nft
  # needs.

  /*
    Reference a conntrack key with optional refinements. `key` is the
    conntrack key, `family` the optional address family, and `dir` the
    optional direction. Returns a ct expression.
  */
  ct =
    {
      key,
      family ? null,
      dir ? null,
    }:
    {
      ct = compact { inherit key family dir; };
    };

  /*
    Reference routing data. `key` is the routing key and `family` the
    optional address family. Returns an rt expression.
  */
  rt =
    {
      key,
      family ? null,
    }:
    {
      rt = compact { inherit key family; };
    };

  /*
    Look up the forwarding information base. `result` is the requested
    result (`"oif"`, `"type"`, …) and `flags` the lookup flags, one or a
    list. nft needs `saddr` or `daddr` among them, so the constructor
    throws without either. Returns a fib expression.
  */
  fib =
    {
      result,
      # Required; the default lets the throw below carry the
      # `nix-nftypes: dsl.expr.fib:` prefix (ADR 0009).
      flags ? null,
    }:
    if builtins.any (flag: flag == "saddr" || flag == "daddr") (lib.toList flags) then
      { fib = { inherit result flags; }; }
    else
      fail "fib" "a FIB lookup needs saddr or daddr among its flags";

  /*
    Reference passive OS fingerprinting data. `key` is `"name"` or
    `"version"` and `ttl` the optional TTL mode. Returns an osf expression.
  */
  osf =
    {
      key,
      ttl ? null,
    }:
    {
      osf = compact { inherit key ttl; };
    };

  /*
    Reference IPsec (xfrm) state. `key` is the ipsec key and `dir` the
    policy direction, `"in"` or `"out"`, which nft needs for every key, so
    the constructor throws without it. `family` and `spnum` are optional
    refinements. Returns an ipsec expression.
  */
  ipsec =
    {
      key,
      # Required; the default lets the throw below carry the
      # `nix-nftypes: dsl.expr.ipsec:` prefix (ADR 0009).
      dir ? null,
      family ? null,
      spnum ? null,
    }:
    if dir == null then
      fail "ipsec" "an IPsec key needs a direction, dir = \"in\" or \"out\""
    else
      {
        ipsec = compact {
          inherit
            key
            family
            dir
            spnum
            ;
        };
      };

  # -- Binary operators -----------------------------------------------------

  /*
    Combine two expressions with bitwise OR. `a` and `b` are the operands.
    Returns a `|` expression.
  */
  bitOr = a: b: {
    "|" = [
      a
      b
    ];
  };

  /*
    Combine two expressions with bitwise XOR. `a` and `b` are the operands.
    Returns a `^` expression.
  */
  bitXor = a: b: {
    "^" = [
      a
      b
    ];
  };

  /*
    Combine two expressions with bitwise AND, typically to mask a value.
    `a` and `b` are the operands. Returns a `&` expression.
  */
  bitAnd = a: b: {
    "&" = [
      a
      b
    ];
  };

  /*
    Shift an expression left. `a` is the value and `b` the shift count.
    Returns a `<<` expression.
  */
  shiftLeft = a: b: {
    "<<" = [
      a
      b
    ];
  };

  /*
    Shift an expression right. `a` is the value and `b` the shift count.
    Returns a `>>` expression.
  */
  shiftRight = a: b: {
    ">>" = [
      a
      b
    ];
  };
}
