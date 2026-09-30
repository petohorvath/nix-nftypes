/*
  Expression helpers not covered by the pre-built field tree in ./fields/:
  structural and generator expressions (concat, set, map, prefix, range,
  numgen, …), header-option expressions (tcpOption, ipOption, …), and escape
  hatches for key-string expressions (meta, ct, rt, …) when the caller needs
  refinements that the bare field-tree leaves do not support.
*/
{ lib }:

let
  compact = import ./internal/compact.nix { inherit lib; };
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
        expr.set: a bare string ("${xs}") is not a valid anonymous-set body —
        anonymous sets are lists. For a named-set reference, use
        `expr.setRef "${xs}"` (or pass `"@${xs}"` directly to inSet/notInSet).
      ''
    else
      { set = xs; };

  /*
    Reference a named set. `name` is the set name, with or without the
    leading `@` that libnftables JSON uses for named references. Returns
    `{ set = "@<name>"; }` and throws when `name` is not a string.
  */
  setRef =
    name:
    if !(builtins.isString name) then
      throw "expr.setRef: expected a name string, got ${builtins.typeOf name}"
    else if lib.hasPrefix "@" name then
      { set = name; }
    else
      { set = "@${name}"; };

  /*
    Build a map lookup. `key` is the lookup expression and `data` the
    anonymous map body or named map reference. Returns a map expression.
  */
  map =
    { key, data }:
    {
      map = { inherit key data; };
    };

  /*
    Reference a named map, mirroring `setRef`. `name` is the map name, with
    or without a leading `@`. Returns `{ map = "@<name>"; }` and throws when
    `name` is not a string.
  */
  mapRef =
    name:
    if !(builtins.isString name) then
      throw "expr.mapRef: expected a name string, got ${builtins.typeOf name}"
    else if lib.hasPrefix "@" name then
      { map = name; }
    else
      { map = "@${name}"; };

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
    value; `timeout`, `expires`, `comment`, and `stmt` are optional and
    omitted when null. Returns an elem expression.
  */
  elem =
    {
      val,
      timeout ? null,
      expires ? null,
      comment ? null,
      stmt ? null,
    }:
    {
      elem = compact {
        inherit
          val
          timeout
          expires
          comment
          stmt
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

  # -- Key-string escape hatches --------------------------------------------
  # The pre-built field tree covers known keys with bare access; these accept
  # any key string and optional refinements (`family`, `dir`, …).

  /*
    Reference any meta key. `key` is the meta key string. Returns a meta
    expression.
  */
  meta = key: { meta = { inherit key; }; };

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
    Reference any socket key. `key` is the socket key string. Returns a
    socket expression.
  */
  socket = key: { socket = { inherit key; }; };

  /*
    Look up the forwarding information base. `result` is the requested
    result (`"oif"`, `"type"`, …) and `flags` the optional lookup flags.
    Returns a fib expression.
  */
  fib =
    {
      result,
      flags ? null,
    }:
    {
      fib = compact { inherit result flags; };
    };

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
    Reference IPsec (xfrm) state. `key` is the ipsec key; `family`, `dir`,
    and `spnum` are optional refinements. Returns an ipsec expression.
  */
  ipsec =
    {
      key,
      family ? null,
      dir ? null,
      spnum ? null,
    }:
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
  bitor = a: b: {
    "|" = [
      a
      b
    ];
  };

  /*
    Combine two expressions with bitwise XOR. `a` and `b` are the operands.
    Returns a `^` expression.
  */
  bitxor = a: b: {
    "^" = [
      a
      b
    ];
  };

  /*
    Combine two expressions with bitwise AND, typically to mask a value.
    `a` and `b` are the operands. Returns a `&` expression.
  */
  bitand = a: b: {
    "&" = [
      a
      b
    ];
  };

  /*
    Shift an expression left. `a` is the value and `b` the shift count.
    Returns a `<<` expression.
  */
  lshift = a: b: {
    "<<" = [
      a
      b
    ];
  };

  /*
    Shift an expression right. `a` is the value and `b` the shift count.
    Returns a `>>` expression.
  */
  rshift = a: b: {
    ">>" = [
      a
      b
    ];
  };
}
