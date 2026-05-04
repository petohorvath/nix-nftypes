{ lib }:

# Expression helpers not covered by the pre-built field tree in ./fields/.
# Structural/generator expressions (concat, set, map, prefix, range, numgen,
# …), header-option expressions (tcpOption, ipOption, …), and escape hatches
# for the key-string expressions (meta, ct, rt, …) when the user needs
# optional refinements not supported by the bare field-tree leaves.

let
  compact = import ./internal/compact.nix { inherit lib; };
in
rec {
  # -- Structural -----------------------------------------------------------

  concat = xs: { concat = xs; };

  # Anonymous set literal. Body must be a list of expressions; a bare string
  # would render as `{"set":"<x>"}`, which `nft` interprets as a 1-element
  # anonymous set whose sole element is the literal string `<x>` — never the
  # caller's intent. For a named-set reference use `expr.setRef`.
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

  # Named set reference: `{ set = "@<name>"; }`. The leading `@` is the
  # libnftables-JSON convention for named refs (vs. anonymous-set bodies which
  # are lists). Callers pass the bare name; we prepend the `@`. An already
  # `@`-prefixed name is tolerated to keep migration painless.
  setRef =
    name:
    if !(builtins.isString name) then
      throw "expr.setRef: expected a name string, got ${builtins.typeOf name}"
    else if lib.hasPrefix "@" name then
      { set = name; }
    else
      { set = "@${name}"; };

  map =
    { key, data }:
    {
      map = { inherit key data; };
    };

  # Named map reference, mirroring `setRef`. Pass the bare name; the helper
  # prepends the `@`. Tolerates an already-prefixed name.
  mapRef =
    name:
    if !(builtins.isString name) then
      throw "expr.mapRef: expected a name string, got ${builtins.typeOf name}"
    else if lib.hasPrefix "@" name then
      { map = name; }
    else
      { map = "@${name}"; };

  prefix = addr: len: { prefix = { inherit addr len; }; };
  range = lo: hi: {
    range = [
      lo
      hi
    ];
  };

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

  numgen =
    {
      mode,
      mod,
      offset ? null,
    }:
    {
      numgen = compact { inherit mode mod offset; };
    };

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

  symhash =
    {
      mod,
      offset ? null,
    }:
    {
      symhash = compact { inherit mod offset; };
    };

  # -- Header option / extension escape hatches -----------------------------

  tcpOption =
    {
      name,
      field ? null,
    }:
    {
      "tcp option" = compact { inherit name field; };
    };

  tcpOptionRaw =
    {
      base,
      offset,
      len,
    }:
    {
      "tcp option" = { inherit base offset len; };
    };

  ipOption =
    {
      name,
      field ? null,
    }:
    {
      "ip option" = compact { inherit name field; };
    };

  sctpChunk =
    {
      name,
      field ? null,
    }:
    {
      "sctp chunk" = compact { inherit name field; };
    };

  dccpOption = t: {
    "dccp option" = {
      type = t;
    };
  };

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

  meta = key: { meta = { inherit key; }; };

  ct =
    {
      key,
      family ? null,
      dir ? null,
    }:
    {
      ct = compact { inherit key family dir; };
    };

  rt =
    {
      key,
      family ? null,
    }:
    {
      rt = compact { inherit key family; };
    };

  socket = key: { socket = { inherit key; }; };

  fib =
    {
      result,
      flags ? null,
    }:
    {
      fib = compact { inherit result flags; };
    };

  osf =
    {
      key,
      ttl ? null,
    }:
    {
      osf = compact { inherit key ttl; };
    };

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

  bitor = a: b: {
    "|" = [
      a
      b
    ];
  };
  bitxor = a: b: {
    "^" = [
      a
      b
    ];
  };
  bitand = a: b: {
    "&" = [
      a
      b
    ];
  };
  lshift = a: b: {
    "<<" = [
      a
      b
    ];
  };
  rshift = a: b: {
    ">>" = [
      a
      b
    ];
  };
}
