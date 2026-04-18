{ lib }:

# Expression combinators. One entry per tag in `lib/expressions.nix`.
# Each function returns a plain attrset shaped exactly like what the
# `expression` type accepts; no module-system interaction happens here.

let
  # Helper: drop null attrs at construction time. The render pipeline strips
  # them too, but doing it here keeps intermediate values ergonomic to read.
  compact = lib.filterAttrs (_: v: v != null);
in
rec {
  # -- Compound / structural ------------------------------------------------

  concat = xs: { concat = xs; };
  set = xs: { set = xs; };
  map = { key, data }: { map = { inherit key data; }; };
  prefix = addr: len: { prefix = { inherit addr len; }; };
  range = lo: hi: { range = [ lo hi ]; };

  # -- Payload (three disjoint forms) ---------------------------------------

  # Named form: { protocol, field } — the common one.
  payload = protocol: field: { payload = { inherit protocol field; }; };

  # Raw form: { base, offset, len } — base ∈ ll|nh|th|ih.
  payloadRaw =
    { base, offset, len }:
    { payload = { inherit base offset len; }; };

  # Tunnel inner-header form: { tunnel, protocol, field }.
  payloadTunnel =
    { tunnel, protocol, field }:
    { payload = { inherit tunnel protocol field; }; };

  # -- Header field accessors -----------------------------------------------

  exthdr =
    {
      name,
      field ? null,
      offset ? null,
    }:
    { exthdr = compact { inherit name field offset; }; };

  tcpOption =
    { name, field ? null }:
    { "tcp option" = compact { inherit name field; }; };

  tcpOptionRaw =
    { base, offset, len }:
    { "tcp option" = { inherit base offset len; }; };

  ipOption =
    { name, field ? null }:
    { "ip option" = compact { inherit name field; }; };

  sctpChunk =
    { name, field ? null }:
    { "sctp chunk" = compact { inherit name field; }; };

  dccpOption = t: { "dccp option" = { type = t; }; };

  # -- Meta / routing / conntrack -------------------------------------------

  meta = key: { meta = { inherit key; }; };

  rt =
    {
      key,
      family ? null,
    }:
    { rt = compact { inherit key family; }; };

  ct =
    {
      key,
      family ? null,
      dir ? null,
    }:
    { ct = compact { inherit key family dir; }; };

  # -- Generators / derived -------------------------------------------------

  numgen =
    {
      mode,
      mod,
      offset ? null,
    }:
    { numgen = compact { inherit mode mod offset; }; };

  jhash =
    {
      mod,
      expr,
      offset ? null,
      seed ? null,
    }:
    { jhash = compact { inherit mod expr offset seed; }; };

  symhash =
    { mod, offset ? null }:
    { symhash = compact { inherit mod offset; }; };

  fib =
    { result, flags ? null }:
    { fib = compact { inherit result flags; }; };

  socket = key: { socket = { inherit key; }; };

  osf =
    { key, ttl ? null }:
    { osf = compact { inherit key ttl; }; };

  ipsec =
    {
      key,
      family ? null,
      dir ? null,
      spnum ? null,
    }:
    { ipsec = compact { inherit key family dir spnum; }; };

  # Tunnel metadata key (distinct from the payload tunnel form and from
  # the `tunnel` named object).
  tunnelMeta = key: { tunnel = { inherit key; }; };

  elem =
    {
      val,
      timeout ? null,
      expires ? null,
      comment ? null,
    }:
    { elem = compact { inherit val timeout expires comment; }; };

  # -- Verdicts as expressions (valid in vmap data positions) ---------------

  accept = { accept = null; };
  drop = { drop = null; };
  continue = { continue = null; };
  return = { return = null; };
  jump = target: { jump = { inherit target; }; };
  goto = target: { goto = { inherit target; }; };

  # -- Binary operators -----------------------------------------------------

  bitor = a: b: { "|" = [ a b ]; };
  bitxor = a: b: { "^" = [ a b ]; };
  bitand = a: b: { "&" = [ a b ]; };
  lshift = a: b: { "<<" = [ a b ]; };
  rshift = a: b: { ">>" = [ a b ]; };
}
