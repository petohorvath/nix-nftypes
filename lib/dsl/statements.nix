{ lib }:

# Statement combinators. One entry per tag in `lib/statements.nix`.

let
  compact = lib.filterAttrs (_: v: v != null);
in
rec {
  # -- Verdict statements ---------------------------------------------------

  accept = { accept = null; };
  drop = { drop = null; };
  continue = { continue = null; };
  return = { return = null; };
  notrack = { notrack = null; };
  jump = target: { jump = { inherit target; }; };
  goto = target: { goto = { inherit target; }; };

  # -- Match ----------------------------------------------------------------

  match =
    op: left: right:
    { match = { inherit op left right; }; };
  matchEq = left: right: match "==" left right;
  matchNe = left: right: match "!=" left right;
  matchLt = left: right: match "<" left right;
  matchGt = left: right: match ">" left right;
  matchLe = left: right: match "<=" left right;
  matchGe = left: right: match ">=" left right;
  matchIn = left: right: match "in" left right;

  # -- Counters / rate limiting / quota -------------------------------------

  # Counter has three forms per parser_json.c:1914:
  #   null                        — stateless output
  #   "name"                      — reference to named counter
  #   { packets?; bytes?; }       — inline anonymous counter
  counterNull = { counter = null; };
  counterRef = name: { counter = name; };
  counter =
    {
      packets ? null,
      bytes ? null,
    }:
    { counter = compact { inherit packets bytes; }; };

  quotaRef = name: { quota = name; };
  quota =
    {
      val,
      val_unit ? null,
      used ? null,
      used_unit ? null,
      inv ? null,
    }:
    {
      quota = compact {
        inherit
          val
          val_unit
          used
          used_unit
          inv
          ;
      };
    };

  limitRef = name: { limit = name; };
  limit =
    {
      rate,
      per,
      rate_unit ? null,
      burst ? null,
      burst_unit ? null,
      inv ? null,
    }:
    {
      limit = compact {
        inherit
          rate
          per
          rate_unit
          burst
          burst_unit
          inv
          ;
      };
    };

  # -- Mangle ---------------------------------------------------------------

  mangle = key: value: { mangle = { inherit key value; }; };

  # -- NAT ------------------------------------------------------------------

  snat =
    {
      addr ? null,
      family ? null,
      port ? null,
      flags ? null,
      type_flags ? null,
    }:
    {
      snat = compact {
        inherit
          addr
          family
          port
          flags
          type_flags
          ;
      };
    };

  dnat =
    {
      addr ? null,
      family ? null,
      port ? null,
      flags ? null,
      type_flags ? null,
    }:
    {
      dnat = compact {
        inherit
          addr
          family
          port
          flags
          type_flags
          ;
      };
    };

  masquerade =
    { port ? null, flags ? null }:
    { masquerade = compact { inherit port flags; }; };

  redirect =
    { port ? null, flags ? null }:
    { redirect = compact { inherit port flags; }; };

  masqueradePlain = { masquerade = { }; };
  redirectPlain = { redirect = { }; };

  fwd =
    {
      dev,
      family ? null,
      addr ? null,
    }:
    { fwd = compact { inherit dev family addr; }; };

  dup =
    { addr, dev ? null }:
    { dup = compact { inherit addr dev; }; };

  # -- Reject ---------------------------------------------------------------

  reject =
    {
      type ? null,
      expr ? null,
    }:
    { reject = compact { inherit type expr; }; };

  rejectPlain = { reject = { }; };
  rejectIcmp = code: { reject = { type = "icmp"; expr = code; }; };
  rejectIcmpv6 = code: { reject = { type = "icmpv6"; expr = code; }; };
  rejectIcmpx = code: { reject = { type = "icmpx"; expr = code; }; };
  rejectTcpReset = { reject = { type = "tcp reset"; }; };

  # -- Set / map statements (dynamic element add/update/delete) -------------

  setStmt =
    {
      op,
      elem,
      set,
      stmt ? null,
    }:
    {
      set = compact {
        inherit
          op
          elem
          set
          stmt
          ;
      };
    };

  mapStmt =
    {
      op,
      elem,
      data,
      map,
      stmt ? null,
    }:
    {
      map = compact {
        inherit
          op
          elem
          data
          map
          stmt
          ;
      };
    };

  # -- Log ------------------------------------------------------------------

  log =
    {
      prefix ? null,
      group ? null,
      snaplen ? null,
      queue-threshold ? null,
      level ? null,
      flags ? null,
    }:
    {
      log = compact {
        inherit
          prefix
          group
          snaplen
          level
          flags
          ;
        "queue-threshold" = queue-threshold;
      };
    };

  logPlain = { log = { }; };

  # -- Conntrack modifiers --------------------------------------------------

  ctHelperSet = e: { "ct helper" = e; };
  ctTimeoutSet = e: { "ct timeout" = e; };
  ctExpectationSet = e: { "ct expectation" = e; };

  ctCount =
    { val, inv ? null }:
    { "ct count" = compact { inherit val inv; }; };

  # -- Meter, queue, vmap ---------------------------------------------------

  meter =
    {
      name,
      key,
      stmt,
      size ? null,
    }:
    {
      meter = compact {
        inherit
          name
          key
          stmt
          size
          ;
      };
    };

  queue =
    {
      num ? null,
      flags ? null,
    }:
    { queue = compact { inherit num flags; }; };

  queuePlain = { queue = { }; };

  vmap = key: data: { vmap = { inherit key data; }; };

  # -- xtables bridge -------------------------------------------------------

  xt = type: name: { xt = { inherit type name; }; };

  # -- Statements audited in beyond the adoc --------------------------------

  last = { last = null; };
  lastUsed = t: { last = { used = t; }; };

  flow =
    { op ? "add", flowtable }:
    { flow = { inherit op flowtable; }; };

  tproxy =
    {
      family ? null,
      addr ? null,
      port ? null,
    }:
    { tproxy = compact { inherit family addr port; }; };

  # synproxy has three forms: null (empty), anonymous config, or reference/expr.
  synproxyNull = { synproxy = null; };
  synproxy =
    {
      mss,
      wscale,
      flags ? null,
    }:
    { synproxy = compact { inherit mss wscale flags; }; };
  synproxyRef = e: { synproxy = e; };

  # `reset` strips a TCP option; body is a tcp-option expression.
  reset = e: { reset = e; };

  # `secmark` and `tunnel` statement bodies are expressions (typically string refs).
  secmark = e: { secmark = e; };
  tunnel = e: { tunnel = e; };
}
