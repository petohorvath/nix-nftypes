/*
  compatibility — static reference data for nftables family×hook,
  family×chain-type, chain-type×hook, and chain-priority tables, plus
  helpers that combine them: `resolvePriority` (symbol → int),
  `priorityNameOf` (int → symbol; reverse direction), `chainTypeFor`
  (derive chain type from a `(family, hook, priority)` placement),
  and `validChainPlacement` ((family, chainType, hook) → bool).
  Sources: `man nft` Tables 6 (default families) and 7 (bridge
  family overrides), cross-checked against
  `include/uapi/linux/netfilter_ipv4.h` /
  `include/uapi/linux/netfilter_ipv6.h` /
  `include/uapi/linux/netfilter_bridge.h` and the kernel's
  `nf_chain_type` registrations in `net/netfilter/nf_tables_api.c`.

  Example:
    nftypes.lib.compatibility.hooksByFamily.netdev
    # → [ "ingress" "egress" ]

    nftypes.lib.resolvePriority "bridge" "filter"
    # → -200

    nftypes.lib.priorityNameOf "bridge" (-200)
    # → "filter"

    nftypes.lib.chainTypeFor "bridge" "postrouting" 300
    # → "nat"

    nftypes.lib.validChainPlacement "ip" "nat" "forward"
    # → false  (nat does not attach at forward)
*/

let
  /*
    Per-family kernel hook points — derived from `str2hooknum` in
    nftables `src/evaluate.c` (the authoritative kernel mapping, more
    complete than `man nft` Tables 6/7 which document priorities, not
    hook availability). Hooks listed here are the points each family
    actually exposes; the kernel rejects base-chain creation with an
    unsupported (family, hook) pair.

    Note: `inet` also supports `ingress` (since kernel 5.10), but
    only when the chain binds devices via `dev_expr` — see
    `evaluate.c` around the `NFPROTO_INET && NF_INET_INGRESS` guard.
  */
  hooksByFamily = {
    ip = [
      "prerouting"
      "input"
      "forward"
      "output"
      "postrouting"
    ];
    ip6 = [
      "prerouting"
      "input"
      "forward"
      "output"
      "postrouting"
    ];
    inet = [
      "prerouting"
      "input"
      "forward"
      "output"
      "postrouting"
      "ingress"
    ];
    bridge = [
      "prerouting"
      "input"
      "forward"
      "output"
      "postrouting"
    ];
    arp = [
      "input"
      "output"
    ];
    netdev = [
      "ingress"
      "egress"
    ];
  };

  /*
    Inverse of the chain-type compatibility matrix in `man nft`
    Table 6: families that natively support each chain type. `nat`
    is rejected for `arp`, `bridge`, `netdev`; `route` is `ip` /
    `ip6` / `inet` (the kernel's `nft_chain_route_*` registrations
    cover the inet meta-family by dispatching to the per-protocol
    implementations — verified on kernel 6.8 with `inet route hook
    output`).
  */
  familiesByChainType = {
    filter = [
      "ip"
      "ip6"
      "inet"
      "bridge"
      "netdev"
      "arp"
    ];
    nat = [
      "ip"
      "ip6"
      "inet"
    ];
    route = [
      "ip"
      "ip6"
      "inet"
    ];
  };

  /*
    Per-chain-type kernel hook restriction. `filter` may attach at
    any hook the family exposes; `nat` is the four routing-related
    hooks (the kernel rejects `forward` / `ingress` / `egress`);
    `route` is `output`-only — its purpose is to trigger a routing
    re-evaluation when the locally-generated packet's headers
    change, which has no analog at the inbound hooks.

    Combine with `hooksByFamily` to get the actual allowed set for
    a `(family, chainType)` pair (the intersection). `null` is the
    sentinel for "any hook the family exposes" — used by `filter`
    to avoid duplicating each family's hook list here.

    Sourced from `man nft` Table 6 and the kernel's `nf_chain_type`
    registrations in `net/netfilter/nf_tables_api.c`.
  */
  hooksByChainType = {
    filter = null;
    nat = [
      "prerouting"
      "input"
      "output"
      "postrouting"
    ];
    route = [ "output" ];
  };

  /*
    Symbolic chain priority → int. Default table from `man nft`
    Table 6 (applies to ip / ip6 / inet / arp / netdev). Mirrors
    NF_IP_PRI_* in `include/uapi/linux/netfilter_ipv4.h`.
  */
  priorityIntsDefault = {
    raw = -300;
    mangle = -150;
    dstnat = -100;
    filter = 0;
    security = 50;
    srcnat = 100;
  };

  /*
    Bridge-family overrides — `man nft` Table 7. Mirrors NF_BR_PRI_*
    in `include/uapi/linux/netfilter_bridge.h`. Note: `out` is
    bridge-specific (no equivalent in the default table); `dstnat` /
    `filter` / `srcnat` differ from the default table's values.
  */
  priorityIntsBridge = {
    dstnat = -300;
    filter = -200;
    out = 100;
    srcnat = 300;
  };

  /*
    Hooks at which the kernel has made a routing decision and
    `oifname` resolves to a real interface. Useful for validators
    that want to flag a `oifname` match in a hook where the result
    is always empty (`prerouting`, `input`).
  */
  hooksWithOifname = [
    "forward"
    "output"
    "postrouting"
  ];

  knownFamilies = builtins.attrNames hooksByFamily;

  /*
    priorityIntsByFamily :: family -> { symbol -> int }

    Returns the canonical symbol→int priority table for `family`.
    `bridge` gets `priorityIntsBridge`; every other known family
    gets `priorityIntsDefault`. Throws on unknown family.

    Internal dispatch shared by `resolvePriority` (symbol → int)
    and the reverse-lookup helpers `priorityNameOf` / `chainTypeFor`.
    Exposed because consumers occasionally need the raw table to
    iterate symbols family-aware.
  */
  priorityIntsByFamily =
    family:
    if !(builtins.elem family knownFamilies) then
      throw (
        "priorityIntsByFamily: unknown family '${toString family}'. "
        + "Valid families: "
        + builtins.concatStringsSep ", " knownFamilies
        + "."
      )
    else if family == "bridge" then
      priorityIntsBridge
    else
      priorityIntsDefault;

  /*
    resolvePriority :: family -> (int | symbol) -> int

    Pass an int through unchanged; look a symbol up in the
    family-appropriate table (bridge → priorityIntsBridge, every
    other known family → priorityIntsDefault). Throws separately
    for unknown family vs unknown symbol so the error message
    distinguishes the two.

    Scope: symbol-to-int translation only. The kernel accepts any
    int as a priority, so `man nft` Table 6's family/hook
    restrictions (e.g. `mangle` is conventionally ip/ip6/inet only;
    `dstnat` is prerouting-only) are *not* enforced here —
    `resolvePriority "netdev" "mangle"` returns `-150` even though
    `mangle` isn't conventional for netdev. Validators that need
    Table 6 compliance should layer on top using
    `familiesByChainType` and equivalent hook restrictions.
  */
  resolvePriority =
    family: prio:
    if builtins.isInt prio then
      prio
    else
      let
        table = priorityIntsByFamily family;
        symNames = builtins.attrNames table;
      in
      table.${prio} or (throw (
        "resolvePriority: unknown priority symbol '${toString prio}' "
        + "for family '${family}'. Valid symbols: "
        + builtins.concatStringsSep ", " symNames
        + "."
      ));

  /*
    validChainPlacement :: family -> chainType -> hook -> bool

    True iff the kernel will accept a base chain with this
    `(family, chainType, hook)` triple. Combines three checks:
      - `family` supports `chainType`        (familiesByChainType)
      - `family` exposes `hook`              (hooksByFamily)
      - `chainType` permits `hook`           (hooksByChainType)
    All three must hold; any one failing means kernel rejection.

    Useful for consumers that synthesize chain placements from
    higher-level abstractions (e.g. zone-based firewalls) and want
    to flag invalid combinations at compile time rather than at
    `nft -f` time.
  */
  validChainPlacement =
    family: chainType: hook:
    let
      families = familiesByChainType.${chainType} or [ ];
      familyHooks = hooksByFamily.${family} or [ ];
      typeHooks = hooksByChainType.${chainType} or null;
    in
    builtins.elem family families
    && builtins.elem hook familyHooks
    && (typeHooks == null || builtins.elem hook typeHooks);

  /*
    priorityNameOf :: family -> (int | symbol) -> (symbol | int)

    Reverse of `resolvePriority`. Given a priority value, return
    the canonical symbol if one exists for the family, else the
    raw value unchanged. Symbols pass through unchanged (already
    canonical). Throws on unknown family.

    Use case: consumers that key chain buckets by a stable
    `(hook, priorityName)` pair want int-form and symbol-form
    inputs to collapse into one bucket. Without this, a user
    override `priority = 0` produces a different bucket from the
    default `priority = "filter"`, even though the kernel sees the
    same int.

    When multiple symbols share an int (none today, but defensive),
    `attrNames` order is undefined; consumers that care should not
    rely on which symbol wins.
  */
  priorityNameOf =
    family: prio:
    if !(builtins.isInt prio) then
      prio
    else
      let
        table = priorityIntsByFamily family;
        symbols = builtins.attrNames table;
        matching = builtins.filter (s: table.${s} == prio) symbols;
      in
      if matching == [ ] then prio else builtins.head matching;

  /*
    chainTypeFor :: family -> hook -> (int | symbol) -> (chainType | null)

    Derive the nftables chain type (`"filter"` / `"nat"` /
    `"route"`) implied by a `(family, hook, priority)` placement.
    Returns `"filter"` for any placement that doesn't unambiguously
    pick another type; returns `null` only if `prio` is a symbol
    not in the family's priority table.

    Mapping (family-aware via `priorityIntsByFamily`):
      - priority == srcnat || priority == dstnat
          → "nat"
      - priority == mangle && hook is a route-chain hook
          → "route"  (route chains are output-only;
                       prerouting + mangle is a filter chain
                       that does mangling)
      - otherwise
          → "filter"

    Bridge family note: `priorityIntsBridge` has different ints
    for `srcnat` (300) / `dstnat` (-300) / `filter` (-200), plus a
    `bridge`-only `out` symbol. The mapping above resolves symbols
    via `priorityIntsByFamily`, so bridge int 300 correctly
    classifies as `"nat"`. Bridge has no `mangle`, so the route
    branch is unreachable for bridge.

    Throws on unknown family (via `priorityIntsByFamily`); never
    throws on unknown hook (the kernel rejects those separately —
    see `validChainPlacement`).
  */
  chainTypeFor =
    family: hook: prio:
    let
      table = priorityIntsByFamily family;
      p = if builtins.isInt prio then prio else table.${prio} or null;
    in
    if p == null then
      null
    else if p == (table.srcnat or null) || p == (table.dstnat or null) then
      "nat"
    else if (table ? mangle) && p == table.mangle && builtins.elem hook hooksByChainType.route then
      "route"
    else
      "filter";
in
{
  inherit
    hooksByFamily
    familiesByChainType
    hooksByChainType
    priorityIntsDefault
    priorityIntsBridge
    priorityIntsByFamily
    hooksWithOifname
    resolvePriority
    validChainPlacement
    priorityNameOf
    chainTypeFor
    ;
}
