/*
  compatibility — static reference data for nftables family×hook,
  family×chain-type, and chain-priority tables, plus a `resolvePriority`
  helper that converts symbolic priorities to ints with family-aware
  lookup. Sources: `man nft` Tables 6 (default families) and 7 (bridge
  family overrides), cross-checked against
  `include/uapi/linux/netfilter_ipv4.h` /
  `include/uapi/linux/netfilter_ipv6.h` /
  `include/uapi/linux/netfilter_bridge.h`.

  Example:
    nftypes.lib.compatibility.hooksByFamily.netdev
    # → [ "ingress" "egress" ]

    nftypes.lib.resolvePriority "bridge" "filter"
    # → -200
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
    is rejected for `arp`, `bridge`, `netdev`; `route` is `ip`/`ip6`
    only (and inet's compat shim does not extend to `route`).
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
    ];
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
    else if !(builtins.elem family knownFamilies) then
      throw (
        "resolvePriority: unknown family '${toString family}'. "
        + "Valid families: "
        + builtins.concatStringsSep ", " knownFamilies
        + "."
      )
    else
      let
        table = if family == "bridge" then priorityIntsBridge else priorityIntsDefault;
        symNames = builtins.attrNames table;
      in
      table.${prio} or (throw (
        "resolvePriority: unknown priority symbol '${toString prio}' "
        + "for family '${family}'. Valid symbols: "
        + builtins.concatStringsSep ", " symNames
        + "."
      ));
in
{
  inherit
    hooksByFamily
    familiesByChainType
    priorityIntsDefault
    priorityIntsBridge
    hooksWithOifname
    resolvePriority
    ;
}
