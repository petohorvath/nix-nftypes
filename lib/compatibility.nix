/*
  compatibility — static reference data for nftables family×hook,
  family×chain-type, chain-type×hook, and family×hook×priority tables,
  plus helpers that look placements and priorities up in them:
  `priorityValue` (symbol → int), `priorityName` (int → symbol),
  `chainTypeFor` (derive chain type from a `(family, hook, priority)`
  placement), and `validChainPlacement` ((family, chainType, hook) →
  bool). Every helper throws on a family, chain type, hook, or priority
  outside its table.
  Sources: `man nft` Tables 6 (default families) and 7 (bridge
  family overrides), cross-checked against
  `include/uapi/linux/netfilter_ipv4.h` /
  `include/uapi/linux/netfilter_ipv6.h` /
  `include/uapi/linux/netfilter_bridge.h`, the kernel's
  `nf_chain_type` registrations in `net/netfilter/nf_tables_api.c`, and
  `std_prio_family_hook_compat` in nftables `src/rule.c`.

  Example:
    nftypes.lib.compatibility.hooksByFamily.netdev
    # → [ "ingress" "egress" ]

    nftypes.lib.compatibility.priorityValue "bridge" "input" "filter"
    # → -200

    nftypes.lib.compatibility.priorityName "bridge" "input" (-200)
    # → "filter"

    nftypes.lib.compatibility.chainTypeFor "ip" "postrouting" "srcnat"
    # → "nat"

    nftypes.lib.compatibility.chainTypeFor "bridge" "postrouting" 300
    # → "filter"  (bridge has no nat chains)

    nftypes.lib.compatibility.validChainPlacement "ip" "nat" "forward"
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
    any hook the family exposes, so it lists every hook; `nat` is the
    four routing-related hooks (the kernel rejects `forward` /
    `ingress` / `egress`); `route` is `output`-only — its purpose is
    to trigger a routing re-evaluation when the locally-generated
    packet's headers change, which has no analog at the inbound hooks.

    Combine with `hooksByFamily` to get the actual allowed set for
    a `(family, chainType)` pair (the intersection).

    Sourced from `man nft` Table 6 and the kernel's `nf_chain_type`
    registrations in `net/netfilter/nf_tables_api.c`.
  */
  hooksByChainType = {
    filter = [
      "prerouting"
      "input"
      "forward"
      "output"
      "postrouting"
      "ingress"
      "egress"
    ];
    nat = [
      "prerouting"
      "input"
      "output"
      "postrouting"
    ];
    route = [ "output" ];
  };

  /*
    The symbolic priorities nft accepts at `hook` of an ip, ip6, or inet
    chain. Values from `man nft` Table 6, mirroring NF_IP_PRI_* in
    `include/uapi/linux/netfilter_ipv4.h`; the hooks from
    `std_prio_family_hook_compat` in nftables `src/rule.c`, which
    accepts `dstnat` only at prerouting and output, and `srcnat` only
    at input and postrouting.
  */
  inetPrioritiesAt =
    hook:
    {
      raw = -300;
      mangle = -150;
      filter = 0;
      security = 50;
    }
    // (if hook == "prerouting" || hook == "output" then { dstnat = -100; } else { })
    // (if hook == "input" || hook == "postrouting" then { srcnat = 100; } else { });

  /*
    The symbolic priorities nft accepts at `hook` of a bridge chain.
    Values from `man nft` Table 7, mirroring NF_BR_PRI_* in
    `include/uapi/linux/netfilter_bridge.h`: `out` is bridge-specific,
    and `dstnat` / `filter` / `srcnat` differ from Table 6. nft accepts
    `filter` at every hook and each of the others at one hook.
  */
  bridgePrioritiesAt =
    hook:
    {
      filter = -200;
    }
    // (if hook == "prerouting" then { dstnat = -300; } else { })
    // (if hook == "output" then { out = 100; } else { })
    // (if hook == "postrouting" then { srcnat = 300; } else { });

  /*
    prioritiesByFamily.<family>.<hook> :: { symbol -> int }

    The symbolic priorities nft accepts for a chain at each hook of each
    family, indexed like `hooksByFamily`: arp and netdev accept only
    `filter`, bridge has its own table, and ip, ip6, and inet the
    default one. The same tables back `priorityValue` (symbol → int) and
    the reverse lookups `priorityName` and `chainTypeFor`.
  */
  prioritiesByFamily =
    let
      prioritiesAt = {
        ip = inetPrioritiesAt;
        ip6 = inetPrioritiesAt;
        inet = inetPrioritiesAt;
        bridge = bridgePrioritiesAt;
        arp = _: { filter = 0; };
        netdev = _: { filter = 0; };
      };
    in
    builtins.mapAttrs (
      family: hooks:
      builtins.listToAttrs (
        map (hook: {
          name = hook;
          value = prioritiesAt.${family} hook;
        }) hooks
      )
    ) hooksByFamily;

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

  # `value` quoted when it's a string or an int, else its type.
  describe =
    value:
    if builtins.isString value || builtins.isInt value then
      "'${toString value}'"
    else
      "of type ${builtins.typeOf value}";

  # Throws `message` from the helper `caller`, followed by the values
  # `valid` it accepts.
  fail =
    caller: message: validLabel: valid:
    throw (
      "nix-nftypes: compatibility.${caller}: ${message}. Valid ${validLabel}: "
      + builtins.concatStringsSep ", " valid
      + "."
    );

  # `value` when it is one of `valid`; otherwise a throw naming `caller`
  # and `what`, such as `"family"`, with its plural `whats`.
  checkKnown =
    caller: what: whats: valid: value:
    if builtins.isString value && builtins.elem value valid then
      value
    else
      fail caller "unknown ${what} ${describe value}" whats valid;

  checkFamily = caller: checkKnown caller "family" "families" (builtins.attrNames hooksByFamily);

  # The priority table of `hook` in `family`; a hook the family lacks
  # throws, as nft rejects it.
  prioritiesAt =
    caller: family: hook:
    let
      hooks = hooksByFamily.${checkFamily caller family};
    in
    if builtins.isString hook && builtins.elem hook hooks then
      prioritiesByFamily.${family}.${hook}
    else
      fail caller "family '${family}' has no hook ${describe hook}" "hooks" hooks;

  # The int of `priority` in `priorities`, the table of `hook` in
  # `family`: an int passes through once `priorities` is forced, so an
  # unknown family or hook throws for it too, and a symbol nft rejects
  # there throws.
  valueIn =
    caller: family: hook: priorities: priority:
    if builtins.isInt priority then
      builtins.seq priorities priority
    else if builtins.isString priority && priorities ? ${priority} then
      priorities.${priority}
    else
      fail caller "family '${family}' has no priority ${describe priority} at hook '${hook}'" "priorities"
        ([ "any int" ] ++ builtins.attrNames priorities);

  # The symbol of `value` in `priorities`, or null if it has none. When
  # several symbols share a value (none today), `attrNames` order
  # decides.
  nameIn =
    priorities: value:
    let
      matching = builtins.filter (symbol: priorities.${symbol} == value) (builtins.attrNames priorities);
    in
    if matching == [ ] then null else builtins.head matching;

  /*
    priorityValue :: family -> hook -> (int | symbol) -> int

    Look a symbol up in the priorities nft accepts at `hook` of
    `family`, and pass an int through unchanged. Throws on an unknown
    family, on a hook the family lacks, and on a symbol nft rejects
    there: `priorityValue "netdev" "ingress" "mangle"` and
    `priorityValue "ip" "input" "dstnat"` throw, as nft rejects both.

    Scope: symbol-to-int translation only. It takes a bare symbol such
    as `"filter"`, not an expression such as `"filter + 10"`; add an
    offset with Nix arithmetic: `priorityValue "ip" "input" "filter" + 10`.
  */
  priorityValue =
    family: hook: priority:
    valueIn "priorityValue" family hook (prioritiesAt "priorityValue" family hook) priority;

  /*
    priorityName :: family -> hook -> (int | symbol) -> (symbol | int)

    Reverse of `priorityValue`. Given an int, return the symbol nft
    accepts for it at `hook` of `family`, else the int unchanged, as
    nft lists it: `priorityName "ip" "input" (-100)` is `-100`, since
    nft rejects `dstnat` at input. A symbol nft accepts there passes
    through. Throws as `priorityValue` does.

    Use case: consumers that key chain buckets by a stable
    `(hook, priorityName)` pair want int-form and symbol-form
    inputs to collapse into one bucket. Without this, a user
    override `priority = 0` produces a different bucket from the
    default `priority = "filter"`, even though the kernel sees the
    same int.
  */
  priorityName =
    family: hook: priority:
    let
      priorities = prioritiesAt "priorityName" family hook;
      value = valueIn "priorityName" family hook priorities priority;
      name = nameIn priorities value;
    in
    if name == null then value else name;

  /*
    validChainPlacement :: family -> chainType -> hook -> bool

    True when the triple appears in the static compatibility tables:
      - `family` supports `chainType`        (familiesByChainType)
      - `family` exposes `hook`              (hooksByFamily)
      - `chainType` permits `hook`           (hooksByChainType)

    Throws on a family, chain type, or hook outside its table, so a typo
    doesn't read as an invalid placement.

    This intentionally does not model runtime requirements such as kernel
    version/modules, devices, or `dev` on ingress chains. A true result is a
    useful compile-time placement check, not a guarantee that `nft -f` will
    accept a complete chain body.
  */
  validChainPlacement =
    family: chainType: hook:
    let
      caller = "validChainPlacement";
      knownFamily = checkFamily caller family;
      knownType =
        checkKnown caller "chain type" "chain types" (builtins.attrNames familiesByChainType)
          chainType;
      knownHook = checkKnown caller "hook" "hooks" hooksByChainType.filter hook;
    in
    builtins.elem knownFamily familiesByChainType.${knownType}
    && builtins.elem knownHook hooksByFamily.${knownFamily}
    && builtins.elem knownHook hooksByChainType.${knownType};

  /*
    chainTypeFor :: family -> hook -> (int | symbol) -> chainType

    Classify a `(family, hook, priority)` placement according to this
    library's conventional `"filter"` / `"nat"` / `"route"` policy, and
    never return a type `validChainPlacement` rejects for the placement.

    Mapping (via `prioritiesByFamily.<family>.<hook>`, so an int counts
    as a symbol only where nft accepts that symbol):
      - priority == srcnat || priority == dstnat
          → "nat"
      - priority == mangle
          → "route"
      - otherwise
          → "filter"

    When `validChainPlacement` rejects the classified type at `hook`,
    the result is `"filter"`: nat doesn't attach in the arp, bridge, or
    netdev family; route attaches only at output in ip, ip6, and inet.
    So `prerouting` at `mangle` is a filter chain that mangles, and
    bridge `srcnat` (300, not 100) is a filter chain.

    Throws as `priorityValue` does.
  */
  chainTypeFor =
    family: hook: priority:
    let
      priorities = prioritiesAt "chainTypeFor" family hook;
      name = nameIn priorities (valueIn "chainTypeFor" family hook priorities priority);
      classified =
        if name == "srcnat" || name == "dstnat" then
          "nat"
        else if name == "mangle" then
          "route"
        else
          "filter";
    in
    if validChainPlacement family classified hook then classified else "filter";
in
{
  inherit
    chainTypeFor
    familiesByChainType
    hooksByChainType
    hooksByFamily
    hooksWithOifname
    prioritiesByFamily
    priorityName
    priorityValue
    validChainPlacement
    ;
}
