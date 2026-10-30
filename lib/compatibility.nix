/*
  compatibility — static reference data for nftables family×hook,
  family×chain-type, chain-type×hook, and family×hook×priority tables,
  plus helpers that look placements and priorities up in them:
  `priorityValue` (symbol → int), `priorityName` (int → symbol), and
  `validChainPlacement` ((family, chainType, hook) → bool). Every helper
  throws on a family, chain type, hook, or priority outside its table.

  Scope: what nft accepts on load. Conventions built on top of it, such
  as which chain type a priority suggests or the hooks where an
  `oifname` match can succeed, belong to the consumer.

  The known families, chain types, and hooks are the schema's `enums`,
  so the tables cannot drift from `types.family`, `types.chainType`,
  and `types.hook`.

  Sources: `man nft` Tables 6 (default families) and 7 (bridge
  family overrides), cross-checked against
  `include/uapi/linux/netfilter_ipv4.h` /
  `include/uapi/linux/netfilter_ipv6.h` /
  `include/uapi/linux/netfilter_bridge.h`, the kernel's
  `nf_chain_type` registrations in `net/netfilter/nf_tables_api.c`, and
  `std_prio_family_hook_compat` in nftables `src/rule.c`.

  Example:
    nftlib.compatibility.hooksByFamily.netdev
    # → [ "ingress" "egress" ]

    nftlib.compatibility.priorityValue "bridge" "input" "filter"
    # → -200

    nftlib.compatibility.priorityName "bridge" "input" (-200)
    # → "filter"

    nftlib.compatibility.validChainPlacement "ip" "nat" "forward"
    # → false  (nat does not attach at forward)
*/

{ enums, lib }:

let
  inherit (import ./word-list.nix { inherit lib; }) withValid;

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
    filter = enums.family;
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
    filter = enums.hook;
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
    the reverse lookup `priorityName`.
  */
  prioritiesByFamily =
    let
      prioritiesAtByFamily = {
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
          value = prioritiesAtByFamily.${family} hook;
        }) hooks
      )
    ) hooksByFamily;

  # `value` quoted when it's a string or an int, else its type. Unlike
  # ./describe.nix, it shows the value itself, which the error rejects.
  quoted =
    value:
    if builtins.isString value || builtins.isInt value then
      "'${toString value}'"
    else
      "of type ${builtins.typeOf value}";

  # Throws `message` from the helper `caller`.
  helperError = caller: message: throw "nix-nftypes: compatibility.${caller}: ${message}";

  # `value` when it is one of `valid`; otherwise `throwError`, such as
  # `helperError caller`, called with a message naming `what`, such as
  # `"family"`, with its plural `whats`.
  knownOrThrow =
    throwError: what: whats: valid: value:
    if builtins.isString value && builtins.elem value valid then
      value
    else
      throwError (withValid "unknown ${what} ${quoted value}" whats valid);

  /*
    The int of `priority` at `hook` of `family`, and `name`, the symbol
    nft accepts for it there, or null. An int passes through once the
    hook's table is forced, so an unknown family or a hook the family
    lacks throws for it too, as does a symbol nft rejects at the hook;
    each throw calls `throwError` with its message. When several symbols
    share a value (none today), `attrNames` order decides.
  */
  lookupPriority =
    throwError: family: hook: priority:
    let
      hooks = hooksByFamily.${knownOrThrow throwError "family" "families" enums.family family};
      priorities =
        if builtins.isString hook && builtins.elem hook hooks then
          prioritiesByFamily.${family}.${hook}
        else
          throwError (withValid "family '${family}' has no hook ${quoted hook}" "hooks" hooks);
      symbols = builtins.attrNames priorities;
      value =
        if builtins.isInt priority then
          builtins.seq priorities priority
        else if builtins.isString priority && priorities ? ${priority} then
          priorities.${priority}
        else
          throwError (
            withValid "family '${family}' has no priority ${quoted priority} at hook '${hook}'" "priorities" (
              [ "any int" ] ++ symbols
            )
          );
      matching = builtins.filter (symbol: priorities.${symbol} == value) symbols;
    in
    {
      inherit value;
      name = if matching == [ ] then null else builtins.head matching;
    };

  /*
    resolvePriority :: (string -> never) -> family -> hook
      -> (int | symbol) -> int

    `priorityValue` with its errors thrown by `throwError`, which takes
    the message without the helper's prefix. Internal: the DSL resolves a
    chain's Symbolic priority with it, so the error names the chain.
  */
  resolvePriority =
    throwError: family: hook: priority:
    (lookupPriority throwError family hook priority).value;

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
  priorityValue = resolvePriority (helperError "priorityValue");

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
      found = lookupPriority (helperError "priorityName") family hook priority;
    in
    if found.name == null then found.value else found.name;

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
      throwError = helperError "validChainPlacement";
      knownFamily = knownOrThrow throwError "family" "families" enums.family family;
      knownType = knownOrThrow throwError "chain type" "chain types" enums.chainType chainType;
      knownHook = knownOrThrow throwError "hook" "hooks" enums.hook hook;
    in
    builtins.elem knownFamily familiesByChainType.${knownType}
    && builtins.elem knownHook hooksByFamily.${knownFamily}
    && builtins.elem knownHook hooksByChainType.${knownType};

in
{
  inherit
    familiesByChainType
    hooksByChainType
    hooksByFamily
    prioritiesByFamily
    priorityName
    priorityValue
    resolvePriority
    validChainPlacement
    ;
}
