{
  lib,
  nftSafeIfname,
  nftSafeLogPrefix,
  nftSafeString,
}:

let
  inherit (lib) mkOptionType types;

  nullLiteral = mkOptionType {
    name = "null";
    description = "null literal";
    descriptionClass = "noun";
    check = x: x == null;
    merge = lib.mergeEqualOption;
  };

  portNumber = types.ints.between 0 65535;
  prefixLength = types.ints.between 0 128;

  # A comment: a free-form string safe for rendering into nft's
  # quoted-string syntax (`comment "…"`; a log prefix has its own
  # `logPrefix`). The safe-character set lives in lib/nft-safe-string.nix;
  # the text renderer's defense-in-depth `assertSafeString` asserts the
  # same predicate, so neither path can drift. 128-byte length cap matches
  # kernel NFTNL_UDATA_COMMENT_MAXLEN.
  comment = mkOptionType {
    name = "comment";
    description = "nft-safe quoted string (no '\"', '\\', or control characters; ≤128 bytes)";
    descriptionClass = "noun";
    check = s: builtins.isString s && nftSafeString.isSafe s && builtins.stringLength s <= 128;
    merge = lib.mergeEqualOption;
  };

  # A log prefix nft loads as written: 1 to 127 bytes, no `$` (nft's text
  # expands `$name` there), and the quoted-string rules. See
  # lib/nft-safe-log-prefix.nix; the text renderer's `quoteLogPrefix`
  # checks the same predicate.
  logPrefix = mkOptionType {
    name = "logPrefix";
    description = "nft log prefix (1-127 bytes; no '$' '\"' '\\' or control characters)";
    descriptionClass = "noun";
    check = nftSafeLogPrefix.isSafe;
    merge = lib.mergeEqualOption;
  };

  # Interface name the kernel accepts (`dev_valid_name`) and text can
  # quote. See lib/nft-safe-ifname.nix for the rules; the text renderer's
  # `quoteIfname` checks the same predicate.
  ifname = mkOptionType {
    name = "ifname";
    description = "interface name (1-15 bytes; no '/' ':' whitespace (byte 0xA0 included) '\"' '\\' or control chars; not '.' or '..')";
    descriptionClass = "noun";
    check = nftSafeIfname.isSafe;
    merge = lib.mergeEqualOption;
  };

  # A named set, map or flowtable reference in a statement: `@` and a
  # name. nft's JSON parser rejects it without the `@` ("Illegal set
  # reference"), and the text renderer prints it as stored.
  namedReference = mkOptionType {
    name = "namedReference";
    description = "named reference (\"@\" followed by a name)";
    descriptionClass = "noun";
    check = s: builtins.isString s && lib.hasPrefix "@" s && builtins.stringLength s > 1;
    merge = lib.mergeEqualOption;
  };

  /*
    Source-of-truth value lists for every primitive enum. Consumed
    twice: by the `types.enum` calls below (producing `types.<name>`)
    and re-exported under `nftypes.lib.enums` via `default.nix`. A
    single binding prevents the two surfaces drifting. The enum
    extraction suite compares the table-backed lists with the patched
    nftables source.
  */
  enumValues = {
    family = [
      "ip"
      "ip6"
      "inet"
      "arp"
      "bridge"
      "netdev"
    ];

    hook = [
      "prerouting"
      "input"
      "forward"
      "output"
      "postrouting"
      "ingress"
      "egress"
    ];

    chainPolicy = [
      "accept"
      "drop"
    ];

    chainType = [
      "filter"
      "nat"
      "route"
    ];

    operator = [
      "=="
      "!="
      "<"
      ">"
      "<="
      ">="
      "in"
    ];

    tableFlag = [
      "dormant"
      "owner"
      "persist"
    ];

    setFlag = [
      "constant"
      "interval"
      "timeout"
      "dynamic"
    ];

    setPolicy = [
      "performance"
      "memory"
    ];

    logLevel = [
      "emerg"
      "alert"
      "crit"
      "err"
      "warn"
      "notice"
      "info"
      "debug"
      "audit"
    ];

    logFlag = [
      "tcp sequence"
      "tcp options"
      "ip options"
      "skuid"
      "ether"
      "all"
    ];

    natFlag = [
      "random"
      "fully-random"
      "persistent"
      "netmap"
    ];

    # NAT statement `type_flags` (parser_json.c:2274-2283).
    natTypeFlag = [
      "interval"
      "prefix"
      "concat"
    ];

    synproxyFlag = [
      "timestamp"
      "sack-perm"
    ];

    flowOp = [ "add" ];

    ipsecDirection = [
      "in"
      "out"
    ];

    ipsecKey = [
      "saddr"
      "daddr"
      "reqid"
      "spi"
    ];

    tunnelKey = [
      "path"
      "id"
    ];

    # Tunnel encapsulation kind for the tunnel named object's `type` field.
    tunnelType = [
      "vxlan"
      "erspan"
      "geneve"
    ];

    queueFlag = [
      "bypass"
      "fanout"
    ];

    rejectType = [
      "tcp reset"
      "icmpx"
      "icmp"
      "icmpv6"
    ];

    # parser_json.c:2494-2502 accepts add/update/delete.
    setOp = [
      "add"
      "update"
      "delete"
    ];

    # Meta keys — matches meta_templates[] in src/meta.c plus the backcompat
    # aliases accepted by meta_key_parse (ibriport, obriport, secpath).
    metaKey = [
      "length"
      "protocol"
      "nfproto"
      "l4proto"
      "priority"
      "mark"
      "iif"
      "iifname"
      "iiftype"
      "oif"
      "oifname"
      "oiftype"
      "skuid"
      "skgid"
      "nftrace"
      "rtclassid"
      "ibrname"
      "obrname"
      "pkttype"
      "cpu"
      "iifgroup"
      "oifgroup"
      "cgroup"
      "random"
      "ipsec"
      "iifkind"
      "oifkind"
      "ibrpvid"
      "ibrvproto"
      "time"
      "day"
      "hour"
      "secmark"
      "sdif"
      "sdifname"
      "broute"
      "ibrhwaddr"
      # Backwards-compatibility aliases (meta_key_parse 1020-1030)
      "ibriport"
      "obriport"
      "secpath"
    ];

    # parser_json.c:993-997 rt_key_tbl[]: classid (NFT_RT_CLASSID), nexthop
    # (NFT_RT_NEXTHOP4, swapped to NEXTHOP6 when family=ip6), mtu
    # (NFT_RT_TCPMSS), ipsec (NFT_RT_XFRM — boolean: skb->dst->xfrm != NULL).
    rtKey = [
      "classid"
      "nexthop"
      "mtu"
      "ipsec"
    ];

    # `ip`/`ip6` family enum, used wherever the parser restricts a `family`
    # field to IPv4/IPv6 (rt expression, ipsec/xfrm expression, ct
    # expression's l3-specific keys, NAT statement).
    ipFamily = [
      "ip"
      "ip6"
    ];

    # `l3proto` of the ct helper, timeout and expectation objects. nft
    # lists an object in an inet table with `inet` when none was given,
    # and accepts it on input (parser_json.c parse_family).
    ctL3Proto = [
      "ip"
      "ip6"
      "inet"
    ];

    ctDirection = [
      "original"
      "reply"
    ];

    numgenMode = [
      "inc"
      "random"
    ];

    # parser_json.c:1176-1182. "check" is the predicate form: result resolves
    # to NFT_FIB_RESULT_OIF with NFT_FIB_F_PRESENT flag set ("does this route
    # exist?" rather than a value lookup).
    fibResult = [
      "oif"
      "oifname"
      "type"
      "check"
    ];

    fibFlag = [
      "saddr"
      "daddr"
      "mark"
      "iif"
      "oif"
    ];

    payloadBase = [
      "ll"
      "nh"
      "th"
      "ih"
    ];

    # parser_json.c:484-489 accepts "name" (default OSF lookup) and "version"
    # (sets NFT_OSF_F_VERSION).
    osfKey = [
      "name"
      "version"
    ];

    osfTtl = [
      "loose"
      "skip"
    ];

    socketKey = [
      "transparent"
      "mark"
      "wildcard"
    ];

    # parser_json.c uses identical tcp/udp branching for ct helper
    # (parser_json.c:3795-3802), ct timeout (parser_json.c:3815-3823), and ct
    # expectation (parser_json.c:3844-3852) `protocol` fields. Adoc lists more
    # protocols for ct timeout but those aren't honoured by the JSON path.
    tcpUdpProto = [
      "tcp"
      "udp"
    ];

    xtType = [
      "match"
      "target"
      "watcher"
    ];

    limitUnit = [
      "packets"
      "bytes"
    ];

    timeUnit = [
      "second"
      "minute"
      "hour"
      "day"
      "week"
    ];
  };

  listOrSingleton = elemType: types.either elemType (types.listOf elemType);
in
{
  inherit enumValues listOrSingleton;

  # One `types.enum` per `enumValues` entry, plus the non-enum primitives.
  types = lib.mapAttrs (_: types.enum) enumValues // {
    inherit
      comment
      ifname
      logPrefix
      namedReference
      nullLiteral
      portNumber
      prefixLength
      ;
  };
}
