{ lib }:

let
  inherit (lib) types mkOptionType;

  nullType = mkOptionType {
    name = "null";
    description = "null literal";
    descriptionClass = "noun";
    check = x: x == null;
    merge = lib.mergeEqualOption;
  };

  portNumber = types.ints.between 0 65535;
  prefixLength = types.ints.between 0 128;

  familyType = types.enum [
    "ip"
    "ip6"
    "inet"
    "arp"
    "bridge"
    "netdev"
  ];

  hookType = types.enum [
    "prerouting"
    "input"
    "forward"
    "output"
    "postrouting"
    "ingress"
    "egress"
  ];

  policyType = types.enum [
    "accept"
    "drop"
  ];

  chainTypeType = types.enum [
    "filter"
    "nat"
    "route"
  ];

  operatorType = types.enum [
    "=="
    "!="
    "<"
    ">"
    "<="
    ">="
    "in"
  ];

  tableFlagType = types.enum [
    "dormant"
    "owner"
    "persist"
  ];

  setFlagType = types.enum [
    "constant"
    "interval"
    "timeout"
    "dynamic"
  ];

  setPolicyType = types.enum [
    "performance"
    "memory"
  ];

  logLevelType = types.enum [
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

  logFlagType = types.enum [
    "tcp sequence"
    "tcp options"
    "ip options"
    "skuid"
    "ether"
    "all"
  ];

  natFlagType = types.enum [
    "random"
    "fully-random"
    "persistent"
    "netmap"
  ];

  synproxyFlagType = types.enum [
    "timestamp"
    "sack-perm"
  ];

  flowOpType = types.enum [
    "add"
  ];

  xfrmDirType = types.enum [
    "in"
    "out"
  ];

  xfrmKeyType = types.enum [
    "saddr"
    "daddr"
    "reqid"
    "spi"
  ];

  tunnelKeyType = types.enum [
    "path"
    "id"
  ];

  queueFlagType = types.enum [
    "bypass"
    "fanout"
  ];

  rejectTypeType = types.enum [
    "tcp reset"
    "icmpx"
    "icmp"
    "icmpv6"
  ];

  # parser_json.c:2494-2502 accepts add/update/delete.
  setOpType = types.enum [
    "add"
    "update"
    "delete"
  ];

  # Meta keys — matches meta_templates[] in src/meta.c plus the backcompat
  # aliases accepted by meta_key_parse (ibriport, obriport, secpath).
  metaKeyType = types.enum [
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
  # (NFT_RT_NEXTHOP4, swapped to NEXTHOP6 when family=ip6), mtu (NFT_RT_TCPMSS),
  # ipsec (NFT_RT_XFRM — boolean: skb->dst->xfrm != NULL).
  rtKeyType = types.enum [
    "classid"
    "nexthop"
    "mtu"
    "ipsec"
  ];

  # `ip`/`ip6` family enum, used wherever the parser restricts a `family`
  # field to IPv4/IPv6 (rt expression, ipsec/xfrm expression, ct expression's
  # l3-specific keys, NAT statement, and named-object l3proto fields).
  ipFamilyType = types.enum [
    "ip"
    "ip6"
  ];

  ctDirectionType = types.enum [
    "original"
    "reply"
  ];

  ngModeType = types.enum [
    "inc"
    "random"
  ];

  # parser_json.c:1176-1182. "check" is the predicate form: result resolves
  # to NFT_FIB_RESULT_OIF with NFT_FIB_F_PRESENT flag set ("does this route
  # exist?" rather than a value lookup).
  fibResultType = types.enum [
    "oif"
    "oifname"
    "type"
    "check"
  ];

  fibFlagType = types.enum [
    "saddr"
    "daddr"
    "mark"
    "iif"
    "oif"
  ];

  payloadBaseType = types.enum [
    "ll"
    "nh"
    "th"
    "ih"
  ];

  # NAT statement `type_flags` (parser_json.c:2274-2283).
  natTypeFlagType = types.enum [
    "interval"
    "prefix"
    "concat"
  ];

  # parser_json.c:484-489 accepts "name" (default OSF lookup) and "version"
  # (sets NFT_OSF_F_VERSION).
  osfKeyType = types.enum [
    "name"
    "version"
  ];

  osfTtlType = types.enum [
    "loose"
    "skip"
  ];

  socketKeyType = types.enum [
    "transparent"
    "mark"
    "wildcard"
  ];

  # parser_json.c uses identical tcp/udp branching for ct helper
  # (parser_json.c:3795-3802), ct timeout (parser_json.c:3815-3823), and ct
  # expectation (parser_json.c:3844-3852) `protocol` fields. Adoc lists more
  # protocols for ct timeout but those aren't honoured by the JSON path.
  tcpUdpProtoType = types.enum [
    "tcp"
    "udp"
  ];

  xtTypeType = types.enum [
    "match"
    "target"
    "watcher"
  ];

  limitUnitType = types.enum [
    "packets"
    "bytes"
  ];

  perUnitType = types.enum [
    "second"
    "minute"
    "hour"
    "day"
    "week"
  ];

  listOrSingleton = elemType: types.either elemType (types.listOf elemType);
in
{
  inherit listOrSingleton;

  types = {
    inherit
      familyType
      hookType
      policyType
      chainTypeType
      operatorType
      tableFlagType
      setFlagType
      setPolicyType
      logLevelType
      logFlagType
      natFlagType
      natTypeFlagType
      synproxyFlagType
      flowOpType
      xfrmDirType
      xfrmKeyType
      tunnelKeyType
      queueFlagType
      rejectTypeType
      setOpType
      metaKeyType
      rtKeyType
      ipFamilyType
      ctDirectionType
      ngModeType
      fibResultType
      fibFlagType
      payloadBaseType
      osfKeyType
      osfTtlType
      socketKeyType
      tcpUdpProtoType
      xtTypeType
      limitUnitType
      perUnitType
      portNumber
      prefixLength
      nullType
      ;
  };
}
