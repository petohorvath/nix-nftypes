{ lib }:

let
  inherit (lib) types mkOptionType;

  nullLiteral = mkOptionType {
    name = "null";
    description = "null literal";
    descriptionClass = "noun";
    check = x: x == null;
    merge = lib.mergeEqualOption;
  };

  portNumber = types.ints.between 0 65535;
  prefixLength = types.ints.between 0 128;

  family = types.enum [
    "ip"
    "ip6"
    "inet"
    "arp"
    "bridge"
    "netdev"
  ];

  hook = types.enum [
    "prerouting"
    "input"
    "forward"
    "output"
    "postrouting"
    "ingress"
    "egress"
  ];

  policy = types.enum [
    "accept"
    "drop"
  ];

  chainType = types.enum [
    "filter"
    "nat"
    "route"
  ];

  operator = types.enum [
    "=="
    "!="
    "<"
    ">"
    "<="
    ">="
    "in"
  ];

  tableFlag = types.enum [
    "dormant"
    "owner"
    "persist"
  ];

  setFlag = types.enum [
    "constant"
    "interval"
    "timeout"
    "dynamic"
  ];

  setPolicy = types.enum [
    "performance"
    "memory"
  ];

  logLevel = types.enum [
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

  logFlag = types.enum [
    "tcp sequence"
    "tcp options"
    "ip options"
    "skuid"
    "ether"
    "all"
  ];

  natFlag = types.enum [
    "random"
    "fully-random"
    "persistent"
    "netmap"
  ];

  synproxyFlag = types.enum [
    "timestamp"
    "sack-perm"
  ];

  flowOp = types.enum [
    "add"
  ];

  xfrmDir = types.enum [
    "in"
    "out"
  ];

  xfrmKey = types.enum [
    "saddr"
    "daddr"
    "reqid"
    "spi"
  ];

  tunnelKey = types.enum [
    "path"
    "id"
  ];

  queueFlag = types.enum [
    "bypass"
    "fanout"
  ];

  rejectType = types.enum [
    "tcp reset"
    "icmpx"
    "icmp"
    "icmpv6"
  ];

  # parser_json.c:2494-2502 accepts add/update/delete.
  setOp = types.enum [
    "add"
    "update"
    "delete"
  ];

  # Meta keys — matches meta_templates[] in src/meta.c plus the backcompat
  # aliases accepted by meta_key_parse (ibriport, obriport, secpath).
  metaKey = types.enum [
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
  rtKey = types.enum [
    "classid"
    "nexthop"
    "mtu"
    "ipsec"
  ];

  # `ip`/`ip6` family enum, used wherever the parser restricts a `family`
  # field to IPv4/IPv6 (rt expression, ipsec/xfrm expression, ct expression's
  # l3-specific keys, NAT statement, and named-object l3proto fields).
  ipFamily = types.enum [
    "ip"
    "ip6"
  ];

  ctDirection = types.enum [
    "original"
    "reply"
  ];

  ngMode = types.enum [
    "inc"
    "random"
  ];

  # parser_json.c:1176-1182. "check" is the predicate form: result resolves
  # to NFT_FIB_RESULT_OIF with NFT_FIB_F_PRESENT flag set ("does this route
  # exist?" rather than a value lookup).
  fibResult = types.enum [
    "oif"
    "oifname"
    "type"
    "check"
  ];

  fibFlag = types.enum [
    "saddr"
    "daddr"
    "mark"
    "iif"
    "oif"
  ];

  payloadBase = types.enum [
    "ll"
    "nh"
    "th"
    "ih"
  ];

  # NAT statement `type_flags` (parser_json.c:2274-2283).
  natTypeFlag = types.enum [
    "interval"
    "prefix"
    "concat"
  ];

  # parser_json.c:484-489 accepts "name" (default OSF lookup) and "version"
  # (sets NFT_OSF_F_VERSION).
  osfKey = types.enum [
    "name"
    "version"
  ];

  osfTtl = types.enum [
    "loose"
    "skip"
  ];

  socketKey = types.enum [
    "transparent"
    "mark"
    "wildcard"
  ];

  # parser_json.c uses identical tcp/udp branching for ct helper
  # (parser_json.c:3795-3802), ct timeout (parser_json.c:3815-3823), and ct
  # expectation (parser_json.c:3844-3852) `protocol` fields. Adoc lists more
  # protocols for ct timeout but those aren't honoured by the JSON path.
  tcpUdpProto = types.enum [
    "tcp"
    "udp"
  ];

  xtType = types.enum [
    "match"
    "target"
    "watcher"
  ];

  limitUnit = types.enum [
    "packets"
    "bytes"
  ];

  perUnit = types.enum [
    "second"
    "minute"
    "hour"
    "day"
    "week"
  ];

  # Tunnel encapsulation kind for the tunnel named object's `type` field.
  tunnelType = types.enum [
    "vxlan"
    "erspan"
    "geneve"
  ];

  listOrSingleton = elemType: types.either elemType (types.listOf elemType);
in
{
  inherit listOrSingleton;

  types = {
    inherit
      family
      hook
      policy
      chainType
      operator
      tableFlag
      setFlag
      setPolicy
      logLevel
      logFlag
      natFlag
      natTypeFlag
      synproxyFlag
      flowOp
      xfrmDir
      xfrmKey
      tunnelKey
      tunnelType
      queueFlag
      rejectType
      setOp
      metaKey
      rtKey
      ipFamily
      ctDirection
      ngMode
      fibResult
      fibFlag
      payloadBase
      osfKey
      osfTtl
      socketKey
      tcpUdpProto
      xtType
      limitUnit
      perUnit
      portNumber
      prefixLength
      nullLiteral
      ;
  };
}
