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

  rtKeyType = types.enum [
    "classid"
    "nexthop"
    "mtu"
  ];

  rtFamilyType = types.enum [
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

  fibResultType = types.enum [
    "oif"
    "oifname"
    "type"
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

  osfKeyType = types.enum [
    "name"
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

  ctHelperProtoType = types.enum [
    "tcp"
    "udp"
  ];

  # ct timeout and ct expectation objects: parser_json.c accepts only tcp/udp
  # (lines 3815-3823 for timeout, 3844-3852 for expectation). Adoc lists more
  # but those aren't honored by the JSON path.
  ctTimeoutProtoType = ctHelperProtoType;

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

  natFamilyType = types.enum [
    "ip"
    "ip6"
  ];

  listOrSingleton = elemType: types.either elemType (types.listOf elemType);
in
{
  inherit
    nullType
    portNumber
    prefixLength
    listOrSingleton
    ;

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
      rtFamilyType
      ctDirectionType
      ngModeType
      fibResultType
      fibFlagType
      payloadBaseType
      osfKeyType
      osfTtlType
      socketKeyType
      ctHelperProtoType
      ctTimeoutProtoType
      xtTypeType
      limitUnitType
      perUnitType
      natFamilyType
      portNumber
      prefixLength
      nullType
      ;
  };
}
