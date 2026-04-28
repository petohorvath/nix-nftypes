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

  /*
    Source-of-truth value lists for every primitive enum. Consumed
    twice: by the `types.enum` calls below (producing `types.<name>`)
    and re-exported under `nftypes.lib.enums` via `default.nix`. A
    single binding prevents the two surfaces drifting; a unit test
    asserts `enums.<x> == types.<x>.functor.payload.values` per entry.
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

    policy = [
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

    xfrmDir = [
      "in"
      "out"
    ];

    xfrmKey = [
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
    # expression's l3-specific keys, NAT statement, and named-object
    # l3proto fields).
    ipFamily = [
      "ip"
      "ip6"
    ];

    ctDirection = [
      "original"
      "reply"
    ];

    ngMode = [
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

    perUnit = [
      "second"
      "minute"
      "hour"
      "day"
      "week"
    ];
  };

  family = types.enum enumValues.family;
  hook = types.enum enumValues.hook;
  policy = types.enum enumValues.policy;
  chainType = types.enum enumValues.chainType;
  operator = types.enum enumValues.operator;
  tableFlag = types.enum enumValues.tableFlag;
  setFlag = types.enum enumValues.setFlag;
  setPolicy = types.enum enumValues.setPolicy;
  logLevel = types.enum enumValues.logLevel;
  logFlag = types.enum enumValues.logFlag;
  natFlag = types.enum enumValues.natFlag;
  natTypeFlag = types.enum enumValues.natTypeFlag;
  synproxyFlag = types.enum enumValues.synproxyFlag;
  flowOp = types.enum enumValues.flowOp;
  xfrmDir = types.enum enumValues.xfrmDir;
  xfrmKey = types.enum enumValues.xfrmKey;
  tunnelKey = types.enum enumValues.tunnelKey;
  tunnelType = types.enum enumValues.tunnelType;
  queueFlag = types.enum enumValues.queueFlag;
  rejectType = types.enum enumValues.rejectType;
  setOp = types.enum enumValues.setOp;
  metaKey = types.enum enumValues.metaKey;
  rtKey = types.enum enumValues.rtKey;
  ipFamily = types.enum enumValues.ipFamily;
  ctDirection = types.enum enumValues.ctDirection;
  ngMode = types.enum enumValues.ngMode;
  fibResult = types.enum enumValues.fibResult;
  fibFlag = types.enum enumValues.fibFlag;
  payloadBase = types.enum enumValues.payloadBase;
  osfKey = types.enum enumValues.osfKey;
  osfTtl = types.enum enumValues.osfTtl;
  socketKey = types.enum enumValues.socketKey;
  tcpUdpProto = types.enum enumValues.tcpUdpProto;
  xtType = types.enum enumValues.xtType;
  limitUnit = types.enum enumValues.limitUnit;
  perUnit = types.enum enumValues.perUnit;

  listOrSingleton = elemType: types.either elemType (types.listOf elemType);
in
{
  inherit listOrSingleton enumValues;

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
