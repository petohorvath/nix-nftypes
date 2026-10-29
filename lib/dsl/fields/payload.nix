/*
  Pre-built payload fields. Each leaf is a plain expression attrset:
    fields.tcp.dport == { payload = { protocol = "tcp"; field = "dport"; }; }

  Attribute names use camelCase; the emitted JSON `field` string uses the
  hyphenated form that libnftables expects (e.g. `fragOff` → `"frag-off"`).
  For protocols or fields not covered here, fall back to
  `dsl.expr.payload protocol field` in lib/dsl/payload.nix.
*/
{ lib }:

let
  mkLeaf = protocol: field: { payload = { inherit protocol field; }; };

  # Build `field → mkLeaf protocol field` for fields whose leaf name is
  # nft's field name.
  mkProtocol = protocol: fields: lib.genAttrs fields (mkLeaf protocol);

  # As above, plus explicit camelCase leaf names for fields whose nft name
  # contains hyphens or spaces.
  mkProtocolWithRenames =
    protocol: fields: renames:
    (mkProtocol protocol fields) // lib.mapAttrs (_: mkLeaf protocol) renames;
in
{
  # -- Layer 4 ---------------------------------------------------------------
  tcp = mkProtocol "tcp" [
    "sport"
    "dport"
    "sequence"
    "ackseq"
    "doff"
    "reserved"
    "flags"
    "window"
    "checksum"
    "urgptr"
  ];

  udp = mkProtocol "udp" [
    "sport"
    "dport"
    "length"
    "checksum"
  ];

  udplite = mkProtocol "udplite" [
    "sport"
    "dport"
    "csumcov"
    "checksum"
  ];

  sctp = mkProtocol "sctp" [
    "sport"
    "dport"
    "vtag"
    "checksum"
  ];

  dccp = mkProtocol "dccp" [
    "sport"
    "dport"
    "type"
  ];

  ah = mkProtocol "ah" [
    "nexthdr"
    "hdrlength"
    "reserved"
    "spi"
    "sequence"
  ];

  esp = mkProtocol "esp" [
    "spi"
    "sequence"
  ];

  comp = mkProtocol "comp" [
    "nexthdr"
    "flags"
    "cpi"
  ];

  # nft's transport header, whatever the transport protocol (proto_th in
  # src/proto.c): the ports at the offsets TCP, UDP, UDP-Lite, SCTP, and
  # DCCP share.
  th = mkProtocol "th" [
    "sport"
    "dport"
  ];

  gre = mkProtocol "gre" [
    "flags"
    "version"
    "protocol"
  ];

  # -- Layer 3 ---------------------------------------------------------------
  ip =
    mkProtocolWithRenames "ip"
      [
        "version"
        "hdrlength"
        "dscp"
        "ecn"
        "length"
        "id"
        "ttl"
        "protocol"
        "checksum"
        "saddr"
        "daddr"
      ]
      {
        fragOff = "frag-off";
      };

  ip6 = mkProtocol "ip6" [
    "version"
    "dscp"
    "ecn"
    "flowlabel"
    "length"
    "nexthdr"
    "hoplimit"
    "saddr"
    "daddr"
  ];

  icmp = mkProtocol "icmp" [
    "type"
    "code"
    "checksum"
    "id"
    "sequence"
    "mtu"
    "gateway"
  ];

  igmp = mkProtocol "igmp" [
    "type"
    "mrt"
    "checksum"
    "group"
  ];

  icmpv6 =
    mkProtocolWithRenames "icmpv6"
      [
        "type"
        "code"
        "checksum"
        "id"
        "sequence"
        "mtu"
      ]
      {
        paramProblem = "parameter-problem";
        maxDelay = "max-delay";
      };

  # -- Layer 2 ---------------------------------------------------------------
  ether = mkProtocol "ether" [
    "saddr"
    "daddr"
    "type"
  ];

  vlan = mkProtocol "vlan" [
    "id"
    "pcp"
    "dei"
    "type"
  ];

  # nft splits each arp address by its hardware or protocol part.
  arp =
    mkProtocolWithRenames "arp"
      [
        "htype"
        "ptype"
        "hlen"
        "plen"
        "operation"
      ]
      {
        saddrEther = "saddr ether";
        saddrIp = "saddr ip";
        daddrEther = "daddr ether";
        daddrIp = "daddr ip";
      };
}
