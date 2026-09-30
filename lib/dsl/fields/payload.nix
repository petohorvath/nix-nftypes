/*
  Pre-built payload fields. Each leaf is a plain expression attrset:
    fields.tcp.dport == { payload = { protocol = "tcp"; field = "dport"; }; }

  Attribute names use camelCase; the emitted JSON `field` string uses the
  hyphenated form that libnftables expects (e.g. `fragOff` → `"frag-off"`).
  For protocols or fields not covered here, fall back to
  `dsl.payload { protocol; field; }` in lib/dsl/payload.nix.
*/
{ lib }:

let
  mkLeaf = protocol: field: { payload = { inherit protocol field; }; };

  # Build `field → mkLeaf protocol field` for fields whose attribute and
  # JSON names coincide.
  mkProtocol = protocol: fields: lib.genAttrs fields (mkLeaf protocol);

  # As above, plus explicit camelCase → JSON renames for fields whose JSON
  # name contains hyphens.
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
    "cksumcov"
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
        packetTooBig = "packet-too-big";
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

  arp = mkProtocol "arp" [
    "htype"
    "ptype"
    "hlen"
    "plen"
    "operation"
    "saddr"
    "daddr"
  ];
}
