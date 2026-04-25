{ lib }:

# Pre-built payload fields. Each leaf is a plain expression attrset:
#   fields.tcp.dport == { payload = { protocol = "tcp"; field = "dport"; }; }
#
# Attribute names use camelCase; the emitted JSON `field` string uses the
# hyphenated form that libnftables expects (e.g. `fragOff` → `"frag-off"`).
# For protocols or fields not covered here, fall back to
# `dsl.payload { protocol; field; }` in lib/dsl/payload.nix.

let
  mkLeaf = protocol: field: { payload = { inherit protocol field; }; };

  # Build `name → mkLeaf proto name` for fields whose attribute and JSON
  # names coincide.
  proto = name: fields: lib.genAttrs fields (mkLeaf name);

  # As above but with explicit camelCase → JSON mappings for fields whose
  # JSON name contains hyphens.
  protoMapped =
    name: direct: mapped:
    (proto name direct) // lib.mapAttrs (_: json: mkLeaf name json) mapped;
in
{
  # -- Layer 4 ---------------------------------------------------------------
  tcp = proto "tcp" [
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

  udp = proto "udp" [
    "sport"
    "dport"
    "length"
    "checksum"
  ];

  udplite = proto "udplite" [
    "sport"
    "dport"
    "cksumcov"
    "checksum"
  ];

  sctp = proto "sctp" [
    "sport"
    "dport"
    "vtag"
    "checksum"
  ];

  dccp = proto "dccp" [
    "sport"
    "dport"
    "type"
  ];

  ah = proto "ah" [
    "nexthdr"
    "hdrlength"
    "reserved"
    "spi"
    "sequence"
  ];

  esp = proto "esp" [
    "spi"
    "sequence"
  ];

  comp = proto "comp" [
    "nexthdr"
    "flags"
    "cpi"
  ];

  gre = proto "gre" [
    "flags"
    "version"
    "protocol"
  ];

  # -- Layer 3 ---------------------------------------------------------------
  ip =
    protoMapped "ip"
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

  ip6 = proto "ip6" [
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

  icmp = proto "icmp" [
    "type"
    "code"
    "checksum"
    "id"
    "sequence"
    "mtu"
    "gateway"
  ];

  icmpv6 =
    protoMapped "icmpv6"
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
  ether = proto "ether" [
    "saddr"
    "daddr"
    "type"
  ];

  vlan = proto "vlan" [
    "id"
    "pcp"
    "dei"
    "type"
  ];

  arp = proto "arp" [
    "htype"
    "ptype"
    "hlen"
    "plen"
    "operation"
    "saddr"
    "daddr"
  ];
}
