/*
  The protocols and fields `dsl.expr.payload` takes: each payload protocol
  nft's JSON parser looks up (proto_lookup_byname in src/parser_json.c),
  with the fields it looks up in the protocol's templates (src/proto.c),
  in nft's spelling and in template order. The enum extraction suite
  compares the table with the patched nftables source.

  The parser also takes forms nft does not load as written, which the
  table leaves out (tests/helpers/token-drift.nix lists them):
  - `l4proto` of `ip`, `ip6`, `gre`, and `gretap`, a template for the
    `meta l4proto` dependency, which nft loads as a header field at offset
    0, such as `ip version 0 ip hdrlength 6` for `ip l4proto 6`; `gretap`
    has no other field;
  - `vxlan` and `geneve`, whose fields nft loads only through the tunnel
    form, `expr.payloadTunnel`.
*/
_: {
  ether = [
    "daddr"
    "saddr"
    "type"
  ];
  vlan = [
    "pcp"
    "dei"
    "cfi"
    "id"
    "type"
  ];
  arp = [
    "htype"
    "ptype"
    "hlen"
    "plen"
    "operation"
    "saddr ether"
    "saddr ip"
    "daddr ether"
    "daddr ip"
  ];
  ip = [
    "version"
    "hdrlength"
    "dscp"
    "ecn"
    "length"
    "id"
    "frag-off"
    "ttl"
    "protocol"
    "checksum"
    "saddr"
    "daddr"
  ];
  icmp = [
    "type"
    "code"
    "checksum"
    "id"
    "sequence"
    "gateway"
    "mtu"
  ];
  igmp = [
    "type"
    "mrt"
    "checksum"
    "group"
  ];
  ip6 = [
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
  icmpv6 = [
    "type"
    "code"
    "checksum"
    "parameter-problem"
    "mtu"
    "id"
    "sequence"
    "max-delay"
    "taddr"
    "daddr"
  ];
  ah = [
    "nexthdr"
    "hdrlength"
    "reserved"
    "spi"
    "sequence"
  ];
  esp = [
    "spi"
    "sequence"
  ];
  comp = [
    "nexthdr"
    "flags"
    "cpi"
  ];
  udp = [
    "sport"
    "dport"
    "length"
    "checksum"
  ];
  udplite = [
    "sport"
    "dport"
    "csumcov"
    "checksum"
  ];
  tcp = [
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
  dccp = [
    "sport"
    "dport"
    "type"
  ];
  sctp = [
    "sport"
    "dport"
    "vtag"
    "checksum"
  ];
  th = [
    "sport"
    "dport"
  ];
  gre = [
    "flags"
    "version"
    "protocol"
  ];
}
