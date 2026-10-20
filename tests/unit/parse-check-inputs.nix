/*
  The parse check's inputs (fixtures/parse-check.nix), checked without
  nft: every expected rejection names an enumerated check, its error, and
  either the open ticket under #24 that fixes it or the Known difference
  that explains it, and every per-check context names a check. When a fix
  removes or renames a leaf or a pin, these fail until its entries follow.
*/
{
  fixtures,
  lib,
  nftlib,
  ...
}:
let
  inherit (fixtures.parseCheck) checks contexts expectedRejections;

  inherit (nftlib) dsl;

  isTicket = ticket: lib.isInt ticket && ticket > 24 && ticket <= 53;
in
{
  testEveryRejectionNamesACheck = {
    expr = builtins.attrNames (removeAttrs expectedRejections (builtins.attrNames checks));
    expected = [ ];
  };

  testEveryRejectionNamesTicketOrReason = {
    expr = builtins.attrNames (
      lib.filterAttrs (
        _: entry: !(entry ? error && (isTicket (entry.ticket or null) != (entry ? reason)))
      ) expectedRejections
    );
    expected = [ ];
  };

  testEveryContextNamesACheck = {
    expr = builtins.attrNames (removeAttrs contexts (builtins.attrNames checks));
    expected = [ ];
  };

  # Each leaf check sends its leaf as written, so a rule context may place
  # a leaf but not refine it: a leaf nft loads only refined fails here
  # instead of passing the parse check.
  testLeafChecksSendTheLeafAsWritten = {
    expr = lib.concatLists (
      lib.mapAttrsToList (
        group: leaves:
        lib.concatLists (
          lib.mapAttrsToList (
            leaf: expression:
            lib.optional (
              !lib.hasInfix (builtins.toJSON expression) checks."leaf.json.${group}.${leaf}".subject
            ) "${group}.${leaf}"
          ) leaves
        )
      ) dsl.fields
    );
    expected = [ ];
  };

  # Every Field leaf, pinned. The parse check derives its leaf checks from
  # `dsl.fields`, so a removed, renamed or added leaf only changes which
  # leaves reach nft; this fails until the list changes on purpose.
  testFieldLeafInventory = {
    expr = lib.mapAttrs (_: builtins.attrNames) dsl.fields;
    expected = {
      ah = [
        "hdrlength"
        "nexthdr"
        "reserved"
        "sequence"
        "spi"
      ];
      arp = [
        "daddrEther"
        "daddrIp"
        "hlen"
        "htype"
        "operation"
        "plen"
        "ptype"
        "saddrEther"
        "saddrIp"
      ];
      comp = [
        "cpi"
        "flags"
        "nexthdr"
      ];
      ct = [
        "avgpkt"
        "bytes"
        "direction"
        "event"
        "expiration"
        "helper"
        "id"
        "l3proto"
        "label"
        "mark"
        "packets"
        "protocol"
        "secmark"
        "state"
        "status"
        "zone"
      ];
      dccp = [
        "dport"
        "sport"
        "type"
      ];
      esp = [
        "sequence"
        "spi"
      ];
      ether = [
        "daddr"
        "saddr"
        "type"
      ];
      gre = [
        "flags"
        "protocol"
        "version"
      ];
      icmp = [
        "checksum"
        "code"
        "gateway"
        "id"
        "mtu"
        "sequence"
        "type"
      ];
      icmpv6 = [
        "checksum"
        "code"
        "id"
        "maxDelay"
        "mtu"
        "paramProblem"
        "sequence"
        "type"
      ];
      ip = [
        "checksum"
        "daddr"
        "dscp"
        "ecn"
        "fragOff"
        "hdrlength"
        "id"
        "length"
        "protocol"
        "saddr"
        "ttl"
        "version"
      ];
      ip6 = [
        "daddr"
        "dscp"
        "ecn"
        "flowlabel"
        "hoplimit"
        "length"
        "nexthdr"
        "saddr"
        "version"
      ];
      meta = [
        "broute"
        "cgroup"
        "cpu"
        "day"
        "hour"
        "ibrhwaddr"
        "ibriport"
        "ibrname"
        "ibrpvid"
        "ibrvproto"
        "iif"
        "iifgroup"
        "iifkind"
        "iifname"
        "iiftype"
        "ipsec"
        "l4proto"
        "length"
        "mark"
        "nfproto"
        "nftrace"
        "obriport"
        "obrname"
        "oif"
        "oifgroup"
        "oifkind"
        "oifname"
        "oiftype"
        "pkttype"
        "priority"
        "protocol"
        "random"
        "rtclassid"
        "sdif"
        "sdifname"
        "secmark"
        "secpath"
        "skgid"
        "skuid"
        "time"
      ];
      osf = [
        "name"
        "version"
      ];
      rt = [
        "classid"
        "ipsec"
        "mtu"
        "nexthop"
      ];
      sctp = [
        "checksum"
        "dport"
        "sport"
        "vtag"
      ];
      socket = [
        "mark"
        "transparent"
        "wildcard"
      ];
      tcp = [
        "ackseq"
        "checksum"
        "doff"
        "dport"
        "flags"
        "reserved"
        "sequence"
        "sport"
        "urgptr"
        "window"
      ];
      tunnelMeta = [
        "id"
        "path"
      ];
      udp = [
        "checksum"
        "dport"
        "length"
        "sport"
      ];
      udplite = [
        "checksum"
        "csumcov"
        "dport"
        "sport"
      ];
      vlan = [
        "dei"
        "id"
        "pcp"
        "type"
      ];
    };
  };
}
