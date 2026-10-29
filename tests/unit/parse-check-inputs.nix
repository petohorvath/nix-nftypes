/*
  The parse check's inputs (fixtures/parse-check.nix), checked without
  nft: every expected rejection names an enumerated check, its error, and
  either the open ticket under #24 that fixes it or the Known difference
  that explains it, every per-check context names a check, and every leaf
  check sends its Field leaf as written. When a fix removes or renames a
  leaf or a pin, these fail until its entries follow.
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

  # The statements of the rules a check's JSON subject adds.
  ruleStatements =
    name:
    lib.concatMap (command: command.add.rule.expr or [ ])
      (builtins.fromJSON checks.${name}.subject).nftables;

  # Whether `value` holds `expression` unchanged at any depth.
  holds =
    expression: value:
    value == expression
    || lib.isAttrs value && lib.any (holds expression) (builtins.attrValues value)
    || lib.isList value && lib.any (holds expression) value;
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

  # Each leaf check sends its Field leaf as written, so a rule context may
  # place a leaf but not refine it: a leaf nft loads only refined fails
  # here instead of passing the parse check.
  testLeafChecksSendTheirFieldLeafAsWritten = {
    expr = lib.concatLists (
      lib.mapAttrsToList (
        group: leaves:
        lib.concatLists (
          lib.mapAttrsToList (
            leaf: expression:
            lib.optional (!holds expression (ruleStatements "leaf.json.${group}.${leaf}")) "${group}.${leaf}"
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
      igmp = [
        "checksum"
        "group"
        "mrt"
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
      th = [
        "dport"
        "sport"
      ];
      tunnel = [
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
