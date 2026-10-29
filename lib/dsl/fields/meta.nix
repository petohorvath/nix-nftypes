/*
  Meta-key leaves. Bare attribute access returns the expression:
    fields.meta.mark == { meta = { key = "mark"; }; }

  Key set mirrors meta_templates[] in nftables' src/meta.c, one leaf per
  key. `types.metaKey` also takes meta_key_parse's aliases `ibriport`,
  `obriport`, and `secpath` as raw input, but they name the same keys as
  `ibrname`, `obrname`, and `ipsec`, so they have no leaf.
*/
{ lib }:

let
  keys = [
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
  ];
in
lib.genAttrs keys (key: {
  meta = { inherit key; };
})
