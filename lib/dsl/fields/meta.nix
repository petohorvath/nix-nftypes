{ lib }:

# Meta-key leaves. Bare attribute access returns the expression:
#   fields.meta.mark == { meta = { key = "mark"; }; }
#
# Key set mirrors primitives.metaKeyType (meta_templates[] in nftables'
# src/meta.c, plus the backcompat aliases accepted by meta_key_parse).

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
    # Backwards-compatibility aliases
    "ibriport"
    "obriport"
    "secpath"
  ];
in
lib.genAttrs keys (key: {
  meta = { inherit key; };
})
