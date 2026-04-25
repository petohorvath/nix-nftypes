{ lib }:

# DSL-key → JSON-key rename maps, per-tag.
#
# User-facing DSL attribute names are translated to the JSON key names that
# nftables expects. Two kinds of rename apply:
#
#   1. camelCase → hyphenated JSON keys (`queueThreshold` → `queue-threshold`,
#      `gcInterval` → `gc-interval`, `srcIpv4` → `src-ipv4`, …).
#   2. DSL-idiom renames where the JSON key is inconsistent with the
#      library's plural-for-lists convention (`elements` → `elem`). These
#      are deliberate divergences from the JSON spec — chosen so that
#      list-valued table-body keys match the rest of the DSL (`rules`,
#      `flags`, `chains`, `sets`, …).
#
# Builders and the renderer call the per-tag rename function on the user's
# args before handing them to the schema, so the DSL spelling never leaks
# into evalModules and the JSON spelling never leaks into user code.

let
  # Apply a { dslName = "jsonName"; } map to an attrset's keys. Keys
  # not in the map pass through unchanged.
  applyMap = map: attrs: lib.mapAttrs' (k: v: lib.nameValuePair (map.${k} or k) v) attrs;
in
{
  log = applyMap {
    queueThreshold = "queue-threshold";
  };

  # Shared rename for named-set and named-map bodies.
  # `elements` is a DSL-only name — the JSON schema (parser_json.c) uses
  # the singular `elem` regardless of whether the value is one element
  # or a list. We rename it to match the plural convention used for
  # `rules`, `flags`, `chains`, etc.
  set = applyMap {
    gcInterval = "gc-interval";
    autoMerge = "auto-merge";
    elements = "elem";
  };

  # Same `elements` → `elem` rename for the standalone `element` object
  # kind (used to add elements to an existing set/map).
  element = applyMap {
    elements = "elem";
  };

  tunnel = applyMap {
    srcIpv4 = "src-ipv4";
    srcIpv6 = "src-ipv6";
    dstIpv4 = "dst-ipv4";
    dstIpv6 = "dst-ipv6";
  };
}
