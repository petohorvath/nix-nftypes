/*
  DSL-key → JSON-key rename maps, per-tag.

  User-facing DSL attribute names are translated to the JSON key names that
  nftables expects. Two kinds of rename apply:

    1. camelCase → hyphenated or underscored JSON keys (`queueThreshold`
       → `queue-threshold`, `gcInterval` → `gc-interval`, `rateUnit` →
       `rate_unit`, `typeFlags` → `type_flags`, …). Every DSL key is
       camelCase, whatever separator the JSON key uses.
    2. DSL-idiom renames where the JSON key is inconsistent with the
       library's plural-for-lists convention (`elements` → `elem`). These
       are deliberate divergences from the JSON spec — chosen so that
       list-valued table-body keys match the rest of the DSL (`rules`,
       `flags`, `chains`, `sets`, …).

  Builders and table preparation call the per-tag rename function on the
  user's arguments before handing them to the schema, so the DSL spelling
  never leaks into evalModules and the JSON spelling never leaks into user
  code.
*/
{ lib }:

let
  # Apply a { dslName = "jsonName"; } map to an attrset's keys. Keys
  # not in the map pass through unchanged.
  renameKeys = renames: attrs: lib.mapAttrs' (k: v: lib.nameValuePair (renames.${k} or k) v) attrs;
in
{
  log = renameKeys {
    queueThreshold = "queue-threshold";
  };

  # Shared by the limit statement and the named limit object.
  limit = renameKeys {
    rateUnit = "rate_unit";
    burstUnit = "burst_unit";
  };

  quota = renameKeys {
    valUnit = "val_unit";
    usedUnit = "used_unit";
  };

  nat = renameKeys {
    typeFlags = "type_flags";
  };

  # Shared rename for named-set and named-map bodies.
  # `elements` is a DSL-only name — the JSON schema (parser_json.c) uses
  # the singular `elem` regardless of whether the value is one element
  # or a list. We rename it to match the plural convention used for
  # `rules`, `flags`, `chains`, etc.
  set = renameKeys {
    gcInterval = "gc-interval";
    autoMerge = "auto-merge";
    elements = "elem";
  };

  # Same `elements` → `elem` rename for the standalone `element` object
  # kind (used to add elements to an existing set/map).
  element = renameKeys {
    elements = "elem";
  };

  metainfo = renameKeys {
    releaseName = "release_name";
    jsonSchemaVersion = "json_schema_version";
  };

  # A geneve tunnel's nested `tunnel` is a list of options, each carrying
  # `opt-type`; the vxlan and erspan nested attrsets need no rename.
  tunnel =
    body:
    let
      renamed = renameKeys {
        srcIpv4 = "src-ipv4";
        srcIpv6 = "src-ipv6";
        dstIpv4 = "dst-ipv4";
        dstIpv6 = "dst-ipv6";
      } body;
      renameGeneveOption = renameKeys { optType = "opt-type"; };
    in
    if builtins.isList (renamed.tunnel or null) then
      renamed // { tunnel = map renameGeneveOption renamed.tunnel; }
    else
      renamed;
}
