_:

# Shared predicate for nft `ifname`-typed set/map elements. The set body
# declares `type ifname;` and elements render bare into the
# `elements = { … }` clause — so an element string containing `,` lexes
# as TWO elements, silently widening the set to interfaces the user
# never declared. The kernel's `dev_valid_name` already rejects `/` `:`
# whitespace and `.` / `..` and >15-byte names; this predicate is the
# strict-superset that the renderer also requires (no `,` `;` `{` `}`
# `"` `\` `#` or control characters).
#
# Both the schema type (`primitives.types.ifname`) and the renderer's
# defence-in-depth assert (lib/text/objects.nix) consult this predicate,
# so the two layers cannot drift.

let
  # Bytes excluded from an unquoted ifname element. `[:space:]` covers
  # ASCII whitespace; `[:cntrl:]` covers NUL..0x1F + DEL. `\\` is the
  # regex-escaped backslash, matching one literal `\` byte.
  regex = ''[^/:[:space:],;{}"\\#[:cntrl:]]*'';

  # Full kernel-and-renderer-safe ifname predicate:
  #   - non-empty, ≤ IFNAMSIZ-1 (15) bytes
  #   - not `.` or `..`
  #   - byte-set excluded by `regex` above
  isSafe =
    s:
    builtins.isString s
    && builtins.stringLength s >= 1
    && builtins.stringLength s <= 15
    && s != "."
    && s != ".."
    && builtins.match regex s != null;

  # Return the first value in `vs` that is a plain string failing
  # `isSafe`, or `null` if every plain string is safe (non-string values
  # pass through). Shared scanner for the ifname-list surfaces — set/map
  # element walker, `chain.dev`, `flowtable.dev` — so callers can embed
  # the bad bytes in their error message verbatim.
  firstUnsafe =
    vs:
    let
      vList = if builtins.isList vs then vs else [ vs ];
      bads = builtins.filter (v: builtins.isString v && !(isSafe v)) vList;
    in
    if bads == [ ] then null else builtins.head bads;

  # Walk a set/map body and return the first plain-string element that
  # fails `isSafe`, or `null` if every plain-string element is safe (or
  # the body's `type` isn't `"ifname"` at all). Two callers — the DSL
  # emit step (lib/dsl/structure/render.nix) and the text renderer
  # (lib/text/objects.nix) — share this walker so the validation rule
  # cannot drift between layers.
  #
  # Permissive about non-string element shapes (range expressions,
  # tagged elem-with-options, [k, v] map pairs); only flags plain
  # strings carrying the ifname value. For map elements `[k, v]` the
  # KEY is what's typed `ifname` (the set/map's `type` field describes
  # the key datatype).
  badIfnameElement =
    body:
    let
      isIfname = (body.type or null) == "ifname";
      rawElems = body.elem or null;
      elemList =
        if rawElems == null then
          [ ]
        else if builtins.isList rawElems then
          rawElems
        else
          [ rawElems ];
      valueOf =
        e:
        if builtins.isList e && builtins.length e == 2 then
          builtins.elemAt e 0
        else if builtins.isAttrs e && e ? elem && (e.elem ? val) then
          e.elem.val
        else
          e;
    in
    if !isIfname then null else firstUnsafe (map valueOf elemList);
in
{
  inherit
    regex
    isSafe
    firstUnsafe
    badIfnameElement
    ;
}
