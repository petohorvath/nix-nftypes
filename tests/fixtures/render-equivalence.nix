/*
  What Render equivalence runs: the forms each Integration case loads
  through, how each form is rendered, and the named exclusions. The probe
  (../helpers/probes/nft.nix) loads each form in its own network namespace and
  records `nft list ruleset`; the suite
  (../integration/render-equivalence.nix) compares each text listing with the
  JSON listing.
*/
{
  integrationCases,
  lib,
  nftlib,
}:
let
  inherit (import ../../lib/table-tree-marker.nix { }) isTableTree;

  # A table node in block form, wrapped as a host module would wrap it.
  # Any other child stays an imperative command, rendered alone: the block
  # form concatenates the children's renders as they are, so it also
  # loads `toText a + toText b`.
  renderBlockChild =
    child:
    if isTableTree child then
      "table ${child.family} ${child.name} {\n${nftlib.toTextBlock child}}\n"
    else
      nftlib.toText { nftables = [ child ]; };

  # A text form after the case's `textDefines`, one `define` line each.
  withDefines =
    case: text:
    lib.concatStrings (
      lib.mapAttrsToList (name: value: "define ${name} = \"${value}\"\n") (case.textDefines or { })
    )
    + text;
in
rec {
  inherit (integrationCases) cases;

  /*
    Each form's renderer, from an Integration case. Every case has the
    JSON form and both imperative forms. A case given as `children` also
    has block form: each table node in compact block form, wrapped in
    `table <family> <name> { … }`, and each other command in compact
    imperative form. Each text form starts with the case's `textDefines`.
  */
  render = {
    json = case: nftlib.toJson case.ruleset;
    compact = case: withDefines case (nftlib.toText case.ruleset);
    pretty = case: withDefines case (nftlib.toTextPretty case.ruleset);
    block = case: withDefines case (lib.concatMapStrings renderBlockChild (lib.flatten case.children));
  };

  # The forms a case has.
  formNames =
    case:
    [
      "json"
      "compact"
      "pretty"
    ]
    ++ lib.optional (case ? children) "block";

  # Forms that raise a Refusal, which ADR 0001 allows instead of loading:
  # `<case>.<form>` is a pattern the refusal's message matches. The probe
  # skips these forms and the suite asserts they still refuse.
  refusals = {
    commented-set-and-map =
      let
        jsonIgnored = "nix-nftypes: toText(Pretty|Block|BlockPretty)?: refusing\\s+to\\s+render\\s+a\\s+field\\s+that\\s+nft's\\s+JSON\\s+parser\\s+ignores[\\s\\S]*Field: (set|map) comment\\.";
      in
      {
        compact = jsonIgnored;
        pretty = jsonIgnored;
        block = jsonIgnored;
      };
  };

  /*
    Named exclusions: forms whose listing differs from the JSON listing.
    The suite asserts that each one still differs, so a fixed form fails
    until its entry goes. Each entry is `<case>.<form> = { reason; … }`:
    - `knownDifferences`: a Known difference, documented in
      docs/text-coverage.md;
    - `pending`: a bug that the open ticket under #24 named by `ticket`
      fixes. That ticket removes its own entries.
    An entry with `from` or `before` applies only to nft versions from
    `from` on, or older than `before`.
  */
  knownDifferences = {
    typeof-verdict-map =
      let
        typeofVerdictMap.reason = "nft's JSON parser declares a typeof map with a verdict value with `type`, while text keeps its `typeof`";
      in
      {
        compact = typeofVerdictMap;
        pretty = typeofVerdictMap;
        block = typeofVerdictMap;
      };
  };
  pending = { };

  # The forms the probe loads for a case.
  loadedForms =
    case: builtins.filter (form: !((refusals.${case.name} or { }) ? ${form})) (formNames case);

  # The named exclusion for `form` of `case` on nft `version`, or null.
  exclusionOn =
    version: case: form:
    let
      entries = builtins.filter (entry: entry != null) [
        (knownDifferences.${case.name}.${form} or null)
        (pending.${case.name}.${form} or null)
      ];
      appliesOn =
        entry:
        !(entry ? from && lib.versionOlder version entry.from)
        && !(entry ? before && !(lib.versionOlder version entry.before));
    in
    lib.findFirst appliesOn null entries;
}
