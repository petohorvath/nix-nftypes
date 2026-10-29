/*
  Single source of truth for the DSL's object-kind registry — the table
  both `commands.nix` (top-level `create.<kind>`/`delete.<kind>`/… builders)
  and lib/table.nix (table preparation and rendering) read to map each
  kind's DSL surface to its JSON command tag, the schema submodule used
  for evalModules validation, and the DSL-key → JSON-key rename function
  applied to user bodies before validation.

  Singular dsl-key is the canonical surface; the `plural` field is the
  attribute name used inside a `dsl.table` body's tree (e.g. `set` lives
  under `sets`, `synproxy` under `synproxies` — note the `y → ies`). The
  pluralization is per-entry and explicit because the irregular forms
  don't follow a single rule.

  Two callers transform the table differently:
    - `commands.nix` keys by singular (`addObjectKinds.set`), and adds
      `table` / `chain` / `rule` / `element` itself since those aren't
      table-tree kinds (chains live under `chains.<name>` and rules under
      `chains.<name>.rules`, both handled by the tree expander; a tree
      gives a set or map its elements in its own body).
    - lib/table.nix keys by plural (`objectKinds.sets`), iterating each
      present plural to prepare named entries for command or block output.

  It has no tunnel: nft's JSON parser loads a tunnel's ports wrongly, and
  nft crashes on delete, destroy, and list of one (Known differences, see
  docs/spec-coverage.md).
*/
{ lib, objects }:

let
  rename = import ../internal/rename.nix { inherit lib; };
in
{
  set = {
    tag = "set";
    plural = "sets";
    renameBody = rename.set;
    body = objects.setBody;
  };
  map = {
    tag = "map";
    plural = "maps";
    renameBody = rename.map;
    body = objects.mapBody;
  };
  flowtable = {
    tag = "flowtable";
    plural = "flowtables";
    renameBody = rename.none;
    body = objects.flowtableBody;
  };
  counter = {
    tag = "counter";
    plural = "counters";
    renameBody = rename.none;
    body = objects.counterBody;
  };
  quota = {
    tag = "quota";
    plural = "quotas";
    renameBody = rename.quotaObject;
    body = objects.quotaBody;
  };
  limit = {
    tag = "limit";
    plural = "limits";
    renameBody = rename.limit;
    body = objects.limitBody;
  };
  ctHelper = {
    tag = "ct helper";
    plural = "ctHelpers";
    renameBody = rename.none;
    body = objects.ctHelperBody;
  };
  ctTimeout = {
    tag = "ct timeout";
    plural = "ctTimeouts";
    renameBody = rename.none;
    body = objects.ctTimeoutBody;
  };
  ctExpectation = {
    tag = "ct expectation";
    plural = "ctExpectations";
    renameBody = rename.none;
    body = objects.ctExpectationBody;
  };
  ctCount = {
    tag = "ct count";
    plural = "ctCounts";
    renameBody = rename.none;
    body = objects.ctCountBody;
  };
  secmark = {
    tag = "secmark";
    plural = "secmarks";
    renameBody = rename.none;
    body = objects.secmarkBody;
  };
  synproxy = {
    tag = "synproxy";
    plural = "synproxies";
    renameBody = rename.none;
    body = objects.synproxyBody;
  };
}
