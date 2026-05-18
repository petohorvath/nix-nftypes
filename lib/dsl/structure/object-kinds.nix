{ lib, objects }:

# Single source of truth for the DSL's object-kind registry — the table
# both `commands.nix` (top-level `create.<kind>`/`delete.<kind>`/… builders)
# and `render.nix` (the declarative table-tree expander) read to map each
# kind's DSL surface to its JSON command tag, the schema submodule used
# for evalModules validation, and the DSL-key → JSON-key rename function
# applied to user bodies before validation.
#
# Singular dsl-key is the canonical surface; the `plural` field is the
# attribute name used inside a `dsl.table` body's tree (e.g. `set` lives
# under `sets`, `synproxy` under `synproxies` — note the `y → ies`). The
# pluralization is per-entry and explicit because the irregular forms
# don't follow a single rule.
#
# Two callers transform the table differently:
#   - `commands.nix` keys by singular (`addObjectKinds.set`), and adds
#     `table` / `chain` / `rule` itself since those aren't table-tree
#     kinds (chains live under `chains.<name>` and rules under
#     `chains.<name>.rules`, both handled by the tree expander).
#   - `render.nix` keys by plural (`objectKinds.sets`), iterating each
#     present plural to emit one `add <tag>` per named entry.

let
  rename = import ../internal/rename.nix { inherit lib; };
in
{
  set = {
    tag = "set";
    plural = "sets";
    renameBody = rename.set;
    body = objects.setObjectBody;
  };
  map = {
    tag = "map";
    plural = "maps";
    renameBody = rename.set;
    body = objects.mapObjectBody;
  };
  element = {
    tag = "element";
    plural = "elements";
    renameBody = rename.element;
    body = objects.elementBody;
  };
  flowtable = {
    tag = "flowtable";
    plural = "flowtables";
    renameBody = lib.id;
    body = objects.flowtableBody;
  };
  counter = {
    tag = "counter";
    plural = "counters";
    renameBody = lib.id;
    body = objects.counterObjectBody;
  };
  quota = {
    tag = "quota";
    plural = "quotas";
    renameBody = lib.id;
    body = objects.quotaObjectBody;
  };
  limit = {
    tag = "limit";
    plural = "limits";
    renameBody = lib.id;
    body = objects.limitObjectBody;
  };
  ctHelper = {
    tag = "ct helper";
    plural = "ctHelpers";
    renameBody = lib.id;
    body = objects.ctHelperObjectBody;
  };
  ctTimeout = {
    tag = "ct timeout";
    plural = "ctTimeouts";
    renameBody = lib.id;
    body = objects.ctTimeoutObjectBody;
  };
  ctExpectation = {
    tag = "ct expectation";
    plural = "ctExpectations";
    renameBody = lib.id;
    body = objects.ctExpectationObjectBody;
  };
  secmark = {
    tag = "secmark";
    plural = "secmarks";
    renameBody = lib.id;
    body = objects.secmarkObjectBody;
  };
  synproxy = {
    tag = "synproxy";
    plural = "synproxies";
    renameBody = lib.id;
    body = objects.synproxyObjectBody;
  };
  # Tunnel bodies have hyphenated top-level keys (src-ipv4, …). The
  # nested `tunnel` attribute's shape depends on `type` and isn't renamed
  # here — users of geneve options write the hyphenated keys directly.
  tunnel = {
    tag = "tunnel";
    plural = "tunnels";
    renameBody = rename.tunnel;
    body = objects.tunnelObjectBody;
  };
}
