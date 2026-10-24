# Flow-offload, meter, and verdict-map statements.
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  reference = import ../internal/reference.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
  location = import ../internal/location.nix { inherit lib; };

  # The pattern names the DSL spellings; `meter` checks for a JSON spelling
  # first, so it throws pointing to its DSL name.
  meterInline =
    {
      name,
      key,
      statement,
      size ? null,
    }:
    {
      meter = compact {
        inherit name key size;
        stmt = statement;
      };
    };
in
{
  /*
    Offload the flow to a flowtable. `flowtable` is the flowtable name, with
    or without its leading `@`, and `op` the operation, `"add"` by default.
    Returns a flow statement referencing `"@<name>"`; throws when
    `flowtable` is not a string.
  */
  flow =
    {
      op ? "add",
      flowtable,
    }:
    {
      flow = {
        inherit op;
        flowtable = reference.atReference "flow" flowtable;
      };
    };

  /*
    Apply a statement per key through a meter. `name` is the meter name,
    `key` the per-flow key expression, `statement` the statement to apply,
    and `size` the optional maximum entry count. Returns a meter statement;
    throws for `stmt`, pointing to `statement`.
  */
  meter = args: meterInline (rename.checkSpelling.meter (location.builder [ "meter" ]) args);

  /*
    Choose a verdict by looking up a key. `key` is the lookup expression and
    `data` the verdict map body, or a named map's name with or without its
    leading `@`. Returns a vmap statement whose named map is `"@<name>"`.
  */
  vmap = key: data: {
    vmap = {
      inherit key;
      data = if builtins.isString data then reference.atReference "vmap" data else data;
    };
  };
}
