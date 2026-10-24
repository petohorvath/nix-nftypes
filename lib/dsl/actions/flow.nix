# Flow-offload, meter, and verdict-map statements.
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  reference = import ../internal/reference.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
in
{
  /*
    Offload the flow to a flowtable. `flowtable` is the flowtable name, with
    or without its leading `@`. Returns a flow statement that adds the flow
    to `"@<name>"`, nft's only flow operation; throws when `flowtable` is
    not a string.
  */
  flow = flowtable: {
    flow = {
      op = "add";
      flowtable = reference.atReference "flow" flowtable;
    };
  };

  /*
    Apply a statement per key through a meter. `name` is the meter name,
    `key` the per-flow key expression, `statement` the statement to apply,
    and `size` the optional maximum entry count. Returns a meter statement;
    throws for `stmt`, pointing to `statement`.
  */
  meter = rename.statementBuilder "meter" (
    renameBody:
    {
      name,
      key,
      statement,
      size ? null,
    }:
    {
      meter = compact (renameBody {
        inherit
          name
          key
          statement
          size
          ;
      });
    }
  );

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
