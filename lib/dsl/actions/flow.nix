# Flow-offload, meter, and verdict-map statements.
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
in
{
  /*
    Offload the flow to a flowtable. `flowtable` is the flowtable name and
    `op` the operation, `"add"` by default. Returns a flow statement.
  */
  flow =
    {
      op ? "add",
      flowtable,
    }:
    {
      flow = { inherit op flowtable; };
    };

  /*
    Apply statements per key through a meter. `name` is the meter name, `key`
    the per-flow key expression, `stmt` the statement to apply, and `size`
    the optional maximum entry count. Returns a meter statement.
  */
  meter =
    {
      name,
      key,
      stmt,
      size ? null,
    }:
    {
      meter = compact {
        inherit
          name
          key
          stmt
          size
          ;
      };
    };

  /*
    Choose a verdict by looking up a key. `key` is the lookup expression and
    `data` the verdict map body or named map reference. Returns a vmap
    statement.
  */
  vmap = key: data: { vmap = { inherit key data; }; };
}
