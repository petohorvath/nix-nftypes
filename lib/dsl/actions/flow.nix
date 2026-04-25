{ lib }:

# Flow-offload, meter, and vmap statements.

let
  compact = import ../internal/compact.nix { inherit lib; };
in
{
  flow =
    {
      op ? "add",
      flowtable,
    }:
    {
      flow = { inherit op flowtable; };
    };

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

  vmap = key: data: { vmap = { inherit key data; }; };
}
