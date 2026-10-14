# Queue statement, which hands packets to a userspace program.
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
in
{
  /*
    Pass matching packets to a userspace queue.

    `queue { num?; flags?; }` takes the optional queue number (or range)
    and queue flags; `queue { }` uses every default. Returns a queue
    statement.
  */
  queue =
    {
      num ? null,
      flags ? null,
    }:
    {
      queue = compact { inherit num flags; };
    };
}
