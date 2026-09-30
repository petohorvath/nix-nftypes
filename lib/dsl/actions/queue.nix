# Queue statement, which hands packets to a userspace program.
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Pass matching packets to a userspace queue.

    `queue { num?; flags?; }` takes the optional queue number (or range)
    and queue flags. `queue.plain` is the empty form with every default.
    Each returns a queue statement.
  */
  queue =
    variant
      (
        {
          num ? null,
          flags ? null,
        }:
        {
          queue = compact { inherit num flags; };
        }
      )
      {
        plain = {
          queue = { };
        };
      };
}
