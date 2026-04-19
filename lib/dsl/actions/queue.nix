{ lib }:

# Queue statement. Two forms:
#   queue { num?; flags?; }
#   queue.plain              — empty queue (all defaults)

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  queue = variant
    (
      { num ? null, flags ? null }:
      { queue = compact { inherit num flags; }; }
    )
    {
      plain = { queue = { }; };
    };
}
