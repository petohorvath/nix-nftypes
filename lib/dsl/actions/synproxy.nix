{ lib }:

# Synproxy statement. Three forms:
#   synproxy { mss; wscale; flags?; }   — anonymous config
#   synproxy.ref e                       — named reference (string or expr)
#   synproxy.auto                        — null body (empty)

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  synproxy =
    variant
      (
        {
          mss,
          wscale,
          flags ? null,
        }:
        {
          synproxy = compact { inherit mss wscale flags; };
        }
      )
      {
        auto = {
          synproxy = null;
        };
        ref = e: { synproxy = e; };
      };
}
