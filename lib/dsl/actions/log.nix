{ lib }:

# Log statement. Two forms:
#   log { prefix?; group?; snaplen?; queueThreshold?; level?; flags?; }
#   log.plain              — empty log (all defaults)
#
# `queueThreshold` is translated to the hyphenated JSON key `queue-threshold`
# by internal/rename.nix; users never see hyphens.

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
in
{
  log = variant
    (
      {
        prefix ? null,
        group ? null,
        snaplen ? null,
        queueThreshold ? null,
        level ? null,
        flags ? null,
      }:
      {
        log = compact (rename.log {
          inherit
            prefix
            group
            snaplen
            queueThreshold
            level
            flags
            ;
        });
      }
    )
    {
      plain = { log = { }; };
    };
}
