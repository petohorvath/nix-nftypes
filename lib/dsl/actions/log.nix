/*
  Log statement. `queueThreshold` is translated to the hyphenated JSON key
  `queue-threshold` by internal/rename.nix, so callers never write hyphens.
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
in
{
  /*
    Log matching packets.

    `log { prefix?; group?; snaplen?; queueThreshold?; level?; flags?; }`
    takes the optional log settings; null values are omitted. `log.plain` is
    the empty log statement with every default. Each returns a log statement.
  */
  log =
    variant
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
          log = compact (
            rename.log {
              inherit
                prefix
                group
                snaplen
                queueThreshold
                level
                flags
                ;
            }
          );
        }
      )
      {
        plain = {
          log = { };
        };
      };
}
