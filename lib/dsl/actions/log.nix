/*
  Log statement. `queueThreshold` is translated to the hyphenated JSON key
  `queue-threshold` by internal/rename.nix, so callers never write hyphens.
*/
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  rename = import ../internal/rename.nix { inherit lib; };
  location = import ../internal/location.nix { inherit lib; };
  at = location.builder [ "log" ];

  logInline =
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
        rename.log at {
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
    };
in
{
  /*
    Log matching packets.

    `log { prefix?; group?; snaplen?; queueThreshold?; level?; flags?; }`
    takes the optional log settings; null values are omitted, so `log { }`
    is the log statement with every default. Returns a log statement.
    Throws for `queue-threshold`, pointing to `queueThreshold`.
  */
  log = args: logInline (rename.checkSpelling.log at args);
}
