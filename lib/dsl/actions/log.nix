/*
  Log statement. `queueThreshold` is translated to the hyphenated JSON key
  `queue-threshold` by internal/rename.nix, so callers never write hyphens.
*/
{ statement, ... }:

{
  /*
    Log matching packets.

    `log { prefix?; group?; snaplen?; queueThreshold?; level?; flags?; }`
    takes the optional log settings; null values are omitted, so `log { }`
    is the log statement with every default. Returns a log statement.
    Throws when the body doesn't validate, and for `queue-threshold`,
    pointing to `queueThreshold`.
  */
  log = statement.fromFields { name = "log"; };
}
