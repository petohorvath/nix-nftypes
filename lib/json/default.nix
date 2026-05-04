{ lib, clean }:

# JSON renderer — produces the libnftables-json form consumed by `nft -j -f`.
# `clean` is injected from lib/clean.nix so the text renderer can share it
# without depending on this module.

let
  toJson = value: builtins.toJSON (clean value);

  # Pretty-printed rendering via nix's builtin — useful for reading generated
  # output. Applies the same cleaning as toJson.
  toNix = value: lib.generators.toPretty { multiline = true; } (clean value);
in
{
  inherit toJson toNix;
}
