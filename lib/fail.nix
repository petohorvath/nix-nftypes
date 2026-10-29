# The error helper of a public function that takes no location, such as a
# renderer or `dsl.ruleset`. `fail api message` throws `message` from `api`,
# the function the caller called, such as `toText`: every error starts
# `nix-nftypes: <api>: ` (ADR 0009).
_: api: message:
throw "nix-nftypes: ${api}: ${message}"
