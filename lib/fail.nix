# A renderer's error helper. `fail api message` throws `message` from `api`,
# the renderer the caller called, such as `toText`: every error starts
# `nix-nftypes: <api>: ` (ADR 0009).
_: api: message:
throw "nix-nftypes: ${api}: ${message}"
