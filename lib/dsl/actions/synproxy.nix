# Synproxy statement, which answers TCP handshakes on behalf of a backend.
{ lib, statement }:

let
  inherit (import ../internal/location.nix { inherit lib; }) fail;
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Proxy the TCP handshake.

    `synproxy { mss?; wscale?; flags?; }` builds an anonymous configuration
    from the maximum segment size, window scale, and flags, at least one
    of them: nft rejects an empty body, so `synproxy { }` throws and points
    to `synproxy.auto`. `synproxy.ref ref` references a named synproxy
    object, as `counter.ref` does. `synproxy.auto` is the null-body form.
    Each returns a synproxy statement; `synproxy { … }` and `synproxy.ref`
    throw when their body doesn't validate.
  */
  synproxy =
    variant "synproxy"
      (statement.fromFields {
        name = "synproxy";
        prepare =
          location: body:
          if body == { } then
            fail location "nft rejects an empty synproxy body; give mss, wscale, or flags, or use synproxy.auto for the null form"
          else
            body;
      })
      {
        auto = {
          synproxy = null;
        };
        ref = statement.ref { name = "synproxy"; };
      };
}
