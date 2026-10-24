# Synproxy statement, which answers TCP handshakes on behalf of a backend.
{ lib, statement }:

let
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Proxy the TCP handshake.

    `synproxy { mss; wscale; flags?; }` builds an anonymous configuration
    from the maximum segment size, window scale, and optional flags.
    `synproxy.ref ref` references a named synproxy object, as
    `counter.ref` does. `synproxy.auto` is the null-body form. Each returns a
    synproxy statement; `synproxy { … }` and `synproxy.ref` throw when their
    body doesn't validate.
  */
  synproxy = variant (statement.fromFields { name = "synproxy"; }) {
    auto = {
      synproxy = null;
    };
    ref = statement.ref { name = "synproxy"; };
  };
}
