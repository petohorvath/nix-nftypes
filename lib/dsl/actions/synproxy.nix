# Synproxy statement, which answers TCP handshakes on behalf of a backend.
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
  reference = import ../internal/reference.nix { inherit lib; };
in
{
  /*
    Proxy the TCP handshake.

    `synproxy { mss; wscale; flags?; }` builds an anonymous configuration
    from the maximum segment size, window scale, and optional flags.
    `synproxy.ref ref` references a named synproxy object, as
    `counter.ref` does. `synproxy.auto` is the null-body form. Each returns a
    synproxy statement.
  */
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
        ref = ref: { synproxy = reference.objectReference "synproxy.ref" ref; };
      };
}
