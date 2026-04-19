{ lib }:

# Address-translation statements: snat, dnat, masquerade, redirect, fwd,
# dup, tproxy. SNAT/DNAT take the full NAT body; masquerade/redirect are a
# reduced port+flags form with an added `.plain` variant for an empty body.

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };

  natBase =
    tag:
    {
      addr ? null,
      family ? null,
      port ? null,
      flags ? null,
      type_flags ? null,
    }:
    {
      ${tag} = compact {
        inherit
          addr
          family
          port
          flags
          type_flags
          ;
      };
    };

  masqBase =
    tag:
    { port ? null, flags ? null }:
    { ${tag} = compact { inherit port flags; }; };
in
{
  snat = natBase "snat";
  dnat = natBase "dnat";

  masquerade = variant (masqBase "masquerade") {
    plain = { masquerade = { }; };
  };

  redirect = variant (masqBase "redirect") {
    plain = { redirect = { }; };
  };

  fwd =
    {
      dev,
      family ? null,
      addr ? null,
    }:
    { fwd = compact { inherit dev family addr; }; };

  dup =
    { addr, dev ? null }:
    { dup = compact { inherit addr dev; }; };

  tproxy =
    {
      family ? null,
      addr ? null,
      port ? null,
    }:
    { tproxy = compact { inherit family addr port; }; };
}
