/*
  Address-translation statements: snat, dnat, masquerade, redirect, fwd,
  dup, and tproxy. SNAT/DNAT take the full NAT body; masquerade/redirect take
  a reduced port-and-flags body plus a `.plain` variant for an empty body.
*/
{ lib }:

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

  masqueradeBase =
    tag:
    {
      port ? null,
      flags ? null,
    }:
    {
      ${tag} = compact { inherit port flags; };
    };
in
{
  /*
    Rewrite the source address. Every argument is optional and omitted when
    null: `addr` is the new address, `family` the address family, `port`
    the new port, `flags` the NAT flags, and `type_flags` the address-type
    flags. Returns an snat statement.
  */
  snat = natBase "snat";

  /*
    Rewrite the destination address. Every argument is optional and omitted
    when null: `addr` is the new address, `family` the address family,
    `port` the new port, `flags` the NAT flags, and `type_flags` the
    address-type flags. Returns a dnat statement.
  */
  dnat = natBase "dnat";

  /*
    Rewrite the source address to the outgoing interface's address.

    `masquerade { port?; flags?; }` takes an optional port and NAT flags.
    `masquerade.plain` is the empty form. Each returns a masquerade
    statement.
  */
  masquerade = variant (masqueradeBase "masquerade") {
    plain = {
      masquerade = { };
    };
  };

  /*
    Redirect the packet to the local machine.

    `redirect { port?; flags?; }` takes an optional port and NAT flags.
    `redirect.plain` is the empty form. Each returns a redirect
    statement.
  */
  redirect = variant (masqueradeBase "redirect") {
    plain = {
      redirect = { };
    };
  };

  /*
    Forward the packet out of a device. `dev` is the output device, and
    `family` and `addr` optionally select a next hop. Returns a fwd
    statement.
  */
  fwd =
    {
      dev,
      family ? null,
      addr ? null,
    }:
    {
      fwd = compact { inherit dev family addr; };
    };

  /*
    Duplicate the packet to another destination. `addr` is the destination
    address and `dev` the optional output device. Returns a dup statement.
  */
  dup =
    {
      addr,
      dev ? null,
    }:
    {
      dup = compact { inherit addr dev; };
    };

  /*
    Redirect the packet to a local socket without rewriting it. `family`,
    `addr`, and `port` are optional and omitted when null. Returns a tproxy
    statement.
  */
  tproxy =
    {
      family ? null,
      addr ? null,
      port ? null,
    }:
    {
      tproxy = compact { inherit family addr port; };
    };
}
