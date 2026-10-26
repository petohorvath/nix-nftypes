/*
  Address-translation statements: snat, dnat, masquerade, redirect, fwd,
  dup, and tproxy. SNAT/DNAT take the full NAT body; masquerade/redirect take
  a reduced port-and-flags body.
*/
{ statement, ... }:

{
  /*
    Rewrite the source address.

    `snat { addr?; family?; port?; flags?; typeFlags?; }` takes `addr`, the
    new address, `port`, the new port, or both: the kernel refuses an snat
    with neither. `family` is the address family, `flags` the NAT flags,
    and `typeFlags` the address-type flags. Null values are omitted.
    Returns an snat statement, and throws when the body doesn't validate.
  */
  snat = statement.fromFields { name = "snat"; };

  /*
    Rewrite the destination address.

    `dnat { addr?; family?; port?; flags?; typeFlags?; }` takes `addr`, the
    new address, `port`, the new port, or both: the kernel refuses a dnat
    with neither. `family` is the address family, `flags` the NAT flags,
    and `typeFlags` the address-type flags. Null values are omitted.
    Returns a dnat statement, and throws when the body doesn't validate.
  */
  dnat = statement.fromFields { name = "dnat"; };

  /*
    Rewrite the source address to the outgoing interface's address.

    `masquerade { port?; flags?; }` takes an optional port and NAT flags;
    `masquerade { }` is the empty form. Returns a masquerade statement,
    and throws when the body doesn't validate.
  */
  masquerade = statement.fromFields { name = "masquerade"; };

  /*
    Redirect the packet to the local machine.

    `redirect { port?; flags?; }` takes an optional port and NAT flags;
    `redirect { }` is the empty form. Returns a redirect statement, and
    throws when the body doesn't validate.
  */
  redirect = statement.fromFields { name = "redirect"; };

  /*
    Forward the packet out of a device.

    `fwd { dev; family?; addr?; }` takes the output device `dev`, and
    `family` and `addr` optionally select a next hop. Returns a fwd
    statement, and throws when the body doesn't validate.
  */
  fwd = statement.fromFields { name = "fwd"; };

  /*
    Duplicate the packet to another destination.

    `dup { addr; dev?; }` takes the destination address `addr` and the
    optional output device `dev`. Returns a dup statement, and throws when
    the body doesn't validate.
  */
  dup = statement.fromFields { name = "dup"; };

  /*
    Redirect the packet to a local socket without rewriting it.

    `tproxy { family?; addr?; port?; }` takes `addr`, the local address,
    `port`, the local port, or both: nft refuses a tproxy with neither.
    `family` is the address family. Null values are omitted. Returns a
    tproxy statement, and throws when the body doesn't validate.
  */
  tproxy = statement.fromFields { name = "tproxy"; };
}
