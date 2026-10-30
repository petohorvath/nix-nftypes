/*
  The payload forms a Field leaf can't express, from parser_json.c:660-733:
    1. raw     { base; offset; len; }       — arbitrary bits under a base layer
    2. tunnel  { tunnel; protocol; field; } — inner-header access
  A named field, `{ protocol; field; }`, is a Field leaf, such as
  `fields.tcp.dport`. Each validates its form of the payload body when
  called (./internal/builder.nix).
*/
{ expression, expressionBodies }:

{
  /*
    Reference raw bits when no named field exists. Takes `base`, the header
    layer (`"ll"`, `"nh"`, `"th"`, …), and `offset` and `len`, bit counts.
    Returns a payload expression.
  */
  payloadRaw = expression.fromFields {
    name = "payloadRaw";
    tag = "payload";
    type = expressionBodies.payloadRawBody;
  };

  /*
    Reference a field of a tunnel's inner header. Takes `tunnel`, the
    tunnel header, `protocol`, the inner header, and `field`, its field.
    Returns a payload expression.
  */
  payloadTunnel = expression.fromFields {
    name = "payloadTunnel";
    tag = "payload";
    type = expressionBodies.payloadTunnelBody;
  };
}
