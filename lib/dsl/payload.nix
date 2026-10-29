/*
  Payload escape hatches for fields missing from the pre-built `fields`
  tree. They cover the three disjoint forms from parser_json.c:660-733:
    1. named   protocol field               — covers fields.<proto>.<field>
    2. raw     { base; offset; len; }       — arbitrary bits under a base layer
    3. tunnel  { tunnel; protocol; field; } — inner-header access
  Each validates its form of the payload body when called
  (./internal/builder.nix).
*/
{ expression, expressionBodies }:

{
  /*
    Reference a protocol header field by name. `protocol` is the header
    (for example `"tcp"`) and `field` its JSON field name. Returns a payload
    expression.
  */
  payload =
    protocol: field:
    expression.tagged {
      name = "payload";
      type = expressionBodies.payloadNamedBody;
    } { inherit protocol field; };

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
