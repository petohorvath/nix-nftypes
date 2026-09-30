/*
  Payload escape hatches for fields missing from the pre-built `fields`
  tree. They cover the three disjoint forms from parser_json.c:660-733:
    1. named   { protocol; field; }         — covers fields.<proto>.<field>
    2. raw     { base; offset; len; }       — arbitrary bits under a base layer
    3. tunnel  { tunnel; protocol; field; } — inner-header access
*/
{ lib }:

{
  /*
    Reference a protocol header field by name. `protocol` is the header
    (for example `"tcp"`) and `field` its JSON field name. Returns a payload
    expression.
  */
  payload =
    { protocol, field }:
    {
      payload = { inherit protocol field; };
    };

  /*
    Reference raw bits when no named field exists. `base` is the header
    layer (`"ll"`, `"nh"`, `"th"`, …), `offset` and `len` are bit counts.
    Returns a payload expression.
  */
  payloadRaw =
    {
      base,
      offset,
      len,
    }:
    {
      payload = { inherit base offset len; };
    };

  /*
    Reference a field of a tunnel's inner header. `tunnel` names the
    tunnel header, `protocol` the inner header, and `field` its field.
    Returns a payload expression.
  */
  payloadTunnel =
    {
      tunnel,
      protocol,
      field,
    }:
    {
      payload = { inherit tunnel protocol field; };
    };
}
