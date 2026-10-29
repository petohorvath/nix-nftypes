/*
  Payload escape hatches for fields missing from the pre-built `fields`
  tree. They cover the three disjoint forms from parser_json.c:660-733:
    1. named   protocol field               — covers fields.<proto>.<field>
    2. raw     { base; offset; len; }       — arbitrary bits under a base layer
    3. tunnel  { tunnel; protocol; field; } — inner-header access
  Each validates its form of the payload body when called
  (./internal/builder.nix); the named form also checks its protocol and
  field against `payloadFieldsByProtocol` (../schema/payload-fields.nix).
*/
{
  expression,
  expressionBodies,
  lib,
  payloadFieldsByProtocol,
}:

let
  inherit (import ./internal/location.nix { inherit lib; }) fail;
  inherit (import ../word-list.nix { inherit lib; }) withValid;

  location = expression.locationOf [ "payload" ];

  # `body` once its string protocol and field are in the table. A
  # non-string is left to the body's type, which names its option.
  known =
    { protocol, field }@body:
    let
      fields = payloadFieldsByProtocol.${protocol} or null;
    in
    if !builtins.isString protocol || !builtins.isString field then
      body
    else if fields == null then
      fail location (
        withValid "unknown protocol '${protocol}'" "protocols" (builtins.attrNames payloadFieldsByProtocol)
      )
    else if !builtins.elem field fields then
      fail location (withValid "unknown ${protocol} field '${field}'" "${protocol} fields" fields)
    else
      body;
in
{
  /*
    Reference a protocol header field by name. `protocol` is the header
    (for example `"tcp"`) and `field` its JSON field name, in nft's
    spelling (`"frag-off"`). Both must be in `enums.payloadFieldsByProtocol`.
    Returns a payload expression.
  */
  payload =
    protocol: field:
    expression.tagged
      {
        name = "payload";
        type = expressionBodies.payloadNamedBody;
      }
      (known {
        inherit protocol field;
      });

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
