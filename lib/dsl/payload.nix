{ lib }:

# Payload escape hatches — the three disjoint forms from parser_json.c:660-733.
# Used when a field isn't in the pre-built tree under `fields`:
#   1. named   { protocol; field; }         — covers fields.<proto>.<field>
#   2. raw     { base; offset; len; }       — arbitrary bits under a base layer
#   3. tunnel  { tunnel; protocol; field; } — inner-header access

{
  payload =
    { protocol, field }:
    {
      payload = { inherit protocol field; };
    };

  payloadRaw =
    {
      base,
      offset,
      len,
    }:
    {
      payload = { inherit base offset len; };
    };

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
