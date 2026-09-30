# Reject statement, which drops a packet and answers the sender.
{ lib }:

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  /*
    Reject matching packets.

    `reject { type?; expr?; }` builds an arbitrary reject body.
    `reject.plain` is the empty form. `reject.icmp code`,
    `reject.icmpv6 code`, and `reject.icmpx code` answer with an ICMP,
    ICMPv6, or family-independent ICMPX `code`. `reject.tcpReset` answers
    with a TCP RST. Each returns a reject statement.
  */
  reject =
    variant
      (
        {
          type ? null,
          expr ? null,
        }:
        {
          reject = compact { inherit type expr; };
        }
      )
      {
        plain = {
          reject = { };
        };
        icmp = code: {
          reject = {
            type = "icmp";
            expr = code;
          };
        };
        icmpv6 = code: {
          reject = {
            type = "icmpv6";
            expr = code;
          };
        };
        icmpx = code: {
          reject = {
            type = "icmpx";
            expr = code;
          };
        };
        tcpReset = {
          reject = {
            type = "tcp reset";
          };
        };
      };
}
