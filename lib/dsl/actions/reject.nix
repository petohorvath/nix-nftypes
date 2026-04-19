{ lib }:

# Reject statement. Six forms:
#   reject { type?; expr?; }    — arbitrary reject body
#   reject.plain                — empty reject (defaults)
#   reject.icmp code            — ICMP reject with code
#   reject.icmpv6 code          — ICMPv6 reject with code
#   reject.icmpx code           — ICMPX (family-independent) reject with code
#   reject.tcpReset             — TCP RST reject

let
  compact = import ../internal/compact.nix { inherit lib; };
  variant = import ../internal/variant.nix { inherit lib; };
in
{
  reject = variant
    (
      { type ? null, expr ? null }:
      { reject = compact { inherit type expr; }; }
    )
    {
      plain = { reject = { }; };
      icmp = code: { reject = { type = "icmp"; expr = code; }; };
      icmpv6 = code: { reject = { type = "icmpv6"; expr = code; }; };
      icmpx = code: { reject = { type = "icmpx"; expr = code; }; };
      tcpReset = { reject = { type = "tcp reset"; }; };
    };
}
