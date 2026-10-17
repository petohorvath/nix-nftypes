# The evaluated examples, by name.
{ nftlib }:
{
  basicFirewall = import ../../examples/basic-firewall.nix { inherit nftlib; };
  basicFirewallDsl = import ../../examples/basic-firewall-dsl.nix { inherit nftlib; };
  homeRouterDsl = import ../../examples/home-router-dsl.nix { inherit nftlib; };
}
