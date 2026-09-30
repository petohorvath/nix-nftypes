{
  description = "Nix type definitions mirroring the libnftables-json schema";

  # The library targets BOTH nixpkgs flake inputs: `nixpkgs` is the current
  # NixOS stable release (the compatibility floor consumers deploy on) and
  # `nixpkgs-unstable` tracks the branch where a newer nftables lands first.
  # Every package-set-dependent check is instantiated against both — the
  # stable set keeps the plain names, the unstable set gets an `-unstable`
  # suffix — so a divergence between the two package sets' `nft` (or `lib`
  # module system) turns a check red instead of surfacing in a consumer's
  # deployment (see tests/default.nix). When a new NixOS release becomes
  # stable, repoint `nixpkgs` here (see docs/upstream-sync.md, "Updating
  # inputs").
  #
  # nftables has no independent flake input. Each compatibility surface uses
  # the exact binary, release source, and downstream patches carried by its
  # nixpkgs package set. This keeps the test oracle identical to what
  # consumers install and avoids a second, fragile upstream-Git authority.
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      # The library itself is platform-independent. Packages and checks
      # invoke Linux-only nftables/network-namespace tooling.
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      imports = [ flake-parts.flakeModules.partitions ];

      partitions.dev.module = ./dev;
      partitionedAttrs = {
        checks = "dev";
        devShells = "dev";
        formatter = "dev";
      };

      perSystem =
        { pkgs, system, ... }:
        {
          packages = import ./packages {
            inherit pkgs;
            pkgsUnstable = inputs.nixpkgs-unstable.legacyPackages.${system};
          };
        };

      flake.lib = import ./lib { inherit (nixpkgs) lib; };
    };
}
