{
  description = "Nix type definitions mirroring the libnftables-json schema";

  # `nixpkgs` is the NixOS stable release consumers deploy on and
  # `nixpkgs-unstable` is the branch where a newer nftables lands first; the
  # checks cover both. nftables has no independent flake input (see
  # tests/default.nix and docs/upstream-sync.md).
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
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

      flake.lib = import ./lib { inherit (inputs.nixpkgs) lib; };
    };
}
