/*
  The development-only inputs, which the root flake loads into its `dev`
  partition (`partitions.dev.extraInputsFlake`). They have their own lock
  file, dev/flake.lock, so consumers' lock files never record them.

  The partition adds these inputs to the root flake's, so this flake
  declares no `nixpkgs`, which would replace the root input there. The
  partition takes both tools' packages from the root package set and uses
  only their flake-parts modules, so their own `nixpkgs` follows nothing.
*/
{
  description = "Development inputs of nix-nftypes";

  inputs = {
    nix-unit = {
      url = "github:nix-community/nix-unit";
      inputs = {
        nixpkgs.follows = "";
        treefmt-nix.follows = "";
        nix-github-actions.follows = "";
      };
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "";
    };
  };

  # The root flake reads only the inputs.
  outputs = _: { };
}
