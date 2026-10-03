{ inputs, self, ... }:
{
  # nix-unit's flake entry point: `nix-unit --flake .#tests`.
  flake.tests = import ../tests/unit.nix { inherit (inputs.nixpkgs) lib; };

  perSystem =
    {
      config,
      pkgs,
      system,
      ...
    }:
    {
      formatter = pkgs.callPackage ./formatter.nix { };
      devShells.default = pkgs.callPackage ./shell.nix {
        inherit (config) formatter;
      };
      devShells.review = pkgs.callPackage ./review-shell.nix { };
      checks = import ./checks.nix {
        inherit pkgs;
        packages = self.packages.${system};
        pkgsUnstable = inputs.nixpkgs-unstable.legacyPackages.${system};
      };
    };
}
