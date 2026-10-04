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
    let
      tests = import ../tests {
        inherit pkgs;
        packages = self.packages.${system};
        pkgsUnstable = inputs.nixpkgs-unstable.legacyPackages.${system};
      };
    in
    {
      formatter = pkgs.callPackage ./formatter.nix { };
      devShells.default = pkgs.callPackage ./shell.nix {
        inherit (config) formatter;
      };
      devShells.review = pkgs.callPackage ./review-shell.nix { };
      checks = import ./checks.nix {
        inherit (config) formatter;
        inherit (tests) checks;
        inherit pkgs;
      };
      # The policy builds these on x86_64-linux with KVM.
      legacyPackages.vmTests = tests.vmTests;
    };
}
