{ inputs, self, ... }:
{
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
      # Ad-hoc parser checks use the same stable nftables as the check
      # matrix. Nix itself is supplied by the caller's upstream installation.
      devShells.review = pkgs.callPackage ./review-shell.nix { };
      checks = import ./checks.nix {
        inherit pkgs;
        packages = self.packages.${system};
        pkgsUnstable = inputs.nixpkgs-unstable.legacyPackages.${system};
      };
    };
}
