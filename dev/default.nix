{ inputs, self, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    {
      formatter = pkgs.callPackage ./formatter.nix { };
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
