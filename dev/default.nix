{ inputs, ... }:
{
  perSystem =
    { config, pkgs, ... }:
    {
      formatter = pkgs.callPackage ./formatter.nix { };
      devShells.default = pkgs.callPackage ./shell.nix {
        inherit (config) formatter;
      };
      devShells.review = pkgs.callPackage ./review-shell.nix { };
      checks = import ./checks.nix {
        inherit (config) formatter;
        inherit pkgs;
        checks = import ../tests { inherit inputs pkgs; };
      };
    };
}
