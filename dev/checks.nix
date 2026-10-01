{
  packages,
  pkgs,
  pkgsUnstable,
}:
import ../tests { inherit packages pkgs pkgsUnstable; }
