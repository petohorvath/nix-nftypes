{
  git,
  jq,
  mkShellNoCC,
  nftables,
  nil,
  nix,
  nix-unit,
  python3,
  statix,
  treefmtShell,
  util-linux,
}:
mkShellNoCC {
  inputsFrom = [ treefmtShell ];
  packages = [
    nix
    nix-unit
    git
    nil
    statix
    jq
    python3
    nftables
    util-linux
  ];
}
