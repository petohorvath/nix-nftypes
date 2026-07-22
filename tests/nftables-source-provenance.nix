{
  pkgs,
  nftablesSource,
}:

# Contract test for the source tree consumed by the corpus and enum checks.
# It must be derived from the exact source and patch set of the channel's
# nftables package—not from an independent upstream pin and not from the raw,
# unpatched release archive.
let
  inherit (pkgs) lib;
  nftables = pkgs.nftables;

  assertions = {
    inheritsPackageSource =
      nftablesSource ? src && toString nftablesSource.src == toString nftables.src;
    inheritsPackagePatches =
      nftablesSource ? patches
      && map toString nftablesSource.patches == map toString (nftables.patches or [ ]);
  };
  failedAssertions = builtins.attrNames (lib.filterAttrs (_: ok: !ok) assertions);
  failureMessage = lib.concatMapStringsSep "\n" (name: "FAILED: ${name}") failedAssertions;
in
{
  inherit failedAssertions;

  runTests =
    _pkgs:
    if failedAssertions != [ ] then
      pkgs.runCommandLocal "nftables-source-provenance-tests-fail" { } ''
        cat >&2 <<'EOF'
        nftables source provenance assertions failed:
        ${failureMessage}
        EOF
        exit 1
      ''
    else
      pkgs.runCommandLocal "nftables-source-provenance-tests"
        {
          sourceVersion = nftables.version;
        }
        ''
          test -f ${nftablesSource}/src/parser_json.c
          test -f ${nftablesSource}/src/json.c
          test -d ${nftablesSource}/tests/py
          echo "nftables $sourceVersion source and patches match pkgs.nftables"
          touch $out
        '';
}
