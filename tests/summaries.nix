/*
  Build-log summaries for live checks, keyed by check name. nix-unit
  prints only test results, so these restore the informational counts a
  passing check reports. Each takes the check's observation paths and
  returns a shell snippet that runs after the suites pass.
*/
{ fixtures, pkgs }:
let
  inherit (pkgs) lib;
  inherit (fixtures.integrationCases) knownNoLoad;

  # jq program over the round-trip probe record: the listings of the
  # loaded cases and the read-back commands they hold.
  roundtripCounts = "[.[] | select(.status == 0) | .output | fromjson | .nftables | length] | \"nftables-roundtrip: \\(length) case listings, \\(add // 0) read-back commands validated against `ruleset`\"";

  skippedNote = lib.concatStringsSep "\n" (
    [ "Skipped (cannot real-load in an unprivileged netns):" ]
    ++ lib.mapAttrsToList (name: reason: "    ${name}: ${reason}") knownNoLoad
  );

  provenanceNote = "nftables ${pkgs.nftables.version} source and patches match pkgs.nftables";
in
{
  nftables-corpus-tests = observationPaths: ''
    rules=$(jq length ${observationPaths.nftablesCorpus})
    echo "nftables-corpus: $rules corpus rules validated against \`statement\`"
  '';

  nftables-roundtrip-tests = observationPaths: ''
    jq -r ${lib.escapeShellArg roundtripCounts} \
      ${observationPaths.nftablesRoundtrip}
    echo ${lib.escapeShellArg skippedNote}
  '';

  nftables-source-provenance-tests = _: ''
    echo ${lib.escapeShellArg provenanceNote}
  '';
}
