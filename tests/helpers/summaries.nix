/*
  Build-log summaries for integration entries, keyed by suite name.
  nix-unit prints only test results, so these restore the informational
  counts a passing entry reports. Each takes the entry's observation paths
  and returns a shell snippet that runs after the suite passes.
*/
{ pkgs }:
let
  inherit (pkgs) lib;

  # jq program over the round-trip probe record: the listings of the
  # loaded cases and the read-back commands they hold. The `nftVersion`
  # run's output is not JSON, so it is left out.
  roundtripSummaryFilter = "del(.nftVersion) | [.[] | select(.status == 0) | .output | fromjson | .nftables | length] | \"nftables-roundtrip: \\(length) case listings, \\(add // 0) read-back commands validated against `ruleset`\"";

  provenanceNote = "nftables ${pkgs.nftables.version} source, patches, and patch hooks match pkgs.nftables";
in
{
  nftables-corpus = observationPaths: ''
    rules=$(jq length ${observationPaths.nftablesCorpus})
    echo "nftables-corpus: $rules corpus rules validated against \`statement\`"
  '';

  nftables-roundtrip = observationPaths: ''
    jq -r ${lib.escapeShellArg roundtripSummaryFilter} \
      ${observationPaths.nftablesRoundtrip}
  '';

  nftables-source-provenance = _: ''
    echo ${lib.escapeShellArg provenanceNote}
  '';
}
