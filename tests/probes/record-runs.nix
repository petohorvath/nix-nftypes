/*
  Builds a probe: runs each named shell script (under `set -euo pipefail`)
  and records its exit status and combined stdout/stderr as JSON,
  `{ <run> = { status; output; }; }`. A probe never judges its runs; the
  live nix-unit suites assert on this record (their `observations`).
*/
{
  jq,
  lib,
  runCommandLocal,
}:
{
  name,
  runs,
  nativeBuildInputs ? [ ],
}:
runCommandLocal name { nativeBuildInputs = [ jq ] ++ nativeBuildInputs; } ''
  echo '{}' > results.json
  ${lib.concatStrings (
    lib.mapAttrsToList (runName: script: ''
      echo ${lib.escapeShellArg "=== ${runName}"}
      status=0
      bash -euo pipefail -c ${lib.escapeShellArg script} > output.txt 2>&1 \
        || status=$?
      sed 's/^/    /' output.txt
      jq --arg name ${lib.escapeShellArg runName} --argjson status "$status" \
        --rawfile output output.txt \
        '. + { ($name): { status: $status, output: $output } }' \
        results.json > results.next.json
      mv results.next.json results.json
    '') runs
  )}
  mv results.json $out
''
