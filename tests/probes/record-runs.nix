/*
  Probe builders. A probe runs each named shell script (under
  `set -euo pipefail`) and records its exit status and combined
  stdout/stderr as JSON, `{ <run> = { status; output; }; }`. A probe never
  judges its runs; the live nix-unit suites assert on this record (their
  `observations`).

  - `mkRunner` returns an executable that runs the scripts in a fresh
    temporary directory and writes the record to the path in its first
    argument. The VM tests (../vm.nix) run these inside a NixOS VM.
  - `recordRuns` runs a runner in the build sandbox and returns the record.
*/
{
  bash,
  coreutils,
  gnused,
  jq,
  lib,
  runCommandLocal,
  writeShellScript,
}:
let
  mkRunner =
    {
      name,
      runs,
      nativeBuildInputs ? [ ],
    }:
    writeShellScript "${name}-runner" ''
      set -euo pipefail
      export PATH=${
        lib.makeBinPath (
          [
            bash
            coreutils
            gnused
            jq
          ]
          ++ nativeBuildInputs
        )
      }:$PATH
      out=$(realpath -m "$1")
      cd "$(mktemp -d)"
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
      mv results.json "$out"
    '';
in
{
  inherit mkRunner;

  recordRuns =
    args:
    runCommandLocal args.name { } ''
      ${mkRunner args} $out
    '';
}
