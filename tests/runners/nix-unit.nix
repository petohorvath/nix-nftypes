# test-standard v1: copied from the test-standard skill; do not edit here.
/*
  Turns a nix-unit entry point (tests/unit or tests/integration) into an
  entry of the `checks` output, so the suites run in the build sandbox
  under `nix flake check` and the project policy's `test`.

  - `inputs`: the flake inputs. Each argument the entry point declares is
    taken from them, so `--override-input` reaches every input.
  - `pkgs`: the package set that supplies nix-unit and the system.
  - `repo`: the repo name, which prefixes the derivation name.
  - `srcDir`: a store path holding the files the suites read.

  Returns a function from the entry's options to its derivation.
*/
{
  inputs,
  pkgs,
  repo,
  srcDir,
}:
{
  # "unit" or "integration".
  kind,
  name ? kind,
  # Top-level suites to run; null runs all.
  suites ? null,
  # Extra or overriding --arg values, as Nix expression strings.
  extraArgs ? { },
  # Features of builds the suites read, such as a VM run.
  requiredSystemFeatures ? [ ],
  # Shell commands run after the suites pass.
  postCheck ? "",
  # nix-unit processes run at once; null uses $NIX_BUILD_CORES.
  jobs ? null,
}:
let
  inherit (pkgs) lib;

  entryPointPath = "${srcDir}/tests/${kind}";
  evaluationInputsPath = ../helpers/evaluation-inputs.nix;

  # A flake input as a tree of store paths, keeping every transitive input.
  inputTree =
    input:
    if input._type or null == "flake" then
      {
        path = input.outPath;
        inputs = lib.mapAttrs (_: inputTree) input.inputs;
      }
    else
      {
        path = input.outPath;
        flake = false;
      };

  # The tree as a Nix expression. Store paths stay strings, so the
  # evaluator reads them in place, and their context makes them inputs of
  # the derivation.
  treeExpr =
    tree:
    if tree.flake or true then
      "{ path = ${builtins.toJSON tree.path}; inputs = { ${
        lib.concatStrings (
          lib.mapAttrsToList (
            inputName: input: "${lib.strings.escapeNixIdentifier inputName} = ${treeExpr input}; "
          ) tree.inputs
        )
      }}; }"
    else
      "{ path = ${builtins.toJSON tree.path}; flake = false; }";

  # Read from the runner's own tree, beside the entry points: the source
  # copy in `srcDir` is not in the store under `nix flake check --no-build`.
  declaredArgs = builtins.functionArgs (import (../. + "/${kind}"));

  # An argument left to its default would reach for the root flake,
  # which the sandbox cannot evaluate.
  unsuppliedArgs = builtins.attrNames (
    removeAttrs declaredArgs ([ "system" ] ++ builtins.attrNames (inputs // extraArgs))
  );

  inputArgs = lib.mapAttrs (
    _: input: "(import ${evaluationInputsPath}) ${treeExpr (inputTree input)}"
  ) (removeAttrs (builtins.intersectAttrs declaredArgs inputs) [ "system" ]);

  entryArgs = lib.escapeShellArgs (
    lib.concatLists (
      lib.mapAttrsToList (argName: value: [
        "--arg"
        argName
        value
      ]) (inputArgs // extraArgs)
    )
    ++ [
      "--argstr"
      "system"
      pkgs.stdenv.hostPlatform.system
    ]
  );

  suiteNamesExpr =
    if suites == null then "null" else "[ ${lib.concatMapStringsSep " " builtins.toJSON suites} ]";

  /*
    Called with the entry point's arguments. Without `groupPath`, returns
    `groups`, the attribute paths of the attrsets that directly hold
    `test*` attributes. With `groupPath`, a JSON list, returns the tests
    directly in that group, nested under its path, so each nix-unit
    process runs one group under its full name.
  */
  suitesFile = pkgs.writeText "${repo}-${name}-suites.nix" ''
    args@{ ... }:
    let
      entryPoint = import ${entryPointPath};
      tests = entryPoint (
        builtins.intersectAttrs (builtins.functionArgs entryPoint) args
      );
      suiteNames = ${suiteNamesExpr};
      selected =
        if suiteNames == null then
          tests
        else
          builtins.listToAttrs (
            map (name: {
              inherit name;
              value = tests.''${name};
            }) suiteNames
          );
      isTest = attrName: builtins.substring 0 4 attrName == "test";
      groupPaths =
        path: value:
        let
          names = builtins.attrNames value;
          nested = builtins.concatMap (
            attrName:
            if !isTest attrName && builtins.isAttrs value.''${attrName} then
              groupPaths (path ++ [ attrName ]) value.''${attrName}
            else
              [ ]
          ) names;
        in
        (if builtins.any isTest names then [ path ] else [ ]) ++ nested;
    in
    if args ? groupPath then
      let
        path = builtins.fromJSON args.groupPath;
        group = builtins.foldl' (
          value: attrName: value.''${attrName}
        ) selected path;
        groupTests = removeAttrs group (
          builtins.filter (attrName: !isTest attrName) (
            builtins.attrNames group
          )
        );
        reversedPath = builtins.foldl' (
          reversed: attrName: [ attrName ] ++ reversed
        ) [ ] path;
      in
      builtins.foldl' (
        value: attrName: { ''${attrName} = value; }
      ) groupTests reversedPath
    else
      { groups = groupPaths [ ] selected; }
  '';

  gcRootsArgs = lib.optionalString (lib.versionOlder pkgs.nix-unit.version "2.35") "--gc-roots-dir \"$TMPDIR/gc-roots/$index\"";

  jobsShell = if jobs == null then "\"\${NIX_BUILD_CORES:-0}\"" else toString jobs;
in
assert lib.assertMsg (unsuppliedArgs == [ ])
  "${repo}-${name}: the ${kind} entry point takes ${lib.concatStringsSep ", " unsuppliedArgs}, which is neither a flake input nor in extraArgs";
pkgs.runCommandLocal "${repo}-${name}"
  {
    inherit requiredSystemFeatures;
    nativeBuildInputs = [
      pkgs.jq
      pkgs.nix
      pkgs.nix-unit
    ];
  }
  ''
    export HOME="$TMPDIR"
    nix --extra-experimental-features nix-command eval \
      --eval-store "$TMPDIR/eval-store" --show-trace --json \
      --file ${suitesFile} groups ${entryArgs} > groups.json
    if [ "$(jq length groups.json)" -eq 0 ]; then
      echo "${name}: the entry point holds no tests" >&2
      exit 1
    fi

    jobs=${jobsShell}
    if [ "$jobs" -eq 0 ]; then jobs=$(nproc); fi

    groupCount=0
    while IFS= read -r groupPath; do
      printf '%s' "$groupPath" > "$TMPDIR/group-$groupCount.json"
      groupCount=$((groupCount + 1))
    done < <(jq -c '.[]' groups.json)

    # One nix-unit process per group bounds the memory of each.
    runGroup() {
      index=$1
      groupPath=$(< "$TMPDIR/group-$index.json")
      mkdir -p "$TMPDIR/gc-roots/$index"
      log="$TMPDIR/group-$index.log"
      echo "=== $(jq -r 'join(".")' <<< "$groupPath")" > "$log"
      status=0
      nix-unit --quiet --show-trace \
        --eval-store "$TMPDIR/eval-store" ${gcRootsArgs} \
        ${entryArgs} --argstr groupPath "$groupPath" \
        ${suitesFile} >> "$log" 2>&1 || status=$?
      # One write per group keeps parallel groups' logs apart.
      cat "$log"
      return "$status"
    }
    export -f runGroup

    seq 0 $((groupCount - 1)) \
      | xargs -P "$jobs" -I '{}' bash -c 'runGroup {}' \
      || { echo "${name}: a suite failed" >&2; exit 1; }

    ${postCheck}
    touch "$out"
  ''
