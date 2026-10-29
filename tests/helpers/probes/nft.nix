/*
  Live-parser probe runners. Each run feeds rendered output to the package
  set's `nft` inside a private network namespace (`unshare -rn`), so every
  run gets its own netfilter instance. Creating the namespaces needs
  unprivileged user namespaces, which hosted CI runners deny inside the
  build sandbox, so these return runners (./record-runs.nix) that the VM
  run (./vm.nix) runs inside a NixOS VM.
*/
{
  fixtures,
  writeRunner,
  nftlib,
  pkgs,
}:
let
  inherit (pkgs) lib;
  inherit (fixtures) integrationCases;

  nftInputs = [
    pkgs.iproute2
    pkgs.jq
    pkgs.nftables
    pkgs.util-linux
  ];

  # `nft -c` resolves device names in flowtable.dev / chain.dev against
  # the namespace's link table, so cases naming real-NIC interfaces get
  # dummy stand-ins.
  addDummyLinks = interfaces: ''
    for dev in ${toString interfaces}; do
      ip link add "$dev" type dummy 2>/dev/null || true
    done
  '';

  # Runs `command` in a fresh network namespace.
  inNamespace =
    {
      command,
      interfaces ? [ ],
    }:
    "unshare -rn bash -c ${lib.escapeShellArg ''
      set -eo pipefail
      ${addDummyLinks interfaces}
      ${command}
    ''}";

  # A command line loading an Integration case's `state`, the nft text
  # each of its runs needs in place first, or nothing. A state that fails
  # to load ends the run with status 100.
  loadState =
    case:
    lib.optionalString (case ? state) ''
      nft -f ${pkgs.writeText "${case.name}-state.nft" case.state} \
        || { echo "the state failed to load"; exit 100; }
    '';

  writeRulesetJson = name: ruleset: pkgs.writeText "${name}.json" (nftlib.toJson ruleset);
  writeRulesetText = name: ruleset: pkgs.writeText "${name}.nft" (nftlib.toTextPretty ruleset);

  # Two runs loading `ruleset` through JSON (`<name>-json`) and through
  # text (`<name>-text`) in separate namespaces, then running `inspect`.
  # Load-time stdout is discarded: `reset counter`/`reset quota` print
  # observed values in the input's format, which is not what is compared.
  loadBothWays = name: ruleset: inspect: {
    "${name}-json" = inNamespace {
      command = "nft -j -f ${writeRulesetJson name ruleset} >/dev/null\n${inspect}";
    };
    "${name}-text" = inNamespace {
      command = "nft -f ${writeRulesetText name ruleset} >/dev/null\n${inspect}";
    };
  };

  # Every nft probe records the package set's nft version as the
  # `nftVersion` run, so suites can expect per-version behaviour.
  writeNftRunner =
    name: runs:
    writeRunner {
      inherit name;
      runs = runs // {
        nftVersion = "nft --version";
      };
      nativeBuildInputs = nftInputs;
    };
in
{
  # JSON output through `nft -c -j -f`, including the parser-negative
  # cases.
  dslIntegration = writeNftRunner "dsl-integration-probe" (
    lib.listToAttrs (
      map (
        case:
        lib.nameValuePair case.name (inNamespace {
          interfaces = case.interfaces or [ ];
          command = loadState case + "nft -c -j -f ${writeRulesetJson case.name case.ruleset}";
        })
      ) (integrationCases.cases ++ integrationCases.rejectionCases)
    )
  );

  # Block output in both forms, wrapped in `table <family> <name> { … }`.
  textBlockIntegration = writeNftRunner "text-block-integration-probe" (
    lib.concatMapAttrs (
      name: table:
      lib.mapAttrs'
        (
          form: render:
          let
            ruleset = pkgs.writeText "${name}-${form}.nft" "table ${table.family} ${table.name} {\n${render table}}\n";
          in
          lib.nameValuePair "${name}-${form}" (inNamespace {
            command = "nft -c -f ${ruleset}";
          })
        )
        {
          compact = nftlib.toTextBlock;
          pretty = nftlib.toTextBlockPretty;
        }
    ) fixtures.blockTables.integrationTables
  );

  /*
    Each Integration case loaded through each of its forms, run
    `<case>-<form>`, in its own namespace (../../fixtures/render-equivalence.nix
    lists the forms). The output is the resulting `nft list ruleset`, or
    the load error.

    `last used <time>` lists the time since the rule last matched, and an
    element's `expires <time>` the time left until it times out; both
    change between a load and its listing. So the listing drops the
    seconds and milliseconds of each such time (`last used 1d3ms` lists
    as `last used 1d~`, and an element's `expires 1m29s997ms,` as
    `expires 1m~,`), and still tells a day from a millisecond.
  */
  renderEquivalence =
    let
      plan = fixtures.renderEquivalence;
      dropElapsedSeconds = "sed -E 's/((last used|expires) ([0-9]+[dh])*([0-9]+m)?)([0-9]+s)?([0-9]+ms)?([ ,]|$)/\\1~\\7/g'";
      loadForm =
        case: form:
        let
          rendered = pkgs.writeText "${case.name}-${form}" (plan.render.${form} case);
          jsonFlag = lib.optionalString (form == "json") "-j ";
        in
        lib.nameValuePair "${case.name}-${form}" (inNamespace {
          interfaces = case.interfaces or [ ];
          command = loadState case + ''
            nft ${jsonFlag}-f ${rendered} >/dev/null
            nft list ruleset | ${dropElapsedSeconds}
          '';
        });
    in
    writeNftRunner "render-equivalence-probe" (
      lib.listToAttrs (lib.concatMap (case: map (loadForm case) (plan.loadedForms case)) plan.cases)
    );

  # Each "still misbehaves" case loaded through JSON, then inspected, with
  # `$subject` naming the case's subject ruleset, if any.
  nftMisbehaviour = writeNftRunner "nft-misbehaviour-probe" (
    lib.listToAttrs (
      map (
        case:
        let
          subject = writeRulesetJson "${case.name}-subject" case.subject;
        in
        lib.nameValuePair case.name (inNamespace {
          command = ''
            nft -j -f ${writeRulesetJson case.name case.ruleset} >/dev/null
            ${lib.optionalString (case ? subject) "subject=${subject}"}
            ${case.inspect}
          '';
        })
      ) fixtures.nftMisbehaviour.cases
    )
  );

  # Each placement's base chain really loaded, with the output set to the
  # listed chain's type and hook.
  chainPlacement = writeNftRunner "chain-placement-probe" (
    lib.listToAttrs (
      map (
        placement:
        lib.nameValuePair placement.name (inNamespace {
          interfaces = [ "eth0" ];
          command = ''
            nft -j -f ${writeRulesetJson placement.name placement.ruleset}
            nft -j list chain ${placement.family} t c \
              | jq -j '.nftables[] | select(.chain) | .chain
                | "\(.type) \(.hook)"'
          '';
        })
      ) fixtures.chainPlacement.placements
    )
  );

  # Each priority symbol's filter chain really loaded, with the output
  # set to the listed chain's priority.
  prioritySymbols = writeNftRunner "priority-symbols-probe" (
    lib.listToAttrs (
      map (
        case:
        lib.nameValuePair case.name (inNamespace {
          interfaces = [ "eth0" ];
          command = ''
            nft -f ${pkgs.writeText "${case.name}.nft" case.text}
            nft -j list chain ${case.family} t c \
              | jq -j '.nftables[] | select(.chain) | .chain.prio'
          '';
        })
      ) fixtures.chainPlacement.prioritySymbols
    )
  );

  /*
    The parse check: each check's state really loaded, then its subject
    through `nft -c` (`nft -c -j` for JSON). A state that fails to load
    exits 100, apart from the subject's own rejection. The `kernelVersion`
    run records the kernel version, which expected rejections can be
    scoped to, like the nft version.
  */
  parseCheck = writeNftRunner "parse-check-probe" (
    lib.mapAttrs (
      _: check:
      inNamespace {
        interfaces = [
          "eth0"
          "eth1"
        ];
        command = ''
          printf '%s\n' ${lib.escapeShellArg check.state} > state
          printf '%s\n' ${lib.escapeShellArg check.subject} > subject
          nft ${lib.optionalString check.stateJson "-j "}-f state \
            || { echo "parse-check: the state failed to load"; exit 100; }
          nft -c ${lib.optionalString check.json "-j "}-f subject
        '';
      }
    ) fixtures.parseCheck.checks
    // {
      kernelVersion = "uname -r";
    }
  );

  # The table comment read back after loading a safe comment through each
  # renderer.
  commentSafetyIntegration =
    let
      readComment = "nft -j list ruleset | jq -j '.nftables[] | select(.table) | .table.comment'";
    in
    writeNftRunner "comment-safety-integration-probe" (
      loadBothWays "comment" (fixtures.commentRulesets.tableComment fixtures.roundTripComment) readComment
      // loadBothWays "byte-a0" (fixtures.commentRulesets.tableComment fixtures.byteA0Comment) readComment
    );

  # The element count of the `iifs` set after loading ifname sets through
  # each renderer.
  ifnameSafetyIntegration =
    let
      countElements = "nft -j list set inet fw iifs | jq -j '[.nftables[] | select(.set) | .set.elem[]] | length'";
    in
    writeNftRunner "ifname-safety-integration-probe" (
      loadBothWays "one" (fixtures.ifnameRulesets.setElem "eth0") countElements
      // loadBothWays "two" (fixtures.ifnameRulesets.setElemList [
        "eth0"
        "wlp3s0"
      ]) countElements
      // loadBothWays "comma" (fixtures.ifnameRulesets.setElem "eth0,eth1") countElements
    );

  /*
    Each round-trip case really loaded (no `-c`) through JSON, and each
    text Read-back state through text, with the output set to the
    `nft -j list ruleset` listing. The mount namespace shadows /etc
    with iana-etc's /etc/protocols: json.c resolves l4 protocol numbers to
    names via glibc, and without that file ct helper/timeout/expectation
    list back as `"protocol": 6`, a form parser_json.c rejects on input.
    Diagnostics go to the output only when a step fails, so a successful
    run's output is the bare listing.
  */
  nftablesRoundtrip =
    let
      loadAndList =
        {
          load,
          interfaces ? [ ],
        }:
        "unshare -rnm bash -c ${lib.escapeShellArg ''
          set -e
          mount -t tmpfs none /etc
          cp ${pkgs.iana-etc}/etc/protocols /etc/protocols
          ${addDummyLinks interfaces}
          ${load} >/dev/null 2>load.err || { cat load.err; exit 1; }
          nft -j list ruleset 2>list.err || { cat list.err; exit 1; }
        ''}";
    in
    writeNftRunner "nftables-roundtrip-probe" (
      lib.listToAttrs (
        map (
          case:
          lib.nameValuePair case.name (loadAndList {
            load = loadState case + "nft -j -f ${writeRulesetJson case.name case.ruleset}";
            interfaces = case.interfaces or [ ];
          })
        ) integrationCases.cases
        ++ map (
          state:
          lib.nameValuePair state.name (loadAndList {
            load = "nft -f ${pkgs.writeText "${state.name}.nft" state.text}";
          })
        ) integrationCases.textReadbacks
      )
    );
}
