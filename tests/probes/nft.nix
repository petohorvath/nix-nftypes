/*
  Live-parser probes. Each run feeds rendered output to the package set's
  `nft` inside a private network namespace (`unshare -rn`), so the real
  parser and kernel netfilter instance are exercised without root.
*/
{
  fixtures,
  nftlib,
  pkgs,
  recordRuns,
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

  recordNftRuns =
    name: runs:
    recordRuns {
      inherit name runs;
      nativeBuildInputs = nftInputs;
    };
in
{
  # JSON output through `nft -c -j -f`, including the parser-negative
  # cases.
  dslIntegration = recordNftRuns "dsl-integration-probe" (
    lib.listToAttrs (
      map (
        case:
        lib.nameValuePair case.name (inNamespace {
          interfaces = case.interfaces or [ ];
          command = "nft -c -j -f ${writeRulesetJson case.name case.ruleset}";
        })
      ) (integrationCases.cases ++ integrationCases.rejectionCases)
    )
  );

  # Pretty text output through `nft -c -f` (no `-j`), for the text cases
  # render equivalence cannot load.
  textIntegration = recordNftRuns "text-integration-probe" (
    lib.listToAttrs (
      map (
        case:
        lib.nameValuePair case.name (inNamespace {
          command = "nft -c -f ${writeRulesetText case.name case.ruleset}";
        })
      ) integrationCases.textCheckOnlyCases
    )
  );

  # Block output in both forms, wrapped in `table <family> <name> { … }`.
  textBlockIntegration = recordNftRuns "text-block-integration-probe" (
    lib.concatMapAttrs (
      name: table:
      lib.mapAttrs'
        (
          form: render:
          let
            ruleset = pkgs.writeText "${name}-${form}.nft" ''
              table ${table.family} ${table.name} {
              ${render table}
              }
            '';
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

  # Each case loaded through JSON and through text; the output is the
  # resulting `nft list ruleset`.
  renderEquivalence = recordNftRuns "render-equivalence-probe" (
    lib.concatMapAttrs (_: case: loadBothWays case.name case.ruleset "nft list ruleset") (
      lib.listToAttrs (map (case: lib.nameValuePair case.name case) integrationCases.equivalenceCases)
    )
  );

  # The table comment read back after loading a safe comment through each
  # renderer.
  commentSafetyIntegration = recordNftRuns "comment-safety-integration-probe" (
    loadBothWays "comment" (fixtures.commentRulesets.tableComment fixtures.roundTripComment)
      "nft -j list ruleset | jq -j '.nftables[] | select(.table) | .table.comment'"
  );

  # The element count of the `iifs` set after loading safe ifname sets
  # through each renderer.
  ifnameSafetyIntegration =
    let
      countElements = "nft -j list set inet fw iifs | jq -j '[.nftables[] | select(.set) | .set.elem[]] | length'";
    in
    recordNftRuns "ifname-safety-integration-probe" (
      loadBothWays "one" (fixtures.ifnameRulesets.setElem "eth0") countElements
      // loadBothWays "two" (fixtures.ifnameRulesets.setElemList [
        "eth0"
        "wlp3s0"
      ]) countElements
    );

  /*
    Each round-trip case really loaded (no `-c`) with the output set to
    the `nft -j list ruleset` listing. The mount namespace shadows /etc
    with iana-etc's /etc/protocols: json.c resolves l4 protocol numbers to
    names via glibc, and without that file ct helper/timeout/expectation
    list back as `"protocol": 6`, a form parser_json.c rejects on input.
    Diagnostics go to the output only when a step fails, so a successful
    run's output is the bare listing.
  */
  nftablesRoundtrip =
    let
      loadAndList =
        case:
        let
          rulesetJson = writeRulesetJson case.name case.ruleset;
        in
        ''
          set -e
          mount -t tmpfs none /etc
          cp ${pkgs.iana-etc}/etc/protocols /etc/protocols
          ${addDummyLinks (case.interfaces or [ ])}
          nft -j -f ${rulesetJson} >/dev/null 2>load.err \
            || { cat load.err; exit 1; }
          nft -j list ruleset 2>list.err || { cat list.err; exit 1; }
        '';
    in
    recordNftRuns "nftables-roundtrip-probe" (
      lib.listToAttrs (
        map (
          case: lib.nameValuePair case.name "unshare -rnm bash -c ${lib.escapeShellArg (loadAndList case)}"
        ) integrationCases.roundtripCases
      )
    );
}
