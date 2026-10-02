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

  # Runs `command` in a fresh network namespace. `nft -c` resolves device
  # names in flowtable.dev / chain.dev against the namespace's link table,
  # so cases naming real-NIC interfaces get dummy stand-ins.
  inNamespace =
    {
      command,
      interfaces ? [ ],
    }:
    "unshare -rn bash -c ${lib.escapeShellArg ''
      set -e
      for dev in ${toString interfaces}; do
        ip link add "$dev" type dummy 2>/dev/null || true
      done
      ${command}
    ''}";

  jsonFile = name: value: pkgs.writeText "${name}.json" (nftlib.toJson value);
  textFile = name: value: pkgs.writeText "${name}.nft" (nftlib.toTextPretty value);

  probeRuns =
    name: runs:
    recordRuns {
      inherit name runs;
      nativeBuildInputs = nftInputs;
    };
in
{
  # JSON output through `nft -c -j -f`, including the parser-negative
  # cases.
  dslIntegration = probeRuns "dsl-integration-probe" (
    lib.listToAttrs (
      map (
        case:
        lib.nameValuePair case.name (inNamespace {
          interfaces = case.interfaces or [ ];
          command = "nft -c -j -f ${jsonFile case.name case.ruleset}";
        })
      ) (integrationCases.cases ++ integrationCases.rejectionCases)
    )
  );

  # Pretty text output through `nft -c -f` (no `-j`).
  textIntegration = probeRuns "text-integration-probe" (
    lib.listToAttrs (
      map (
        case:
        lib.nameValuePair case.name (inNamespace {
          command = "nft -c -f ${textFile case.name case.ruleset}";
        })
      ) integrationCases.textCases
    )
  );

  # Block output in both forms, wrapped in `table <family> <name> { … }`.
  textBlockIntegration = probeRuns "text-block-integration-probe" (
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

  # Each case loaded through JSON and through text in separate
  # namespaces; the output is the resulting `nft list ruleset`. Load-time
  # stdout is discarded: `reset counter`/`reset quota` print observed
  # values in the input's format, which is not what is compared.
  renderEquivalence = probeRuns "render-equivalence-probe" (
    lib.listToAttrs (
      lib.concatMap (case: [
        (lib.nameValuePair "${case.name}-json" (inNamespace {
          command = "nft -j -f ${jsonFile case.name case.ruleset} >/dev/null && nft list ruleset";
        }))
        (lib.nameValuePair "${case.name}-text" (inNamespace {
          command = "nft -f ${textFile case.name case.ruleset} >/dev/null && nft list ruleset";
        }))
      ]) integrationCases.equivalenceCases
    )
  );

  # The table comment read back after loading a safe comment through each
  # renderer.
  commentSafetyIntegration =
    let
      ruleset = fixtures.commentRulesets.tableComment fixtures.roundTripComment;
      readComment = "nft -j list ruleset | jq -j '.nftables[] | select(.table) | .table.comment'";
    in
    probeRuns "comment-safety-integration-probe" {
      json = inNamespace {
        command = "nft -j -f ${jsonFile "comment" ruleset}\n${readComment}";
      };
      text = inNamespace {
        command = "nft -f ${textFile "comment" ruleset}\n${readComment}";
      };
    };

  # The element count of the `iifs` set after loading safe ifname sets
  # through each renderer.
  ifnameSafetyIntegration =
    let
      countElements = "nft -j list set inet fw iifs | jq -j '[.nftables[] | select(.set) | .set.elem[]] | length'";
    in
    probeRuns "ifname-safety-integration-probe" (
      lib.concatMapAttrs
        (name: ruleset: {
          "${name}-json" = inNamespace {
            command = "nft -j -f ${jsonFile name ruleset}\n${countElements}";
          };
          "${name}-text" = inNamespace {
            command = "nft -f ${textFile name ruleset}\n${countElements}";
          };
        })
        {
          one = fixtures.ifnameRulesets.setElem "eth0";
          two = fixtures.ifnameRulesets.setElemList [
            "eth0"
            "wlp3s0"
          ];
        }
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
      loadAndList = case: ''
        set -e
        mount -t tmpfs none /etc
        cp ${pkgs.iana-etc}/etc/protocols /etc/protocols
        for dev in ${toString (case.interfaces or [ ])}; do
          ip link add "$dev" type dummy 2>/dev/null || true
        done
        nft -j -f ${jsonFile case.name case.ruleset} >/dev/null 2>load.err \
          || { cat load.err; exit 9; }
        nft -j list ruleset 2>list.err || { cat list.err; exit 1; }
      '';
    in
    probeRuns "nftables-roundtrip-probe" (
      lib.listToAttrs (
        map (
          case: lib.nameValuePair case.name "unshare -rnm bash -c ${lib.escapeShellArg (loadAndList case)}"
        ) integrationCases.roundtripCases
      )
    );
}
