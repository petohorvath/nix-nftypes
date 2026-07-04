{
  pkgs,
  nftlib,
  nftablesPinned,
}:

# Read-back round-trip check (docs/upstream-sync.md): everything
# `nft -j list ruleset` emits must validate against the schema.
#
# Every other suite tests the INPUT direction — our JSON/text is accepted
# by a real parser. This one tests the OUTPUT direction, which is the
# README's "round-trip safe" claim: each integration case is really loaded
# (no `-c`) into a private netns with the pinned `nft`, the resulting
# `nft -j list ruleset` is captured, and every command in it is validated
# against `nftlib.types.ruleset` (whose `topLevel` union deliberately
# accepts bare listed objects alongside command wrappers).
#
# This is also the only deterministic net for two drift surfaces nothing
# else covers:
#   - `src/json.c`, the serializer — it evolves independently of
#     `parser_json.c`, and a new emitted field breaks read-back consumers
#     even when the input direction is fine;
#   - object bodies — the tests/py corpus (upstream-corpus.nix) only
#     carries per-rule statement arrays, so a new field on an emitted
#     set/chain/ct-timeout/… is invisible to it.
#
# The listing derivation is imported at eval time (IFD, same pattern as
# upstream-corpus.nix) so the validation itself runs through evalModules
# and failures are classified against a baseline. The listing content is
# deterministic for a fixed pinned `nft`: handles are assigned
# sequentially in a fresh netns and the metainfo version string is the
# pinned build's own.
#
# /etc/protocols note: json.c resolves l4 protocol numbers to names via
# glibc (getprotobynumber → /etc/protocols). Without that file — as in
# the bare Nix sandbox, or a minimal container — ct helper/timeout/
# expectation list back with `"protocol": 6` instead of `"tcp"`, a form
# parser_json.c REJECTS on input (verified against the pinned nft): on
# such systems nftables' own listing does not round-trip through its own
# parser. The runner below bind-provides iana-etc's /etc/protocols
# inside the namespace so the serializer behaves as on a normal system
# and the captured listing is deterministic; the asymmetry itself is
# documented in docs/upstream-sync.md.

let
  inherit (pkgs) lib;

  integration = import ./dsl-integration.nix {
    inherit (pkgs) lib;
    inherit nftlib;
  };

  /*
    Cases that cannot be really loaded (as opposed to `nft -c` checked)
    in an unprivileged netns, with the observed reason. Everything not
    listed here is expected to load; an unexpected load failure is
    reported in the build log and eats into `minLoaded` below.
  */
  knownNoLoad = {
    "add-rule-via-tree-and-standalone" =
      "uses `handle 42`, which the pinned parser validates against live kernel state (same class as pinnedConformanceSkip)";
    "example-home-router-dsl" =
      "flowtable `flags offload` is rejected on dummy devices — real-load fails with 'Operation not supported'";
  };

  loadCases = builtins.filter (c: !(knownNoLoad ? ${c.name})) integration.cases;

  # Vacuous-pass guard: if environment rot (missing kernel modules,
  # broken userns) makes cases silently fail to load, the check must not
  # stay green with nothing validated. At least this many cases must
  # produce a listing. example-basic-firewall-dsl and the flush/reset
  # cases need no optional kernel features, so this floor holds on any
  # Linux builder that can run the other netns suites at all.
  minLoaded = 4;

  # One JSON document: [ { name, loaded, listing? } ] per case. Load
  # errors go to the build log only, keeping $out deterministic.
  listingsJson =
    pkgs.runCommandLocal "nft-roundtrip-listings.json"
      {
        nativeBuildInputs = [
          nftablesPinned
          pkgs.util-linux
          pkgs.iproute2
          pkgs.jq
        ];
      }
      ''
        loaded=0
        : > entries.jsonl
        ${lib.concatMapStringsSep "\n" (c: ''
          printf '=== %s ===\n' ${lib.escapeShellArg c.name}
          cat > ./in.json <<'RULESET_EOF'
          ${nftlib.toJson c.ruleset}
          RULESET_EOF
          ifaces=${lib.escapeShellArg (lib.concatStringsSep " " (c.interfaces or [ ]))}
          # -m: mount namespace so a tmpfs can shadow /etc and carry
          # /etc/protocols (see the /etc/protocols note above).
          if unshare -rnm bash -c "
              mount -t tmpfs none /etc
              cp ${pkgs.iana-etc}/etc/protocols /etc/protocols
              for dev in $ifaces; do
                ip link add \"\$dev\" type dummy 2>/dev/null || true
              done
              nft -j -f $PWD/in.json >/dev/null || exit 9
              exec nft -j list ruleset
            " > ./listing.json 2> ./err.txt; then
            echo "LOADED ($(jq '.nftables | length' ./listing.json) objects listed)"
            jq -n --arg name ${lib.escapeShellArg c.name} --slurpfile l ./listing.json \
              '{name: $name, loaded: true, listing: $l[0]}' >> entries.jsonl
            loaded=$((loaded + 1))
          else
            echo "NOLOAD:"
            sed 's/^/    /' ./err.txt
            jq -n --arg name ${lib.escapeShellArg c.name} \
              '{name: $name, loaded: false}' >> entries.jsonl
          fi
        '') loadCases}
        if [ "$loaded" -lt ${toString minLoaded} ]; then
          echo "only $loaded case(s) produced a listing (< ${toString minLoaded});" \
               "refusing a vacuous pass — the environment cannot exercise the round-trip"
          exit 1
        fi
        jq -s '.' entries.jsonl > $out
      '';

  listings = builtins.fromJSON (builtins.readFile listingsJson);
  loadedListings = builtins.filter (e: e.loaded) listings;

  # True iff a single read-back command validates as a `topLevel` entry —
  # wrapped as a singleton ruleset so the same oneOf the public type uses
  # (command wrapper | bare listed object) is exercised.
  validates =
    cmd:
    (builtins.tryEval (
      builtins.deepSeq
        (lib.evalModules {
          modules = [
            { options.v = lib.mkOption { type = nftlib.types.ruleset; }; }
            {
              v = {
                nftables = [ cmd ];
              };
            }
          ];
        }).config.v
        true
    )).success;

  # Read-back commands the schema rejects, deduped by JSON form.
  offending = lib.unique (
    lib.flatten (map (e: builtins.filter (c: !(validates c)) e.listing.nftables) loadedListings)
  );

  classify = cmd: "readback:${builtins.head (builtins.attrNames cmd)}";

  /*
    Baselined read-back divergences: shapes the pinned `nft -j list
    ruleset` emits that the schema (deliberately or not-yet) rejects.
    EMPTY today — every command the pinned serializer emits for the
    current case set validates, which is the round-trip claim holding.
    A future `nftables-src` bump that makes json.c emit a new field
    lands here (or, preferably, in the schema).
  */
  knownReadbackDivergences = { };
  knownCategories = builtins.attrNames knownReadbackDivergences;

  newDrift = builtins.filter (c: !(builtins.elem (classify c) knownCategories)) offending;
  staleCategories = lib.subtractLists (lib.unique (map classify offending)) knownCategories;

  commandCount = lib.foldl' (n: e: n + builtins.length e.listing.nftables) 0 loadedListings;
  fmtList = items: lib.concatMapStringsSep "\n" (x: "    ${x}") items;
  skippedNote = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (name: why: "    ${name}: ${why}") knownNoLoad
  );
  staleNote =
    if staleCategories == [ ] then
      ""
    else
      "\nStale baseline patterns (no longer emitted — prune from knownReadbackDivergences):\n"
      + fmtList staleCategories;

  runTests =
    _pkgs:
    if newDrift == [ ] then
      pkgs.runCommandLocal "upstream-roundtrip-tests-pass" { } ''
        cat <<'EOF'
        upstream-roundtrip: ${toString (builtins.length loadedListings)} case listings, ${toString commandCount} read-back commands validated against `ruleset`.
        ${toString (builtins.length offending)} divergences (baseline has ${toString (builtins.length knownCategories)}).
        Skipped (cannot real-load in an unprivileged netns):
        ${skippedNote}
        ${staleNote}
        EOF
        touch $out
      ''
    else
      pkgs.runCommandLocal "upstream-roundtrip-tests-fail" { } ''
        cat <<'EOF'
        upstream-roundtrip: READ-BACK drift — the pinned `nft -j list ruleset`
        emits ${toString (builtins.length newDrift)} command shape(s) the schema rejects and that match
        no baselined pattern. This breaks the round-trip contract: state
        read back from the kernel no longer fits the model. Either extend
        the schema to accept the shape (preferred) or baseline it in
        `knownReadbackDivergences` with the reason.

        New offending read-back commands:
        ${fmtList (map builtins.toJSON newDrift)}
        EOF
        exit 1
      '';
in
{
  inherit
    runTests
    listings
    offending
    newDrift
    validates
    knownNoLoad
    knownReadbackDivergences
    ;
}
