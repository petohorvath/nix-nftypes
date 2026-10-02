/*
  Corpus drift (docs/upstream-sync.md): validate nftables' *own*
  regression corpus against this library's schema.

  nftables ships `.t.json` files under `tests/py`: for every rule it tests,
  the exact libnftables-JSON `expr` array it expects. That is upstream
  telling us, revision by revision, what valid input looks like, including
  constructs we never thought to test. Feeding it through
  `nftlib.types.statement` catches the "schema too restrictive" drift
  direction (D2) that hand-written tests structurally cannot: you cannot
  write a test for a field you do not know exists. Every confirmed gap in
  docs/spec-coverage.md (G1 `rt key ipsec`, G3 `fib result check`, …) is
  exactly this class.

  The corpus already exercises shapes the schema rejects. Each is
  classified into a named pattern in `knownDivergences`
  (tests/helpers/corpus-drift.nix) with the reason and the parser
  evidence. The suite fails only on an offending statement that matches
  NO known pattern, i.e. *new* drift introduced by a nixpkgs package
  update. Fixing a baselined gap is tracked in docs/upstream-sync.md.
*/
{
  helpers,
  observations,
  ...
}:
{
  testCorpusHasNoNewDrift = {
    expr = map builtins.toJSON (helpers.corpusDrift observations.nftablesCorpus).newDrift;
    expected = [ ];
  };
}
