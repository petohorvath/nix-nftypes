# Use the nftables in nixpkgs as the only compatibility authority

Compatibility is judged against the nftables that Nix users install: the package set's `nft` binary, its release source with every downstream nixpkgs patch applied, and its `lib` for module validation. The project dropped its directly pinned Netfilter source so that the test authority matches what consumers deploy and there is no second, fragile upstream-Git authority. Later it also dropped its second nixpkgs input, because the project policy already reruns the checks with its stable and unstable pins overriding `nixpkgs`.

## Considered options

- A Netfilter source revision pinned as its own flake input (`nftables-src`), with an `nft` built from it: added in `9e239ae`, replaced in `b787032`.
- A separate `nixpkgs-unstable` input with `-unstable` copies of every check: removed in `bd0a4ea`.

## Evidence

- `b787032`: "Make each locked Nixpkgs channel's packaged nftables binary and fully patched source tree authoritative … without relying on direct Netfilter Git access."
- `bd0a4ea` (#13): the policy's pins made the second input duplicate coverage.
- The header of `tests/default.nix` gives the rationale; `tests/suites/nixpkgs-source-policy.nix` fails if a `nixpkgs-unstable` or `nftables-src` input returns.
- `docs/upstream-sync.md` "Authorities" and `docs/spec-coverage.md` "Compatibility authority".
