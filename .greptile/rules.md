# Executable review environment

For T-Rex validation, run commands through `bash tooling/review-env.sh` from
the checkout. It supplies the locked stable `nft` and `unshare` tools and checks
that a real nftables ruleset can be validated in a private network namespace.
Use standard upstream Nix (NixOS/nix).

In a disposable Linux sandbox without Nix, enable the wrapper's opt-in
bootstrap. It downloads a checksum-pinned official upstream Nix installer,
uses a single-user installation without systemd, and leaves the lock file and
shell profiles unchanged:

```sh
bash tooling/review-env.sh --install-nix true
```

Bootstrap prerequisites are Bash, CA certificates, curl, xz, tar, and
sha256sum. On a bare Debian/Ubuntu sandbox, install missing prerequisites with
`apt-get update && apt-get install -y ca-certificates curl xz-utils` (use
`sudo -n` when needed). Creating `/nix` requires root, passwordless sudo, or an
administrator-prepared directory owned by the current user. Existing Nix
installations are reused. A daemonless root container uses process-local
single-user build settings; no host security policy is changed.

Once the probe succeeds, run the relevant checks from `flake.nix` through the
same wrapper. For example, on x86_64 Linux:

```sh
bash tooling/review-env.sh nix build --no-link -L \
  .#checks.x86_64-linux.text-block-integration-tests \
  .#checks.x86_64-linux.text-block-integration-tests-unstable
```

For a custom reproduction, pass its command and arguments to the wrapper.
Run every `nft` invocation inside `unshare -rn`, including `nft -c`: the parser
consults kernel state, and mutating commands must stay in a private namespace.
The full CI command is `nix flake check -L`; it covers both locked flake inputs.

Success means the namespace/parser probe and the requested test commands
actually exited zero. Exit 125 from the wrapper means environment setup is
blocked; preserve that distinction from a test failure and report the command
and error. If `unshare` is denied, the sandbox provider must permit private
user/network namespaces. On an administrator-controlled Ubuntu host,
`.github/apparmor/nix-unshare` documents the narrow profile used in GitHub CI.
Keep host-wide security settings and the host firewall unchanged. Cached Nix
checks are prior build evidence; use `--rebuild` when fresh execution matters
and attach the new logs to the review.
