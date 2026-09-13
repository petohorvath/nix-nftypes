#!/usr/bin/env bash
# Run a command with the flake's parser tools after checking kernel support.
# --install-nix is opt-in and intended for disposable Linux review sandboxes.
set -euo pipefail

blocked() {
  printf 'Review environment blocked: %s\n' "$*" >&2
  exit 125
}

install_nix=false
if [[ ${1:-} == --install-nix ]]; then
  install_nix=true
  shift
fi
if [[ $# == 0 ]]; then
  printf 'Usage: bash tooling/review-env.sh [--install-nix] COMMAND [ARG...]\n' >&2
  exit 2
fi
case "$(uname -s).$(uname -m)" in
  Linux.x86_64|Linux.aarch64) ;;
  *) blocked 'the parser environment requires x86_64-linux or aarch64-linux' ;;
esac

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$repo_root"

# Non-login shells often miss an existing Nix installation.
if ! command -v nix >/dev/null 2>&1; then
  export PATH="$HOME/.nix-profile/bin:/nix/var/nix/profiles/default/bin:$PATH"
fi
export NIX_CONFIG="${NIX_CONFIG:-}"$'\nextra-experimental-features = nix-command flakes'

# A root-only, daemonless container builds as its invoking user. Keep these
# options local to this process tree; the outer sandbox still isolates it.
# The nft probes and tests continue to require their own private namespaces.
if [[ $EUID == 0 && ! -S /nix/var/nix/daemon-socket/socket ]]; then
  export NIX_CONFIG="$NIX_CONFIG"$'\nbuild-users-group =\nsandbox = false'
fi

if ! command -v nix >/dev/null 2>&1; then
  [[ $install_nix == true ]] || blocked 'Nix is missing; in a disposable sandbox, rerun with --install-nix'
  for tool in curl xz tar sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || blocked "install prerequisite: $tool (see .greptile/rules.md)"
  done
  if [[ ! -e /nix ]]; then
    if [[ $EUID == 0 ]]; then
      mkdir -m 0755 /nix
    elif command -v sudo >/dev/null 2>&1 && sudo -n true; then
      sudo -n install -d -m 0755 -o "$(id -u)" -g "$(id -g)" /nix
    else
      blocked 'an administrator must create /nix owned by the current user'
    fi
  fi
  [[ -w /nix ]] || blocked '/nix exists but is not writable; reuse its Nix installation or ask its administrator'

  # Official upstream installer, pinned and verified before execution. Its
  # first stage also verifies the platform-specific binary archive's hash.
  installer_dir=$(mktemp -d -t nix-nftypes-review.XXXXXXXX)
  trap 'rm -f -- "$installer_dir/install"; rmdir -- "$installer_dir"' EXIT
  curl --proto '=https' --tlsv1.2 -fsSL \
    https://releases.nixos.org/nix/nix-2.34.6/install \
    -o "$installer_dir/install"
  printf '%s  %s\n' \
    bf6d12da4aeaae38ab509dc736df648597bcdee051046ea76d3d53d5b18fa54a \
    "$installer_dir/install" | sha256sum --check --status
  sh "$installer_dir/install" --no-daemon --yes --no-channel-add --no-modify-profile
fi

command -v nix >/dev/null 2>&1 || blocked 'the installer did not provide a Nix executable'
nix --version
nix develop --no-write-lock-file .#review --command bash -euo pipefail -c '
  nft --version
  if ! unshare -rn true; then
    echo "Review environment blocked: private user/network namespaces are unavailable." >&2
    echo "The sandbox provider must supply those capabilities; see .greptile/rules.md." >&2
    exit 125
  fi
  if ! unshare -rn nft -c -f - <<< "table inet review_probe {
    chain input {
      type filter hook input priority 0; policy accept;
    }
  }"; then
    echo "Review environment blocked: the nftables parser/kernel probe failed (see error above)." >&2
    exit 125
  fi
  echo "Review environment ready: Nix, pinned nftables, and private namespaces."
  exec "$@"
' review-env "$@"
