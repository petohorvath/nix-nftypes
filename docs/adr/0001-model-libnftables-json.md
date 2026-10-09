# Model libnftables JSON and treat JSON as the compatibility target

The schema types libnftables JSON rather than the nftables text grammar, and the JSON renderer is the compatibility target: when JSON and text disagree, JSON wins. The text grammar cannot spell every JSON-valid value (reserved words such as `offload`, no escape syntax for quoted strings), so the text renderer is a secondary form that carries its own, narrower evidence and refuses what it cannot spell.

## Evidence

- `a987379` (initial commit) introduces "typed Nix bindings for libnftables-json" with a `toJSON` renderer; `1b1b172` adds text later as a "second renderer alongside `toJSON`" that consumes the same cleaned values.
- `README.md` states "The **JSON path is the compatibility target**"; `docs/api.md` states "The JSON renderer is authoritative when JSON and text grammar capabilities differ".
- `docs/text-coverage.md` "Support policy" tells callers to use `toJson` when names interact with text keywords or when text-path evidence is missing.
