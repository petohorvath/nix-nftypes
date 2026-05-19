_:

# Shared predicate for the bare-string atoms that the text renderer
# emits unquoted at expression scalar position — IP addresses
# (`192.0.2.1`, `2001:db8::1`), set/map references (`@trusted`),
# ICMP type names (`host-unreachable`), enum-like names (`established`).
# `renderScalar` outputs the string byte-for-byte, so any whitespace
# or nft-grammar metacharacter would either split the token or break
# the parser context — at rule scope a newline + `add chain …` payload
# silently appends an attacker-controlled chain.
#
# The regex below covers the exact subset that's safe at this
# position; both the schema's expression-string branch (via
# `nftSafeScalar`) and the renderer's defence-in-depth assert in
# `lib/text/expressions.nix renderScalar` use it so neither path can
# drift from the other.

let
  # Forbidden byte set:
  #   - `,` `;` `{` `}` `"` `\` `#`  parser-meta in scope context
  #   - `[:space:]`                  whitespace (incl. newline/tab)
  #                                  would split a single scalar into
  #                                  multiple tokens
  #   - `[:cntrl:]`                  control characters (NUL, DEL, …)
  #
  # Non-empty: a zero-byte scalar carries no meaning at this position
  # and would also be rendered as a syntactically empty token.
  regex = ''[^,;{}"\\#[:space:][:cntrl:]]+'';
  isSafe = s: builtins.match regex s != null;
in
{
  inherit regex isSafe;
}
