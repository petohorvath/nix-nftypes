_:

# Shared predicate for nft's quoted-string positions (`comment "…"`,
# `log prefix "…"`). nft has no string-escape grammar — the lexer ends a
# quoted token at the next bare `"`, treats `\` as a literal byte, and
# control characters (incl. NUL/\n) corrupt the rendered output. The
# regex below covers the exact subset that's safe to emit; both the
# schema type (`nftQuotedString`) and the text renderer's defense-in-depth
# `escape` assert use it so neither path can drift from the other.

let
  # Match-all (no anchoring needed — builtins.match implicitly anchors).
  regex = ''[^"\\[:cntrl:]]*'';
  isSafe = s: builtins.match regex s != null;
in
{
  inherit regex isSafe;
}
