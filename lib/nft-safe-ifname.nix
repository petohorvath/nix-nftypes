/*
  Shared predicate for interface names. The text renderer quotes every
  value it knows to be an interface name (ADR 0004), so a name needs only
  what a quoted string needs (no `"`, `\`, or control characters) and what
  the kernel's `dev_valid_name` needs: 1 to 15 bytes (IFNAMSIZ - 1), not
  `.` or `..`, and no `/`, `:`, or whitespace. The kernel's `isspace` reads
  bytes as Latin-1, so whitespace includes byte 0xA0, which UTF-8 uses in
  U+00A0 (no-break space), U+00E0, U+0420 and more.

  The schema type (`primitives.types.ifname`) and the renderer's
  `quoteIfname` (lib/text/primitives.nix) both consult this predicate, so
  the two layers cannot drift.
*/
_:

let
  # Bytes excluded from an interface name. `[:space:]` covers ASCII
  # whitespace; `[:cntrl:]` covers NUL..0x1F + DEL. `\\` is the
  # regex-escaped backslash, matching one literal `\` byte.
  regex = ''[^/:"\\[:space:][:cntrl:]]*'';

  # Byte 0xA0 alone: the second byte of U+00A0's UTF-8 encoding.
  byteA0 = builtins.substring 1 1 (builtins.fromJSON ''"\u00a0"'');

  isSafe =
    s:
    builtins.isString s
    && builtins.stringLength s >= 1
    && builtins.stringLength s <= 15
    && s != "."
    && s != ".."
    && builtins.match regex s != null
    && builtins.replaceStrings [ byteA0 ] [ "" ] s == s;
in
{
  inherit isSafe regex;
}
