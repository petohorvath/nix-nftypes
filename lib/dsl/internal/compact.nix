{ lib }:

# Drop null-valued attrs. Used before wrapping into a tagged shape so that
# optional args omitted by the user don't appear as `{ foo = null; }` in the
# intermediate value. The renderer also strips them, but doing it here keeps
# debug output readable.
lib.filterAttrs (_: v: v != null)
