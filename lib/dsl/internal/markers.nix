_:

# Private marker attribute names used to tag DSL-internal nodes in the
# declarative tree. These must not collide with any JSON-schema field name;
# the `__` prefix makes them visually distinctive and unlikely to appear
# in nftables output. The renderer strips them before emitting commands.

{
  table = "__nftTable";
}
